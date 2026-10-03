//! What a title WRITES, learned from witness words the loader paints.
//!
//! WHY THIS EXISTS
//!
//! `game-memory.tsv` learned where disc reads land, because every read this
//! host serves names its destination. What a title writes with the CPU -- a
//! heap, a file decompressed out of a read buffer, a table -- passes through
//! nothing the host can see. Measured 2026-09-30 on Shenmue II: at the end of a
//! cinematic the title writes ~2 KB at 0x8cfd0000, in a block no read had ever
//! touched, and a loader placed there was overwritten -- a silent reset,
//! reproducible, with the map saying the block was free.
//!
//! HOW
//!
//! Before EXEC the host asks the loader to paint the RAM no read has landed in
//! (`MARK`, `cmd_mark` in dcload-ip's commands.c): one word every 256 bytes,
//! each holding its own address XOR a key. While the title runs it asks, a few
//! blocks at a time, which 64 KB blocks still carry every word, and records
//! the others in the same map, merged by OR like everything else there. The
//! next session's placement pass then avoids them with no new rule.
//!
//! The loader does both halves: painting 16 MB over the network would take
//! seconds, and it takes milliseconds there; a check is one datagram each way
//! instead of a SendBinQ per sample.
//!
//! WHAT IT CANNOT SEE
//!
//! - The loader's own span, which is not painted. A title that writes where
//!   the loader is was not observed doing so; the next session, with the
//!   loader elsewhere, observes that block like any other.
//! - A write smaller than the 256-byte stride that misses every sample.
//! - Windows CE titles, which are not painted: their placement comes from
//!   their ROM header, and their kernel owns the RAM.
//!
//! WHAT IT COSTS THE TITLE
//!
//! Nothing it can notice before EXEC (a few milliseconds of painting). While it
//! runs, one check of `SLICE_BLOCKS` clean blocks is ~4096 purges and uncached
//! reads, about a millisecond, answered from inside a GD wait or the interrupt
//! tick like every SendBinQ -- once every `INTERVAL`.
//!
//! RAM the title has not written is not what a real boot leaves there: it is
//! mostly zero after the BIOS, and here one word in 64 is not. Titles run from
//! a chainloaded loader already find whatever the previous session left in
//! RAM, so no title can rely on it; `--no-marks` turns this off all the same.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::cmds::{DCLoadCmd, DCLoadCmds, DCReturnCmd};
use crate::io::{ExternalDcIo, PacketSink};
use crate::memmap::{BLOCK, BLOCKS, MemoryMap, MemoryRecorder};

/// `size` bit 31: check instead of paint.
const CHECK: u32 = 0x8000_0000;
/// The loader's refusal: the range reached something of its own.
const REFUSED: u32 = 0xffff_ffff;
/// The most one command may cover (the loader refuses more): 16 MB.
const MAX_RUN_BLOCKS: usize = 256;
/// Clean blocks per check while the title runs. See the module header.
const SLICE_BLOCKS: usize = 16;
/// One check this often. A whole sweep of ~200 painted blocks is then ~13 s.
const INTERVAL: Duration = Duration::from_secs(1);
/// The same, once the console has stopped answering (a title that no longer
/// reads its disc no longer looks at the wire). See `stackwatch`.
const QUIET_INTERVAL: Duration = Duration::from_secs(30);
const QUIET_AFTER: u32 = 6;
const TIMEOUT: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_millis(500);
/// Before EXEC: one answer per paint command, retried like a MAPL.
const PAINT_TIMEOUT: Duration = Duration::from_millis(500);
const PAINT_TRIES: usize = 3;

/// Which 64 KB blocks to paint: every whole block above the title's image,
/// minus what is already known to be used and anything of the loader's.
///
/// ABOVE THE IMAGE because below it are the BIOS work area, IP.BIN, the guest
/// VBR and the title's own code; nothing there is a place for a loader, and
/// some of it is read before the title writes it. The image's BSS is painted
/// and then zeroed by the title's crt0, which marks those blocks as used --
/// which they are.
pub fn blocks_to_paint(image_end: u32, base: u32, known: &MemoryMap) -> Vec<usize> {
    let end = (image_end & 0x1fff_ffff) | 0x8c00_0000;
    let first = (end.saturating_sub(0x8c00_0000)).div_ceil(BLOCK) as usize;
    (first..BLOCKS)
        .filter(|&b| !known.is_marked(b))
        .filter(|&b| {
            let lo = MemoryMap::block_addr(b);
            crate::loaders::overlapping_range(base, (lo, lo + BLOCK)).is_none()
        })
        .collect()
}

/// Consecutive blocks as `(first block, count)`, none longer than `max`.
fn runs(blocks: &[usize], max: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = vec![];
    for &b in blocks {
        match out.last_mut() {
            Some((first, n)) if *first + *n == b && *n < max => *n += 1,
            _ => out.push((b, 1)),
        }
    }
    out
}

fn command(first: usize, n: usize, check: bool) -> DCLoadCmd {
    DCLoadCmd {
        cmd: DCLoadCmds::Mark(None),
        address: MemoryMap::block_addr(first),
        size: (n as u32 * BLOCK) | if check { CHECK } else { 0 },
    }
}

/// The MARK reply to `addr` among `replies`: its `size` and payload.
fn reply_to(replies: &[DCReturnCmd], addr: u32) -> Option<(u32, Vec<u8>)> {
    replies.iter().find_map(|r| {
        let c = r.cmd.as_ref()?;
        match &c.cmd {
            DCLoadCmds::Mark(bits) if c.address == addr => {
                Some((c.size, bits.clone().unwrap_or_default()))
            }
            _ => None,
        }
    })
}

/// Paint `blocks`. Before EXEC only: it blocks on each answer.
///
/// An error means nothing may be checked this session: a loader without MARK
/// (older than 2026-09-30) never answers, and one that refused a range has
/// said the host's idea of its footprint is wrong.
pub fn paint(conn: &mut impl ExternalDcIo, blocks: &[usize]) -> Result<(), String> {
    for (first, n) in runs(blocks, MAX_RUN_BLOCKS) {
        let cmd = command(first, n, false);
        let addr = cmd.address;
        let mut answer = None;
        'tries: for _ in 0..PAINT_TRIES {
            conn.send_command(cmd.clone()).map_err(|e| e.to_string())?;
            let deadline = Instant::now() + PAINT_TIMEOUT;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                // Keep waiting when a batch is not ours: the socket may still
                // hold the tail of the upload (see vm2::transact).
                let Ok(replies) = crate::dispatch::await_result(conn, Some(left)) else {
                    break;
                };
                if let Some((size, _)) = reply_to(&replies, addr) {
                    answer = Some(size);
                    break 'tries;
                }
            }
        }
        match answer {
            None => {
                return Err("the loader does not answer MARK (a build older than \
                            2026-09-30?)"
                    .into());
            }
            Some(REFUSED) => {
                return Err(format!(
                    "the loader refused to paint 0x{addr:08x}+0x{:x}: it overlaps the \
                     loader's own memory, so this host's layout table is wrong",
                    n as u32 * BLOCK
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Where replies land: inside whatever transfer is polling (`io::PacketSink`).
struct Sink {
    want: Option<u32>,
    done: Option<(u32, Vec<u8>)>,
}

impl PacketSink for Sink {
    /// Every MARK is ours -- nothing else on this host sends one -- including
    /// a late answer to a request already given up on, which must not reach
    /// the syscall loop.
    fn claim(&mut self, cmd: &DCReturnCmd) -> bool {
        let Some(inner) = cmd.cmd.as_ref() else {
            return false;
        };
        let DCLoadCmds::Mark(bits) = &inner.cmd else {
            return false;
        };
        if self.want == Some(inner.address) {
            self.want = None;
            self.done = Some((inner.size, bits.clone().unwrap_or_default()));
        }
        true
    }
}

/// The check while the title runs. Ticked from the top of the syscall loop,
/// like `stackwatch::StackWatch`, and for the same reason.
pub struct MarkWatch {
    sink: Arc<Mutex<Sink>>,
    recorder: Arc<Mutex<MemoryRecorder>>,
    /// Painted blocks not yet seen written, in address order.
    clean: Vec<usize>,
    /// Where the next slice starts, as an index into `clean`.
    cursor: usize,
    /// The slice on the wire: first block, count.
    asked: Option<(usize, usize)>,
    started: Option<Instant>,
    last_sent: Instant,
    next_at: Instant,
    misses: u32,
}

impl MarkWatch {
    pub fn new(painted: Vec<usize>, recorder: Arc<Mutex<MemoryRecorder>>) -> Self {
        MarkWatch {
            sink: Arc::new(Mutex::new(Sink { want: None, done: None })),
            recorder,
            clean: painted,
            cursor: 0,
            asked: None,
            started: None,
            last_sent: Instant::now(),
            next_at: Instant::now() + INTERVAL,
            misses: 0,
        }
    }

    pub fn install(&self, conn: &mut impl ExternalDcIo) {
        conn.add_sink(self.sink.clone() as crate::io::SharedSink);
    }

    /// The next run of consecutive clean blocks, from the cursor.
    fn next_slice(&mut self) -> Option<(usize, usize)> {
        if self.clean.is_empty() {
            return None;
        }
        if self.cursor >= self.clean.len() {
            self.cursor = 0;
        }
        let first = self.clean[self.cursor];
        let mut n = 1;
        while n < SLICE_BLOCKS
            && self.cursor + n < self.clean.len()
            && self.clean[self.cursor + n] == first + n
        {
            n += 1;
        }
        self.cursor += n;
        Some((first, n))
    }

    /// Apply one answer: `size` bytes of bitmap for the slice asked.
    fn apply(&mut self, (first, n): (usize, usize), size: u32, bits: &[u8]) {
        if size == REFUSED {
            warn!(
                "memory marks: the loader refused to check 0x{:08x}+0x{:x}; no more checks \
                 this session",
                MemoryMap::block_addr(first),
                n as u32 * BLOCK
            );
            self.clean.clear();
            return;
        }
        let written: Vec<usize> = (0..n)
            .filter(|&i| bits.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0))
            .map(|i| first + i)
            .collect();
        if written.is_empty() {
            return;
        }
        if let Ok(mut rec) = self.recorder.lock() {
            for &b in &written {
                rec.record_written(MemoryMap::block_addr(b), BLOCK);
            }
        }
        // Written once is written: never asked about again. The cursor stays
        // on the block after the slice.
        let before = self.clean.len();
        self.clean.retain(|b| !written.contains(b));
        let removed_before_cursor = before - self.clean.len();
        self.cursor = self.cursor.saturating_sub(removed_before_cursor);
    }

    pub fn tick(&mut self, conn: &mut impl ExternalDcIo) {
        let done = self.sink.lock().expect("sink poisoned").done.take();
        if let (Some((size, bits)), Some(slice)) = (done, self.asked) {
            self.asked = None;
            self.started = None;
            self.misses = 0;
            self.next_at = Instant::now() + INTERVAL;
            self.apply(slice, size, &bits);
        }
        if let Some(started) = self.started
            && started.elapsed() > TIMEOUT
        {
            self.sink.lock().expect("sink poisoned").want = None;
            self.asked = None;
            self.started = None;
            self.misses = self.misses.saturating_add(1);
            debug!("memory marks: no answer ({} in a row)", self.misses);
            self.next_at = Instant::now() + self.interval();
        }
        if self.started.is_none() {
            if Instant::now() < self.next_at {
                return;
            }
            let Some(slice) = self.next_slice() else {
                return;
            };
            self.asked = Some(slice);
            self.sink.lock().expect("sink poisoned").want = Some(MemoryMap::block_addr(slice.0));
            self.started = Some(Instant::now());
            self.last_sent = Instant::now() - RETRY;
        }
        if self.last_sent.elapsed() < RETRY {
            return;
        }
        let Some((first, n)) = self.asked else {
            return;
        };
        if let Err(e) = conn.send_command(command(first, n, true)) {
            debug!("memory marks: could not ask: {e}");
            self.sink.lock().expect("sink poisoned").want = None;
            self.asked = None;
            self.started = None;
            self.next_at = Instant::now() + self.interval();
            return;
        }
        self.last_sent = Instant::now();
    }

    fn interval(&self) -> Duration {
        if self.misses >= QUIET_AFTER {
            QUIET_INTERVAL
        } else {
            INTERVAL
        }
    }

    /// How long the syscall loop may block before this wants the CPU again.
    pub fn poll_timeout(&self) -> Option<Duration> {
        if self.clean.is_empty() && self.started.is_none() {
            return None;
        }
        let due = match self.started {
            Some(started) => (started + TIMEOUT).min(self.last_sent + RETRY),
            None => self.next_at,
        };
        Some(due.saturating_duration_since(Instant::now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorder() -> Arc<Mutex<MemoryRecorder>> {
        Arc::new(Mutex::new(MemoryRecorder::new(
            std::env::temp_dir().join("dcload-marks-unused.tsv"),
            "md5",
            "A GAME",
            MemoryMap::new(),
        )))
    }

    /// Shenmue II with the loader at 0x8cfe0000 and its reads known: what is
    /// painted starts above the image, skips the known blocks and the loader.
    #[test]
    fn paints_above_the_image_around_the_known_and_the_loader() {
        let mut known = MemoryMap::new();
        known.mark(0x8ccf_0000, 2 * BLOCK);
        let blocks = blocks_to_paint(0x8c32_c428, 0x8cfe_0000, &known);
        assert_eq!(blocks.first(), Some(&0x33), "the first WHOLE block past the image");
        assert!(!blocks.contains(&0xcf) && !blocks.contains(&0xd0), "known blocks");
        assert!(!blocks.contains(&0xfe), "the loader's own span");
        assert!(blocks.contains(&0xfd) && blocks.contains(&0xff));
        // A LOW loader keeps its buffers at 0x8cfe8000: that block is its own.
        let low = blocks_to_paint(0x8c32_c428, crate::loaders::DEFAULT_BASE, &MemoryMap::new());
        assert!(!low.contains(&0xfe) && low.contains(&0xfd));
    }

    #[test]
    fn runs_are_consecutive_and_bounded() {
        assert_eq!(runs(&[1, 2, 3, 7, 8, 20], 2), vec![(1, 2), (3, 1), (7, 2), (20, 1)]);
        let c = command(0xfd, 3, true);
        assert_eq!((c.address, c.size), (0x8cfd_0000, 0x8003_0000));
    }

    /// A block seen written is recorded and never asked about again; the
    /// sweep goes on from where it was.
    #[test]
    fn a_written_block_is_recorded_once_and_dropped_from_the_sweep() {
        let rec = recorder();
        let mut w = MarkWatch::new(vec![0xfb, 0xfc, 0xfd, 0xff], rec.clone());
        let slice = w.next_slice().unwrap();
        assert_eq!(slice, (0xfb, 3), "0xfe is not painted, so the run stops there");
        w.apply(slice, 1, &[0b010]);
        assert!(rec.lock().unwrap().known().is_marked(0xfc));
        assert_eq!(w.clean, vec![0xfb, 0xfd, 0xff]);
        assert_eq!(w.next_slice(), Some((0xff, 1)));
        assert_eq!(w.next_slice(), Some((0xfb, 1)), "then round again");
        w.apply((0xfb, 1), REFUSED, &[]);
        assert!(w.clean.is_empty() && w.next_slice().is_none());
    }

    /// Every MARK is claimed, but only the awaited one completes the check.
    #[test]
    fn the_sink_takes_every_mark_and_completes_only_its_own() {
        let mut s = Sink { want: Some(0x8cfd_0000), done: None };
        let reply = |addr| DCReturnCmd {
            cmd: Some(DCLoadCmd { cmd: DCLoadCmds::Mark(Some(vec![1])), address: addr, size: 1 }),
            request: None,
            error_code: None,
        };
        assert!(s.claim(&reply(0x8cfc_0000)));
        assert!(s.done.is_none());
        assert!(s.claim(&reply(0x8cfd_0000)));
        assert_eq!(s.done, Some((1, vec![1])));
    }
}
