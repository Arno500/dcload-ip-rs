//! Random access into a deflate stream, so a zipped disc image never has to be
//! unpacked.
//!
//! # The problem
//!
//! A zip member compressed with deflate is one continuous stream: byte
//! 900 000 000 of a 1.1 GB track cannot be read without having decoded
//! everything before it. The three usual answers are all bad here -- unpack the
//! archive (what we are trying to avoid), hold the whole image in RAM (1.1 GB),
//! or re-inflate from the start on every seek (seconds per read, while a
//! Dreamcast title is frozen waiting for its sector).
//!
//! # What is done instead
//!
//! Deflate has no restart points, but it does have BLOCK boundaries, and at a
//! block boundary a decoder's entire state is (a) which bit of the input comes
//! next and (b) the last 32 KiB of output. `miniz_oxide`'s `block-boundary`
//! feature exposes both: `BlockBoundaryState` is five small fields, and the
//! window is a plain 32 KiB copy. So one pass over the stream records a
//! checkpoint every megabyte or so, and a read afterwards resumes from the
//! nearest one and inflates forward at most that far.
//!
//! What it costs, measured on the 1.10 GiB Sonic Adventure data track (1.01 GiB
//! deflated, on a WSL DrvFs mount):
//!
//! | | cost |
//! | --- | --- |
//! | one-off index pass | 4.7 s, before the title starts |
//! | index in RAM | 32 KiB per checkpoint, budgeted to 64 MiB per member |
//! | a sequential read | 0.28 ms per 16 KiB -- the cursor is already there |
//! | reads interleaved across 3 files | 0.34 ms |
//! | a random read | 3.5 ms mean, 7.8 ms worst |
//!
//! The worst case is still an order of magnitude faster than a seek on the
//! GD-ROM drive this is emulating, and the two common cases are not seeks at
//! all.
//!
//! # Where that 4.7 s went, because guessing was wrong
//!
//! It was 13 s. In order of what it cost:
//!
//! - **Reading was 58 % of it**, not inflating. One reader gets 211 MB/s off
//!   this mount and four get 467 MB/s, so [`CompressedFeed`] reads ahead on
//!   four threads and the decoder now waits 0.04 s in total. -4.3 s.
//! - **The CRC was byte-at-a-time**, a dependent chain through one table.
//!   Slice-by-16 took it from ~3 s to 0.5 s.
//! - A bigger output ring was tried and does nothing (see [`RING`]); the
//!   per-call overhead is not where the time is.
//!
//! What is left is 3.8 s of inflate, which is `miniz_oxide` running at
//! ~310 MB/s on one thread. Going faster than that means decoding blocks in
//! parallel (speculatively finding boundaries, then repairing the
//! back-references that reach before each thread's start) -- a large and subtle
//! piece of work, and the reason it is not here.
//!
//! # The index pass is also the only correctness proof there is
//!
//! It has to decode every byte anyway, so it checksums them and compares
//! against the CRC-32 the zip's central directory carries. A disc reader that
//! hands a running title plausible-but-wrong bytes is the worst failure mode
//! there is (see the `cdi` module for the last time that happened), and here it
//! is ruled out for the whole member before the first sector is served.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex, OnceLock};

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{
    BlockBoundaryState, DecompressorOxide, decompress, inflate_flags::*,
};

use crate::disc_formats::source::ImageSource;

/// Deflate's maximum back-reference distance, and therefore the exact amount of
/// history a checkpoint has to carry.
const WINDOW: usize = 32768;

/// The index pass's output ring. Must be a power of two and at least `WINDOW`,
/// which is all the decoder requires; beyond that it only trades memory for
/// fewer returns from `decompress`.
///
/// Left at the minimum deliberately. Measured at 256 KiB on the 1.10 GiB Sonic
/// Adventure track: calls into `decompress` fell from 71098 to 39436 and the
/// inflate time did not move (3.79 s against 3.77 s). The per-call overhead is
/// not where the time goes, so the memory buys nothing.
const RING: usize = WINDOW;

/// How much RAM the whole checkpoint table may take, so that a 40 MB image and
/// a 1.1 GB one cost about the same and the big one simply gets coarser
/// checkpoints.
///
/// THIS IS A LATENCY KNOB, not a memory one. A random read costs an inflate of
/// at most one spacing, and the spacing is the member's size divided by
/// `budget / 32 KiB`. Measured on the Sonic Adventure PAL GDI (1.10 GiB
/// deflated, random 16 KiB reads, warm index):
///
/// | budget | spacing | random read |
/// | --- | --- | --- |
/// | 24 MiB | 1.45 MiB | 10.3 ms mean, 19.1 ms worst |
/// | 64 MiB | 576 KiB | 3.5 ms mean, 7.8 ms worst |
///
/// Only a genuine SEEK pays this. A title streaming a file, or reading a few
/// of them at once, is served by a cursor for ~0.3 ms and never consults the
/// table at all -- see [`CURSORS`]. And the drive being emulated here takes
/// upwards of 100 ms to do a seek.
///
/// 64 MiB is the default because the thing on the other end of this is a
/// Dreamcast title that is FROZEN for the duration of the read (AGENTS.md 16),
/// and RAM on the host side is the cheapest thing in the system. Override with
/// `DCLOAD_ZIP_INDEX_BUDGET` in MiB.
///
/// PER MEMBER, not per process. Each indexed member gets its own table and
/// [`INDEX_CACHE`] keeps them all, so a zipped GDI whose data tracks are both
/// deflated holds two. In practice only the track being read is ever indexed --
/// `Gdi::num_sectors` opens the last data track and nothing opens the others --
/// but a dump that splits the high-density area across several tracks would
/// pay per track.
fn index_budget() -> u64 {
    static BUDGET: OnceLock<u64> = OnceLock::new();
    *BUDGET.get_or_init(|| {
        std::env::var("DCLOAD_ZIP_INDEX_BUDGET")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|mib| *mib > 0)
            .map(|mib| mib << 20)
            .unwrap_or(64 << 20)
    })
}

/// Never checkpoint more finely than this. Below it the table stops buying
/// anything the cursor's own forward run was not already going to give.
const MIN_SPACING: u64 = 256 << 10;

/// How much compressed data the cursor reads at a time while catching up.
const CURSOR_READ: usize = 64 * 1024;

/// The cursor's decompressed working buffer, on top of the 32 KiB of history it
/// must always keep. Reads land inside it; only when it fills does the cursor
/// slide, keeping the history.
const CURSOR_SPAN: usize = 256 * 1024;

/// How many places in the stream stay open at once.
///
/// A cursor can only go FORWARDS, so with one of them a title that interleaves
/// two files -- a level being loaded while music streams, which is the normal
/// shape of a Dreamcast title's disc traffic -- turns every single read into a
/// restart from a checkpoint.
///
/// Measured on the 1.10 GiB Sonic Adventure track, three streams read
/// round-robin (`three_interleaved_streams_do_not_thrash` in `zip.rs`):
///
/// | cursors | mean read |
/// | --- | --- |
/// | 1 | 3.59 ms |
/// | 2 | 3.86 ms |
/// | 4 | 0.35 ms |
/// | 8 | 0.33 ms |
///
/// Four already fixes three streams. Eight is what is here because of the
/// shape of that table: being ONE cursor short of the number of streams a
/// title keeps open costs a factor of ten, and each spare costs 288 KiB
/// against an index already budgeted 64 MiB. There is no graceful middle to
/// aim at, so the cheap side is the right one to err on.
const CURSORS: usize = 8;

/// How much compressed data one read asks for.
///
/// Measured indexing a 1.0 GiB member off a WSL DrvFs mount, single reader:
/// 256 KiB -> 5.83 s, 1 MiB -> 5.09 s, 4 MiB -> 4.84 s. The mount charges per
/// call, and past a few megabytes there is nothing left to win.
const READ_CHUNK: usize = 4 << 20;

/// How many of those are in flight at once.
///
/// Same mount, whole file: one reader 211 MB/s, four readers 467 MB/s. The
/// filesystem is not the bottleneck, the round trip to it is, so the fix is to
/// have several outstanding rather than to ask for more per call.
const READ_THREADS: usize = 4;

/// Hands the decoder its next compressed bytes, ideally before it asks.
///
/// Reading and inflating used to take turns, which wasted whichever of the two
/// was faster -- 4.84 s of reading and 4.15 s of inflating, 9 s of wall clock
/// for 9 s of work that could have been 5. The threads here read ahead into a
/// bounded queue, so the pass costs the SLOWER of the two and not the sum.
///
/// Ordering is by construction rather than by sorting: reader `t` takes chunks
/// `t`, `t + N`, `t + 2N`, ... and the consumer takes from reader `k % N` for
/// chunk `k`. Each queue holds one chunk, so a reader that falls behind stalls
/// itself and nothing else, and at most `N * 2` chunks are ever in memory.
struct CompressedFeed<'a> {
    comp: &'a dyn ImageSource,
    pos: u64,
    len: u64,
    threaded: Option<Threaded>,
}

struct Threaded {
    rxs: Vec<std::sync::mpsc::Receiver<io::Result<Vec<u8>>>>,
    next: usize,
}

impl<'a> CompressedFeed<'a> {
    fn new(comp: &'a dyn ImageSource) -> Self {
        let len = comp.len();
        let mut rxs = Vec::new();
        // Not worth threads for something that fits in a couple of reads, and
        // a source with nothing to gain (bytes already in RAM) says so by
        // handing out no handles at all.
        if len > (2 * READ_CHUNK) as u64 {
            for t in 0..READ_THREADS {
                let Some(src) = comp.thread_handle() else {
                    rxs.clear();
                    break;
                };
                let (tx, rx) = std::sync::mpsc::sync_channel::<io::Result<Vec<u8>>>(1);
                let start = (t * READ_CHUNK) as u64;
                std::thread::spawn(move || {
                    let mut at = start;
                    while at < len {
                        let n = (READ_CHUNK as u64).min(len - at) as usize;
                        let mut buf = vec![0u8; n];
                        let result = src.read_at(at, &mut buf).map(|()| buf);
                        let failed = result.is_err();
                        // A send error means the consumer is gone -- an error
                        // further along, or the whole index abandoned.
                        if tx.send(result).is_err() || failed {
                            return;
                        }
                        at += (READ_THREADS * READ_CHUNK) as u64;
                    }
                });
                rxs.push(rx);
            }
        }
        let threaded = (!rxs.is_empty()).then_some(Threaded { rxs, next: 0 });
        Self {
            comp,
            pos: 0,
            len,
            threaded,
        }
    }

    fn remaining(&self) -> u64 {
        self.len - self.pos
    }

    fn threads(&self) -> usize {
        self.threaded.as_ref().map_or(0, |t| t.rxs.len())
    }

    fn next(&mut self) -> io::Result<Vec<u8>> {
        let want = (READ_CHUNK as u64).min(self.remaining()) as usize;
        let buf = match self.threaded.as_mut() {
            Some(t) => {
                let rx = &t.rxs[t.next];
                t.next = (t.next + 1) % t.rxs.len();
                rx.recv().map_err(|_| {
                    io::Error::other("a prefetch thread stopped before the stream ended")
                })??
            }
            None => {
                let mut b = vec![0u8; want];
                self.comp.read_at(self.pos, &mut b)?;
                b
            }
        };
        if buf.len() != want {
            return Err(io::Error::other(format!(
                "prefetch delivered {} bytes where {want} were expected",
                buf.len()
            )));
        }
        self.pos += buf.len() as u64;
        Ok(buf)
    }
}

struct Checkpoint {
    /// Compressed-stream offset of the first byte that has NOT been consumed.
    /// The bits of the byte before it that the next block still needs live in
    /// `state.bit_buf` / `state.num_bits`.
    in_pos: u64,
    /// Uncompressed offset this checkpoint sits at.
    out_pos: u64,
    state: BlockBoundaryState,
    /// The up-to-32 KiB of output immediately preceding `out_pos`.
    window: Vec<u8>,
}

pub struct DeflateIndex {
    checkpoints: Vec<Checkpoint>,
    pub uncompressed_len: u64,
}

impl DeflateIndex {
    /// One pass over the member: index it and check it.
    ///
    /// `comp` must be a source covering exactly the member's compressed bytes,
    /// addressed from zero.
    pub fn build(
        comp: &dyn ImageSource,
        uncompressed_len: u64,
        expected_crc: u32,
        label: &str,
    ) -> io::Result<Self> {
        let comp_len = comp.len();
        let budget_entries = (index_budget() / WINDOW as u64).max(1);
        let spacing = (uncompressed_len / budget_entries).max(MIN_SPACING);

        debug!(
            "indexing deflate member {label}: {comp_len} compressed -> {uncompressed_len} \
             bytes, checkpoint every {spacing} bytes"
        );

        let mut dec = DecompressorOxide::new();
        // The ring is exactly the deflate window: nothing further back can be
        // referenced, so nothing further back has to be kept.
        let mut ring = vec![0u8; RING];
        let mut ring_pos = 0usize;

        // A deflate stream begins at a block boundary with no history, and the
        // default `BlockBoundaryState` is that state exactly -- so entry zero
        // costs nothing and removes the "before the first checkpoint" case that
        // every read would otherwise have to special-case.
        let mut checkpoints = vec![Checkpoint {
            in_pos: 0,
            out_pos: 0,
            state: BlockBoundaryState::default(),
            window: Vec::new(),
        }];
        let mut last_checkpoint = 0u64;

        let mut feed = CompressedFeed::new(comp);
        let mut in_buf: Vec<u8> = Vec::new();
        let mut buf_base = 0u64;
        let mut consumed = 0u64;
        let mut total_out = 0u64;
        let mut crc = Crc32::new();

        let bar = crate::ui::bytes_bar(uncompressed_len, format!("index {label}"));

        // WHERE THE TIME GOES, because guessing was wrong twice. Reading the
        // compressed bytes, inflating them and checksumming them are three
        // different costs with three different fixes, and the split is the only
        // thing that says which one to work on.
        let mut t_read = Duration::ZERO;
        let mut t_inflate = Duration::ZERO;
        let mut t_crc = Duration::ZERO;
        let mut calls = 0u64;
        let mut boundaries = 0u64;

        loop {
            if consumed == buf_base + in_buf.len() as u64 && feed.remaining() > 0 {
                buf_base = consumed;
                let t = Instant::now();
                in_buf = feed.next()?;
                t_read += t.elapsed();
            }
            let off = (consumed - buf_base) as usize;
            let have = in_buf.len();
            // "Is there input after what I am handing over now" -- which is
            // what TINFL_FLAG_HAS_MORE_INPUT means, and getting it wrong at the
            // very end turns a finished stream into a corrupt one.
            let more_input = feed.remaining() > 0;
            let flags = TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY
                | if more_input {
                    TINFL_FLAG_HAS_MORE_INPUT
                } else {
                    0
                };

            let t = Instant::now();
            let (status, used_in, used_out) =
                decompress(&mut dec, &in_buf[off..have], &mut ring, ring_pos, flags);
            t_inflate += t.elapsed();
            calls += 1;

            let t = Instant::now();
            crc.update(&ring[ring_pos..ring_pos + used_out]);
            t_crc += t.elapsed();
            consumed += used_in as u64;
            total_out += used_out as u64;
            ring_pos = (ring_pos + used_out) % RING;
            bar.inc(used_out as u64);

            match status {
                TINFLStatus::BlockBoundary => {
                    boundaries += 1;
                    if total_out - last_checkpoint >= spacing
                        && let Some(state) = dec.block_boundary_state()
                    {
                        // The history preceding `ring_pos`, in order. Two slice
                        // copies rather than a byte loop with a modulo in it:
                        // this runs 32 KiB per checkpoint and there are
                        // thousands of them.
                        let have_hist = (total_out as usize).min(WINDOW);
                        let start = (ring_pos + ring.len() - have_hist) % ring.len();
                        let mut window = Vec::with_capacity(have_hist);
                        if start + have_hist <= ring.len() {
                            window.extend_from_slice(&ring[start..start + have_hist]);
                        } else {
                            window.extend_from_slice(&ring[start..]);
                            window.extend_from_slice(&ring[..have_hist - (ring.len() - start)]);
                        }
                        checkpoints.push(Checkpoint {
                            in_pos: consumed,
                            out_pos: total_out,
                            state,
                            window,
                        });
                        last_checkpoint = total_out;
                    }
                }
                TINFLStatus::HasMoreOutput | TINFLStatus::NeedsMoreInput => {
                    if used_in == 0 && used_out == 0 && !more_input {
                        drop(bar);
                        return Err(io::Error::other(format!(
                            "{label}: the deflate stream ends before the {uncompressed_len} \
                             bytes the archive says it holds ({total_out} decoded)"
                        )));
                    }
                }
                TINFLStatus::Done => break,
                other => {
                    drop(bar);
                    return Err(io::Error::other(format!(
                        "{label}: deflate stream is corrupt ({other:?} after {total_out} bytes)"
                    )));
                }
            }
        }
        drop(bar);

        if total_out != uncompressed_len {
            return Err(io::Error::other(format!(
                "{label}: decoded {total_out} bytes, the archive says {uncompressed_len}"
            )));
        }
        // The zip stores 0 for a member written with no CRC; anything else is
        // checked, because this pass is the only chance to check it.
        let got = crc.finish();
        if expected_crc != 0 && got != expected_crc {
            return Err(io::Error::other(format!(
                "{label}: CRC-32 mismatch -- decoded 0x{got:08x}, archive says \
                 0x{expected_crc:08x}. The archive is damaged; nothing read out of it \
                 could be trusted."
            )));
        }

        info!(
            "{label}: {} indexed, {} checkpoints, CRC-32 verified",
            indicatif::HumanBytes(uncompressed_len),
            checkpoints.len()
        );
        debug!(
            "{label}: waited {:.2}s on {} reader thread(s), inflate {:.2}s, crc \
             {:.2}s over {calls} calls and {boundaries} block boundaries",
            t_read.as_secs_f64(),
            feed.threads(),
            t_inflate.as_secs_f64(),
            t_crc.as_secs_f64()
        );

        Ok(Self {
            checkpoints,
            uncompressed_len,
        })
    }

    fn checkpoint_for(&self, out_pos: u64) -> &Checkpoint {
        let i = self
            .checkpoints
            .partition_point(|c| c.out_pos <= out_pos)
            .saturating_sub(1);
        &self.checkpoints[i]
    }
}

/// Built indexes, kept for the life of the process, one per member.
///
/// This is now a backstop rather than the mechanism it started as: `main` opens
/// each image once and hands the reader to identity, boot binary, IP.BIN and
/// the syscall loop, so a normal run indexes a member once because it only
/// builds one reader for it. What the cache still covers is any path that
/// builds a second reader over the same member -- two different images in one
/// run that share a track, the tests, a future caller -- where the alternative
/// is silently inflating 1.1 GB again.
///
/// Nothing is evicted. See [`index_budget`] for what that costs.
static INDEX_CACHE: OnceLock<Mutex<HashMap<String, Arc<DeflateIndex>>>> = OnceLock::new();

fn cached_index(
    key: String,
    build: impl FnOnce() -> io::Result<DeflateIndex>,
) -> io::Result<Arc<DeflateIndex>> {
    let cache = INDEX_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(map) = cache.lock()
        && let Some(found) = map.get(&key)
    {
        return Ok(found.clone());
    }
    let built = Arc::new(build()?);
    if let Ok(mut map) = cache.lock() {
        map.insert(key, built.clone());
    }
    Ok(built)
}

/// A live decoder parked somewhere in the stream, with the output it has
/// produced but not yet been asked for.
struct Cursor {
    dec: DecompressorOxide,
    /// Next compressed byte to feed.
    in_pos: u64,
    /// Uncompressed offset of the next byte to be produced.
    out_pos: u64,
    /// `buf[..fill]` holds the uncompressed range `[buf_start, out_pos)`.
    buf: Vec<u8>,
    buf_start: u64,
    fill: usize,
    in_buf: Vec<u8>,
    done: bool,
}

impl Cursor {
    fn at(cp: &Checkpoint) -> Self {
        let mut buf = vec![0u8; WINDOW + CURSOR_SPAN];
        buf[..cp.window.len()].copy_from_slice(&cp.window);
        Self {
            dec: DecompressorOxide::from_block_boundary_state(&cp.state),
            in_pos: cp.in_pos,
            out_pos: cp.out_pos,
            buf,
            buf_start: cp.out_pos - cp.window.len() as u64,
            fill: cp.window.len(),
            in_buf: vec![0u8; CURSOR_READ],
            done: false,
        }
    }

    /// Decode forward until `out_pos` is past `upto`.
    fn advance_past(&mut self, comp: &dyn ImageSource, upto: u64) -> io::Result<()> {
        let comp_len = comp.len();
        while self.out_pos <= upto && !self.done {
            if self.fill == self.buf.len() {
                // Slide, keeping exactly the history the decoder may still
                // reference. Everything older is unreachable by construction.
                self.buf.copy_within(self.fill - WINDOW.., 0);
                self.buf_start += (self.fill - WINDOW) as u64;
                self.fill = WINDOW;
            }
            let n = (self.in_buf.len() as u64).min(comp_len - self.in_pos) as usize;
            if n > 0 {
                comp.read_at(self.in_pos, &mut self.in_buf[..n])?;
            }
            let more_input = (self.in_pos + n as u64) < comp_len;
            let flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
                | if more_input {
                    TINFL_FLAG_HAS_MORE_INPUT
                } else {
                    0
                };
            let (status, used_in, used_out) = decompress(
                &mut self.dec,
                &self.in_buf[..n],
                &mut self.buf,
                self.fill,
                flags,
            );
            self.in_pos += used_in as u64;
            self.fill += used_out;
            self.out_pos += used_out as u64;
            match status {
                TINFLStatus::Done => self.done = true,
                TINFLStatus::HasMoreOutput | TINFLStatus::NeedsMoreInput => {}
                other => {
                    return Err(io::Error::other(format!(
                        "deflate stream is corrupt while reading ({other:?})"
                    )));
                }
            }
            if used_in == 0 && used_out == 0 && !more_input {
                self.done = true;
            }
        }
        Ok(())
    }
}

/// A deflated zip member, read at random without being unpacked.
pub struct DeflateSource {
    /// The member's compressed bytes, addressed from zero.
    comp: Box<dyn ImageSource>,
    index: Arc<DeflateIndex>,
    /// Open positions in the stream, most recently used first.
    cursors: std::cell::RefCell<Vec<Cursor>>,
    name: String,
}

impl DeflateSource {
    pub fn new(
        comp: Box<dyn ImageSource>,
        uncompressed_len: u64,
        crc32: u32,
        cache_key: String,
        name: String,
    ) -> io::Result<Self> {
        let index = cached_index(cache_key, || {
            DeflateIndex::build(comp.as_ref(), uncompressed_len, crc32, &name)
        })?;
        Ok(Self {
            comp,
            index,
            cursors: std::cell::RefCell::new(Vec::new()),
            name,
        })
    }
}

impl ImageSource for DeflateSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.index.uncompressed_len {
            return Err(io::Error::other(format!(
                "{}: read of {} bytes at {offset} runs past the {}-byte member",
                self.name,
                buf.len(),
                self.index.uncompressed_len
            )));
        }

        let mut pool = self.cursors.borrow_mut();

        // PICK THE CHEAPEST WAY TO GET THERE, rather than applying a rule of
        // thumb. A cursor can serve `offset` for nothing if it already holds
        // it, for the cost of inflating the gap if it sits behind it, and not
        // at all if it has gone past -- deflate has no reverse. Against that,
        // restarting costs the distance from the nearest checkpoint, which is
        // bounded by the spacing. Comparing the three is exact and replaces the
        // "restart if further than one spacing ahead" heuristic this used to
        // carry.
        let checkpoint = self.index.checkpoint_for(offset);
        let restart_cost = offset - checkpoint.out_pos;
        let mut best: Option<(usize, u64)> = None;
        for (i, c) in pool.iter().enumerate() {
            let cost = if offset >= c.buf_start && offset < c.out_pos {
                0
            } else if offset >= c.out_pos {
                offset - c.out_pos
            } else {
                continue;
            };
            if best.is_none_or(|(_, b)| cost < b) {
                best = Some((i, cost));
            }
        }

        // Ties go to an existing cursor: a restart also has to allocate its
        // buffer and copy a 32 KiB window in, which the comparison above does
        // not count.
        match best {
            Some((i, cost)) if cost <= restart_cost => {
                // Most-recently-used first, so the next read's scan finds the
                // likely winner immediately.
                let c = pool.remove(i);
                pool.insert(0, c);
            }
            _ => {
                if pool.len() == CURSORS {
                    pool.pop();
                }
                pool.insert(0, Cursor::at(checkpoint));
            }
        }
        let cursor = &mut pool[0];

        let mut got = 0usize;
        while got < buf.len() {
            let want_at = offset + got as u64;
            if want_at >= cursor.out_pos {
                cursor.advance_past(self.comp.as_ref(), want_at)?;
                if want_at >= cursor.out_pos {
                    return Err(io::Error::other(format!(
                        "{}: the deflate stream ended at {} while reading {} bytes at {offset}",
                        self.name,
                        cursor.out_pos,
                        buf.len()
                    )));
                }
            }
            // `[buf_start, out_pos)` is what the cursor holds, and `advance_past`
            // only ever slides history away that is older than the byte asked
            // for, so the target is inside it.
            let at = (want_at - cursor.buf_start) as usize;
            let avail = ((cursor.out_pos - want_at) as usize).min(buf.len() - got);
            buf[got..got + avail].copy_from_slice(&cursor.buf[at..at + avail]);
            got += avail;
        }
        Ok(())
    }

    fn len(&self) -> u64 {
        self.index.uncompressed_len
    }

    fn describe(&self) -> String {
        self.name.clone()
    }
}

/// Inflate a whole member into RAM. For anything small, this beats indexing it.
pub fn inflate_all(
    comp: &dyn ImageSource,
    uncompressed_len: u64,
    expected_crc: u32,
    label: &str,
) -> io::Result<Vec<u8>> {
    let comp_len = comp.len();
    let mut input = vec![0u8; comp_len as usize];
    comp.read_at(0, &mut input)?;
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(
        &input,
        uncompressed_len as usize + 1,
    )
    .map_err(|e| io::Error::other(format!("{label}: cannot inflate ({:?})", e.status)))?;
    if out.len() as u64 != uncompressed_len {
        return Err(io::Error::other(format!(
            "{label}: inflated {} bytes, the archive says {uncompressed_len}",
            out.len()
        )));
    }
    let mut crc = Crc32::new();
    crc.update(&out);
    let got = crc.finish();
    if expected_crc != 0 && got != expected_crc {
        return Err(io::Error::other(format!(
            "{label}: CRC-32 mismatch -- inflated 0x{got:08x}, archive says 0x{expected_crc:08x}"
        )));
    }
    Ok(out)
}

/// CRC-32 (IEEE), the one a zip carries.
///
/// SLICE-BY-16, not the textbook byte-at-a-time loop, because this runs over
/// EVERY byte of a member during indexing and the naive version is a dependent
/// chain: each table lookup needs the previous result, so it cannot use more
/// than one of the CPU's load ports. Consuming sixteen bytes per step turns
/// that into sixteen independent lookups and one XOR tree.
///
/// Measured on the 1.10 GiB Sonic Adventure track: see the timings the index
/// pass prints at debug level.
pub struct Crc32 {
    value: u32,
}

static CRC_TABLES: OnceLock<[[u32; 256]; 16]> = OnceLock::new();

fn crc_tables() -> &'static [[u32; 256]; 16] {
    CRC_TABLES.get_or_init(|| {
        let mut t = [[0u32; 256]; 16];
        for (i, slot) in t[0].iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        // Table k holds the CRC contribution of a byte that is k positions
        // further back in the stream, so sixteen bytes can be folded at once.
        for i in 0..256 {
            for k in 1..16 {
                let prev = t[k - 1][i];
                t[k][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            }
        }
        t
    })
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    pub fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        let t = crc_tables();
        let mut c = self.value;
        let mut blocks = data.chunks_exact(16);
        for b in &mut blocks {
            let w0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) ^ c;
            let w1 = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
            let w2 = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
            let w3 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
            c = t[15][(w0 & 0xff) as usize]
                ^ t[14][((w0 >> 8) & 0xff) as usize]
                ^ t[13][((w0 >> 16) & 0xff) as usize]
                ^ t[12][(w0 >> 24) as usize]
                ^ t[11][(w1 & 0xff) as usize]
                ^ t[10][((w1 >> 8) & 0xff) as usize]
                ^ t[9][((w1 >> 16) & 0xff) as usize]
                ^ t[8][(w1 >> 24) as usize]
                ^ t[7][(w2 & 0xff) as usize]
                ^ t[6][((w2 >> 8) & 0xff) as usize]
                ^ t[5][((w2 >> 16) & 0xff) as usize]
                ^ t[4][(w2 >> 24) as usize]
                ^ t[3][(w3 & 0xff) as usize]
                ^ t[2][((w3 >> 8) & 0xff) as usize]
                ^ t[1][((w3 >> 16) & 0xff) as usize]
                ^ t[0][(w3 >> 24) as usize];
        }
        for b in blocks.remainder() {
            c = t[0][((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.value = c;
    }

    pub fn finish(&self) -> u32 {
        self.value ^ 0xFFFF_FFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disc_formats::source::MemorySource;

    /// Data that compresses but is not uniform, so back-references genuinely
    /// reach across block boundaries -- which is the whole thing a checkpoint
    /// has to survive.
    fn sample(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut s: u32 = 0x1234_5678;
        while out.len() < len {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let run = 3 + (s >> 29) as usize;
            let byte = (s >> 11) as u8;
            for _ in 0..run {
                out.push(byte);
            }
        }
        out.truncate(len);
        out
    }

    fn indexed(data: &[u8]) -> (DeflateSource, Vec<u8>) {
        let comp = miniz_oxide::deflate::compress_to_vec(data, 6);
        let mut crc = Crc32::new();
        crc.update(data);
        let src = DeflateSource::new(
            Box::new(MemorySource::new(comp, "test.deflate".into())),
            data.len() as u64,
            crc.finish(),
            format!("test-{}-{}", data.len(), crc.finish()),
            "test member".into(),
        )
        .expect("index");
        (src, data.to_vec())
    }

    /// THE CLAIM THE LIVE AUDIT MAKES, TESTED AGAINST GROUND TRUTH.
    ///
    /// A session warned "re-reading LBA 0x0004e6ce by way of a checkpoint
    /// restart gives DIFFERENT bytes (first at Some(0)): this host's
    /// random-access read of the image is wrong" (2026-09-11). That is a
    /// falsifiable statement about THIS reader, so it gets a test rather than
    /// an opinion: read a range warm, force the cursor pool to turn over so the
    /// next read must restart from a checkpoint, read it again -- and compare
    /// both against the original bytes, not merely against each other. Two
    /// wrong reads that agree would pass the audit's own test and fail this
    /// one.
    #[test]
    fn a_warm_read_and_a_checkpoint_restart_agree_with_the_original() {
        let data = sample(8 << 20);
        let (src, data) = indexed(&data);
        let span = 2352 * 3; // one PCM CD-DA sub-fetch
        for off in [0usize, 4096, 1 << 20, (3 << 20) + 7, 5 << 20, (8 << 20) - span] {
            let mut warm = vec![0u8; span];
            src.read_at(off as u64, &mut warm).expect("warm read");

            // Walk far enough away, CURSORS + 1 times, that every cursor which
            // could still serve `off` has been evicted or left behind it.
            let mut scratch = vec![0u8; 4096];
            for k in 0..=CURSORS {
                let far = ((7 << 20) - k * (1 << 19)) as u64;
                src.read_at(far, &mut scratch).expect("far read");
            }

            let mut restarted = vec![0u8; span];
            src.read_at(off as u64, &mut restarted).expect("restarted read");

            assert_eq!(&warm[..], &data[off..off + span], "warm read wrong at {off}");
            assert_eq!(
                &restarted[..],
                &data[off..off + span],
                "restarted read wrong at {off}"
            );
        }
    }

    #[test]
    fn reads_match_the_original_everywhere() {
        let data = sample(3 << 20);
        let (src, data) = indexed(&data);
        // Deliberately out of order: the point of the index is that going
        // BACKWARDS is not a full re-inflate, and a forward-only test would
        // pass even with the checkpoints ignored.
        for off in [
            0usize,
            1,
            WINDOW - 1,
            WINDOW,
            WINDOW + 1,
            2 << 20,
            1 << 20,
            100_000,
            (3 << 20) - 4096,
            7,
        ] {
            let mut buf = vec![0u8; 4096];
            src.read_at(off as u64, &mut buf).expect("read");
            assert_eq!(&buf[..], &data[off..off + 4096], "mismatch at {off}");
        }
    }

    /// The CD-DA access pattern: long runs of consecutive small reads (here
    /// 7056 bytes, a PCM sub-fetch; ADPCM reads 9408 raw bytes per request).
    ///
    /// Unlike the jumping test above, this never restarts from a checkpoint and
    /// instead exercises the buffer slide in `advance_past`: the cursor holds
    /// WINDOW + CURSOR_SPAN bytes, so a slide falls every few dozen reads and
    /// must keep exactly the history the back-references straddling it need.
    /// 16 MiB is ~60 slides and ~2400 reads.
    #[test]
    fn a_long_sequential_stream_matches_byte_for_byte() {
        const FETCH: usize = 7056;
        let data = sample(16 << 20);
        let (src, data) = indexed(&data);
        let mut buf = vec![0u8; FETCH];
        let mut off = 0usize;
        while off + FETCH <= data.len() {
            src.read_at(off as u64, &mut buf).expect("read");
            if buf[..] != data[off..off + FETCH] {
                let i = (0..FETCH).find(|&i| buf[i] != data[off + i]).unwrap();
                panic!(
                    "sequential read at {off} differs at byte {i} (offset {}):                      got 0x{:02x}, want 0x{:02x}",
                    off + i,
                    buf[i],
                    data[off + i]
                );
            }
            off += FETCH;
        }
    }

    #[test]
    fn a_read_longer_than_the_cursor_span_still_works() {
        let data = sample(2 << 20);
        let (src, data) = indexed(&data);
        let mut buf = vec![0u8; CURSOR_SPAN * 3];
        src.read_at(1000, &mut buf).expect("read");
        assert_eq!(&buf[..], &data[1000..1000 + buf.len()]);
    }

    #[test]
    fn past_the_end_is_an_error_not_a_short_read() {
        let data = sample(64 * 1024);
        let (src, _) = indexed(&data);
        let mut buf = vec![0u8; 4096];
        assert!(src.read_at(64 * 1024 - 100, &mut buf).is_err());
    }

    /// A damaged archive must be refused, not served. The index pass is the
    /// only place this can be caught, and it is caught for the whole member.
    #[test]
    fn a_wrong_crc_is_refused() {
        let data = sample(256 * 1024);
        let comp = miniz_oxide::deflate::compress_to_vec(&data, 6);
        let err = DeflateSource::new(
            Box::new(MemorySource::new(comp, "bad".into())),
            data.len() as u64,
            0xDEAD_BEEF,
            "test-bad-crc".into(),
            "bad member".into(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn crc32_matches_the_known_vector() {
        let mut c = Crc32::new();
        c.update(b"123456789");
        assert_eq!(c.finish(), 0xCBF4_3926);
    }

    /// The textbook byte-at-a-time CRC-32, kept ONLY as something to check the
    /// fast one against. Slice-by-16 folds sixteen bytes per step and has two
    /// places to get wrong -- the table derivation and the tail -- neither of
    /// which the single known test vector would catch, since "123456789" is
    /// nine bytes and never enters the fast path at all.
    fn crc32_reference(data: &[u8]) -> u32 {
        let t = crc_tables();
        let mut c = 0xFFFF_FFFFu32;
        for b in data {
            c = t[0][((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8);
        }
        c ^ 0xFFFF_FFFF
    }

    #[test]
    fn crc32_agrees_with_the_reference_at_every_length() {
        let data = sample(600);
        // Every length across the 16-byte step, so the tail is exercised in
        // all its forms.
        for len in 0..data.len() {
            let mut c = Crc32::new();
            c.update(&data[..len]);
            assert_eq!(c.finish(), crc32_reference(&data[..len]), "length {len}");
        }
    }

    /// The index pass feeds it in whatever pieces the decoder happens to
    /// produce, so a split must not change the answer.
    #[test]
    fn crc32_is_the_same_however_it_is_split() {
        let data = sample(100_000);
        let whole = crc32_reference(&data);
        for split in [1usize, 15, 16, 17, 4096, 33_333] {
            let mut c = Crc32::new();
            for piece in data.chunks(split) {
                c.update(piece);
            }
            assert_eq!(c.finish(), whole, "split every {split}");
        }
    }
}
