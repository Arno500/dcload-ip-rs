//! How close the title's stack comes to the loader, measured while it still can be.
//!
//! WHY THIS EXISTS
//!
//! Two things decide where the loader may go, and both of them look for an
//! address COLLISION: constants in the title's binary that point into the
//! loader's span, and `game-memory.tsv`, which records where the disc reads
//! this host served actually landed. Neither can see a stack.
//!
//! A retail title uses the BIOS work area as a stack, because from its point of
//! view that is free memory -- and at a LOW base that area is where the loader
//! lives (AGENTS.md 4.6). The stack descends into it from 0x8c00f400. It is
//! named by no constant, no read is ever served into it, and the first evidence
//! of it reaching the loader is the loader's own state coming back wrong: a
//! ReadSector request built out of clobbered memory, or nothing at all.
//!
//! Sonic Adventure is the measured case. It enters GD syscalls with
//! `SP = 0x8c00b9d0`; the loader's `_end` was 0x8c00a558 when it was measured
//! booting and playing, and 0x8c00b044 once CD-DA had been added -- 5240 bytes
//! of margin against 2444, and the second one corrupts the loader. Nothing on
//! this host could tell the two builds apart, because from here they differ by
//! nothing observable.
//!
//! WHAT IT COSTS, AND WHY THAT IS ACCEPTABLE
//!
//! dcload latches the number itself, always, for free: `g_gd_sp_min` is the
//! lowest SP any GD syscall was entered with and `g_gd_sp_in_image` counts the
//! ones already inside the image. Reading them is one SendBinQ for eight bytes
//! every ten seconds, answered from inside `bb->loop()` like the counter panel's
//! -- against a title making sixty GD syscalls a second. It is posted from the
//! top of the syscall loop and claimed in the IO layer, which is the only
//! arrangement that works (see `io::PacketSink`).
//!
//! The value is latched on the title's FIRST GD syscall, so the verdict is
//! available within seconds of the boot -- long before the crash it predicts.
//! That is the whole point: what used to be a mysterious freeze minutes in is
//! now a line in the log saying which base is wrong and that a re-run will move
//! it.
//!
//! WHAT IS DONE WITH IT
//!
//! It is written to `game-memory.tsv` beside that title's block map, merged by
//! MINIMUM, and read back by the placement pass on the next run. So a session
//! at a base that works teaches exactly as much as one at a base that does not,
//! and the second run of any title needs no argument to place the loader out of
//! its stack's way.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::CHUNK_SIZE;
use crate::cmds::{DCLoadCmd, DCLoadCmds, DCReturnCmd};
use crate::io::{ExternalDcIo, PacketSink};
use crate::memmap::{MemoryMap, MemoryRecorder};

/// How often the pair is read back.
///
/// SLOW ON PURPOSE. `g_gd_sp_min` only ever decreases, so nothing is missed by
/// asking rarely -- and every request is a datagram dcload answers from the
/// path a blocked title is waiting on. Ten seconds is roughly six hundred of
/// that title's own GD syscalls per sample.
const INTERVAL: Duration = Duration::from_secs(10);

/// The same interval once the console has stopped answering.
///
/// A title that has stopped reading the disc has stopped looking at the wire
/// (dcload polls it from the read path only), so silence here is the normal
/// state of a freeze rather than a fault. Backing off keeps a hung session from
/// emitting a request every ten seconds forever.
const QUIET_INTERVAL: Duration = Duration::from_secs(60);
const QUIET_AFTER: u32 = 6;

/// Long enough for a reply to sit behind a title's own traffic before it is
/// given up on. The counter panel settled on the same figure for the same
/// reason: giving up early costs the measurement, holding on costs a late
/// sample and nothing else.
const TIMEOUT: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_millis(500);

/// dcload's initial value: no GD syscall has been entered yet.
const NEVER: u32 = 0xffff_ffff;

/// The half that has to live where the packets arrive. See `io::PacketSink`:
/// dcload answers a SendBinQ from inside `bb->loop()`, which it only reaches
/// while waiting for a host transfer, so the reply lands in the middle of
/// somebody else's polling and never in the syscall loop.
struct Sink {
    lo: u32,
    span: usize,
    buf: Vec<u8>,
    have: Vec<bool>,
    open: bool,
    done: Option<Vec<u8>>,
    /// Is this watch the one on the wire? AN INACTIVE SINK CLAIMS NOTHING --
    /// see the note on `StackVerdict` for why exactly one of this and the
    /// panel's sink may be, and `d` for what moves it.
    active: bool,
}

impl PacketSink for Sink {
    /// A packet is ours if its address is inside the eight bytes we asked
    /// about. THE TEST IS THE ADDRESS AND NOTHING ELSE -- claiming a transfer's
    /// terminator instead of our own breaks the disc read the title is blocked
    /// on, which is measured and written up in `diag::SampleSink`.
    fn claim(&mut self, cmd: &DCReturnCmd) -> bool {
        if !self.active {
            return false;
        }
        let Some(inner) = cmd.cmd.as_ref() else {
            return false;
        };
        let Some(off) = inner
            .address
            .checked_sub(self.lo)
            .map(|d| d as usize)
            .filter(|&d| d < self.span)
        else {
            return false;
        };
        // The terminator of our own read. Nothing is done with it -- the sample
        // completes on bytes -- but it must not reach the syscall loop, where it
        // would be taken for a transfer's acknowledgement.
        if matches!(inner.cmd, DCLoadCmds::DoneBinary()) {
            return true;
        }
        let chunk = match &inner.cmd {
            DCLoadCmds::SendBinary(Some(c)) | DCLoadCmds::SendBinaryQuiet(Some(c)) => c,
            _ => return false,
        };
        let n = (inner.size as usize).min(chunk.len()).min(self.span - off);
        if n == 0 || !self.open {
            return false;
        }
        self.buf[off..off + n].copy_from_slice(&chunk[..n]);
        self.have[off..off + n].fill(true);
        if self.have.iter().all(|h| *h) {
            self.open = false;
            self.done = Some(self.buf.clone());
        }
        true
    }
}

/// What is DONE with the two numbers, on its own.
///
/// SPLIT OUT BECAUSE THERE ARE TWO WAYS TO GET THEM, and only one of them may
/// be on the wire at a time. `--diag`'s counter panel already reads a range
/// that CONTAINS these two counters, and both sinks claim by address, so
/// running the watch alongside it means whichever sink is consulted first eats
/// the other's reply -- the watch would miss every sample for the whole
/// session, silently, in exactly the sessions someone is watching closest. So
/// with the panel up the panel feeds this, and without it the watch does.
pub struct StackVerdict {
    base: u32,
    image_end: u32,
    recorder: Option<Arc<Mutex<MemoryRecorder>>>,
    sp_min: Option<u32>,
    reported: bool,
    warned: bool,
    /// A reading that was not a stack pointer has been reported.
    foreign: bool,
    /// A virtual stack (an MMU title) has been reported.
    virtual_sp: bool,
}

impl StackVerdict {
    pub fn new(
        base: u32,
        image_end: u32,
        recorder: Option<Arc<Mutex<MemoryRecorder>>>,
    ) -> Self {
        StackVerdict {
            base,
            image_end,
            recorder,
            sp_min: None,
            reported: false,
            warned: false,
            foreign: false,
            virtual_sp: false,
        }
    }

    /// The same, taking `_end` out of the image the console is running.
    pub fn from_elf(
        elf: &[u8],
        base: u32,
        recorder: Option<Arc<Mutex<MemoryRecorder>>>,
    ) -> Result<Self, String> {
        let end = crate::loaders::symbols(elf)?
            .get("end")
            .map(|&(addr, _)| addr)
            .ok_or("this loader ELF has no _end")?;
        Ok(Self::new(base, end, recorder))
    }

    /// One reading of `g_gd_sp_min` / `g_gd_sp_in_image`.
    pub fn observe(&mut self, sp: u32, in_image: u32) {
        if sp == NEVER {
            // The title has not made a GD syscall yet -- normal for the first
            // seconds of a boot, and permanent for a title with no disc.
            return;
        }
        // A THREAD STACK IN A WINDOWS CE PROCESS SLOT IS NOT FOREIGN. CE runs
        // with the MMU on and maps each process at a 32 MB slot from
        // 0x02000000; Sega Rally 2 entered the GD driver with SP 0x080df62c
        // and 0x0205f0c4 (2026-09-27), and this said the loader was gone while
        // it was answering. Such a stack is not in the physical RAM a loader
        // occupies, so there is no margin to measure and nothing to record.
        // Main RAM's own P0 window is left to the test below: a Katana stack
        // may be recorded through it.
        if sp & 3 == 0
            && (0x0200_0000..0x4200_0000).contains(&sp)
            && !(0x0c00_0000..0x0d00_0000).contains(&sp)
        {
            if !self.virtual_sp {
                self.virtual_sp = true;
                info!(
                    "this title enters GD syscalls on a virtual stack (SP 0x{sp:08x}): its \
                     MMU is on, as Windows CE's is, so the loader's stack margin does not apply"
                );
            }
            return;
        }
        // A VALUE THAT IS NOT RAM WAS READ OUT OF SOMETHING ELSE. Measured
        // 2026-09-17: Snow Surfers went back to the BIOS menu 180 ms after
        // EXEC, flycast booted the dcload disc again, and this read that
        // build's `_global_bg_color` and three flag bytes -- 16 and 0x00010100
        // -- then declared the title's stack inside the loader. `note_stack`
        // already refused to record it; this refuses to report it.
        if MemoryMap::index(sp).is_none() {
            if !self.foreign {
                self.foreign = true;
                warn!(
                    "the stack counters read back 0x{sp:08x} and {in_image}, which is no \
                     stack pointer: the console is not running the loader verified at \
                     0x{:08x} any more. If the title went back to the BIOS menu or the \
                     console was reset, whatever booted since answered this read.",
                    self.base
                );
            }
            return;
        }
        let sp = sp.min(self.sp_min.unwrap_or(u32::MAX));
        let deeper = self.sp_min != Some(sp);
        self.sp_min = Some(sp);
        if deeper && let Some(rec) = self.recorder.as_ref()
            && let Ok(mut rec) = rec.lock()
        {
            rec.note_stack(sp);
        }
        let margin = sp.saturating_sub(self.image_end);
        if !self.reported {
            self.reported = true;
            info!(
                "this title enters GD syscalls with SP 0x{sp:08x}; the loader at \
                 0x{:08x} ends at 0x{:08x}, so it has {margin} bytes under that stack \
                 (recorded, so the next run can place the loader knowing it)",
                self.base, self.image_end
            );
        }
        self.verdict(sp, in_image, margin);
    }

    /// Say it once, and say what to do about it.
    fn verdict(&mut self, sp: u32, in_image: u32, margin: u32) {
        if in_image > 0 {
            if !self.warned {
                self.warned = true;
                error!(
                    "THIS TITLE'S STACK IS INSIDE THE LOADER: {in_image} GD syscall(s) were \
                     entered with a stack pointer below 0x{:08x}. Whatever this loader reports \
                     from here is built out of overwritten memory. Re-run without \
                     --loader-base: the depth has been recorded and the loader will be placed \
                     out of this title's way.",
                    self.image_end
                );
                self.persist();
            }
            return;
        }
        // ONLY A LOW BASE IS IN THIS RACE. A high loader is nowhere near the
        // BIOS work area, so the title has the whole 0x8c004000..0x8c00f400
        // hole to descend through and the number above is a fact about the
        // title, not a warning about the placement.
        if crate::loaders::is_high(self.base)
            || margin >= crate::loaders::LOW_BASE_MIN_MARGIN
            || self.warned
        {
            return;
        }
        self.warned = true;
        warn!(
            "THE LOADER IS ABOUT TO BE OVERWRITTEN. This title's stack reaches \
             0x{sp:08x} and the loader at 0x{:08x} ends at 0x{:08x}: {margin} bytes, of \
             which dcload's own disc-read path needs up to {}. Sonic Adventure was \
             measured booting and playing with 5240 bytes here and corrupting the loader \
             with 2444. Nothing has gone wrong yet -- this is the warning, not the \
             symptom. The depth is being recorded now, so RE-RUN and the loader will be \
             placed off the low family without any argument.",
            self.base,
            self.image_end,
            crate::loaders::GD_STACK_WORST_CASE,
        );
        self.persist();
    }

    /// Straight to disk: the failure this predicts often ends the process in a
    /// way no handler is told about, and the whole value of the measurement is
    /// that the NEXT run has it.
    fn persist(&self) {
        if let Some(rec) = self.recorder.as_ref()
            && let Ok(mut rec) = rec.lock()
        {
            rec.flush();
        }
    }
}

pub struct StackWatch {
    sink: Arc<Mutex<Sink>>,
    lo: u32,
    span: usize,
    /// Read by address, never by position in the reply: the two counters are
    /// adjacent globals today and the order they land in is the linker's
    /// business, not this file's.
    at_sp_min: u32,
    at_in_image: u32,
    /// Where the loader is, and where its image ends. Both from the ELF that
    /// was verified against the running image, so the margin below is a
    /// measurement and not an assumption about which build is on the console.
    verdict: StackVerdict,
    next_at: Instant,
    started: Option<Instant>,
    last_sent: Instant,
    misses: u32,
    samples: u64,
}

impl StackWatch {
    /// `elf` must be the image the console is actually running -- the same one
    /// `diag::verify_image` compares against. Two builds at the same base put
    /// the same counter at different addresses (AGENTS.md 14.19), so a watch
    /// aimed at the wrong ELF reports a believable number that means nothing.
    pub fn new(
        elf: &[u8],
        base: u32,
        recorder: Option<Arc<Mutex<MemoryRecorder>>>,
    ) -> Result<Self, String> {
        let syms = crate::loaders::symbols(elf)?;
        let want = |name: &str| -> Result<u32, String> {
            syms.get(name)
                .map(|&(addr, _)| addr)
                .ok_or_else(|| format!("this loader has no {name} (an older build?)"))
        };
        let sp_min = want("g_gd_sp_min")?;
        let in_image = want("g_gd_sp_in_image")?;
        let image_end = want("end")?;
        let verdict = StackVerdict::new(base, image_end, recorder);
        let lo = sp_min.min(in_image);
        let hi = sp_min.max(in_image) + 4;
        let span = (hi - lo) as usize;
        // Adjacent in practice -- both are plain `unsigned int` globals, in
        // declaration order. Refusing a wide range rather than reading it keeps
        // one request one packet, which is the shape dcload is known to answer.
        if span > CHUNK_SIZE {
            return Err(format!(
                "the two stack counters are {span} bytes apart, which is more than one read"
            ));
        }
        Ok(StackWatch {
            sink: Arc::new(Mutex::new(Sink {
                lo,
                span,
                buf: vec![0u8; span],
                have: vec![false; span],
                open: false,
                done: None,
                active: !crate::ui::sampling_wanted(),
            })),
            lo,
            span,
            at_sp_min: sp_min,
            at_in_image: in_image,
            verdict,
            // The first sample is asked for as soon as the title is running:
            // the value is latched on its very first GD syscall, and a verdict
            // is worth most before the failure it predicts.
            next_at: Instant::now() + Duration::from_secs(2),
            started: None,
            last_sent: Instant::now(),
            misses: 0,
            samples: 0,
        })
    }

    pub fn install(&self, conn: &mut impl ExternalDcIo) {
        conn.add_sink(self.sink.clone() as crate::io::SharedSink);
    }

    /// Called from the top of the syscall loop, and only from there: posting a
    /// command anywhere else would put it in the middle of a transfer that owns
    /// the conversation.
    pub fn tick(&mut self, conn: &mut impl ExternalDcIo) {
        // THE COMPLEMENT OF THE PANEL, decided once per tick. Both read the
        // same two counters and both sinks claim by address, so exactly one of
        // them may be on the wire; `d` moves the boundary and this is the side
        // that gives way, because the panel shows these numbers itself.
        if !self.sync_switch() {
            return;
        }
        let done = self.sink.lock().expect("sink poisoned").done.take();
        if let Some(blob) = done {
            self.started = None;
            self.samples += 1;
            self.misses = 0;
            self.next_at = Instant::now() + INTERVAL;
            self.decode(&blob);
        }

        if let Some(started) = self.started
            && started.elapsed() > TIMEOUT
        {
            let mut sink = self.sink.lock().expect("sink poisoned");
            sink.open = false;
            sink.have.fill(false);
            drop(sink);
            self.started = None;
            self.misses = self.misses.saturating_add(1);
            // NOT A FAULT, and saying so at anything above debug would bury the
            // log of every title that has simply stopped reading its disc.
            debug!(
                "stack watch: no answer for 0x{:08x}+{} ({} in a row)",
                self.lo, self.span, self.misses
            );
            self.next_at = Instant::now() + self.interval();
        }

        if self.started.is_none() {
            if Instant::now() < self.next_at {
                return;
            }
            let mut sink = self.sink.lock().expect("sink poisoned");
            sink.open = true;
            sink.have.fill(false);
            sink.buf.fill(0);
            drop(sink);
            self.started = Some(Instant::now());
            self.last_sent = Instant::now() - RETRY;
        }
        if self.last_sent.elapsed() < RETRY {
            return;
        }
        // ASK AGAIN, because nothing else will. One datagram, no
        // acknowledgement, over a link where a full RX ring is documented as
        // normal back-pressure.
        let cmd = DCLoadCmd {
            cmd: DCLoadCmds::SendBinaryQuiet(None),
            address: self.lo,
            size: self.span as u32,
        };
        if let Err(e) = conn.send_command(cmd) {
            debug!("stack watch: could not ask for the stack counters: {e}");
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

    /// Give way to the panel, or take over from it. Returns whether this watch
    /// should do anything this tick.
    fn sync_switch(&mut self) -> bool {
        let want = !crate::ui::sampling_wanted();
        let mut sink = self.sink.lock().expect("sink poisoned");
        if sink.active == want {
            return want;
        }
        sink.active = want;
        sink.open = false;
        sink.done = None;
        drop(sink);
        self.started = None;
        if want {
            self.next_at = Instant::now();
        }
        want
    }

    /// How long the syscall loop may block before this wants the CPU again.
    pub fn poll_timeout(&self) -> Option<Duration> {
        if !self.sink.lock().expect("sink poisoned").active {
            return None;
        }
        let due = match self.started {
            Some(started) => (started + TIMEOUT).min(self.last_sent + RETRY),
            None => self.next_at,
        };
        Some(due.saturating_duration_since(Instant::now()))
    }

    fn word(&self, blob: &[u8], addr: u32) -> Option<u32> {
        let off = addr.checked_sub(self.lo)? as usize;
        let b = blob.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn decode(&mut self, blob: &[u8]) {
        let (Some(sp), Some(in_image)) = (
            self.word(blob, self.at_sp_min),
            self.word(blob, self.at_in_image),
        ) else {
            return;
        };
        self.verdict.observe(sp, in_image);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memmap::{MemoryDb, MemoryMap};

    fn recorder(dir: &std::path::Path) -> Arc<Mutex<MemoryRecorder>> {
        Arc::new(Mutex::new(MemoryRecorder::new(
            dir.join("game-memory.tsv"),
            "md5",
            "A GAME",
            MemoryMap::new(),
        )))
    }

    /// The whole chain: a reading off the console reaches the file the next
    /// run's placement pass reads, and it only ever goes DEEPER.
    #[test]
    fn what_the_console_says_reaches_the_file_and_only_deepens() {
        let dir = std::env::temp_dir().join("dcload-stackverdict");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("game-memory.tsv");
        let rec = recorder(&dir);
        // The loader as it stands with CD-DA in it, at the stock base.
        let mut v = StackVerdict::new(
            crate::loaders::DEFAULT_BASE,
            0x8c00_b034,
            Some(rec.clone()),
        );

        // Before the title's first GD syscall there is nothing to say, and
        // 0xffffffff must not be recorded as a stack pointer.
        v.observe(NEVER, 0);
        rec.lock().unwrap().flush();
        assert_eq!(MemoryDb::load(&path).get("md5").and_then(|r| r.sp_min), None);

        // Sonic Adventure's measured depth: 2460 bytes, which is under the
        // threshold, so this both records and warns -- and the warning path
        // writes the file itself, because the run it predicts often ends in a
        // way no handler is told about.
        v.observe(0x8c00_b9d0, 0);
        assert_eq!(
            MemoryDb::load(&path).get("md5").and_then(|r| r.sp_min),
            Some(0x8c00_b9d0),
            "the warning path must not leave the measurement in memory only"
        );

        // A shallower reading is not news...
        v.observe(0x8c00_c000, 0);
        rec.lock().unwrap().flush();
        assert_eq!(
            MemoryDb::load(&path).get("md5").and_then(|r| r.sp_min),
            Some(0x8c00_b9d0)
        );
        // ...and a deeper one is.
        v.observe(0x8c00_b000, 0);
        rec.lock().unwrap().flush();
        assert_eq!(
            MemoryDb::load(&path).get("md5").and_then(|r| r.sp_min),
            Some(0x8c00_b000)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What a rebooted console answered: another build's globals, at the
    /// addresses the verified loader keeps its stack counters.
    #[test]
    fn a_reading_that_is_not_ram_is_neither_recorded_nor_a_verdict() {
        let dir = std::env::temp_dir().join("dcload-stackverdict-foreign");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rec = recorder(&dir);
        let mut v = StackVerdict::new(crate::loaders::DEFAULT_BASE, 0x8c00_cb48, Some(rec.clone()));
        v.observe(0x0001_0100, 16);
        assert!(v.foreign && !v.warned && !v.reported);
        assert_eq!(v.sp_min, None);
        rec.lock().unwrap().flush();
        assert_eq!(
            MemoryDb::load(&dir.join("game-memory.tsv"))
                .get("md5")
                .and_then(|r| r.sp_min),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A high loader is not in this race: the title has the whole BIOS work
    /// area to descend through, so the same depth is a fact and not a warning.
    /// The measurement is still recorded -- that is what makes a session at a
    /// base that works worth as much as one at a base that does not.
    #[test]
    fn a_high_base_records_without_warning() {
        let dir = std::env::temp_dir().join("dcload-stackverdict-high");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rec = recorder(&dir);
        let mut v = StackVerdict::new(
            crate::loaders::ISOLDR_HIGH_ADDR,
            0x8cff_3000,
            Some(rec.clone()),
        );
        v.observe(0x8c00_b9d0, 0);
        assert!(!v.warned, "nothing to warn about at a high base");
        rec.lock().unwrap().flush();
        assert_eq!(
            MemoryDb::load(&dir.join("game-memory.tsv"))
                .get("md5")
                .and_then(|r| r.sp_min),
            Some(0x8c00_b9d0)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
