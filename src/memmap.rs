//! What memory a title actually uses, learned by watching it.
//!
//! WHY THIS EXISTS
//!
//! Where to put the loader is decided from two things: DreamShell's preset, and
//! a scan of the boot binary for constants naming RAM inside the loader's span.
//! Both are guesses about an allocator, and measured 2026-08-27 on Sonic
//! Adventure 2, both miss:
//!
//! - its preset (0x8cfe8000) points at a 32 KB hole that fits isoldr's 13 KB
//!   image and not our 56 KB one;
//! - 0x8cfd0000 has no constant pointing into it and freezes anyway, because
//!   the title decompresses COURSE.PVM into ~0x8cfc0000..0x8cfc6000, 41 KB
//!   below it;
//! - 0x8ce00000 likewise, with KART.ADX streaming into 0x8ce3a920.
//!
//! None of those addresses appears anywhere in the binary: they are computed.
//! No static pass can find them. But the host SEES them -- every disc read it
//! serves names its destination -- so the one thing missing is a memory.
//!
//! WHAT IS STORED, AND WHY IT IS SHAPED THIS WAY
//!
//! A bitmap of 64 KB blocks over the Dreamcast's 16 MB: 256 bits, 64 hex
//! characters, one line per game. Not a min..max range, which would say "this
//! title uses everything from 0x8c010000 to 0x8cfc6000" and be true and
//! useless; the holes are the whole point, and 0x8cef8000 is one.
//!
//! It merges by OR, which is what makes it a shared file worth committing:
//! two people playing different parts of the same game produce two partial maps
//! that combine into a better one, in any order, with no conflict to resolve.
//! A run only ever adds bits, so a stale entry is incomplete, never wrong.

use std::collections::BTreeMap;
use std::path::Path;

/// RAM is 16 MB at 0x8c000000, in 64 KB blocks.
pub const BLOCK: u32 = 0x1_0000;
pub const BLOCKS: usize = 256;
const RAM_BASE: u32 = 0x0c00_0000;

/// Which 64 KB blocks of RAM a title has been seen writing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MemoryMap {
    bits: [u8; BLOCKS / 8],
}

impl MemoryMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Block index for a guest address, in any of the three windows.
    fn index(addr: u32) -> Option<usize> {
        let phys = addr & 0x1fff_ffff;
        if phys < RAM_BASE {
            return None;
        }
        let i = ((phys - RAM_BASE) / BLOCK) as usize;
        (i < BLOCKS).then_some(i)
    }

    /// Record that `len` bytes were written at `addr`.
    pub fn mark(&mut self, addr: u32, len: u32) {
        let Some(first) = Self::index(addr) else {
            return;
        };
        // The last BYTE, not the byte past the end: a write that ends exactly on
        // a block boundary does not touch the next block.
        let last = Self::index(addr.saturating_add(len.saturating_sub(1))).unwrap_or(BLOCKS - 1);
        for i in first..=last.max(first) {
            self.bits[i / 8] |= 1 << (i % 8);
        }
    }

    pub fn is_marked(&self, block: usize) -> bool {
        block < BLOCKS && self.bits[block / 8] & (1 << (block % 8)) != 0
    }

    /// Does `[base, base+span)` touch anything the title has been seen using?
    ///
    /// `margin` widens the window on both sides. The failures this file exists
    /// for were 41 KB and 182 KB away from a loader that did not overlap
    /// anything at all -- what is recorded is where a read LANDED, and what
    /// follows is an allocator that was already heading there.
    pub fn hits(&self, base: u32, span: u32, margin: u32) -> bool {
        let lo = (base & 0x1fff_ffff).saturating_sub(margin);
        let hi = (base & 0x1fff_ffff)
            .saturating_add(span)
            .saturating_add(margin);
        let first = Self::index(lo).unwrap_or(0);
        let last = Self::index(hi.saturating_sub(1)).unwrap_or(BLOCKS - 1);
        (first..=last.max(first)).any(|i| self.is_marked(i))
    }

    /// The address a block starts at, in the cached window this host names RAM
    /// by everywhere else.
    fn block_addr(block: usize) -> u32 {
        0x8c00_0000 + block as u32 * BLOCK
    }

    /// Runs of RAM this title has NEVER been seen using, clipped to `[lo, hi)`
    /// and ordered longest first.
    ///
    /// THE BIGGEST HOLE, NOT THE HIGHEST FREE ADDRESS, and the difference is
    /// the whole point. A run is bounded at both ends by blocks a read really
    /// landed in, so its middle is the furthest a loader can get from anything
    /// this title is known to touch -- and since a map is only ever a lower
    /// bound on what a title uses, distance from the nearest evidence is the
    /// only ranking available. The top of RAM, by contrast, looks gloriously
    /// free on a map that stopped growing the moment the title overwrote the
    /// loader, which is exactly the map this is read from: every row here for a
    /// title that failed is truncated at its own failure.
    ///
    /// Ties keep block order, lowest first. Two runs of equal length carry no
    /// information to choose between them, and being deterministic is worth
    /// more than being clever.
    pub fn free_runs(&self, lo: u32, hi: u32) -> Vec<(u32, u32)> {
        let first = Self::index(lo).unwrap_or(0);
        let last = Self::index(hi.saturating_sub(1)).unwrap_or(BLOCKS - 1).max(first);
        let mut runs: Vec<(usize, usize)> = vec![];
        let mut start: Option<usize> = None;
        for i in first..=last {
            match (self.is_marked(i), start) {
                (true, Some(s)) => {
                    runs.push((s, i));
                    start = None;
                }
                (false, None) => start = Some(i),
                _ => {}
            }
        }
        if let Some(s) = start {
            runs.push((s, last + 1));
        }
        runs.sort_by_key(|&(a, b)| std::cmp::Reverse(b - a));
        runs.into_iter()
            .map(|(a, b)| (Self::block_addr(a).max(lo), Self::block_addr(b).min(hi)))
            .collect()
    }

    /// Everything either map has seen. Order does not matter, which is what
    /// lets two people's files merge.
    pub fn merge(&mut self, other: &MemoryMap) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    pub fn blocks_marked(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Lowest-block-first hex, so a diff of two versions reads left to right
    /// across RAM.
    pub fn to_hex(&self) -> String {
        self.bits.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != BLOCKS / 4 {
            return None;
        }
        let mut m = MemoryMap::new();
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            m.bits[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        }
        Some(m)
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    pub title: String,
    pub map: MemoryMap,
    pub sessions: u32,
}

/// One row per boot-sector md5 -- the same key `presets.rs` uses, so a game
/// identified there is identified here.
#[derive(Default, Debug)]
pub struct MemoryDb {
    rows: BTreeMap<String, Row>,
}

const HEADER: &str = "\
# dcload-ip-rs: RAM a title has been seen writing, learned from the disc reads
# it asks for. Used to place the loader somewhere the game does not go.
#
# One row per boot-sector md5 (the key DreamShell's presets use). `blocks` is a
# 256-bit bitmap, one bit per 64 KB of the Dreamcast's 16 MB, lowest first: bit
# n covers 0x8c000000 + n*0x10000.
#
# ROWS MERGE BY OR, so this file is worth sharing: play a part of a game nobody
# has, commit the row, and everyone's placement gets better. A row is only ever
# incomplete, never wrong -- a bit is set because a read really landed there.
#
# md5\ttitle\tblocks\tsessions
";

impl MemoryDb {
    pub fn load(path: &Path) -> Self {
        let mut db = MemoryDb::default();
        let Ok(text) = std::fs::read_to_string(path) else {
            return db;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.split('\t');
            let (Some(md5), Some(title), Some(blocks)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let Some(map) = MemoryMap::from_hex(blocks.trim()) else {
                continue;
            };
            let sessions = f.next().and_then(|s| s.trim().parse().ok()).unwrap_or(1);
            db.rows.insert(
                md5.trim().to_string(),
                Row {
                    title: title.trim().to_string(),
                    map,
                    sessions,
                },
            );
        }
        db
    }

    pub fn get(&self, md5: &str) -> Option<&Row> {
        self.rows.get(md5)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Fold one observation in, counting a session only the first time.
    pub fn record(&mut self, md5: &str, title: &str, map: &MemoryMap, new_session: bool) {
        match self.rows.get_mut(md5) {
            Some(row) => {
                row.map.merge(map);
                if new_session {
                    row.sessions = row.sessions.saturating_add(1);
                }
            }
            None => {
                self.rows.insert(
                    md5.to_string(),
                    Row {
                        title: title.to_string(),
                        map: *map,
                        sessions: 1,
                    },
                );
            }
        }
    }

    /// Write it out, MERGING WITH WHAT IS ON DISK FIRST.
    ///
    /// The file is meant to be committed and shared, so another process, another
    /// session or a `git pull` may have added rows since this one started. A
    /// plain overwrite would silently drop them -- and the loss would look
    /// exactly like nobody having played that game.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut merged = MemoryDb::load(path);
        for (md5, row) in &self.rows {
            merged.record(md5, &row.title, &row.map, false);
            if let Some(dst) = merged.rows.get_mut(md5) {
                dst.sessions = dst.sessions.max(row.sessions);
            }
        }
        let mut out = String::from(HEADER);
        for (md5, row) in &merged.rows {
            out.push_str(&format!(
                "{md5}\t{}\t{}\t{}\n",
                row.title,
                row.map.to_hex(),
                row.sessions
            ));
        }
        // Written beside the target and renamed, so an interrupted run cannot
        // leave a half-file where a database belongs.
        let tmp = path.with_extension("tsv.tmp");
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, path)
    }
}

/// Accumulates one session's observations and writes them out as it goes.
///
/// SAVED WHILE RUNNING, not at the end, and not from the read path either.
/// A session with a title is normally ended by Ctrl-C or by pulling the
/// console's plug, and neither runs any shutdown path -- so "write it when we
/// are done" means writing it almost never, and the interesting sessions (the
/// ones that hang) would be exactly the ones that record nothing.
///
/// **There are ends this process is not told about at all.** Under a debugger
/// the Ctrl-C handler is not reached (see `install_signal_handler`), and a
/// Stop button is a kill. So the file is kept current by a ticker thread that
/// owes nothing to either: `record()` marks and returns, `flush_if_due()` on
/// the ticker does the I/O. Two consequences, both wanted:
///
/// - the worst a `kill -9` can cost is `EVERY`, not a whole session;
/// - **no disc read pays for a file write.** dcload answers a read
///   synchronously, so anything done on that path is time the title is frozen.
pub struct MemoryRecorder {
    path: std::path::PathBuf,
    md5: String,
    title: String,
    map: MemoryMap,
    saved: MemoryMap,
    /// What was already known about this game when the session started. The
    /// difference against `map` is what this session TAUGHT, which is the only
    /// number worth telling anyone at the end.
    baseline: MemoryMap,
    last_save: std::time::Instant,
    first: bool,
    /// How many new blocks have already been named in the log. The end-of-run
    /// report is not reachable from every kind of exit, so the verdict it
    /// carries is also emitted as it becomes true.
    reported_new: usize,
}

impl MemoryRecorder {
    /// The interval between writes -- and, since nothing else is guaranteed to
    /// run at the end, the most a killed session can lose. It used to be 15 s
    /// on the argument that a write is not free; that argument was about the
    /// read path, which no longer writes at all, so the only thing left to
    /// balance is loss against a 1 KB file rewrite every few seconds.
    const EVERY: std::time::Duration = std::time::Duration::from_secs(2);
    /// ...but the FIRST write comes quickly, because a title that dies in the
    /// first few seconds is the one whose map is most worth having, and a long
    /// wait would mean it recorded nothing at all. Everything after that is a
    /// refinement; this one is the difference between a row and no row.
    const FIRST: std::time::Duration = std::time::Duration::from_secs(1);
    /// How often the ticker looks. Finer than `EVERY`, so a change is written
    /// roughly when it is due rather than at the next multiple of anything.
    const TICK: std::time::Duration = std::time::Duration::from_millis(500);

    pub fn new(path: std::path::PathBuf, md5: &str, title: &str, baseline: MemoryMap) -> Self {
        Self {
            path,
            md5: md5.to_string(),
            title: title.to_string(),
            map: MemoryMap::new(),
            saved: MemoryMap::new(),
            baseline,
            last_save: std::time::Instant::now(),
            first: true,
            reported_new: 0,
        }
    }

    /// Blocks this session found that the file did not already have.
    pub fn new_blocks(&self) -> usize {
        let mut merged = self.baseline;
        merged.merge(&self.map);
        merged.blocks_marked() - self.baseline.blocks_marked()
    }

    pub fn known_blocks(&self) -> usize {
        let mut merged = self.baseline;
        merged.merge(&self.map);
        merged.blocks_marked()
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Note a write. Called on the disc-read path -- which is the path the
    /// title is frozen on -- so it does no I/O at all: marking is two shifts,
    /// and the writing is the ticker's job.
    pub fn record(&mut self, addr: u32, len: u32) {
        let before = self.map;
        self.map.mark(addr, len);
        if self.map == before {
            return;
        }
        // WHAT THIS SESSION TAUGHT, SAID WHEN IT IS LEARNED rather than only at
        // the end. `report_and_exit` is the nicer place to say it, and it is
        // also the place a debugger's Stop button never reaches; a line in the
        // log survives any ending, including the ones that leave no trace.
        let new = self.new_blocks();
        if new > self.reported_new {
            self.reported_new = new;
            log::info!(
                "memory map: this title reads into 0x{addr:08x}, a 64 KB block that was \
                 not known before -- {new} new this session"
            );
        }
    }

    /// Write, if there is anything to write and enough time has passed.
    /// Called from the ticker, never from the read path.
    pub fn flush_if_due(&mut self) {
        let due = if self.first { Self::FIRST } else { Self::EVERY };
        if self.map == self.saved || self.last_save.elapsed() < due {
            return;
        }
        self.flush();
    }

    pub fn flush(&mut self) {
        let mut db = MemoryDb::default();
        db.record(&self.md5, &self.title, &self.map, self.first);
        match db.save(&self.path) {
            Ok(()) => {
                self.saved = self.map;
                self.first = false;
                self.last_save = std::time::Instant::now();
            }
            // Not fatal and not silent: the session goes on, the map is simply
            // not learned. Retried at the next interval.
            Err(e) => {
                log::warn!("could not write {}: {e}", self.path.display());
                self.last_save = std::time::Instant::now();
            }
        }
    }
}

/// The recorder the ticker and the signal handler act on, or `None` before a
/// title has been identified.
///
/// A slot rather than a captured value, because the handler has to be in place
/// LONG BEFORE there is anything to hand it: a run spends its first seconds
/// chainloading a loader and pushing several megabytes at the console, and a
/// Ctrl-C in that window used to kill the process outright.
static ACTIVE: std::sync::Mutex<Option<std::sync::Arc<std::sync::Mutex<MemoryRecorder>>>> =
    std::sync::Mutex::new(None);

fn active() -> Option<std::sync::Arc<std::sync::Mutex<MemoryRecorder>>> {
    ACTIVE.lock().ok().and_then(|slot| slot.clone())
}

/// Hand the ticker and the signal handler this session's recorder.
pub fn set_active(rec: Option<std::sync::Arc<std::sync::Mutex<MemoryRecorder>>>) {
    if let Ok(mut slot) = ACTIVE.lock() {
        *slot = rec;
    }
}

/// Install the Ctrl-C handler and start the ticker that keeps the map on disk.
///
/// WHY THE TICKER IS NOT OPTIONAL. Ctrl-C is a courtesy this process is not
/// always paid:
///
/// - **Under a debugger it never arrives.** lldb (so CodeLLDB, so Zed's debug
///   panel) takes SIGINT for itself -- `pass=false, stop=true` -- and on
///   Windows a console Ctrl-C reaches the debugger first as `DBG_CONTROL_C`.
///   Either way the debuggee is *suspended*, which is exactly what it looks
///   like: "it just stopped". Whatever ends it afterwards is a kill.
/// - **A Stop button is a kill**, and `SIGKILL` / `TerminateProcess` run no
///   handler by construction.
/// - A process launched with pipes instead of a console (which is how a DAP
///   adapter usually starts one on Windows) is not in any console process
///   group, so no `CTRL_C_EVENT` is delivered to it at all.
///
/// So the handler is the good ending, not the mechanism. The mechanism is that
/// the file is already current whenever the process dies.
///
/// To get the good ending back inside Zed, tell lldb to hand the signal over:
/// `"postRunCommands": ["process handle SIGINT --stop false --pass true"]`
/// in the debug configuration (see `.zed/debug.json`).
pub fn install_signal_handler() {
    if let Err(e) = ctrlc::set_handler(|| {
        let rec = active();
        report_and_exit(rec.as_deref())
    }) {
        log::warn!(
            "no Ctrl-C handler ({e}); the memory map is still written every few \
             seconds, but the end-of-session report will not be printed"
        );
    }
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(MemoryRecorder::TICK);
            if let Some(rec) = active()
                && let Ok(mut rec) = rec.lock()
            {
                rec.flush_if_due();
            }
        }
    });
}

/// Flush what the session learned, say whether it learned anything, and leave.
///
/// WHY THIS IS A WARNING AND NOT A CLOSING PLEASANTRY. When a title has just
/// misbehaved, the useful question is "will the next run be any different?",
/// and the honest answer is knowable: if this session put blocks in the map
/// that were not there before, the next run places the loader with information
/// it did not have, and may well behave differently. If it learned nothing, the
/// next run is identical and there is no point repeating it -- which is worth
/// saying just as loudly, because retrying unchanged is the obvious thing to do
/// and it is a waste of a session.
pub fn report_and_exit(recorder: Option<&std::sync::Mutex<MemoryRecorder>>) -> ! {
    // The bars own the cursor and hide it while they draw; exiting through
    // them leaves a terminal with no cursor in it.
    let _ = crate::ui::multi().clear();
    if let Some(lock) = recorder {
        // A poisoned lock means the main thread panicked while holding it; the
        // map is then not trustworthy and there is nothing to report.
        if let Ok(mut rec) = lock.lock() {
            rec.flush();
            let (new, known) = (rec.new_blocks(), rec.known_blocks());
            if new > 0 {
                log::warn!(
                    "this session added {new} block(s) of 64 KB to what is known about                      this game's memory ({known} of 256 now), saved in {}. RUN IT AGAIN:                      the loader will be placed knowing about ground it had to guess at                      this time, which is often the difference between a title working and                      not. Commit that file to share what you just measured.",
                    rec.path().display()
                );
            } else {
                log::info!(
                    "this session added nothing to this game's memory map ({known} of 256                      blocks known). A plain re-run will place the loader at the same                      address and do the same thing -- change something first."
                );
            }
        }
    }
    // 128 + SIGINT, the shell convention, so a script can tell this from a
    // failure of the tool itself.
    std::process::exit(130)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_write_does_not_wait_the_full_interval() {
        // A title that hangs in its first seconds is the one whose map matters
        // most; on the old timing it recorded nothing.
        assert!(
            MemoryRecorder::FIRST < MemoryRecorder::EVERY,
            "the first save is not any earlier than the rest"
        );
        assert!(MemoryRecorder::FIRST <= std::time::Duration::from_secs(5));
    }

    #[test]
    fn the_read_path_does_no_io() {
        // dcload answers a disc read synchronously -- the title is frozen for
        // as long as the host takes -- so a file write there is time stolen
        // from the game. It is also what made the map depend on a clean exit:
        // the writing belongs to the ticker now, which owes nothing to how the
        // process ends.
        let dir = std::env::temp_dir().join("dcload-memmap-readpath");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("x.tsv");
        let mut rec = MemoryRecorder::new(path.clone(), "md5", "T", MemoryMap::new());

        rec.record(0x8c40_0000, 16384);
        assert!(
            !path.exists(),
            "record() wrote the database from the disc-read path"
        );
        assert_eq!(rec.new_blocks(), 1, "record() did not mark the block");

        rec.flush();
        assert!(path.exists(), "flush() did not write the database");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn what_a_session_taught_is_counted_against_what_was_known() {
        // The number the end-of-session report turns on: "run it again" is only
        // worth saying when this session actually added something.
        let mut baseline = MemoryMap::new();
        baseline.mark(0x8ce3_a920, 16384);
        let dir = std::env::temp_dir().join("dcload-memmap-report");
        let _ = std::fs::create_dir_all(&dir);
        let mut rec = MemoryRecorder::new(dir.join("x.tsv"), "md5", "T", baseline);

        // A block already known teaches nothing.
        rec.map.mark(0x8ce3_a920, 16384);
        assert_eq!(rec.new_blocks(), 0, "re-seeing a known block counted as new");
        assert_eq!(rec.known_blocks(), 1);

        // A block nobody had teaches one.
        rec.map.mark(0x8cfc_0360, 16384);
        assert_eq!(rec.new_blocks(), 1);
        assert_eq!(rec.known_blocks(), 2);
    }

    /// Jet Set Radio's row, as `game-memory.tsv` held it after the session that
    /// prompted all of this: one low buffer, the boot's big ascending load
    /// TRUNCATED where it overwrote the loader at 0x8ce00000, and the ISO
    /// sector buffer the title keeps at the very top of RAM.
    const JSR: &str = "40000000000000000000000000000000000000000000000000e0ffff01000080";

    #[test]
    fn the_biggest_hole_is_not_the_top_of_ram() {
        let m = MemoryMap::from_hex(JSR).unwrap();
        // What the row actually says, so a change to it is visible here.
        assert!(m.is_marked(224), "0x8ce00000 -- the read that killed the run");
        assert!(m.is_marked(255), "0x8cff0000 -- the title's own sector buffer");

        let runs = m.free_runs(0x8ce0_0000, 0x8d00_0000);
        assert_eq!(
            runs.first().copied(),
            Some((0x8ce1_0000, 0x8cff_0000)),
            "the biggest run in the relocatable window is not the one bounded by \
             the two blocks the title is known to use"
        );
        // The top of RAM looks free only because the map stops at the failure.
        // Taking the highest free address would put the loader at 0x8cfe0000,
        // hard against the block the title demonstrably writes.
        assert!(runs[0].1 <= 0x8cff_0000);
    }

    #[test]
    fn an_empty_map_is_one_run_and_not_a_special_case() {
        // No row for this game yet: every base is equally unproven, and the
        // caller gets the middle of the window rather than a None to branch on.
        let runs = MemoryMap::new().free_runs(0x8ce0_0000, 0x8d00_0000);
        assert_eq!(runs, vec![(0x8ce0_0000, 0x8d00_0000)]);
    }

    #[test]
    fn free_runs_are_ordered_longest_first() {
        let mut m = MemoryMap::new();
        m.mark(0x8ce2_0000, 1); // leaves 0x8ce00000..0x8ce20000 (2 blocks)
        m.mark(0x8ce5_0000, 1); // then 0x8ce30000..0x8ce50000 (2 blocks)
        // ... and 0x8ce60000..0x8ce90000, three blocks, is the longest.
        let runs = m.free_runs(0x8ce0_0000, 0x8ce9_0000);
        assert_eq!(
            runs,
            vec![
                (0x8ce6_0000, 0x8ce9_0000),
                (0x8ce0_0000, 0x8ce2_0000),
                (0x8ce3_0000, 0x8ce5_0000),
            ],
            "longest first, and ties in block order"
        );
    }

    #[test]
    fn a_write_marks_every_block_it_spans() {
        let mut m = MemoryMap::new();
        m.mark(0x8cfc_0360, 16384);
        assert!(m.is_marked(0xfc));
        assert!(!m.is_marked(0xfb));
        assert!(!m.is_marked(0xfd));
    }

    #[test]
    fn a_write_ending_on_a_boundary_does_not_touch_the_next_block() {
        // The off-by-one that would mark a block the title never reached, and
        // so rule out a base that was fine.
        let mut m = MemoryMap::new();
        m.mark(0x8cfc_0000, BLOCK);
        assert!(m.is_marked(0xfc));
        assert!(!m.is_marked(0xfd), "marked the block after the write");
    }

    #[test]
    fn every_window_names_the_same_block() {
        for a in [0x8cfc_0360u32, 0x0cfc_0360, 0xacfc_0360] {
            let mut m = MemoryMap::new();
            m.mark(a, 4);
            assert!(m.is_marked(0xfc), "window 0x{a:08x}");
        }
    }

    #[test]
    fn the_margin_is_what_catches_a_near_miss() {
        // Sonic Adventure 2's Kart textures land at 0x8cfc0360; the loader at
        // 0x8cfd0000 overlaps nothing and freezes anyway.
        let mut m = MemoryMap::new();
        m.mark(0x8cfc_0360, 16384);
        assert!(!m.hits(0x8cfd_0000, 0xe000, 0), "no overlap, as expected");
        assert!(m.hits(0x8cfd_0000, 0xe000, 0x4_0000), "the margin missed it");
        // and 0x8cef8000, which runs, stays clear even with the margin
        assert!(!m.hits(0x8cef_8000, 0xe000, 0x4_0000));
    }

    #[test]
    fn merging_is_order_independent() {
        let (mut a, mut b) = (MemoryMap::new(), MemoryMap::new());
        a.mark(0x8ce3_a920, 16384);
        b.mark(0x8cfc_0360, 16384);
        let (mut ab, mut ba) = (a, b);
        ab.merge(&b);
        ba.merge(&a);
        assert_eq!(ab, ba);
        assert_eq!(ab.blocks_marked(), 2);
    }

    #[test]
    fn hex_round_trips() {
        let mut m = MemoryMap::new();
        m.mark(0x8ce3_a920, 16384);
        m.mark(0x8cfc_0360, 16384);
        let s = m.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(MemoryMap::from_hex(&s), Some(m));
    }

    #[test]
    fn a_malformed_bitmap_is_skipped_not_guessed() {
        assert_eq!(MemoryMap::from_hex("abc"), None);
        assert_eq!(MemoryMap::from_hex(&"z".repeat(64)), None);
    }

    #[test]
    fn saving_keeps_rows_another_session_added() {
        let dir = std::env::temp_dir().join("dcload-memmap-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("game-memory.tsv");
        let _ = std::fs::remove_file(&path);

        let mut theirs = MemoryDb::default();
        let mut m = MemoryMap::new();
        m.mark(0x8ce0_0000, 16);
        theirs.record("aaa", "THEIR GAME", &m, true);
        theirs.save(&path).unwrap();

        // Ours knows nothing of "aaa" and must not drop it.
        let mut ours = MemoryDb::default();
        let mut n = MemoryMap::new();
        n.mark(0x8cfc_0000, 16);
        ours.record("bbb", "OUR GAME", &n, true);
        ours.save(&path).unwrap();

        let back = MemoryDb::load(&path);
        assert_eq!(back.len(), 2, "a row was lost");
        assert!(back.get("aaa").unwrap().map.is_marked(0xe0));
        assert!(back.get("bbb").unwrap().map.is_marked(0xfc));
        let _ = std::fs::remove_file(&path);
    }
}
