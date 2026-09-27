//! The loader's own counters, read off the console while a title runs.
//!
//! WHY THIS EXISTS. dcload keeps a set of always-compiled counters -- the RX
//! ring's polls and misses, the GD syscall histogram, the CD-DA fetches, the
//! upload accounting -- and until now they could only be read from outside the
//! session: `scripts/dc-peek.py` through flycast's GDB stub (which does not
//! exist on a console), or `scripts/dc-counters.py` as a separate process
//! poking the same Dreamcast this host is already talking to. Both answer
//! "what were they a moment ago"; neither shows a number moving, which is the
//! question actually being asked when a title stalls.
//!
//! HOW IT READS THEM. `SBIQ` -- SendBinQ, "send a binary, quiet" -- which
//! dcload answers from inside `bb->loop()`, where it spends its life. One
//! request covers the whole counter span (about 1.4 KB, so two SBIN replies and
//! a DBIN), and it touches neither the screen nor the GD state machine.
//!
//! WHAT IT REFUSES TO DO, and this is the whole reason the identity check
//! below exists: decode against the wrong image. The loader's base is per-title
//! (AGENTS.md 4.11), so the same counter lives at a different address depending
//! on which loader is running -- and worse, TWO BUILDS OF THE SAME BASE put it
//! at different addresses, because adding one global to `commands.c` shifts
//! everything after it in `.data`. Measured on 2026-08-16: the deployed set was
//! eight bytes off the tree's, and every value came back believable and wrong
//! (`g_dbin_count` read 0x0c010000, which is a LoadBinary address). Matching
//! the base does not detect that. Comparing the CODE does, so that is what
//! happens before the first sample -- see `verify`.
//!
//! WHERE IT SITS ON THE CRITICAL PATH. Nowhere, by construction. dcload answers
//! a disc read synchronously -- the title is frozen from the request until the
//! last PartBinary lands (AGENTS.md 16) -- so this never blocks the syscall
//! loop: it posts one SBIQ from the top of an iteration and picks the replies
//! out of the ordinary packet flow as they arrive. If a disc read starts in the
//! meantime and swallows them, the sample is simply missed and re-requested at
//! the next interval. The default interval is two seconds for the same reason:
//! this is an instrument, and an instrument that changes what it measures is
//! the trap this codebase has been caught by twice (AGENTS.md 11).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use elf::endian::AnyEndian;
use elf::{ElfBytes, abi};

use crate::CHUNK_SIZE;
use crate::cmds::{DCLoadCmd, DCLoadCmds, DCReturnCmd};
use crate::io::{ExternalDcIo, PacketSink};
use crate::ui::{self, PanelRow};

/// How a counter's bytes turn into something a human reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fmt {
    /// A plain tally. The only kind a delta is shown for.
    Num,
    /// An address or a status word: decimal is unreadable, and a delta is
    /// meaningless.
    Hex,
    /// A 32-bit IPv4 address, as dcload stores it.
    Ip,
    /// `g_gd_idx_counts[]` -- one slot per GD syscall index.
    GdIdx,
    /// `g_gd_cmd_counts[]` -- one slot per GD command code.
    GdCmd,
    /// A TMU1 tick count (Pck/16, 3125 ticks per ms), shown as milliseconds as
    /// well. The loader measures the CD-DA ring's clearance on this one.
    Tmu1Ms,
    /// A TMU2 tick count (Pck/4, 12500 ticks per ms), shown as milliseconds as
    /// well. The two timers run at DIFFERENT rates and the loader uses both, so
    /// a raw tick count here is four times the millisecond figure it would be
    /// above: that is exactly the kind of arithmetic to do once, here, and
    /// never again in one's head.
    Tmu2Ms,
}

/// What to read, grouped the way `scripts/dc-counters.py` groups it -- for
/// reading, not for the wire: everything is fetched in one range.
///
/// A name that is not in the ELF is skipped in silence. The set of counters
/// depends on the build flags (`WITH_MAPLE`, `WITH_CDDA`, `GD_TRACE`...), so an
/// absent one is a configuration, not an error.
const GROUPS: &[(&str, &[(&str, Fmt)])] = &[
    (
        "RX ring",
        &[
            ("g_rx_polls", Fmt::Num),
            ("g_rx_frames", Fmt::Num),
            ("g_rx_missed", Fmt::Num),
            ("g_rx_overflow", Fmt::Num),
            ("g_rx_reinit", Fmt::Num),
            ("g_rx_wraps", Fmt::Num),
            ("g_rx_hdr_defer", Fmt::Num),
            ("g_rx_copying", Fmt::Num),
            ("g_rx_resync", Fmt::Num),
            ("g_rx_status_drop", Fmt::Num),
            ("g_rx_last_bad_status", Fmt::Hex),
            ("g_rx_linkchange", Fmt::Num),
            ("g_rx_underrun_ack", Fmt::Num),
            ("g_rx_link_giveup", Fmt::Num),
            ("g_rx_last_capr", Fmt::Hex),
            ("g_rx_last_cbr", Fmt::Hex),
        ],
    ),
    (
        "UDP",
        &[
            ("g_udp_ok", Fmt::Num),
            ("g_udp_unmatched", Fmt::Num),
            ("g_udp_cksum_bad", Fmt::Num),
        ],
    ),
    (
        "Upload path",
        &[
            ("g_lbin_count", Fmt::Num),
            // LoadBinaries answered without an echo: the CD-DA sub-fetches,
            // whose answers the host sends without waiting for one.
            ("g_lbin_noecho", Fmt::Num),
            // Transfers ended by their last part rather than by the
            // ReturnValue. In a healthy session this tracks the CD-DA
            // sub-fetch count.
            ("g_bin_data_done", Fmt::Num),
            ("g_dbin_count", Fmt::Num),
            ("g_dbin_incomplete", Fmt::Num),
            ("g_pbin_ok", Fmt::Num),
            ("g_pbin_rejected", Fmt::Num),
            ("g_pbin_clamped", Fmt::Num),
            ("g_last_load_addr", Fmt::Hex),
            ("g_last_load_size", Fmt::Num),
            ("g_last_pbin_addr", Fmt::Hex),
            ("g_last_reject_addr", Fmt::Hex),
            ("g_last_reject_load", Fmt::Hex),
            ("g_last_reject_end", Fmt::Hex),
            ("g_last_reject_size", Fmt::Num),
        ],
    ),
    (
        "GD emulation",
        &[
            // The footprint guard, first to read when a title misbehaves at a
            // low base: `g_gd_sp_min` is the lowest stack pointer a GD syscall
            // was entered with (minus the loader's `_end`, the margin of the
            // loader's AGENTS.md 4.6); `g_gd_sp_in_image` counts entries
            // already inside the loader.
            ("g_gd_sp_min", Fmt::Hex),
            ("g_gd_sp_in_image", Fmt::Num),
            ("g_gd_idx_counts", Fmt::GdIdx),
            ("g_gd_cmd_counts", Fmt::GdCmd),
            ("g_gd_park_longs", Fmt::Num),
            ("g_cdfs_read_retries", Fmt::Num),
            ("g_cdfs_read_fails", Fmt::Num),
            // The host stopped waiting for the LoadBinary echo and stopped
            // probing with DoneBinary on the sector path (`send_sectors`), so
            // this is the ONLY place a lost packet in a disc read now shows up.
            // fails = the host never answered; holes = it answered short.
            ("g_cdfs_read_holes", Fmt::Num),
            // A ReturnValue that ended a read's wait over an incomplete
            // window and was waited past: the late answer to an earlier
            // attempt. Absent from loaders before 2026-09-27.
            ("g_cdfs_read_stale", Fmt::Num),
            ("g_cdfs_sync_chunks", Fmt::Num),
            ("g_cdfs_sync_reentered", Fmt::Num),
            // Non-zero while a disc read waits; CD-DA declines to fetch then.
            ("g_gd_in_transfer", Fmt::Num),
            // The stuck GD lock watchdog: `g_gd_lock_stuck` counts locks
            // released because they were held while the server was parked and
            // unchanged for 250 ms; `_owner` says who held it (0 = the server
            // itself). It has not fired in any recorded session.
            ("g_gd_lock_stuck", Fmt::Num),
            ("g_gd_lock_stuck_owner", Fmt::Num),
            ("g_gd_lock_stuck_ticks", Fmt::Num),
            ("g_gd_lock_owner", Fmt::Num),
            ("g_gd_lock_gen", Fmt::Num),
            // How the boot-time stop of the REAL drive went (the loader's
            // AGENTS.md 4.14): 4 = COMPLETED, the healthy answer. 0 means it
            // never ran -- an older loader, or one built WITH_GD_SPINDOWN=0.
            ("g_gd_spindown", Fmt::Num),
        ],
    ),
    (
        "CD-DA",
        &[
            // Health. Both count SUB-FETCHES: served, and failed and asked
            // again (the host answers a re-ask from its history).
            ("g_cdda_plays", Fmt::Num),
            ("g_cdda_fetches", Fmt::Num),
            ("g_cdda_fetch_fails", Fmt::Num),
            // Why they failed, when it was not the deadline: an answer to
            // another request (refused), or our LBA echoed without our data (a
            // lost answer, caught instead of pushing the previous one again).
            ("g_cdda_wrong_lba", Fmt::Num),
            ("g_cdda_retv_nodata", Fmt::Num),
            // Late LoadBinaries into the staging buffer refused at the door.
            ("g_cdda_stale_lbin", Fmt::Num),
            // The AICA was about to play a part of the ring that was not
            // refilled in time: keyed off and restarted -- a short silence
            // instead of seconds of desynchronised ADPCM.
            ("g_cdda_mutes", Fmt::Num),
            // A title took channel 62/63: the stream was restarted.
            ("g_cdda_ch_stolen", Fmt::Num),
            // The least audio ever left ahead of the AICA (the lead, normally
            // ~890 ms; 0 would be a ring run dry), and the longest the loader
            // went without a service: the music only moves when the title
            // calls the GD driver.
            ("g_cdda_room_min", Fmt::Tmu1Ms),
            ("g_cdda_svc_gap_max", Fmt::Tmu2Ms),
            ("g_cdda_toc_fails", Fmt::Num),
            ("g_cdda_last_lba", Fmt::Hex),
            // Clock: the loop period in TMU1 ticks, and the host's trim in
            // force (1000000 = none yet).
            ("g_cdda_end_tm", Fmt::Num),
            ("g_cdda_scale_ppm", Fmt::Num),
        ],
    ),
    (
        "Warm start / DHCP",
        &[
            ("g_warm_start", Fmt::Num),
            ("g_warm_ip", Fmt::Ip),
            ("g_dhcp_replies", Fmt::Num),
            ("g_dhcp_not_ours", Fmt::Num),
        ],
    ),
    (
        "State",
        &[
            ("booted", Fmt::Num),
            ("running", Fmt::Num),
            ("our_ip", Fmt::Ip),
            ("tool_ip", Fmt::Ip),
            ("g_pmcr_backwards", Fmt::Num),
            ("g_idle_polls_max", Fmt::Num),
            // The millisecond deadline, which is a DIFFERENT exit from the
            // adapter loop than `g_idle_polls_max` records -- reading that one
            // as "no timeout fired" is exactly the mistake that hid a 3.005 s
            // freeze for two sessions.
            ("g_fine_timeouts", Fmt::Num),
        ],
    ),
];

/// `g_gd_idx_counts[]` reads as a row of eighteen numbers otherwise, and the
/// question it answers -- WHICH call is the title spinning on -- needs the
/// names. Indices 2 and 3 are bumped from `cdfs_redir.s` (offsets 8 and 12 off
/// the array), the rest from `cdfs_syscalls.c`.
const GD_IDX_NAMES: &[&str] = &[
    "ReqCmd",
    "GetCmdStat",
    "ExecServer",
    "InitSystem",
    "GetDrvStat",
    "G1DmaEnd",
    "ReqDmaTrans",
    "CheckDmaTrans",
    "ReadAbort",
    "Reset",
    "ChangeDataType",
    "SetPioCallback",
    "ReqPioTrans",
    "CheckPioTrans",
    "idx14",
    "idx15",
    "ChangeDisc",
    "CartRead",
];

/// The GD command codes, same numbering as `cdfs_syscalls.c` and as isoldr. A
/// code with no name here still shows, as its number.
fn gd_cmd_name(code: usize) -> Option<&'static str> {
    Some(match code {
        16 => "PIOREAD",
        17 => "DMAREAD",
        18 => "GETTOC",
        19 => "GETTOC2",
        20 => "PLAY_TRACKS",
        21 => "PLAY_SECTORS",
        22 => "PAUSE",
        23 => "RELEASE",
        24 => "INIT",
        27 => "SEEK",
        29 => "NOP",
        30 => "REQ_MODE",
        31 => "SET_MODE",
        33 => "STOP",
        34 => "GETSCD",
        35 => "GETSES",
        36 => "REQ_STAT",
        40 => "GET_VERS",
        _ => return None,
    })
}

struct Entry {
    name: &'static str,
    group: usize,
    fmt: Fmt,
    addr: u32,
    size: u32,
}

/// One SBIQ in flight: what has landed, and when we gave up waiting.
struct Pending {
    started: Instant,
    buf: Vec<u8>,
    have: Vec<bool>,
}

/// The half of the probe that has to live where the packets arrive.
///
/// WHY THIS IS NOT JUST A METHOD ON `Probe`. It was, and it never claimed a
/// single packet on a running title. dcload answers a SendBinQ only while it is
/// inside `bb->loop()`, and it is only inside `bb->loop()` while it waits for a
/// host transfer to land -- so the reply is emitted, every time, in the middle
/// of `send_data`'s own polling, which discards whatever it did not ask for.
/// The syscall loop never saw one. Measured on a title streaming CD-DA: 43
/// samples posted, 43 timed out, panel permanently empty.
///
/// Registered on the connection (`io::PacketSink`), it is consulted from every
/// poll site instead, which is the only arrangement that can work.
pub struct SampleSink {
    lo: u32,
    span: usize,
    pending: Option<Pending>,
    /// A complete sample, waiting for the probe to come back and decode it.
    /// Decoding needs the entry table and the panel, neither of which belongs
    /// on the packet path.
    done: Option<Vec<u8>>,
    misses: u64,
    /// Replies examined while a sample was open, and bytes actually filled.
    /// ONLY FOR THE LOG, and the log is the point: "no reply at all" and
    /// "a reply I refused" are different faults on different sides of the wire,
    /// and the panel cannot tell them apart -- both read as a missed sample.
    seen: u64,
    turned_away: u64,
    /// When the outstanding piece was last asked for, and whether a new ask is
    /// owed. THE REQUEST IS RETRANSMITTED because nothing else would ever ask
    /// again: one datagram, no acknowledgement, over a link where the RX ring
    /// overflowing is documented as normal back-pressure (AGENTS.md, the BBA
    /// ring rules). Everything else on this wire retries; this did not.
    last_sent: Instant,
    need_send: bool,
    /// True while the sink is pointed at the CONTROL range instead of the
    /// counters -- see `Probe::arm_control`.
    control: bool,
    /// Is the panel switched on? AN INACTIVE SINK CLAIMS NOTHING, and that is
    /// what lets this and `stackwatch`'s sink both stay installed: their ranges
    /// OVERLAP -- the panel's span contains `g_gd_sp_min` -- so whichever came
    /// first in the list would eat the other's replies. Exactly one is on.
    active: bool,
}

impl SampleSink {
    fn new(lo: u32, span: usize) -> Self {
        SampleSink {
            lo,
            span,
            pending: None,
            done: None,
            misses: 0,
            seen: 0,
            turned_away: 0,
            last_sent: Instant::now(),
            need_send: false,
            control: false,
            // A SINK MADE BY HAND IS USABLE. `Probe::new` overrides this with
            // the switch's real state; defaulting to off here would make the
            // constructor's product silently deaf, which is a trap for the next
            // caller and was one for the tests.
            active: true,
        }
    }

    /// Point the sink at a different range and start a request for it.
    fn retarget(&mut self, lo: u32, span: usize, control: bool) {
        self.lo = lo;
        self.span = span;
        self.control = control;
        self.open();
    }

    /// The next piece to ask for: ONE packet's worth, aligned from `lo`.
    ///
    /// A read is asked for a chunk at a time rather than all 1456 bytes at
    /// once, so the answer is exactly the shape of the one read that is known
    /// to work on this console -- `verify_image`'s 256 bytes, one SendBinary
    /// and one DoneBinary. A 1456-byte ask is answered with three frames
    /// back to back, emitted from inside a nested `bb->loop()`, and on real
    /// hardware not one of them came back.
    fn next_piece(&self) -> Option<(u32, u32)> {
        let p = self.pending.as_ref()?;
        let off = p.have.iter().position(|h| !*h)?;
        let start = off - (off % CHUNK_SIZE);
        let len = CHUNK_SIZE.min(self.span - start);
        Some((self.lo + start as u32, len as u32))
    }

    fn open(&mut self) {
        self.seen = 0;
        self.turned_away = 0;
        self.need_send = true;
        self.pending = Some(Pending {
            started: Instant::now(),
            buf: vec![0u8; self.span],
            have: vec![false; self.span],
        });
    }

    fn pending_since(&self) -> Option<Instant> {
        self.pending.as_ref().map(|p| p.started)
    }

    /// Bytes of the open sample that have landed, out of how many.
    fn filled(&self) -> (usize, usize) {
        match self.pending.as_ref() {
            Some(p) => (p.have.iter().filter(|h| **h).count(), self.span),
            None => (0, self.span),
        }
    }

    /// Give up on a request that is never going to be answered. Almost always
    /// a title that has stopped reading: dcload is not looking at the wire.
    fn expire(&mut self, after: Duration) -> bool {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.started.elapsed() > after)
        {
            self.pending = None;
            self.misses += 1;
            return true;
        }
        false
    }
}

impl PacketSink for SampleSink {
    /// Claim a packet that answers our own SBIQ.
    ///
    /// THE TEST IS THE ADDRESS, FOR BOTH KINDS OF PACKET, and getting that
    /// wrong is not a missed sample -- it breaks the disc read the title is
    /// blocked on. Measured 2026-08-30 on Sonic Adventure: the game stopped
    /// for about ten seconds every two seconds, once per sample.
    ///
    /// A DoneBinary used to be claimed on "some of our data has landed", which
    /// is true for essentially the whole life of a sample, and it went wrong in
    /// both directions at once:
    ///
    /// - the DoneBinary that ends a **sector transfer** was swallowed, so
    ///   `request_donebin` timed out ("No DoneBinary response received"), the
    ///   host abandoned the read, and the loader sat out its own 6-second
    ///   timeout before re-requesting;
    /// - our own terminator leaked the other way once the sample had completed
    ///   on its last SendBinary (`pending` is `None` by then, so the old code
    ///   refused it), and a SendBinQ terminator used to be address 0 / size 0
    ///   -- byte for byte what a COMPLETE LoadBinary window answers. The host
    ///   read it as "nothing missing anywhere: done" and credited a sector read
    ///   that still had holes in it.
    ///
    /// So dcload now names the range it served in that terminator
    /// (`cmd_sendbinq`, and the reasoning is written there), and the rule here
    /// is one line: a packet is ours if its address is inside the range we
    /// asked about. A transfer's DoneBinary names a game buffer or nothing;
    /// ours names loader RAM. They cannot collide -- the whole footprint rule
    /// (AGENTS.md 4.6) is that a title's buffers are not where the loader is.
    ///
    /// The terminator is claimed whether or not a sample is still open,
    /// because that is exactly the case that leaked.
    fn claim(&mut self, cmd: &DCReturnCmd) -> bool {
        if !self.active {
            return false;
        }
        let Some(inner) = cmd.cmd.as_ref() else {
            return false;
        };
        let (lo, span) = (self.lo, self.span);
        let off = match inner.address.checked_sub(lo) {
            Some(d) if (d as usize) < span => d as usize,
            _ => {
                // NOT COUNTED AS TURNED AWAY unless it is data. Every
                // DoneBinary on this socket that is not ours lands here, and
                // that is the normal case, not a symptom.
                if matches!(inner.cmd, DCLoadCmds::SendBinary(Some(_))) {
                    self.turned_away += 1;
                    trace!(
                        "diag: not ours, 0x{:08x} is outside 0x{lo:08x}+{span}",
                        inner.address
                    );
                }
                return false;
            }
        };

        // The end of ONE PIECE, not of the sample: a read is asked for a chunk
        // at a time (`next_piece`). Nothing is done with it -- the sample
        // completes on bytes -- it is claimed so it cannot be mistaken for a
        // transfer's acknowledgement further up.
        if matches!(inner.cmd, DCLoadCmds::DoneBinary()) {
            return true;
        }

        let DCLoadCmds::SendBinary(Some(chunk)) = &inner.cmd else {
            return false;
        };
        let n = (inner.size as usize).min(chunk.len());
        if n == 0 || off + n > span {
            self.turned_away += 1;
            trace!(
                "diag: not ours, 0x{:08x}+{} falls outside 0x{lo:08x}+{span}",
                inner.address, inner.size
            );
            return false;
        }
        {
            let Some(p) = self.pending.as_mut() else {
                return false;
            };
            p.buf[off..off + n].copy_from_slice(&chunk[..n]);
            p.have[off..off + n].fill(true);
        }
        self.seen += 1;

        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.have.iter().all(|h| *h))
        {
            let p = self.pending.take().expect("checked above");
            self.done = Some(p.buf);
        } else {
            // Ask for the next piece -- or again for this one.
            self.need_send = true;
        }
        true
    }
}

/// A sample is abandoned after this long.
///
/// GENEROUS ON PURPOSE, and it did not used to be. 1.5 s reads like a sensible
/// bound until you notice what it is bounding: not the console's turnaround --
/// dcload answers a SendBinQ inside one `bb->loop()` -- but how long the reply
/// may sit behind other traffic before this host gets to it. Under a runtime
/// CD-DA load that was long enough to abandon replies that then arrived, so
/// every sample was recorded as missed while the data was on its way. Holding a
/// request open costs nothing but a late next sample; giving up early costs the
/// whole feature.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an unanswered piece waits before it is asked for again.
const PIECE_RETRY: Duration = Duration::from_millis(300);

/// How much of the image is compared against the ELF before anything is
/// decoded. 256 bytes of the first loadable segment, which is what
/// `scripts/dc-counters.py` settled on.
const IDENT_BYTES: usize = 256;

pub struct Probe {
    entries: Vec<Entry>,
    /// Previous numeric reading per entry, parallel to `entries`. `None` until
    /// the first successful sample, so nothing is reported as "changed" on the
    /// strength of having never been read.
    prev: Vec<Option<Vec<u64>>>,
    lo: u32,
    span: usize,
    panel: ui::DiagPanel,
    next_at: Instant,
    /// Shared with the connection, which is where the replies are claimed.
    sink: Arc<Mutex<SampleSink>>,
    samples: u64,
    /// The range `verify_image` already read back successfully, kept as a
    /// CONTROL -- see `arm_control`.
    ctl: (u32, usize),
    /// Whether the control has been run. Once only, whatever it says.
    ctl_done: bool,
    /// The counters' own range, to go back to after the control.
    real: (u32, usize),
    /// What the counters were read out of, for the one line this logs at start.
    label: String,
    /// When the previous sample was DECODED, so the header can report the gap
    /// the deltas are really against. See `status`.
    prev_at: Option<Instant>,
    /// That gap, latched at the TOP of `decode` -- `status()` is called from
    /// the bottom of it and from repaints in between, so measuring it there
    /// against a just-updated `prev_at` reports 0.00s every time.
    last_gap: Option<f64>,
    /// THE PANEL FEEDS THE STACK VERDICT WHEN IT IS UP, because the range this
    /// samples CONTAINS `g_gd_sp_min` and `g_gd_sp_in_image` -- so the separate
    /// watch cannot run alongside it without the two sinks claiming each
    /// other's replies. See `stackwatch::StackVerdict`.
    stack: Option<crate::stackwatch::StackVerdict>,
}

impl Probe {
    /// Build a probe from the loader ELF the host is about to run -- or is
    /// already running. `label` is only what to call it in the log.
    ///
    /// Fails only when NONE of the counters are in the ELF, which means it is
    /// not dcload; a partial set is a build with some features compiled out and
    /// is served as it is.
    pub fn new(
        elf: &[u8],
        label: String,
        interval: Duration,
        start_on: bool,
    ) -> Result<Self, String> {
        let syms = crate::loaders::symbols(elf)?;
        let mut entries = Vec::new();
        for (gi, (_, names)) in GROUPS.iter().enumerate() {
            for (name, fmt) in names.iter() {
                if let Some(&(addr, size)) = syms.get(*name) {
                    entries.push(Entry {
                        name,
                        group: gi,
                        fmt: *fmt,
                        addr,
                        // nm reports 0 for a symbol the assembler sized for
                        // itself; every counter is at least a word.
                        size: if size == 0 { 4 } else { size },
                    });
                }
            }
        }
        if entries.is_empty() {
            return Err("none of dcload's counters are in this ELF -- is it really dcload?".into());
        }
        let lo = entries.iter().map(|e| e.addr).min().unwrap();
        let hi = entries.iter().map(|e| e.addr + e.size).max().unwrap();
        let span = (hi - lo) as usize;
        let n = entries.len();
        Ok(Probe {
            entries,
            prev: vec![None; n],
            lo,
            span,
            panel: ui::DiagPanel::new(interval, start_on),
            // The first sample goes out as soon as the loop starts: a panel
            // that stays empty for two seconds looks broken.
            next_at: Instant::now(),
            sink: Arc::new(Mutex::new(SampleSink {
                active: crate::ui::sampling_wanted(),
                ..SampleSink::new(lo, span)
            })),
            samples: 0,
            ctl: first_load(elf)
                .map(|(a, d)| (a, d.len()))
                .unwrap_or((lo, IDENT_BYTES)),
            ctl_done: false,
            prev_at: None,
            last_gap: None,
            real: (lo, span),
            label,
            stack: None,
        })
    }

    /// How many counters this build actually exposes, for the start-up line.
    pub fn counter_count(&self) -> usize {
        self.entries.len()
    }

    /// The range one sample reads, for the same line. Worth stating once: it is
    /// the whole cost of this feature on the wire.
    pub fn span(&self) -> (u32, usize) {
        (self.lo, self.span)
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// Hand the connection the sink that claims our replies.
    ///
    /// MUST be called before the first `tick`, and it is why `Probe` is not
    /// simply moved into the syscall loop: the packets do not arrive there.
    /// Hand the probe the stack verdict, so a `--diag` session learns and warns
    /// exactly as an ordinary one does.
    pub fn watch_stack(&mut self, verdict: crate::stackwatch::StackVerdict) {
        self.stack = Some(verdict);
    }

    pub fn install(&self, conn: &mut impl ExternalDcIo) {
        conn.add_sink(self.sink.clone() as crate::io::SharedSink);
    }

    /// Decode whatever landed, drop a request that is never going to be
    /// answered, and post the next one when it is due.
    ///
    /// Call from the TOP of a syscall-loop iteration, where no transfer is in
    /// progress: posting a command anywhere else would put it in the middle of
    /// a conversation somebody else owns.
    pub fn tick(&mut self, conn: &mut impl ExternalDcIo) {
        // 0. Follow `d`. Turning off ABANDONS whatever is in flight rather
        //    than waiting it out: the reason to press it is that the console
        //    should stop being asked, and a sample already open would go on
        //    being retransmitted for its whole PIECE_RETRY life.
        if !self.sync_switch() {
            return;
        }
        // 1. Anything complete? Decoding is done here, off the packet path.
        let done = {
            let mut sink = self.sink.lock().expect("sink poisoned");
            sink.done.take().map(|blob| (blob, sink.control))
        };
        if let Some((blob, was_control)) = done {
            self.next_at = Instant::now() + self.panel.interval();
            if was_control {
                // THE ANSWER TO "WHICH SIDE". The control is the very range
                // `verify_image` read back successfully before the title
                // started, so a read that works here and not on the counters
                // is a range problem on this side, not a console that has
                // stopped answering.
                warn!(
                    "diag: the CONTROL read of 0x{:08x}+{} was answered while the title runs, \
                     but 0x{:08x}+{} is not -- the counter range is at fault, not the console",
                    self.ctl.0, self.ctl.1, self.real.0, self.real.1
                );
                let (lo, span) = self.real;
                self.sink
                    .lock()
                    .expect("sink poisoned")
                    .retarget(lo, span, false);
            } else {
                self.samples += 1;
                self.decode(&blob);
            }
        }

        // 2. Anything stale? A title that has stopped asking for sectors has
        //    stopped polling the network too, so this is the normal state of a
        //    freeze -- which is also when the counters would say the most. The
        //    panel header carries the count; a log line per occurrence would
        //    not be worth it.
        let (expired, busy, filled, seen, turned_away) = {
            let mut sink = self.sink.lock().expect("sink poisoned");
            let filled = sink.filled();
            let (seen, turned_away) = (sink.seen, sink.turned_away);
            let expired = sink.expire(SAMPLE_TIMEOUT);
            (expired, sink.pending.is_some(), filled, seen, turned_away)
        };
        if expired {
            // WHICH SIDE FAILED. Nothing landed at all means dcload never
            // answered -- it only looks at the wire from inside `bb->loop()`,
            // which a title that has stopped reading never reaches (unless the
            // loader was built with GD_SERVICE_EVERY_SYSCALL=1). Something
            // landed but not all of it means the run was spliced, which is a
            // transport problem and not the same thing at all. The panel says
            // "missed" for both, so say it here.
            debug!(
                "diag: sample timed out -- {}/{} bytes landed, {seen} replies taken, \
                 {turned_away} turned away as somebody else's",
                filled.0, filled.1
            );
            self.next_at = Instant::now() + self.panel.interval();
            // SAY WHY, once it is clear this is not a one-off. dcload polls the
            // network from the disc-read path only (`cdfs_syscalls.c`), so a
            // title that has stopped asking for sectors answers nothing at all
            // -- and an empty box with a rising miss count reads as a broken
            // instrument rather than as the measurement it is.
            // The control runs ONCE, on the first miss, and settles which side
            // is at fault before another session is spent guessing.
            if self.samples == 0 && !self.ctl_done {
                self.ctl_done = true;
                let (lo, span) = self.ctl;
                info!(
                    "diag: no reply -- reading 0x{lo:08x}+{span} as a control (that exact \
                     read succeeded before the title started)"
                );
                self.sink
                    .lock()
                    .expect("sink poisoned")
                    .retarget(lo, span, true);
                self.next_at = Instant::now();
                return;
            }
            if self.sink.lock().expect("sink poisoned").control {
                // TWO READINGS, AND SILENCE CANNOT TELL THEM APART. This
                // said "the console does not answer SendBinQ while this title
                // runs" as if that were the only one, and it was read that way
                // -- on a session where the disc reads had stopped dead
                // seconds earlier and the console was simply gone. Whether
                // anything else is still arriving is the discriminator, and it
                // is in the log right above this line.
                warn!(
                    "diag: the CONTROL read of 0x{:08x}+{} went unanswered too. Either this \
                     console does not answer SendBinQ while this title runs, or it has stopped \
                     answering altogether -- check whether disc reads are still arriving above",
                    self.ctl.0, self.ctl.1
                );
                let (lo, span) = self.real;
                self.sink
                    .lock()
                    .expect("sink poisoned")
                    .retarget(lo, span, false);
                self.next_at = Instant::now() + self.panel.interval();
                return;
            }
            if self.samples == 0 && self.sink.lock().expect("sink poisoned").misses == 3 {
                self.panel.set_rows(vec![
                    PanelRow::placeholder("no reply: dcload polls the"),
                    PanelRow::placeholder("wire only while the title"),
                    PanelRow::placeholder("is reading the disc"),
                ]);
            }
            self.repaint_status();
        }

        // 3. Post: a new sample when one is due, then one PIECE at a time,
        //    retransmitting a piece that has gone unanswered. Nothing else on
        //    this wire sends a request once and hopes.
        if !busy {
            if Instant::now() < self.next_at {
                return;
            }
            self.sink.lock().expect("sink poisoned").open();
        }
        let (want, first_ask) = {
            let sink = self.sink.lock().expect("sink poisoned");
            if sink.need_send || sink.last_sent.elapsed() > PIECE_RETRY {
                (sink.next_piece(), sink.need_send)
            } else {
                (None, false)
            }
        };
        let Some((addr, len)) = want else {
            return;
        };
        let cmd = DCLoadCmd {
            cmd: DCLoadCmds::SendBinaryQuiet(None),
            address: addr,
            size: len,
        };
        if let Err(e) = conn.send_command(cmd) {
            debug!("diag: could not ask for the counters: {e}");
            self.next_at = Instant::now() + self.panel.interval();
            return;
        }
        // A RETRY IS NOT NEWS. Re-asking every 300 ms is the normal way this
        // gets an answer out of a console that is busy serving the title, so
        // only the first ask of a sample is worth a line -- at `-vv` the rest
        // was drowning the log it shares.
        if first_ask {
            debug!("diag: asking for 0x{addr:08x}+{len}");
        } else {
            trace!("diag: asking again for 0x{addr:08x}+{len}");
        }
        {
            let mut sink = self.sink.lock().expect("sink poisoned");
            sink.need_send = false;
            sink.last_sent = Instant::now();
        }
        self.repaint_status();
    }

    /// Bring the sampling into line with the panel's switch. Returns whether
    /// anything should be done this tick.
    fn sync_switch(&mut self) -> bool {
        let want = crate::ui::sampling_wanted();
        let mut sink = self.sink.lock().expect("sink poisoned");
        if sink.active == want {
            return want;
        }
        sink.active = want;
        sink.pending = None;
        sink.done = None;
        sink.need_send = false;
        drop(sink);
        if want {
            // Straight away: a panel that stays empty for a whole interval
            // after the key was pressed reads as a key that did nothing.
            self.next_at = Instant::now();
            info!("diag: sampling on ({} every {:.1} s) -- d to stop",
                  self.label, self.panel.interval().as_secs_f64());
        } else {
            info!("diag: sampling off -- the console is no longer being asked anything");
        }
        want
    }

    /// How long the syscall loop may block before this wants the CPU again.
    ///
    /// Two things need waking up: the next sample, and the panel's own repaint
    /// -- a keypress is handled on the reader thread, but indicatif throttles
    /// draws, so a repaint asked for between two frames can be dropped. Coming
    /// back within `REPAINT` picks that up, and costs one epoll wakeup that
    /// touches no socket.
    pub fn poll_timeout(&self) -> Option<Duration> {
        const REPAINT: Duration = Duration::from_millis(150);
        // OFF: nothing is outstanding, so there is no sample to wait for. Come
        // back anyway while there is a terminal, or `d` would not be noticed
        // until whatever else wants the loop next -- which, with the stack
        // watch on its ten-second interval, is a switch that appears dead.
        //
        // Slower than REPAINT because there is nothing to repaint: this is a
        // keypress latency and a quarter of a second is not felt. It is the one
        // cost this instrument now imposes on a session that never asks for it
        // -- four wakeups a second that touch no socket, and `settle()` is
        // guarded on its own idle time so they cannot end a burst early.
        const IDLE_KEY_POLL: Duration = Duration::from_millis(250);
        if !self.sink.lock().expect("sink poisoned").active {
            return self.panel.on_screen().then_some(IDLE_KEY_POLL);
        }
        // WHILE A SAMPLE IS IN FLIGHT THE DEADLINE IS ITS OWN, not the next
        // sample's -- which is already in the past, and asking to be woken at a
        // time that has been and gone is a busy loop. It spun at full tilt for
        // the whole 1.5 s of a missed sample, on the one path where the whole
        // point is not to take the machine away from a running title.
        let due = match self.sink.lock().expect("sink poisoned").pending_since() {
            Some(started) => started + SAMPLE_TIMEOUT,
            None => self.next_at,
        };
        let wait = due.saturating_duration_since(Instant::now());
        Some(if self.panel.on_screen() {
            wait.min(REPAINT)
        } else {
            // Nothing to redraw: wake only for the sample itself.
            wait
        })
    }

    /// Repaint without re-reading. Cheap, and rate-limited by indicatif.
    pub fn repaint(&self) {
        self.panel.render();
    }

    fn repaint_status(&self) {
        self.panel.set_status(self.status());
        self.panel.render();
    }

    fn status(&self) -> String {
        let (in_flight, misses) = {
            let sink = self.sink.lock().expect("sink poisoned");
            (sink.pending.is_some(), sink.misses)
        };
        // THE MEASURED GAP, NOT THE ONE THAT WAS ASKED FOR.
        //
        // Every rate anyone reads off this panel is a delta divided by this
        // number, and the setting is not that number: a sample is answered
        // from inside `bb->loop()`, which during CD-DA is a fraction of a
        // percent duty cycle, so a request made on a 2 s timer is regularly
        // served most of a second late. Printing the setting made 49 audio
        // fetches served over a real 2.61 s read as 24.5/s against the
        // 18.75/s real time needs -- a 31 % over-fetch that was not
        // happening. AGENTS.md 11: prove the instrument first.
        let mut s = match self.last_gap {
            Some(secs) => format!("{secs:.2}s"),
            None => format!("{:.1}s set", self.panel.interval().as_secs_f64()),
        };
        if in_flight {
            s.push_str(" ...");
        }
        if misses > 0 {
            s.push_str(&format!(" {misses} missed"));
        }
        s
    }

    /// Turn one raw sample into panel rows, remembering enough of it to say
    /// what moved next time.
    fn decode(&mut self, blob: &[u8]) {
        // BEFORE THE PANEL, and out of the same bytes: the two counters the
        // placement pass needs are in this very range (see `stack`).
        if let Some(stack) = self.stack.as_mut() {
            let word = |name: &str| -> Option<u32> {
                let e = self.entries.iter().find(|e| e.name == name)?;
                let off = e.addr.checked_sub(self.lo)? as usize;
                let b = blob.get(off..off + 4)?;
                Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            };
            if let (Some(sp), Some(in_image)) = (word("g_gd_sp_min"), word("g_gd_sp_in_image")) {
                stack.observe(sp, in_image);
            }
        }
        let now = Instant::now();
        self.last_gap = self.prev_at.map(|t| (now - t).as_secs_f64());
        self.prev_at = Some(now);

        let mut rows: Vec<PanelRow> = Vec::new();
        let mut changed_names: Vec<String> = Vec::new();
        let mut current_group = usize::MAX;

        for (i, e) in self.entries.iter().enumerate() {
            let off = (e.addr - self.lo) as usize;
            let raw = &blob[off..off + e.size as usize];
            let values = words(raw, e.size as usize);
            let previous = self.prev[i].as_deref();

            if e.group != current_group {
                current_group = e.group;
                rows.push(PanelRow::header(GROUPS[e.group].0));
            }

            match e.fmt {
                Fmt::GdIdx | Fmt::GdCmd => {
                    let named = |k: usize| -> String {
                        if e.fmt == Fmt::GdIdx {
                            GD_IDX_NAMES
                                .get(k)
                                .map(|s| (*s).to_string())
                                .unwrap_or_else(|| k.to_string())
                        } else {
                            gd_cmd_name(k)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| k.to_string())
                        }
                    };
                    // ONLY WHAT WAS ASKED FOR. Forty-eight slots of which four
                    // are used reads as a haystack; the calls a title actually
                    // makes are the whole point. A slot that has never been
                    // touched is still listed under `a`, so "it never happened"
                    // stays distinguishable from "the counter is not there".
                    let any = values.iter().any(|v| *v != 0);
                    rows.push(PanelRow::value(
                        e.name.to_string(),
                        if any { String::new() } else { "(none)".into() },
                        false,
                        !any,
                    ));
                    for (k, v) in values.iter().enumerate() {
                        let was = previous.and_then(|p| p.get(k)).copied();
                        let moved = was.is_some_and(|w| w != *v);
                        rows.push(PanelRow::value(
                            format!("  {}", named(k)),
                            with_delta(grouped(*v), was, *v),
                            moved,
                            *v == 0,
                        ));
                        if moved {
                            changed_names.push(format!(
                                "{}[{}]={}",
                                e.name,
                                named(k),
                                plain(*v, was)
                            ));
                        }
                    }
                }
                _ => {
                    let v = values.first().copied().unwrap_or(0);
                    let was = previous.and_then(|p| p.first()).copied();
                    let moved = was.is_some_and(|w| w != v);
                    let text = match e.fmt {
                        Fmt::Hex => format!("0x{v:08x}"),
                        Fmt::Tmu1Ms | Fmt::Tmu2Ms => {
                            // 0xffffffff is the "nothing has been measured yet"
                            // value of the minimum-tracking counters, and
                            // 343 s of milliseconds would read as a measurement.
                            if v == u64::from(u32::MAX) {
                                "not measured yet".to_string()
                            } else {
                                let per_ms = if matches!(e.fmt, Fmt::Tmu1Ms) {
                                    3125.0
                                } else {
                                    12500.0
                                };
                                format!("{} ({:.1} ms)", grouped(v), v as f64 / per_ms)
                            }
                        }
                        Fmt::Ip => format!(
                            "{}.{}.{}.{}",
                            v >> 24,
                            (v >> 16) & 0xff,
                            (v >> 8) & 0xff,
                            v & 0xff
                        ),
                        _ => with_delta(grouped(v), was, v),
                    };
                    if moved {
                        changed_names.push(format!("{}={}", e.name, plain(v, was)));
                    }
                    rows.push(PanelRow::value(e.name.to_string(), text, moved, v == 0));
                }
            }
            self.prev[i] = Some(values);
        }

        self.panel.set_rows(rows);
        self.panel.set_status(self.status());
        self.panel.render();

        // NOT A TERMINAL: the panel draws nothing (indicatif turns every draw
        // into a no-op when stderr is redirected), so the sample would be
        // silently thrown away. Whoever piped the output into a file asked for
        // the numbers just as much, and only the ones that moved are worth a
        // line.
        if !self.panel.on_screen() && !changed_names.is_empty() {
            info!("diag: {}", changed_names.join(" "));
        }
    }
}

/// THE IDENTITY CHECK, and it is not optional.
///
/// Everything this module prints is an address computed from an ELF on disk. If
/// the console is running a different image they are addresses in something
/// else, and every value would be believable and wrong -- see the module header
/// for the measurement that established that matching the BASE is not enough,
/// because two builds of the same base put the same counter in two places. So
/// compare the code, and refuse rather than decode.
///
/// Called with the title not yet started, where blocking for a round trip costs
/// nothing, and before the panel exists so a refusal never flashes a box on the
/// screen on its way out.
pub fn verify_image(conn: &mut impl ExternalDcIo, elf: &[u8], label: &str) -> Result<(), String> {
    let Some((addr, want)) = first_load(elf) else {
        return Err("this ELF has no loadable segment to compare against".into());
    };
    let got = crate::dispatch::receive_data(
        conn,
        Some(Duration::from_millis(500)),
        addr,
        want.len(),
        true,
    )
    .map_err(|e| format!("could not read 0x{addr:08x} back off the console: {e}"))?;
    if got.len() != want.len() {
        return Err(format!(
            "short read at 0x{addr:08x}: {} bytes of {}",
            got.len(),
            want.len()
        ));
    }
    if let Some(i) = (0..want.len()).find(|&i| got[i] != want[i]) {
        return Err(format!(
            "{label} is NOT the image running on the Dreamcast: they differ at \
             0x{:08x} (console 0x{:02x}, ELF 0x{:02x}). Every counter would come \
             from the wrong build",
            addr as usize + i,
            got[i],
            want[i]
        ));
    }
    Ok(())
}

/// The numeric reading of a counter: one value, or one per array slot.
fn words(raw: &[u8], size: usize) -> Vec<u64> {
    match size {
        1 => vec![raw[0] as u64],
        2 => vec![u16::from_le_bytes([raw[0], raw[1]]) as u64],
        _ => raw
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64)
            .collect(),
    }
}

/// `184 210  +4102`. The delta is against the previous SAMPLE, not per second:
/// the interval is adjustable from the panel, and a rate that silently changed
/// meaning when someone pressed `+` would be worse than no rate at all.
fn with_delta(text: String, was: Option<u64>, now: u64) -> String {
    match was {
        Some(w) if w != now => {
            let d = now as i64 - w as i64;
            format!("{text}  {d:+}")
        }
        _ => text,
    }
}

/// The same reading for a log line: one token, no grouping spaces to be split
/// on, and the delta in brackets so `254386+8206` cannot be read as a number.
fn plain(now: u64, was: Option<u64>) -> String {
    match was {
        Some(w) if w != now => format!("{now}({:+})", now as i64 - w as i64),
        _ => now.to_string(),
    }
}

/// Thousands separated by a space, because these run to seven digits and the
/// eye cannot count zeros.
fn grouped(v: u64) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Address and first bytes of the lowest loadable segment -- the identity
/// check's reference.
///
/// A program-header walk rather than a section lookup, because the section
/// names differ between the LOW and HIGH link scripts and this has to work for
/// both, including for an image `loaders::relocate` moved in memory.
fn first_load(bytes: &[u8]) -> Option<(u32, Vec<u8>)> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes).ok()?;
    let segments = elf.segments()?;
    let mut best: Option<(u32, Vec<u8>)> = None;
    for ph in segments.iter() {
        if ph.p_type != abi::PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        let off = ph.p_offset as usize;
        let n = (ph.p_filesz as usize).min(IDENT_BYTES);
        let slice = bytes.get(off..off + n)?;
        let vaddr = ph.p_vaddr as u32;
        if best.as_ref().is_none_or(|(at, _)| vaddr < *at) {
            best = Some((vaddr, slice.to_vec()));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sbin(addr: u32, data: &[u8]) -> Vec<u8> {
        let mut v = b"SBIN".to_vec();
        v.extend_from_slice(&addr.to_be_bytes());
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    /// A read is asked for one packet at a time, and the tail is short.
    ///
    /// The whole 1456-byte range in one ask is answered with three frames back
    /// to back from inside a nested `bb->loop()`, and on real hardware not one
    /// of them came back; `verify_image`'s single-packet read, at the same
    /// moment, did.
    #[test]
    fn a_sample_is_asked_for_one_packet_at_a_time() {
        let mut sink = SampleSink::new(0x8c00_a8c8, 1456);
        sink.open();
        assert_eq!(sink.next_piece(), Some((0x8c00_a8c8, 1440)));
        sink.pending.as_mut().unwrap().have[..1440].fill(true);
        assert_eq!(sink.next_piece(), Some((0x8c00_a8c8 + 1440, 16)));
        sink.pending.as_mut().unwrap().have.fill(true);
        assert_eq!(sink.next_piece(), None);
    }

    /// THE TEST THIS FEATURE DID NOT HAVE, and its absence is the whole reason
    /// the panel stayed empty on a real console: the probe filtered replies in
    /// the syscall loop, and the replies never go there. What matters is that a
    /// packet is claimed at the ONE place every poll site shares.
    #[test]
    fn a_reply_is_claimed_in_the_io_layer_wherever_it_is_polled() {
        use crate::io::DcIoUDP;
        use std::net::UdpSocket;

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let port = peer.local_addr().unwrap().port();
        let mut conn = DcIoUDP::new("127.0.0.1".into(), port, None).expect("bind conn");

        // The peer only learns our address once we have spoken, exactly as
        // dcload does.
        conn.send_command(DCLoadCmd {
            cmd: DCLoadCmds::SendBinaryQuiet(None),
            address: 0x8c00_a000,
            size: 8,
        })
        .expect("send");
        let mut scratch = [0u8; 64];
        let (_, from) = peer.recv_from(&mut scratch).expect("recv");

        let sink = Arc::new(Mutex::new(SampleSink::new(0x8c00_a000, 8)));
        sink.lock().unwrap().open();
        conn.add_sink(sink.clone() as crate::io::SharedSink);

        // One packet that is ours, and one that is not.
        peer.send_to(&sbin(0x8c00_a000, &[1, 2, 3, 4, 5, 6, 7, 8]), from)
            .expect("send ours");
        peer.send_to(&sbin(0x0c01_0000, &[9; 4]), from)
            .expect("send theirs");

        // THE SLEEP IS THE TEST'S PROBLEM, NOT THE PRODUCT'S. What is being
        // asserted is that ONE wakeup drains whatever is queued -- the poller
        // is one-shot, and anything left behind surfaces a wakeup late, which
        // is how the counter probe came to abandon replies that were on their
        // way. Two `send_to` calls on loopback are normally both queued before
        // the receiver looks, but nothing guarantees it: caught 2026-09-05
        // failing about one run in fifty with `seen.len()` 0, the second
        // datagram simply not having arrived yet. Waiting for both to be
        // queued is what makes the measurement the intended one.
        std::thread::sleep(Duration::from_millis(50));
        let evt = conn.poll(Some(Duration::from_millis(500))).expect("poll");
        let seen = conn.handle_data(&evt).expect("handle");

        // Ours was taken off the wire before anybody else could see it...
        let done = sink.lock().unwrap().done.take().expect("sample completed");
        assert_eq!(done, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        // ...and somebody else's transfer still gets its own reply, which is
        // the failure mode a greedy filter would cause.
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].cmd.as_ref().map(|c| c.address), Some(0x0c01_0000));
    }

    /// A sink that is switched off claims NOTHING, terminators included.
    ///
    /// This is the whole of the mutual exclusion between the panel and the
    /// stack watch: their ranges overlap -- the panel's span contains
    /// `g_gd_sp_min` -- so if both claimed at once, whichever the IO layer
    /// consulted first would eat the other's replies, silently, and the loser
    /// would report nothing for the rest of the session. `d` moves the flag;
    /// this is what the flag has to mean.
    #[test]
    fn an_inactive_sink_claims_nothing() {
        fn dbin(addr: u32, size: u32) -> DCReturnCmd {
            let mut v = b"DBIN".to_vec();
            v.extend_from_slice(&addr.to_be_bytes());
            v.extend_from_slice(&size.to_be_bytes());
            DCReturnCmd::try_from(v).expect("DBIN parses")
        }
        let ours = DCReturnCmd::try_from(sbin(0x8c00_a000, &[1, 2, 3, 4])).expect("SBIN parses");

        let mut sink = SampleSink::new(0x8c00_a000, 8);
        sink.open();
        sink.active = false;
        assert!(!sink.claim(&ours), "data inside our own range");
        assert!(!sink.claim(&dbin(0x8c00_a000, 8)), "our own terminator");

        // And the same sink switched back on takes both, so what is being
        // tested is the flag and not a range that never matched.
        sink.active = true;
        assert!(sink.claim(&ours), "data, once switched on");
        assert!(sink.claim(&dbin(0x8c00_a000, 8)), "terminator, once switched on");
    }

    /// A `DoneBinary` is claimed on its ADDRESS, and on nothing else.
    ///
    /// THE TEST THAT WAS MISSING WHEN IT MATTERED. The rule used to be "some of
    /// our data has landed", which is true for nearly the whole life of a
    /// sample, and it broke the disc read the title was blocked on: measured
    /// 2026-08-30 on Sonic Adventure, the game stopped for about ten seconds
    /// every two seconds, once per sample. Both directions are checked here
    /// because both happened -- a transfer's terminator swallowed, and our own
    /// leaking back to be read as "nothing missing anywhere: done".
    #[test]
    fn only_our_own_donebinary_is_swallowed() {
        fn dbin(addr: u32, size: u32) -> DCReturnCmd {
            let mut v = b"DBIN".to_vec();
            v.extend_from_slice(&addr.to_be_bytes());
            v.extend_from_slice(&size.to_be_bytes());
            DCReturnCmd::try_from(v).expect("DBIN parses")
        }

        let mut sink = SampleSink::new(0x8c00_a000, 8);
        sink.open();

        let ours = DCReturnCmd::try_from(sbin(0x8c00_a000, &[1, 2, 3, 4])).expect("SBIN parses");
        assert!(sink.claim(&ours), "our own data");

        // A COMPLETE LoadBinary window answers 0/0, and the sample is wide open
        // with data in it -- the exact state the old rule swallowed on.
        assert!(!sink.claim(&dbin(0, 0)), "a transfer's terminator");
        // One naming a part still missing names a game buffer, never loader RAM.
        assert!(!sink.claim(&dbin(0x0c9b_7000, 1440)), "a repair request");

        // Ours names the range we asked about...
        assert!(sink.claim(&dbin(0x8c00_a000, 8)), "our own terminator");
        // ...and is still ours after the sample completed on its last
        // SendBinary, which is precisely when it used to leak.
        sink.pending = None;
        assert!(sink.claim(&dbin(0x8c00_a000, 8)), "after the sample closed");
    }

    #[test]
    fn thousands_are_grouped_from_the_right() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1000), "1 000");
        assert_eq!(grouped(184210), "184 210");
    }

    #[test]
    fn a_delta_is_only_shown_once_there_is_something_to_compare_with() {
        assert_eq!(with_delta("5".into(), None, 5), "5");
        assert_eq!(with_delta("5".into(), Some(5), 5), "5");
        assert_eq!(with_delta("5".into(), Some(3), 5), "5  +2");
        assert_eq!(with_delta("3".into(), Some(5), 3), "3  -2");
    }

    #[test]
    fn a_byte_sized_counter_reads_as_one_value_not_as_a_word() {
        assert_eq!(words(&[7], 1), vec![7]);
        assert_eq!(words(&[1, 0, 0, 0], 4), vec![1]);
        assert_eq!(words(&[1, 0, 0, 0, 2, 0, 0, 0], 8), vec![1, 2]);
    }

    /// Every name in the table has to be spelled the way the loader spells it,
    /// and the only thing that can check that here is the loader's own ELF --
    /// which is not in this crate. What IS checkable is that the table has no
    /// duplicates: a name listed twice reads the same address twice and makes
    /// the panel silently longer than the set of counters that exist.
    #[test]
    fn no_counter_is_listed_twice() {
        let mut seen = std::collections::HashSet::new();
        for (_, names) in GROUPS {
            for (n, _) in *names {
                assert!(seen.insert(*n), "{n} is in the table twice");
            }
        }
    }

    #[test]
    fn every_gd_syscall_index_has_a_name() {
        // 18 slots, as declared in cdfs_syscalls.c.
        assert_eq!(GD_IDX_NAMES.len(), 18);
    }
}
