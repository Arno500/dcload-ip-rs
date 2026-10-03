//! CD-DA: where samples come from, the continuity check, the clock trim, and
//! serving an audio request (AGENTS.md 4).

use super::*;

/// Where the CD-DA samples come from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CddaSource {
    /// Refuse every audio read (`--no-cdda`), so the loader stops the stream.
    Off,
    /// The disc image.
    Disc,
    /// A two-tone triangle (`--cdda-tone`) in place of the disc read; the
    /// encoder, wire and loader still run.
    Tone,
}

/// The test tone as raw sectors: 344.5 Hz left, 689.1 Hz right. The phase
/// follows the absolute sample index, so requests join seamlessly and a
/// re-asked sector is byte-identical.
pub(super) fn tone_sectors(lba: u32, sectors: u32) -> Vec<u8> {
    const PERIOD_L: u64 = 128;
    const PERIOD_R: u64 = 64;

    fn tri(i: u64, period: u64) -> i16 {
        let half = period / 2;
        let scale = (32768 / half) as i64;
        let t = i % period;
        let a = if t < half { t } else { period - t } as i64;
        ((a - (half / 2) as i64) * scale) as i16
    }

    let mut out = Vec::with_capacity(sectors as usize * RAW_SECTOR_SIZE);
    for s in 0..sectors as u64 {
        let base = (lba as u64 + s) * FRAMES_PER_SECTOR as u64;
        for i in 0..FRAMES_PER_SECTOR as u64 {
            out.extend_from_slice(&tri(base + i, PERIOD_L).to_le_bytes());
            out.extend_from_slice(&tri(base + i, PERIOD_R).to_le_bytes());
        }
    }
    out
}

/// Sample-to-sample continuity scan of the PCM served, before encoding.
///
/// Counts steps over `LIMIT` ("hits") and consecutive pairs ("runs"). Loud
/// music produces thousands, so the counts alone mean nothing: a defect shows
/// as hits concentrated at one offset inside a sector (`verdict`).
pub struct SlewWatch {
    prev: Option<(i32, i32)>,
    pub(super) hits: u64,
    pub(super) runs: u64,
    pub(super) max: i32,
    /// LBA and frame of the first run.
    pub(super) first: Option<(u32, usize)>,
    /// 32 bytes of PCM around the first run.
    pub(super) first_bytes: Vec<u8>,
    /// Hit counts per frame offset inside a sector (588 frames).
    off: Vec<u64>,
}

impl SlewWatch {
    const LIMIT: i32 = 24000;

    pub fn new() -> Self {
        Self {
            prev: None,
            hits: 0,
            runs: 0,
            max: 0,
            first: None,
            first_bytes: Vec::new(),
            off: vec![0; FRAMES_PER_SECTOR as usize],
        }
    }

    /// Where the hits concentrate inside a sector: `(offset, hits there, sigma
    /// above a uniform spread)`, or `None` below 64 hits. Pipeline defects are
    /// aligned to the sector, music is not; callers treat > 8 sigma as a defect.
    pub fn verdict(&self) -> Option<(usize, u64, f64)> {
        if self.hits < 64 {
            return None;
        }
        let n = self.off.len() as f64;
        let mean = self.hits as f64 / n;
        let (i, top) = self
            .off
            .iter()
            .enumerate()
            .max_by_key(|&(_, c)| *c)
            .map(|(i, c)| (i, *c))
            .unwrap();
        let sigma = mean.sqrt().max(1e-9);
        let z = (top as f64 - mean) / sigma;
        Some((i, top, z))
    }

    pub fn describe(&self) -> String {
        match self.verdict() {
            None => "too few steps to say anything".into(),
            Some((i, top, z)) if z > 8.0 => format!(
                "CONCENTRATED at sector offset {i} ({top} of {} hits, {z:.1} sigma) \
                 -- that alignment is a reader or dump defect, not music",
                self.hits
            ),
            Some((_, _, z)) => format!(
                "spread evenly across all {} sector offsets ({z:.1} sigma at the \
                 busiest) -- the fingerprint of loud music, not of a defect",
                self.off.len()
            ),
        }
    }

    /// `pcm` is interleaved little-endian 16-bit stereo.
    pub fn scan(&mut self, lba: u32, pcm: &[u8]) {
        let mut prev_big = false;
        for (i, f) in pcm.chunks_exact(4).enumerate() {
            let l = i16::from_le_bytes([f[0], f[1]]) as i32;
            let r = i16::from_le_bytes([f[2], f[3]]) as i32;
            let Some((pl, pr)) = self.prev else {
                self.prev = Some((l, r));
                continue;
            };
            let (dl, dr) = ((l - pl).abs(), (r - pr).abs());
            self.prev = Some((l, r));
            self.max = self.max.max(dl).max(dr);
            let big = dl > Self::LIMIT || dr > Self::LIMIT;
            if big {
                self.hits += 1;
                let slot = i % self.off.len();
                self.off[slot] += 1;
                if prev_big {
                    self.runs += 1;
                    if self.first.is_none() {
                        self.first = Some((lba, i));
                        let at = i * 4;
                        let lo = at.saturating_sub(16).min(pcm.len());
                        let hi = (lo + 32).min(pcm.len());
                        self.first_bytes = pcm[lo..hi].to_vec();
                    }
                }
            }
            prev_big = big;
        }
    }
}

/// Judge every audio track of an image with `SlewWatch`, offline. Returns the
/// number of steps in tracks judged defective.
pub fn audit_audio(disc: &dyn DiscFormat, only: Option<u8>) -> Result<u64, String> {
    const RUN: u32 = 3;
    let toc = disc.toc_tracks();
    if toc.is_empty() {
        return Err("this image reports no tracks at all".into());
    }
    info!("{} tracks:", toc.len());
    for (i, t) in toc.iter().enumerate() {
        let end = toc.get(i + 1).map(|n| n.start_lba);
        info!(
            "  track {:2} {:5} at LBA {:8} (0x{:08x}){}",
            t.number,
            if t.audio { "audio" } else { "data" },
            t.start_lba,
            t.start_lba,
            match end {
                Some(e) => format!(
                    " .. {:8}, {} sectors, {:.1} s",
                    e - 1,
                    e - t.start_lba,
                    (e - t.start_lba) as f64 * 588.0 / 44100.0
                ),
                None => " .. end of disc".into(),
            }
        );
    }

    let mut total = 0u64;
    for (i, t) in toc.iter().enumerate() {
        if !t.audio || only.is_some_and(|n| n != t.number) {
            continue;
        }
        let Some(end) = toc.get(i + 1).map(|n| n.start_lba) else {
            continue;
        };
        let mut watch = SlewWatch::new();
        // Consecutive bad reads are one band.
        let mut bands: Vec<(u32, u32)> = Vec::new();
        let mut lba = t.start_lba;
        let mut failed = 0u32;
        while lba + RUN <= end {
            match disc.read_audio(lba, RUN) {
                Ok(pcm) => {
                    let before = watch.runs;
                    watch.scan(lba, &pcm);
                    if watch.runs > before {
                        match bands.last_mut() {
                            Some(b) if lba <= b.1 + RUN * 2 => b.1 = lba + RUN,
                            _ => bands.push((lba, lba + RUN)),
                        }
                    }
                }
                Err(_) => failed += 1,
            }
            lba += RUN;
        }
        let secs = |n: u32| n as f64 * 588.0 / 44100.0;
        let aligned = matches!(watch.verdict(), Some((_, _, z)) if z > 8.0);
        if !aligned {
            info!(
                "  track {:2}: clean ({:.1} s, {} big step(s), largest {}) -- {}",
                t.number,
                secs(end - t.start_lba),
                watch.hits,
                watch.max,
                watch.describe()
            );
        } else {
            warn!(
                "  track {:2}: {} big step(s) in {} band(s), largest {}{} -- {}",
                t.number,
                watch.hits,
                bands.len(),
                watch.max,
                if failed > 0 {
                    format!(", {failed} read(s) failed")
                } else {
                    String::new()
                },
                watch.describe()
            );
            for (a, b) in bands.iter().take(16) {
                warn!(
                    "      LBA 0x{a:08x}..0x{b:08x}  ({:.1} s in, {:.1} s long)",
                    secs(a - t.start_lba),
                    secs(b - a)
                );
            }
            if bands.len() > 16 {
                warn!("      ... and {} more band(s)", bands.len() - 16);
            }
        }
        if aligned {
            total += watch.hits;
        }
    }
    Ok(total)
}

/// Stereo frames in one raw sector (1/75 s); also the ADPCM bytes per sector.
pub(super) const FRAMES_PER_SECTOR: u32 = RAW_SECTOR_SIZE as u32 / 4;

/// An answer slower than this (a third of a PAL frame) counts as slow.
pub(super) const CDDA_SLOW_US: u64 = 5_000;

// ---- Clock estimator thresholds (`CddaClock`) ----
//
// They describe the loader's stream: one sub-fetch of 4 sectors (53 ms) at a
// time, paced. If that geometry changes on the loader, re-check these and the
// `feed_stream` tests.

/// Seconds of accepted stream before the first estimate, and between later
/// ones. The error is a few hundred ppm, so resolution beats speed.
pub(super) const CDDA_TRIM_FIRST_S: f64 = 90.0;
pub(super) const CDDA_TRIM_S: f64 = 300.0;
/// The longest gap between requests that still counts as a free-running
/// stream; a longer one is dropped from both sums.
const CDDA_TRIM_GAP_MAX: f64 = 1.0;
/// The furthest one request may advance the disc position and still continue
/// the stream (a sub-fetch is 3-4 sectors).
const CDDA_TRIM_STEP_MAX: u32 = 12;
/// Seconds banked per segment. Short enough that the catch-up burst after a
/// dropped gap (up to the loader's 893 ms lead) fails the segment test.
const CDDA_TRIM_SEG_S: f64 = 2.0;
/// A segment whose audio/time ratio is more than 20 % off is dropped.
const CDDA_TRIM_SEG_SANE: f64 = 0.20;
/// A window whose own estimate is more than 3 % off is discarded.
const CDDA_TRIM_WINDOW_SANE: f64 = 0.03;
/// Estimates outside +/-1.5 % are refused (the loader applies the same gate).
const CDDA_TRIM_SANE: std::ops::RangeInclusive<u32> = 985_000..=1_015_000;

/// What one clock measurement decided.
#[derive(Debug, PartialEq)]
pub(super) enum CddaTrim {
    Applied { from: u32, to: u32, win_ppm: i64, secs: f64 },
    Held { ppm: u32, win_ppm: i64, secs: f64 },
    Refused { est_ppm: u32, secs: f64 },
    Discarded { secs: f64, ratio: f64 },
}

/// Measures the loader's CD-DA clock (an SH4 timer of compiled-in period)
/// against this host's, and returns a scale in ppm with every audio answer.
///
/// It counts disc position, not requests (a re-ask repeats an LBA); it only
/// banks free-running segments that took about as long as their audio; and
/// each estimate is total audio over total time corrected by the scale in force
/// at the time, so it refines one constant rather than stepping.
pub(super) struct CddaClock {
    /// What the loader is running on, in ppm of its constant.
    pub(super) scale_ppm: u32,
    prev: Option<(Instant, u32)>,
    /// The segment not yet judged.
    pend_audio_s: f64,
    pend_time_s: f64,
    win_audio_s: f64,
    win_time_s: f64,
    audio_s: f64,
    denom_s: f64,
    trims: u32,
}

impl CddaClock {
    pub(super) fn new() -> Self {
        Self {
            scale_ppm: 1_000_000,
            prev: None,
            pend_audio_s: 0.0,
            pend_time_s: 0.0,
            win_audio_s: 0.0,
            win_time_s: 0.0,
            audio_s: 0.0,
            denom_s: 0.0,
            trims: 0,
        }
    }

    /// Seconds banked toward the next window, its audio/time rate, the scale in
    /// force, and the number of estimates made.
    pub(super) fn progress(&self) -> (f64, f64, u32, u32) {
        let rate = if self.win_time_s > 0.0 {
            self.win_audio_s / self.win_time_s
        } else {
            0.0
        };
        (self.win_time_s, rate, self.scale_ppm, self.trims)
    }

    /// One audio request, at the instant it arrived and the LBA it asked for.
    pub(super) fn note(&mut self, now: Instant, lba: u32) -> Option<CddaTrim> {
        if let Some((pt, plba)) = self.prev {
            let gap = now.saturating_duration_since(pt).as_secs_f64();
            let step = lba.wrapping_sub(plba);
            if gap <= CDDA_TRIM_GAP_MAX && step <= CDDA_TRIM_STEP_MAX {
                self.pend_audio_s += f64::from(step) / 75.0;
                self.pend_time_s += gap;
            } else {
                // Not free-running: start a fresh segment.
                self.pend_audio_s = 0.0;
                self.pend_time_s = 0.0;
            }
        }
        self.prev = Some((now, lba));
        if self.pend_time_s < CDDA_TRIM_SEG_S {
            return None;
        }
        let (pa, pt) = (self.pend_audio_s, self.pend_time_s);
        self.pend_audio_s = 0.0;
        self.pend_time_s = 0.0;
        // A stall or a catch-up does not look like real time: drop it.
        if ((pa / pt) - 1.0).abs() > CDDA_TRIM_SEG_SANE {
            return None;
        }
        self.win_audio_s += pa;
        self.win_time_s += pt;

        let want = if self.trims == 0 { CDDA_TRIM_FIRST_S } else { CDDA_TRIM_S };
        if self.win_time_s < want {
            return None;
        }
        let scale = f64::from(self.scale_ppm) / 1e6;
        let rate = self.win_audio_s / self.win_time_s;
        let secs = self.win_time_s;
        // Corrected for the scale already in force, or a trimmed loader would
        // look off forever.
        let est_win = rate * scale;
        if (est_win - 1.0).abs() > CDDA_TRIM_WINDOW_SANE {
            self.win_audio_s = 0.0;
            self.win_time_s = 0.0;
            return Some(CddaTrim::Discarded { secs, ratio: rate });
        }
        self.audio_s += self.win_audio_s;
        self.denom_s += self.win_time_s / scale;
        self.win_audio_s = 0.0;
        self.win_time_s = 0.0;
        self.trims += 1;
        let win_ppm = ((est_win - 1.0) * 1e6).round() as i64;
        let est_ppm = ((self.audio_s / self.denom_s) * 1e6).round() as u32;
        if !CDDA_TRIM_SANE.contains(&est_ppm) {
            return Some(CddaTrim::Refused { est_ppm, secs });
        }
        if est_ppm == self.scale_ppm {
            return Some(CddaTrim::Held { ppm: est_ppm, win_ppm, secs });
        }
        let from = self.scale_ppm;
        self.scale_ppm = est_ppm;
        Some(CddaTrim::Applied { from, to: est_ppm, win_ppm, secs })
    }
}

/// The clock trim; `DCLOAD_CDDA_TRIM=0` turns it off (the A/B).
pub(super) fn cdda_trim() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("DCLOAD_CDDA_TRIM").as_deref(),
            Ok("0") | Ok("false") | Ok("no")
        )
    })
}

/// Audio pacing: a spin every 8 packets. An answer is 2 packets (ADPCM) or
/// 5 (PCM), so this only guards a larger sub-fetch.
const AUDIO_BURST_PACKETS: u32 = 8;
const AUDIO_BURST_DELAY: Duration = Duration::from_micros(250);

/// `DCLOAD_CDDA_SAFE=1`: send audio through the acknowledged `send_data`. It
/// waits for a LoadBinary echo current loaders do not send on audio.
fn cdda_safe() -> bool {
    static SAFE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SAFE.get_or_init(|| {
        matches!(
            std::env::var("DCLOAD_CDDA_SAFE").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    })
}

/// Send an audio answer with no acknowledgement round trips: the LoadBinary and
/// the parts. A lost packet leaves the loader's window incomplete, and it
/// re-asks. The caller sends the ReturnValue.
///
/// With `probe`, a DoneBinary follows and the bytes the loader still misses
/// are returned (`None` without a timely answer).
pub(super) fn send_audio(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    probe: bool,
) -> DcResult<Option<u32>> {
    if cdda_safe() {
        send_data(conn, data, address, None)?;
        return Ok(None);
    }
    let (burst_packets, burst_delay) = runtime_pacing();
    conn.send_command(DCLoadCmd::new(DCLoadCmds::LoadBinary(), address, data.len() as u32))?;
    send_parts(
        conn,
        data,
        address,
        burst_packets.min(AUDIO_BURST_PACKETS),
        burst_delay.min(AUDIO_BURST_DELAY),
    )?;
    if !probe {
        return Ok(None);
    }
    // Before the ReturnValue, after which the loader stops listening; one short
    // wait, since the title is frozen.
    let deadline = Duration::from_millis(20);
    conn.send_command(DCLoadCmd::new(DCLoadCmds::DoneBinary(), 0, 0))?;
    Ok(await_result(conn, Some(deadline))
        .ok()
        .as_deref()
        .and_then(extract_donebin)
        .map(|d| d.size))
}

/// An answer that took longer than this to produce is dropped, ReturnValue
/// included: the loader has given up on it and could take it for its next
/// request's answer. Must stay below the loader's `CDDA_FETCH_DEADLINE_TICKS`
/// (20 ms).
const CDDA_GIVE_UP: Duration = Duration::from_millis(15);

/// The ReadAudio side of a session: the encoder, the clock, and the
/// accounting reported every 250 requests.
pub(super) struct AudioServer {
    source: CddaSource,
    reads: u64,
    too_late: u64,
    slew: SlewWatch,
    slew_audited: bool,
    /// One encoder per session, in step with the AICA's decoder.
    adpcm: crate::adpcm::Stream,
    /// Raw sectors in the last request (an ADPCM answer is a quarter of them).
    sectors: u64,
    started: Option<Instant>,
    /// Loss sampling: one request in 256 is probed with a DoneBinary.
    probes: u64,
    probes_lossy: u64,
    /// The current 250-request window: time the title spent frozen.
    win_start: Option<Instant>,
    win_disc_us: u64,
    win_total_us: u64,
    win_max_us: u64,
    /// Requests over `CDDA_SLOW_US`.
    win_slow: u64,
    clock: CddaClock,
    errors: u64,
}

impl AudioServer {
    pub(super) fn new(source: CddaSource) -> Self {
        AudioServer {
            source,
            reads: 0,
            too_late: 0,
            slew: SlewWatch::new(),
            slew_audited: false,
            adpcm: crate::adpcm::Stream::new(),
            sectors: 0,
            started: None,
            probes: 0,
            probes_lossy: 0,
            win_start: None,
            win_disc_us: 0,
            win_total_us: 0,
            win_max_us: 0,
            win_slow: 0,
            clock: CddaClock::new(),
            errors: 0,
        }
    }

    /// Answer one `ReadAudio`. Only a failed socket is an `Err`.
    pub(super) fn serve(
        &mut self,
        conn: &mut impl ExternalDcIo,
        disc: &dyn DiscFormat,
        start: u32,
        dc_address: u32,
        size: u32,
        fmt: AudioFormat,
    ) -> DcResult<()> {
        // The title is frozen from here until the ReturnValue.
        let t0 = Instant::now();
        let answer = self.fetch(disc, start, size, fmt);
        let disc_us = t0.elapsed().as_micros() as u64;
        self.dump_first_discontinuity(answer.is_ok());
        match answer {
            Ok(buf) => {
                let spent = t0.elapsed();
                if spent >= CDDA_GIVE_UP {
                    self.too_late += 1;
                    debug!(
                        "CDDA read of LBA 0x{start:08x}{} took \
                         {:.0} ms ({:.1} ms of it reading and \
                         encoding), past the loader's deadline: \
                         dropping it rather than answering a \
                         request that has moved on ({too_late} \
                         so far)",
                        if let AudioFormat::Adpcm { restart: true } = fmt {
                            " (stream restart)"
                        } else {
                            ""
                        },
                        spent.as_secs_f64() * 1000.0,
                        disc_us as f64 / 1000.0,
                        too_late = self.too_late,
                    );
                    return Ok(());
                }
                let first = self.reads == 0;
                if first {
                    self.started = Some(Instant::now());
                    self.win_start = Some(Instant::now());
                }
                self.reads += 1;
                let probe = self.reads.is_multiple_of(256);
                match send_audio(conn, &buf, dc_address, probe) {
                    Ok(Some(missing)) => {
                        self.probes += 1;
                        if missing > 0 {
                            self.probes_lossy += 1;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!("CDDA read transfer failed: {e}");
                        let _ = conn.send_command(refused());
                        return Ok(());
                    }
                }
                // `address` names the LBA served (the loader rejects any other);
                // `size` carries the clock trim in ppm.
                let release = DCLoadCmd::new(DCLoadCmds::ReturnValue(), start, self.clock.scale_ppm);
                conn.send_command(release)?;
                // The title runs again; accounting only from here.
                let total_us = t0.elapsed().as_micros() as u64;
                self.win_disc_us += disc_us;
                self.win_total_us += total_us;
                self.win_max_us = self.win_max_us.max(total_us);
                if total_us > CDDA_SLOW_US {
                    self.win_slow += 1;
                }
                if cdda_trim()
                    && let Some(step) = self.clock.note(t0, start)
                {
                    log_trim(step);
                }
                const CDDA_LOUD_US: u64 = 20_000;
                if total_us > CDDA_LOUD_US {
                    debug!(
                        "CDDA read took {:.1} ms to serve (disc {:.1}, \
                         rest {:.1}) at LBA 0x{start:08x} -- the title \
                         was frozen for all of it",
                        total_us as f64 / 1000.0,
                        disc_us as f64 / 1000.0,
                        (total_us - disc_us) as f64 / 1000.0,
                    );
                }
                if first {
                    debug!(
                        "CDDA: first audio read served (LBA \
                         0x{start:08x}, {} bytes)",
                        buf.len()
                    );
                }
                if self.reads % 250 == 0 {
                    self.report(start);
                }
            }
            // Not fatal: the loader turns a refusal into silence and the title
            // keeps its data.
            Err(e) => {
                if self.errors == 0 {
                    debug!(
                        "CDDA read refused (LBA 0x{start:08x}): {e}. \
                         The title will get silence; further \
                         refusals are not logged."
                    );
                }
                self.errors += 1;
                conn.send_command(refused())?;
            }
        }
        Ok(())
    }

    /// The samples for one request: replayed, the tone, or read off the disc,
    /// then encoded if the loader asked for ADPCM.
    fn fetch(
        &mut self,
        disc: &dyn DiscFormat,
        start: u32,
        size: u32,
        fmt: AudioFormat,
    ) -> Result<Vec<u8>, String> {
        let per_sector = match fmt {
            AudioFormat::Pcm => RAW_SECTOR_SIZE as u32,
            AudioFormat::Adpcm { .. } => FRAMES_PER_SECTOR,
        };
        if self.source == CddaSource::Off {
            Err("CDDA is off (--no-cdda)".to_string())
        } else if size == 0 || size % per_sector != 0 {
            Err(format!(
                "CDDA read size {size} is not a multiple of \
                 {per_sector}"
            ))
        } else {
            self.sectors = (size / per_sector) as u64;
            // A re-ask is served from the encoder's history, before any disc read.
            if let AudioFormat::Adpcm { restart: false } = fmt
                && let Some(bytes) = self.adpcm.replay(start, size as usize)
            {
                Ok(bytes)
            } else {
                if self.source == CddaSource::Tone {
                    Ok(tone_sectors(start, size / per_sector))
                } else {
                    disc.read_audio(start, size / per_sector)
                        .map_err(|e| e.to_string())
                }
                .inspect(|pcm: &Vec<u8>| {
                    let was = self.slew.runs;
                    self.slew.scan(start, pcm);
                    if self.slew.runs > was && (was == 0 || self.slew.runs % 250 == 0) {
                        match self.slew.verdict() {
                            Some((_, _, z)) if z > 8.0 => debug!(
                                "the audio leaving this host has \
                                 ALIGNED discontinuities: {}",
                                self.slew.describe()
                            ),
                            _ => debug!(
                                "audio slew: {} hit(s), largest step {} -- {}",
                                self.slew.hits,
                                self.slew.max,
                                self.slew.describe()
                            ),
                        }
                    }
                })
                    .and_then(|pcm| match fmt {
                        AudioFormat::Pcm => Ok(pcm),
                        AudioFormat::Adpcm { restart } => {
                            let enc =
                                self.adpcm.encode_request(start, &pcm, restart);
                            // A short answer is refused, and the loader re-asks.
                            if enc.len() as u32 == size {
                                Ok(enc)
                            } else {
                                Err(format!(
                                    "ADPCM encode produced {} bytes, not \
                                     the {size} the loader asked for",
                                    enc.len()
                                ))
                            }
                        }
                    })
            }
        }
    }

    /// Once per session, when the scan finds an aligned spike, log the bytes
    /// around its first run. The image is not re-read here (the title is
    /// waiting); `audit-audio` judges it offline.
    fn dump_first_discontinuity(&mut self, answer_ok: bool) {
        let slew = &self.slew;
        if !self.slew_audited
            && slew.runs > 0
            && answer_ok
            && !slew.first_bytes.is_empty()
            && matches!(slew.verdict(), Some((_, _, z)) if z > 8.0)
            && let Some((bad_lba, bad_frame)) = slew.first
        {
            let lo = (bad_frame * 4).saturating_sub(16);
            let mut hex = String::new();
            let mut txt = String::new();
            for b in &slew.first_bytes {
                hex.push_str(&format!("{b:02x}"));
                txt.push(if (0x20..0x7f).contains(b) {
                    *b as char
                } else {
                    '.'
                });
            }
            debug!(
                "the discontinuity, as bytes: LBA 0x{bad_lba:08x} \
                 +{lo} ({} B) {hex} |{txt}|",
                slew.first_bytes.len()
            );
            debug!(
                "run `dcload-ip-rs audit-audio` on this image to \
                 judge LBA 0x{bad_lba:08x}: it is NOT re-read here, \
                 because doing that froze the title for 223 ms and \
                 cost the audio answer that was in flight"
            );
            self.slew_audited = true;
        }
    }

    /// The report logged every 250 requests: rate against real time (a runaway
    /// guard), the clock estimator, continuity, the ADPCM history, and what the
    /// window cost the title. Resets the window.
    fn report(&mut self, start: u32) {
        let secs = self.started
            .get_or_insert_with(Instant::now)
            .elapsed()
            .as_secs_f64();
        let audio =
            (self.reads * self.sectors) as f64 / 75.0;
        let ratio = if secs > 0.0 { audio / secs } else { 0.0 };
        if ratio > 1.5 {
            debug!(
                "CDDA is streaming {ratio:.1}x faster than \
                 real time ({reads} reads): the \
                 loader's flow control is not holding, and \
                 it will starve the title",
                reads = self.reads,
            );
        } else {
            debug!(
                "CDDA: {reads} reads, {ratio:.2}x real \
                 time, at LBA 0x{start:08x}",
                reads = self.reads,
            );
            {
                let (banked, rate, ppm, trims) =
                    self.clock.progress();
                let want = if trims == 0 {
                    CDDA_TRIM_FIRST_S
                } else {
                    CDDA_TRIM_S
                };
                debug!(
                    "CDDA clock: window has {banked:.1}s of \
                     {want:.0}s free-running stream banked, \
                     reading {:+.0} ppm; {trims} trim(s) \
                     applied, loader running on {ppm} ppm",
                    if rate > 0.0 {
                        (rate * f64::from(ppm) / 1e6 - 1.0)
                            * 1e6
                    } else {
                        0.0
                    }
                );
            }
            debug!(
                "CDDA continuity leaving this host: \
                 {} run(s), {} hit(s), largest step {}",
                self.slew.runs, self.slew.hits, self.slew.max
            );
        }
        // `lost_replay` (a re-ask older than the history) must stay 0.
        if self.adpcm.lost_replay > 0 {
            debug!(
                "CDDA ADPCM: {} re-ask(s) older than the \
                 {}-deep history -- those blocks decoded \
                 from the wrong coder state and ARE the \
                 audible glitches ({} replayed, {} \
                 out of order)",
                self.adpcm.lost_replay,
                crate::adpcm::RECENT,
                self.adpcm.replays,
                self.adpcm.out_of_order
            );
        } else {
            debug!(
                "CDDA ADPCM: {} re-ask(s) answered from \
                 the kept bytes, {} out of order, none lost",
                self.adpcm.replays, self.adpcm.out_of_order
            );
        }
        // This host's half of the cost only.
        let win = self.win_start
            .get_or_insert_with(Instant::now)
            .elapsed()
            .as_secs_f64();
        let n = 250.0_f64;
        let frozen = self.win_total_us as f64 / 1000.0;
        debug!(
            "CDDA: 250 fetches in {win:.2} s ({:.1}/s) -- \
             title frozen {:.2} ms each (disc {:.2} + wire \
             {:.2}), max {:.2} ms, {win_slow} over \
             5 ms = {:.1}% of wall time",
            n / win.max(1e-9),
            frozen / n,
            self.win_disc_us as f64 / 1000.0 / n,
            (self.win_total_us - self.win_disc_us) as f64
                / 1000.0
                / n,
            self.win_max_us as f64 / 1000.0,
            frozen / (win.max(1e-9) * 1000.0) * 100.0,
            win_slow = self.win_slow,
        );
        if self.probes_lossy > 0 {
            debug!(
                "CDDA: {probes_lossy} of \
                 {probes} sampled fetches arrived \
                 incomplete -- the fast path does not \
                 repair them, so this is audible as \
                 crackle",
                probes_lossy = self.probes_lossy,
                probes = self.probes,
            );
        }
        self.win_start = Some(Instant::now());
        self.win_disc_us = 0;
        self.win_total_us = 0;
        self.win_max_us = 0;
        self.win_slow = 0;
    }
}

fn log_trim(step: CddaTrim) {
    match step {
        CddaTrim::Applied { from, to, win_ppm, secs } => {
            debug!(
                "CDDA clock: the loader's model ran {} \
                 ppm {} over {secs:.0} s of free-running \
                 stream -- trim {from} -> {to} ppm",
                win_ppm.abs(),
                if win_ppm < 0 { "slow" } else { "fast" }
            );
        }
        CddaTrim::Held { ppm, win_ppm, secs } => {
            debug!(
                "CDDA clock: the loader's model is within \
                 {} ppm over {secs:.0} s -- the trim \
                 stays at {ppm} ppm",
                win_ppm.abs()
            );
        }
        CddaTrim::Refused { est_ppm, secs } => {
            debug!(
                "CDDA clock: {secs:.0} s of stream say \
                 the trim should be {est_ppm} ppm, which \
                 is further out than any clock can be -- \
                 not applied. Something other than the \
                 model's period is wrong."
            );
        }
        CddaTrim::Discarded { secs, ratio } => {
            debug!(
                "CDDA clock: discarded {secs:.0} s -- \
                 audio against real time came out at \
                 {ratio:.3}, so the stream was not \
                 free-running"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Silent on the clean tone (steps of exactly 512 and 1024), not on
    /// full-scale foreign bytes.
    #[test]
    fn the_continuity_check_is_silent_on_a_clean_signal_and_not_on_a_splice() {
        let mut clean = SlewWatch::new();
        for lba in 1000..1010 {
            clean.scan(lba, &tone_sectors(lba, 1));
        }
        assert_eq!(clean.runs, 0, "the triangle is continuous by construction");
        assert_eq!(clean.hits, 0);
        assert_eq!(clean.max, 1024, "the right ear's step, and the larger one");

        // The tone only reaches +/-16384, so splice in full-scale bytes.
        let mut spliced = SlewWatch::new();
        let mut bad = tone_sectors(1000, 1);
        for (k, f) in bad.chunks_exact_mut(4).skip(300).take(6).enumerate() {
            let v: i16 = if k % 2 == 0 { i16::MAX } else { i16::MIN };
            f[0..2].copy_from_slice(&v.to_le_bytes());
            f[2..4].copy_from_slice(&v.to_le_bytes());
        }
        spliced.scan(1000, &bad);
        assert!(spliced.runs > 0, "foreign bytes have to register as a run");
        assert_eq!(spliced.first.map(|(l, _)| l), Some(1000));
    }

    #[test]
    fn the_served_tone_is_continuous_and_repeatable() {
        let two = tone_sectors(1000, 2);
        assert_eq!(two.len(), 2 * RAW_SECTOR_SIZE);
        assert_eq!(tone_sectors(1000, 1), two[..RAW_SECTOR_SIZE]);
        assert_eq!(tone_sectors(1001, 1), two[RAW_SECTOR_SIZE..]);
        assert!(two.chunks_exact(2).any(|w| w != &two[0..2]));
    }

    /// Records every packet sent, in order.
    struct Wire(std::cell::RefCell<Vec<(String, u32, u32)>>);

    impl ExternalDcIo for Wire {
        fn poll(&self, _t: Option<Duration>) -> Result<polling::Events, std::io::Error> {
            Ok(polling::Events::new())
        }
        fn handle_data(
            &mut self,
            _e: &polling::Events,
        ) -> Result<Vec<DCReturnCmd>, std::io::Error> {
            Ok(Vec::new())
        }
        fn send_command(
            &self,
            c: DCLoadCmd,
        ) -> DcResult<usize> {
            let name = match c.cmd {
                DCLoadCmds::LoadBinary() => "LBIN",
                DCLoadCmds::PartBinary(_) => "PBIN",
                DCLoadCmds::DoneBinary() => "DBIN",
                DCLoadCmds::ReturnValue() => "RETV",
                _ => "other",
            };
            self.0.borrow_mut().push((name.to_string(), c.address, c.size));
            Ok(0)
        }
    }

    /// An ADPCM answer (2352 bytes) is one LoadBinary over the whole answer,
    /// then two parts, and nothing else.
    #[test]
    fn an_audio_fetch_is_one_loadbin_two_parts_and_a_returnvalue() {
        let w = Wire(std::cell::RefCell::new(Vec::new()));
        let buf = vec![0x80u8; 2352];
        send_audio(&mut { w }, &buf, 0x8ce0_cc00, false).unwrap();
        let w2 = Wire(std::cell::RefCell::new(Vec::new()));
        let mut w2 = w2;
        send_audio(&mut w2, &buf, 0x8ce0_cc00, false).unwrap();
        let sent = w2.0.borrow().clone();

        let names: Vec<&str> = sent.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(
            names,
            vec!["LBIN", "PBIN", "PBIN"],
            "send_audio put this on the wire: {sent:?}"
        );
        assert_eq!(sent[0].2, 2352, "the LoadBinary must open the whole window");
        assert_eq!(sent[1].1, 0x8ce0_cc00);
        assert_eq!(sent[1].2, CHUNK_SIZE as u32);
        assert_eq!(sent[2].1, 0x8ce0_cc00 + CHUNK_SIZE as u32);
        assert_eq!(sent[2].2, 2352 - CHUNK_SIZE as u32);
    }

    /// Four sectors to a sub-fetch in ADPCM.
    const TEST_SECTORS: u32 = 4;
    /// The audio in one sub-fetch, and so the period a correct loader asks at.
    fn fetch_audio_s() -> f64 {
        f64::from(TEST_SECTORS) / 75.0
    }

    /// A free-running stream shaped like the loader's: one sub-fetch every
    /// `period_s`. Keep it in step with the loader's geometry.
    fn feed_stream(clock: &mut CddaClock, fetches: u32, period_s: f64) -> Vec<CddaTrim> {
        feed_from(clock, Instant::now(), 1000, fetches, period_s).0
    }

    /// The same, from a given instant and LBA, returning where it got to.
    fn feed_from(
        clock: &mut CddaClock,
        base: Instant,
        first_lba: u32,
        fetches: u32,
        period_s: f64,
    ) -> (Vec<CddaTrim>, Instant, u32) {
        let mut out = Vec::new();
        let mut lba = first_lba;
        let mut at = base;
        for _ in 0..fetches {
            if let Some(step) = clock.note(at, lba) {
                out.push(step);
            }
            lba += TEST_SECTORS;
            at += Duration::from_secs_f64(period_s);
        }
        (out, at, lba)
    }

    #[test]
    fn a_free_running_stream_banks_time_at_all() {
        let mut clock = CddaClock::new();
        feed_stream(&mut clock, 280, fetch_audio_s());
        let (banked, rate, _, _) = clock.progress();
        assert!(banked > 10.0, "banked only {banked}s of a 14.9 s stream");
        assert!((rate - 1.0).abs() < 0.001, "and it must read ~1.0, got {rate}");
    }

    /// Every gap is short, but the stream runs at 2/3 of real time.
    #[test]
    fn a_segment_that_took_too_long_is_not_banked() {
        let mut clock = CddaClock::new();
        feed_stream(&mut clock, 280, fetch_audio_s() * 1.5);
        let (banked, _, _, trims) = clock.progress();
        assert_eq!(banked, 0.0, "a stretched segment was banked");
        assert_eq!(trims, 0);
        assert_eq!(clock.scale_ppm, 1_000_000);
    }

    /// After a dropped gap the loader catches up in a burst; counted, that is
    /// free audio worth ~3000 ppm.
    #[test]
    fn the_catch_up_after_a_long_gap_is_not_free_audio() {
        let mut clock = CddaClock::new();
        let base = Instant::now();
        let (_, at, lba) = feed_from(&mut clock, base, 1000, 200, fetch_audio_s());
        let at = at + Duration::from_secs_f64(3.0);
        let (_, at, lba) = feed_from(&mut clock, at, lba, 17, 0.008);
        let (_, _, _) = feed_from(&mut clock, at, lba, 200, fetch_audio_s());
        let (banked, rate, _, _) = clock.progress();
        assert!(banked > 15.0, "the whole stream was thrown away ({banked}s)");
        assert!(
            (rate - 1.0).abs() < 0.005,
            "the catch-up dragged the rate to {rate}"
        );
    }

    /// A short stall and its catch-up are both counted, and cancel.
    #[test]
    fn a_short_service_stall_still_banks_its_time() {
        let mut clock = CddaClock::new();
        let base = Instant::now();
        let (_, at, lba) = feed_from(&mut clock, base, 1000, 100, fetch_audio_s());
        let at = at + Duration::from_secs_f64(0.30);
        let (_, at, lba) = feed_from(&mut clock, at, lba, 6, 0.008);
        feed_from(&mut clock, at, lba, 200, fetch_audio_s());
        let (banked, rate, _, _) = clock.progress();
        assert!(
            banked > 15.0,
            "a 300 ms stall cost more than one segment of a 16.3 s stream ({banked}s)"
        );
        assert!((rate - 1.0).abs() < 0.005, "rate {rate}");
    }

    #[test]
    fn the_clock_measures_a_model_that_runs_slow() {
        let mut clock = CddaClock::new();
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s() / 0.997);
        let first = steps.first().expect("a long stream must produce a decision");
        match *first {
            CddaTrim::Applied { from, to, .. } => {
                assert_eq!(from, 1_000_000);
                assert!(
                    (996_800..=997_200).contains(&to),
                    "measured {to} ppm, wanted 997000"
                );
            }
            ref other => panic!("expected a trim, got {other:?}"),
        }
        assert_eq!(clock.scale_ppm, 997_000, "and it is what goes back to the loader");
    }

    #[test]
    fn a_model_that_is_already_right_is_left_alone() {
        let mut clock = CddaClock::new();
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s());
        assert!(
            matches!(steps.first(), Some(CddaTrim::Held { ppm: 1_000_000, .. })),
            "got {steps:?}"
        );
    }

    /// A title loading starves the stream; that is not a slow clock.
    #[test]
    fn a_loading_stall_is_not_a_clock_measurement() {
        let mut clock = CddaClock::new();
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s() * 4.0);
        assert!(steps.is_empty(), "a stalled stream decided something: {steps:?}");
        assert_eq!(clock.scale_ppm, 1_000_000);
    }

    /// A re-ask repeats its LBA: time, but no audio.
    #[test]
    fn a_re_asked_sub_fetch_is_not_audio() {
        let mut clock = CddaClock::new();
        let base = Instant::now();
        clock.note(base, 1000);
        clock.note(base + Duration::from_millis(2), 1000);
        assert_eq!(clock.pend_audio_s, 0.0);
        assert!(clock.pend_time_s > 0.0, "but the time it took still counts");
    }

    /// The dump indexes the PCM, so a hit past the ADPCM length (frame 588)
    /// must still produce 32 bytes.
    #[test]
    fn the_discontinuity_dump_is_not_empty_past_the_adpcm_length() {
        let mut pcm = vec![0u8; 2352 * 4];
        let at = 1200 * 4;
        pcm[at..at + 4].copy_from_slice(&[0x00, 0x80, 0x00, 0x80]);
        pcm[at + 4..at + 8].copy_from_slice(&[0xff, 0x7f, 0xff, 0x7f]);
        pcm[at + 8..at + 12].copy_from_slice(&[0x00, 0x80, 0x00, 0x80]);
        let mut slew = SlewWatch::new();
        slew.scan(0x0004_e6ce, &pcm);
        assert!(slew.runs > 0, "the control did not trip the scan at all");
        let (lba, frame) = slew.first.expect("a run must record where it was");
        assert_eq!(lba, 0x0004_e6ce);
        assert!(frame > 588, "place the hit past the ADPCM length, got {frame}");
        assert_eq!(
            slew.first_bytes.len(),
            32,
            "the dump came back empty or short -- the exact defect this is for"
        );
    }

    /// 2.5 % passes the window test but no crystal is that far off.
    #[test]
    fn an_impossible_answer_is_refused() {
        let mut clock = CddaClock::new();
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s() / 0.975);
        assert!(
            matches!(steps.first(), Some(CddaTrim::Refused { .. })),
            "got {steps:?}"
        );
        assert_eq!(clock.scale_ppm, 1_000_000, "and nothing moved");
    }
}
