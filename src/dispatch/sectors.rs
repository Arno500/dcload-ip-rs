//! Serving the title's disc reads (`ReadSector`), and what each one teaches
//! about where the title's memory is.

use super::*;

/// Disc-read diagnostics, read from the environment once.
struct ReadDiag {
    /// `DCLOAD_ZERO_LBA`: blank this LBA's payload.
    zero_lba: Option<u32>,
    /// `DCLOAD_REDIRECT_ABOVE` / `_TO`: send reads above the first to the second.
    redirect: Option<(u32, u32)>,
    /// `DCLOAD_VERIFY_READS`: read every served read back and compare.
    verify: bool,
}

fn read_diag() -> &'static ReadDiag {
    static DIAG: std::sync::OnceLock<ReadDiag> = std::sync::OnceLock::new();
    DIAG.get_or_init(|| {
        let hex = |k: &str| {
            std::env::var(k)
                .ok()
                .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        };
        ReadDiag {
            zero_lba: hex("DCLOAD_ZERO_LBA"),
            redirect: hex("DCLOAD_REDIRECT_ABOVE").zip(hex("DCLOAD_REDIRECT_TO")),
            verify: std::env::var("DCLOAD_VERIFY_READS").is_ok(),
        }
    })
}

/// The ReadSector side of a session: the disc's extent, where the loader is,
/// and what the reads have shown so far.
pub(super) struct SectorServer<'a> {
    toc_start: u32,
    toc_sectors: u32,
    pvd_lba: u32,
    loader_base: u32,
    /// The loader's own staging buffers (`_gd_stage`, `_gd_stage_big`).
    stage: Vec<(u32, u32)>,
    /// Patched words to put back when a read reloads them.
    guards: &'a [(u32, u32)],
    memory: Option<std::sync::Arc<std::sync::Mutex<crate::memmap::MemoryRecorder>>>,
    logged_lbas: HashSet<u32>,
    /// Destinations already reported as landing on the loader (said once each).
    warned_overlap: HashSet<u32>,
    /// Closest a read has come to the loader, and whether that was said.
    nearest_read: u32,
    warned_near: bool,
    /// Groups reads into loading bursts for the bar; also sets the poll timeout.
    pub(super) load: ui::LoadMonitor,
}

impl<'a> SectorServer<'a> {
    pub(super) fn new(
        toc_start: u32,
        toc_sectors: u32,
        running_base: Option<u32>,
        guards: &'a [(u32, u32)],
        memory: Option<std::sync::Arc<std::sync::Mutex<crate::memmap::MemoryRecorder>>>,
        stage: Vec<(u32, u32)>,
    ) -> Self {
        SectorServer {
            toc_start,
            toc_sectors,
            pvd_lba: toc_start.saturating_add(16),
            loader_base: running_base.unwrap_or(crate::loaders::DEFAULT_BASE),
            stage,
            guards,
            memory,
            logged_lbas: HashSet::new(),
            warned_overlap: HashSet::new(),
            nearest_read: u32::MAX,
            warned_near: false,
            load: ui::LoadMonitor::new(),
        }
    }

    /// Answer one `ReadSector`. Only a failed socket is an `Err`: a read that
    /// cannot be served is refused or left to time out, and the session stays.
    pub(super) fn serve(
        &mut self,
        conn: &mut impl ExternalDcIo,
        disc: &dyn DiscFormat,
        start: u32,
        dc_address: u32,
        size: u32,
    ) -> DcResult<()> {
        let (toc_start, toc_sectors, pvd_lba) = (self.toc_start, self.toc_sectors, self.pvd_lba);
        debug!(
            "Received ReadSector syscall: start=0x{:08x}, dc_address=0x{:08x}, size={}",
            start, dc_address, size
        );
        // A malformed request means the loader's state was overwritten (at a
        // low base, by the title's stack). Refuse it and keep the session, and
        // with it the memory map and counters.
        if size % 2048 != 0 || size > MAX_XFER as u32 {
            warn!(
                "ReadSector request is malformed (LBA 0x{start:08x} -> \
                 0x{dc_address:08x}, size {size}). The loader's own state \
                 has been overwritten -- at a low base, check \
                 g_gd_sp_in_image with --diag, and see AGENTS.md 4.6. \
                 Refusing this read and staying up."
            );
            return Ok(());
        }
        let num_sectors = size / 2048;
        // A read off the end of the disc fails, as on a drive.
        let mut buf = match disc.read_sector(start, num_sectors) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "ReadSector for {num_sectors} sector(s) at LBA {start} \
                     (0x{start:08x}) -> 0x{dc_address:08x} cannot be served: \
                     {e}. The disc spans LBA {toc_start}..{}; answering \
                     with a failure, as a drive would.",
                    toc_start.saturating_add(toc_sectors)
                );
                let _ = conn.send_command(refused());
                return Ok(());
            }
        };

        // Diagnostic: blank one LBA's payload.
        if read_diag().zero_lba == Some(start) {
            warn!("ZEROING (diagnostic): LBA 0x{start:08x}");
            buf.iter_mut().for_each(|b| *b = 0);
        }
        let buf = buf;

        // Diagnostic: send reads above a threshold elsewhere, to tell a bad
        // destination from a bad LBA. The title gets wrong data.
        let dc_address = match read_diag().redirect {
            Some((above, to)) if dc_address >= above => {
                warn!(
                    "REDIRECT (diagnostic): 0x{dc_address:08x} -> 0x{to:08x}"
                );
                to
            }
            _ => dc_address,
        };
        if self.logged_lbas.insert(start) && buf.len() >= 8 {
            debug!(
                "ReadSector LBA=0x{start:08x} first8={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                buf[0],
                buf[1],
                buf[2],
                buf[3],
                buf[4],
                buf[5],
                buf[6],
                buf[7]
            );
        }
        if start == pvd_lba && buf.len() >= 6 {
            if &buf[1..6] == b"CD001" {
                info!("PVD signature is valid at LBA 0x{start:08x}");
            } else {
                warn!(
                    "PVD signature mismatch at LBA 0x{start:08x}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
                );
            }
        }
        self.watch_destination(start, dc_address, buf.len() as u32);
        // `send_sectors` fails only if the socket does. No ReturnValue then:
        // the loader times out and asks again rather than take a short buffer.
        // HOW LONG THE ANSWER TOOK TO LEAVE (2026-10-03). Sonic Adventure 2's
        // asynchronous reads failed with the LoadBinary received and nothing
        // after it -- not one part, not the ReturnValue -- while the chip was
        // receiving and its ring empty. Either the rest never left this host
        // in time or it was lost on the way; this says which.
        let sending = std::time::Instant::now();
        let sent = send_sectors(conn, &buf, dc_address);
        let send_time = sending.elapsed();
        match sent {
            Ok(_) => {
                if read_diag().verify {
                    verify_read(conn, start, dc_address, &buf);
                }
                self.reapply_guards(conn, start, dc_address, buf.len() as u32);
                // Tagged with the LBA so the loader can tell this answer from a
                // late one to an earlier read into the same buffer.
                let tag = READ_RETVAL_TAG | (start & 0x3fff_ffff);
                conn.send_command(DCLoadCmd::new(DCLoadCmds::ReturnValue(), tag, 0))?;
                let total = sending.elapsed();
                if total > std::time::Duration::from_millis(20) {
                    warn!(
                        "ReadSector LBA 0x{start:08x} -> 0x{dc_address:08x}: the answer took \
                         {:.1} ms to send ({:.1} ms for the LoadBinary and parts) -- the \
                         loader gives up on a chunk after 250 ms",
                        total.as_secs_f64() * 1000.0,
                        send_time.as_secs_f64() * 1000.0
                    );
                } else {
                    debug!(
                        "ReadSector LBA 0x{start:08x}: answer sent in {:.2} ms",
                        total.as_secs_f64() * 1000.0
                    );
                }
                // After the ReturnValue: the title is frozen until it lands.
                self.load.record(buf.len(), start);
            }
            Err(e) => {
                warn!(
                    "ReadSector transfer unanswered (LBA 0x{start:08x} -> 0x{dc_address:08x}): {e}. \
                     Staying up; the DC will time out and re-request."
                );
            }
        }
        Ok(())
    }

    /// Where a read lands: on the loader (reported, since the loader would
    /// overwrite itself silently), into the memory map for the next session, and
    /// how close it comes to a high loader. Reads into the loader's staging
    /// buffers are neither.
    fn watch_destination(&mut self, start: u32, dc_address: u32, len: u32) {
        let loader_base = self.loader_base;
        let staged = self.stage.iter().any(|&(lo, stage_len)| {
            let (lo, a) = (lo & 0x1fff_ffff, dc_address & 0x1fff_ffff);
            a >= lo && a.saturating_add(len) <= lo + stage_len
        });
        if !staged
            && let Some(hit) = crate::loaders::overlapping_range(
                loader_base,
                (dc_address, dc_address.saturating_add(len)),
            )
            && self.warned_overlap.insert(dc_address)
        {
            error!(
                "DISC READ LANDS ON THE LOADER: LBA 0x{start:08x} -> \
                 0x{dc_address:08x}..0x{:08x} ({} B) runs through \
                 0x{:08x}..0x{:08x}, which the loader running at \
                 0x{loader_base:08x} is using. Serving it anyway, but it \
                 overwrites dcload while dcload is receiving it: expect \
                 the console to go quiet from here with nothing else \
                 logged. This title needs a loader base its own memory \
                 map leaves alone.",
                dc_address.saturating_add(len),
                len,
                hit.0,
                hit.1,
            );
        }
        if !staged
            && let Some(rec) = self.memory.as_ref()
            && let Ok(mut rec) = rec.lock()
        {
            rec.record(dc_address, len);
        }
        // High bases only: at the stock base every read is "near".
        if !staged && loader_base >= 0x8c01_0000 {
            const TOO_NEAR: u32 = 0x4_0000;
            let lo = dc_address & 0x1fff_ffff;
            let (blo, bhi) = (
                loader_base & 0x1fff_ffff,
                (loader_base & 0x1fff_ffff)
                    .saturating_add(crate::loaders::LOADER_SPAN),
            );
            let gap = if lo >= bhi {
                lo - bhi
            } else {
                blo.saturating_sub(lo + len)
            };
            if gap < self.nearest_read {
                self.nearest_read = gap;
            }
            if !self.warned_near && self.nearest_read < TOO_NEAR {
                self.warned_near = true;
                warn!(
                    "this title's disc reads come within {} KB of the \
                     loader at 0x{loader_base:08x} (LBA 0x{start:08x} -> \
                     0x{dc_address:08x}). Its memory reaches this far, so \
                     the loader is in ground it is using -- an allocation \
                     that goes a little further overwrites it, and nothing \
                     reports that. If this title misbehaves, move the \
                     loader further away with --loader-base before \
                     suspecting anything else.",
                    self.nearest_read / 1024
                );
            }
        }
    }

    /// Re-apply patched words a read has just reloaded from disc, before the
    /// ReturnValue lets the title run them.
    fn reapply_guards(&self, conn: &mut impl ExternalDcIo, start: u32, dc_address: u32, len: u32) {
        let reloaded: Vec<(u32, u32)> = self.guards
            .iter()
            .copied()
            .filter(|&(at, _)| {
                let lo = dc_address & 0x1fff_ffff;
                let hi = lo.saturating_add(len);
                (lo..hi).contains(&(at & 0x1fff_ffff))
            })
            .collect();
        if !reloaded.is_empty() {
            warn!(
                "this read reloads {} patched word(s) \
                 (LBA 0x{start:08x} -> 0x{dc_address:08x}, \
                 {} B); re-applying them before the title can \
                 run the bytes just delivered",
                reloaded.len(),
                len
            );
            if let Err(e) = apply_patches(conn, &reloaded) {
                error!("could not re-apply the guard: {e}");
            }
        }
    }
}

/// `DCLOAD_VERIFY_READS`: read a served read back before its ReturnValue and
/// compare. The only check that sees corruption the transfer counters cannot.
fn verify_read(conn: &mut impl ExternalDcIo, start: u32, dc_address: u32, buf: &[u8]) {
    match receive_data(
        conn,
        Some(Duration::from_millis(3000)),
        dc_address,
        buf.len(),
        true,
    ) {
        Ok(back) => {
            let bad: Vec<usize> = back
                .iter()
                .zip(buf.iter())
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(i, _)| i)
                .collect();
            if bad.is_empty() {
                info!(
                    "VERIFY ok: LBA 0x{start:08x} -> 0x{dc_address:08x} {} B clean",
                    buf.len()
                );
            } else {
                error!(
                    "VERIFY MISMATCH: LBA 0x{start:08x} -> 0x{dc_address:08x}: \
                     {} of {} bytes wrong, first at +0x{:x} (sent {:02x}, holds {:02x})",
                    bad.len(),
                    buf.len(),
                    bad[0],
                    buf[bad[0]],
                    back[bad[0]]
                );
            }
        }
        Err(e) => {
            warn!("VERIFY read-back failed: {e}");
        }
    }
}
