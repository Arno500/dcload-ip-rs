use std::cell::RefCell;
use std::fs::{File, read_to_string};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::disc_formats::types::{DiscFormat, Track};
pub struct Gdi {
    tracks: RefCell<Vec<Track>>,
}

impl Gdi {
    pub fn new(filename: String) -> Result<Self, std::io::Error> {
        let parent_path = Path::new(&filename).parent().unwrap_or(Path::new(""));
        match read_to_string(&filename) {
            Err(e) => Err(e),
            Ok(f) => {
                let mut lines = f.lines();
                let number_of_tracks = lines.next();
                if let Some(num_tracks) = number_of_tracks {
                    let num_tracks: usize = num_tracks.trim().parse().unwrap_or(0);
                    let mut tracks = Vec::with_capacity(num_tracks);
                    for _ in 0..num_tracks {
                        if let Some(line) = lines.next() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 6 {
                                let track_number: u8 = parts[0].parse().unwrap_or(0);
                                let start_lba = parts[1].parse().unwrap_or(0);
                                let track_type: u8 = parts[2].parse().unwrap_or(0);
                                let sector_size: u32 = parts[3].parse().unwrap_or(2048);
                                let track = Path::join(parent_path, parts[4])
                                    .to_string_lossy()
                                    .into();
                                let offset: u32 = parts[5].parse().unwrap_or(0);
                                tracks.push(Track {
                                    track_number,
                                    start_lba,
                                    track_type,
                                    sector_size,
                                    track,
                                    offset,
                                    file: None,
                                });
                            }
                        }
                    }
                    Ok(Gdi {
                        tracks: RefCell::new(tracks),
                    })
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid GDI file: missing number of tracks",
                    ))
                }
            }
        }
    }
}
impl DiscFormat for Gdi {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut tracks = self.tracks.borrow_mut();
        let mut buffer = vec![0_u8; (num_sectors * 2048).try_into()?];
        for (sector_idx, chunk) in buffer.chunks_mut(2048).enumerate() {
            let req_lba = lba.saturating_add(sector_idx as u32);

            // Pick the most recent data track whose logical start is <= requested LBA.
            let data_track_index = tracks
                .iter()
                .enumerate()
                .filter(|(_, t)| t.track_type == 4 && t.start_lba.saturating_add(150) <= req_lba)
                .max_by_key(|(_, t)| t.start_lba)
                .map(|(i, _)| i)
                .ok_or_else(|| format!("No data track found for LBA 0x{req_lba:08x}"))?;

            let current_track = &mut tracks[data_track_index];
            if current_track.file.is_none() {
                current_track.file = Some(File::open(current_track.track.clone())?);
            }

            let logical_track_start = current_track.start_lba.saturating_add(150);
            let in_track_lba = req_lba.checked_sub(logical_track_start).ok_or_else(|| {
                format!(
                    "Requested LBA 0x{req_lba:08x} is before logical data track start 0x{logical_track_start:08x}"
                )
            })?;

            let file = current_track.file.as_mut().unwrap();
            file.seek(SeekFrom::Start(
                (current_track.offset as u64)
                    + (in_track_lba as u64) * (current_track.sector_size as u64),
            ))?;

            if current_track.sector_size == 2048 {
                file.read_exact(chunk)?;
                continue;
            }

            let mut raw_sector = vec![0_u8; current_track.sector_size as usize];
            file.read_exact(&mut raw_sector)?;

            let payload_offset: usize = match current_track.sector_size {
                // dc-virtcd-compatible secskip for packed formats.
                2056 | 2336 => 8,
                // Keep raw extraction deterministic for compatibility:
                // Mode 1 payload starts at +16 in 2352/2448 sectors.
                2352 | 2448 => 16,
                s => return Err(format!("Unsupported GDI sector size: {}", s).into()),
            };

            let payload_end = payload_offset + 2048;
            if payload_end > raw_sector.len() {
                return Err(
                    format!(
                        "Raw sector too small for payload extraction: {} bytes (offset {})",
                        raw_sector.len(),
                        payload_offset
                    )
                    .into(),
                );
            }
            chunk.copy_from_slice(&raw_sector[payload_offset..payload_end]);
        }
        Ok(buffer)
    }

    fn start_sector(&self) -> u32 {
        let tracks = self.tracks.borrow();
        tracks
            .iter()
            .filter(|t| t.track_type == 4)
            .map(|t| t.start_lba)
            .min()
            .unwrap_or(0)
            .saturating_add(150)
    }

    /// The HIGHEST-LBA data track, i.e. the high-density area -- the mirror of
    /// `start_sector()`'s `min`. See the trait for why the two differ.
    fn boot_sector(&self) -> u32 {
        let tracks = self.tracks.borrow();
        tracks
            .iter()
            .filter(|t| t.track_type == 4)
            .map(|t| t.start_lba)
            .max()
            .unwrap_or(0)
            .saturating_add(150)
    }

    fn num_sectors(&self) -> u32 {
        let mut tracks = self.tracks.borrow_mut();
        let data_track_indices: Vec<usize> = tracks
            .iter()
            .enumerate()
            .filter(|(_, t)| t.track_type == 4)
            .map(|(i, _)| i)
            .collect();

        if data_track_indices.is_empty() {
            return 0;
        }

        let first_start = data_track_indices
            .iter()
            .map(|i| tracks[*i].start_lba.saturating_add(150))
            .min()
            .unwrap_or(0);

        let mut leadout = first_start;
        for idx in data_track_indices {
            let t = &mut tracks[idx];
            if t.file.is_none()
                && let Ok(f) = File::open(t.track.clone())
            {
                t.file = Some(f);
            }
            if let Some(f) = t.file.as_ref()
                && let Ok(meta) = f.metadata()
            {
                let track_data_len = meta.len().saturating_sub(t.offset as u64);
                let track_sectors = (track_data_len / (t.sector_size as u64)) as u32;
                let track_end = t
                    .start_lba
                    .saturating_add(150)
                    .saturating_add(track_sectors);
                if track_end > leadout {
                    leadout = track_end;
                }
            }
        }

        leadout.saturating_sub(first_start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disc_formats::types::DiscFormat;

    /// The Sonic Adventure GDI that ships in `test/`. Skipped, not failed, if
    /// it is not there: the rest of the suite must stay runnable on a machine
    /// without the dumps.
    fn sa_gdi() -> Option<Gdi> {
        let p = "test/Sonic Adventure v1.003 (1999)(Sega)(PAL)(M5)[!].gdi";
        std::path::Path::new(p).exists().then(|| Gdi::new(p.to_string()).expect("parse gdi"))
    }

    /// THE BUG THIS LOCKS DOWN. `start_sector()` is the LOWEST data track and
    /// `boot_sector()` the HIGHEST, and on a GD-ROM they are different tracks
    /// with the same valid header. Getting them the same way round again would
    /// make `--boot-ipbin` execute 32 KB of zeroes, silently.
    #[test]
    fn boot_sector_is_the_high_density_area() {
        let Some(gdi) = sa_gdi() else { return };
        assert_eq!(gdi.start_sector(), 150, "low-density data track");
        assert_eq!(gdi.boot_sector(), 45150, "high-density data track");
    }

    /// Both areas open with a valid Dreamcast header for the same title --
    /// which is exactly why the header alone cannot tell them apart -- but only
    /// the high-density one carries bootstrap code at +0x6000.
    #[test]
    fn only_the_high_density_ip_bin_has_a_bootstrap() {
        let Some(gdi) = sa_gdi() else { return };
        let low = gdi.read_sector(gdi.start_sector(), 16).expect("low read");
        let high = gdi.read_sector(gdi.boot_sector(), 16).expect("high read");

        for (what, img) in [("low", &low), ("high", &high)] {
            assert!(img.starts_with(b"SEGA SEGAKATANA"), "{what} area header");
        }

        // Bootstrap 1 is the clean discriminator: empty in the low-density
        // area, ~200/256 bytes of code in the high-density one, measured the
        // same way on SA, SA2 and Crazy Taxi. (+0x6000 is NOT -- the
        // low-density area has padding there and looks populated.)
        let live = |img: &[u8]| img[0x300..0x400].iter().filter(|b| **b != 0).count();
        assert_eq!(live(&low), 0, "low-density area must have no bootstrap 1");
        assert!(live(&high) > 128, "high-density bootstrap 1 must carry code");

        // And the guard load_ip_bin() actually uses.
        assert_eq!(&low[0x0cb0..0x0cb4], &[0, 0, 0, 0], "low: no patch site");
        assert_eq!(&high[0x0cb0..0x0cb4], &[0x03, 0x63, 0x00, 0x40], "high: stock");
    }

    /// isoldr's `Load_IPBin()` patch offsets, worked out from its pointer
    /// arithmetic. They are fixed positions in Sega's stock bootstrap, so the
    /// bytes there are the same on every retail disc -- which is what makes it
    /// safe to write them blind. If a dump ever disagrees, the arithmetic is
    /// what to re-check.
    #[test]
    fn isoldr_patch_sites_hold_the_stock_bootstrap_bytes() {
        let Some(gdi) = sa_gdi() else { return };
        let ip = gdi.read_sector(gdi.boot_sector(), 16).expect("read");
        assert_eq!(&ip[0x0cb0..0x0cb4], &[0x03, 0x63, 0x00, 0x40]);
        assert_eq!(&ip[0x21b0..0x21b2], &[0x6e, 0x3a]);
        assert_eq!(&ip[0x2814..0x2816], &[0x04, 0x06]);
        assert_eq!(&ip[0x2818..0x281a], &[0x8f, 0x04]);
    }
}
