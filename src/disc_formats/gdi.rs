use std::cell::RefCell;
use std::path::{Path, PathBuf};

use crate::disc_formats::source::{Container, DirContainer, ImageSource};
use crate::disc_formats::types::{
    DiscFormat, RAW_SECTOR_SIZE, Track, TocTrack, check_read_len,
};

pub struct Gdi {
    tracks: RefCell<Vec<Track>>,
    /// Where the track files come from. A `.gdi` is a text file that NAMES its
    /// tracks, so opening one means opening its siblings -- and "sibling" is a
    /// directory for a loose dump and a prefix inside the archive for a zipped
    /// one. That is the only difference between the two cases.
    container: Box<dyn Container>,
}

impl Gdi {
    /// The files of this `.gdi`'s audio tracks, in the order it lists them.
    ///
    /// For [`crate::disc_formats::zip::warm_track_indexes`]: the audio tracks
    /// only, because the data tracks are indexed before the title runs anyway
    /// (identifying the disc and reading its boot binary go through them), and
    /// building one index twice at once would cost seconds on a 1 GiB track.
    pub fn audio_track_files(&self) -> Vec<String> {
        self.tracks
            .borrow()
            .iter()
            .filter(|t| t.track_type == 0)
            .map(|t| t.track.clone())
            .collect()
    }

    /// A `.gdi` sitting in a directory, with its tracks next to it.
    pub fn open_path(filename: &str) -> Result<Self, std::io::Error> {
        let path = Path::new(filename);
        let parent = path.parent().unwrap_or(Path::new(""));
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| filename.to_string());
        Self::new(Box::new(DirContainer::new(PathBuf::from(parent))), &name)
    }

    pub fn new(container: Box<dyn Container>, name: &str) -> Result<Self, std::io::Error> {
        let text = container.read_text(name)?;
        let mut lines = text.lines();
        let Some(num_tracks) = lines.next() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid GDI file: missing number of tracks",
            ));
        };
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
                    let offset: u32 = parts[5].parse().unwrap_or(0);
                    tracks.push(Track {
                        track_number,
                        start_lba,
                        track_type,
                        sector_size,
                        track: parts[4].to_string(),
                        offset,
                        source: None,
                    });
                }
            }
        }
        Ok(Gdi {
            tracks: RefCell::new(tracks),
            container,
        })
    }

    /// The logical start of the lowest or highest data track. `start_sector`
    /// and `num_sectors` are this same walk with `min` and `max`.
    fn data_track_edge(&self, highest: bool) -> u32 {
        let tracks = self.tracks.borrow();
        let starts = tracks.iter().filter(|t| t.track_type == 4).map(|t| t.start_lba);
        if highest { starts.max() } else { starts.min() }
            .unwrap_or(0)
            .saturating_add(150)
    }

    /// The FIRST data track of the high-density area, which is not always the
    /// last data track on the disc.
    ///
    /// A GD-ROM's high-density area begins at LBA 45000, always -- it is a
    /// property of the medium, and a `.gdi` records its track starts in that
    /// same origin. What is NOT fixed is how many tracks follow: a title whose
    /// CDDA lives up there is mastered `data / audio / ... / data`, and then
    /// the highest-LBA data track is a bare file area with no header and no
    /// filesystem on it.
    ///
    /// Measured on the Buzz Lightyear of Star Command PAL dump, five tracks:
    /// `0 data, 6986 audio, 45000 data, 257827 audio, 263852 data`. IP.BIN and
    /// the ISO9660 PVD are at track 3 (45000 and 45016); track 5 sector 0 is
    /// mid-file payload. Asking the highest track for a header therefore said
    /// "the disc does not say which file it boots" about a disc that says so
    /// perfectly clearly, 219000 sectors earlier.
    ///
    /// `None` when no data track reaches the high-density area at all, which is
    /// every synthetic and single-density image.
    fn high_density_start(&self) -> Option<u32> {
        const HIGH_DENSITY_LBA: u32 = 45000;
        self.tracks
            .borrow()
            .iter()
            .filter(|t| t.track_type == 4 && t.start_lba >= HIGH_DENSITY_LBA)
            .map(|t| t.start_lba)
            .min()
            .map(|lba| lba.saturating_add(150))
    }
}
impl DiscFormat for Gdi {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Before the allocation, not after it: `num_sectors` is whatever the
        // title's syscall asked for. See `types::MAX_READ_SECTORS`.
        check_read_len(num_sectors)?;
        if num_sectors == 0 {
            return Ok(vec![]);
        }
        let mut tracks = self.tracks.borrow_mut();
        let mut buffer = vec![0_u8; (num_sectors as usize) * 2048];

        // Sector by sector only where the format forces it. A request lands in
        // one track and, on a 2048-byte track, in one contiguous run of bytes
        // -- so it is ONE read. The old loop resolved the track and issued a
        // 2048-byte read per sector: 128 of each for a 128-sector request,
        // with the console frozen for all of them.
        let mut done = 0usize;
        while done < num_sectors as usize {
            let req_lba = lba.saturating_add(done as u32);

            // The most recent data track whose logical start is <= requested LBA.
            let idx = tracks
                .iter()
                .enumerate()
                .filter(|(_, t)| t.track_type == 4 && t.start_lba.saturating_add(150) <= req_lba)
                .max_by_key(|(_, t)| t.start_lba)
                .map(|(i, _)| i)
                .ok_or_else(|| format!("No data track found for LBA 0x{req_lba:08x}"))?;

            if tracks[idx].source.is_none() {
                // Name the container, not just the track: "track03.bin is
                // missing" is a very different problem next to a loose .gdi
                // than it is inside an archive that was supposed to be
                // self-contained.
                let opened = self.container.open(&tracks[idx].track).map_err(|e| {
                    format!(
                        "cannot open track '{}' in {}: {e}",
                        tracks[idx].track,
                        self.container.describe()
                    )
                })?;
                tracks[idx].source = Some(opened);
            }

            // Where this track stops being the answer: the next data track's
            // start, if there is one.
            let track_start = tracks[idx].start_lba.saturating_add(150);
            let next_start = tracks
                .iter()
                .filter(|t| t.track_type == 4 && t.start_lba.saturating_add(150) > track_start)
                .map(|t| t.start_lba.saturating_add(150))
                .min();
            let left = num_sectors as usize - done;
            let run = match next_start {
                Some(n) => left.min((n - req_lba) as usize),
                None => left,
            };

            let track = &tracks[idx];
            let payload_offset: u64 = match track.sector_size {
                2048 => 0,
                // dc-virtcd-compatible secskip for packed formats.
                2056 | 2336 => 8,
                // Keep raw extraction deterministic for compatibility:
                // Mode 1 payload starts at +16 in 2352/2448 sectors.
                2352 | 2448 => 16,
                s => return Err(format!("Unsupported GDI sector size: {}", s).into()),
            };
            if payload_offset + 2048 > track.sector_size as u64 {
                return Err(format!(
                    "Raw sector too small for payload extraction: {} bytes (offset {})",
                    track.sector_size, payload_offset
                )
                .into());
            }

            let in_track_lba = req_lba.checked_sub(track_start).ok_or_else(|| {
                format!(
                    "Requested LBA 0x{req_lba:08x} is before logical data track start 0x{track_start:08x}"
                )
            })?;
            let at = (track.offset as u64) + (in_track_lba as u64) * (track.sector_size as u64);
            let source = track.source.as_ref().unwrap();
            let out = &mut buffer[done * 2048..(done + run) * 2048];

            if track.sector_size == 2048 {
                source.read_at(at, out)?;
            } else {
                // Only the user bytes are read: the sync/subheader in front of
                // them is skipped by the seek and the ECC behind them is of no
                // interest -- so a raw track is still one read per sector.
                for (i, chunk) in out.chunks_mut(2048).enumerate() {
                    let sector_at = at + (i as u64) * (track.sector_size as u64);
                    source.read_at(sector_at + payload_offset, chunk)?;
                }
            }
            done += run;
        }
        Ok(buffer)
    }

    fn start_sector(&self) -> u32 {
        self.data_track_edge(false)
    }

    /// Every track the `.gdi` names, audio included.
    ///
    /// A `.gdi` has always listed its audio tracks and nothing ever read them
    /// (see `Track::source`). They are the whole content of a disc's music:
    /// track type 0 is audio, 4 is data, and the lead-in the reader adds to
    /// every data track start is added here too so the numbers are the ones
    /// `read_sector` and `read_audio` take.
    fn toc_tracks(&self) -> Vec<TocTrack> {
        let mut out: Vec<TocTrack> = self
            .tracks
            .borrow()
            .iter()
            .map(|t| TocTrack {
                number: t.track_number,
                start_lba: t.start_lba.saturating_add(150),
                audio: t.track_type == 0,
            })
            .collect();
        out.sort_by_key(|t| t.start_lba);
        out
    }

    /// Raw 2352-byte sectors out of an AUDIO track.
    ///
    /// Deliberately refuses a data track rather than handing back its sync
    /// bytes and ECC as if they were samples: a CDDA read landing on a data
    /// track means the title was told the wrong TOC, and silence is a much
    /// better symptom than full-scale noise into the speakers.
    fn read_audio(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        check_read_len(num_sectors)?;
        if num_sectors == 0 {
            return Ok(vec![]);
        }
        let mut tracks = self.tracks.borrow_mut();
        let mut buffer = vec![0_u8; (num_sectors as usize) * RAW_SECTOR_SIZE];

        let mut done = 0usize;
        while done < num_sectors as usize {
            let req_lba = lba.saturating_add(done as u32);
            let idx = tracks
                .iter()
                .enumerate()
                .filter(|(_, t)| t.start_lba.saturating_add(150) <= req_lba)
                .max_by_key(|(_, t)| t.start_lba)
                .map(|(i, _)| i)
                .ok_or_else(|| format!("No track found for CDDA LBA 0x{req_lba:08x}"))?;

            if tracks[idx].track_type != 0 {
                return Err(format!(
                    "CDDA read at LBA 0x{req_lba:08x} lands on data track {} -- \
                     the title was given a table of contents it cannot have come from",
                    tracks[idx].track_number
                )
                .into());
            }
            if tracks[idx].sector_size as usize != RAW_SECTOR_SIZE {
                return Err(format!(
                    "audio track {} has {}-byte sectors, not {RAW_SECTOR_SIZE}",
                    tracks[idx].track_number, tracks[idx].sector_size
                )
                .into());
            }
            if tracks[idx].source.is_none() {
                let opened = self.container.open(&tracks[idx].track).map_err(|e| {
                    format!(
                        "cannot open audio track '{}' in {}: {e}",
                        tracks[idx].track,
                        self.container.describe()
                    )
                })?;
                tracks[idx].source = Some(opened);
            }

            let track_start = tracks[idx].start_lba.saturating_add(150);
            let next_start = tracks
                .iter()
                .filter(|t| t.start_lba.saturating_add(150) > track_start)
                .map(|t| t.start_lba.saturating_add(150))
                .min();
            let left = num_sectors as usize - done;
            let run = match next_start {
                Some(n) => left.min((n - req_lba) as usize),
                None => left,
            };

            let track = &tracks[idx];
            let source = track.source.as_ref().unwrap();
            let at = (track.offset as u64)
                + ((req_lba - track_start) as u64) * (RAW_SECTOR_SIZE as u64);
            // A track's span runs to the next track's start, and its file can
            // stop short of it: the next track's pregap is not dumped (Snow
            // Surfers' track 18 is 150 sectors short of the data track after
            // it). Those sectors are silence, as on the disc. An error here
            // made the loader ask for the same sectors forever, and a title
            // playing that track to its end, or looping it, went silent.
            let in_file = match next_start {
                Some(_) => run.min((source.len().saturating_sub(at) / RAW_SECTOR_SIZE as u64) as usize),
                None => run,
            };
            let out = &mut buffer[done * RAW_SECTOR_SIZE..(done + in_file) * RAW_SECTOR_SIZE];
            // One read for the whole run: an audio track is raw all the way
            // through, so unlike a data track there is nothing to skip
            // between sectors. The rest of the run stays zero.
            // Nothing of this run is in the file (it lies wholly in the pregap
            // that was not dumped): silence, and no read at all. A zero-length
            // read past the end is an error for an in-memory track, and that
            // error was the loader's endless re-ask at the end of a looping
            // track (Shenmue II's title screen, track 5).
            if in_file > 0 {
                source.read_at(at, out)?;
            }
            done += run;
        }
        Ok(buffer)
    }

    /// The start of the high-density area -- see `high_density_start()` for why
    /// that is not the same thing as the highest data track, and the trait for
    /// why it is not `start_sector()`.
    ///
    /// The fallback is the highest data track, which is what this always used
    /// to answer: on an image with no high-density area there is no better
    /// guess, and on the ordinary three-track GDI the two are the same track.
    fn boot_sector(&self) -> u32 {
        self.high_density_start()
            .unwrap_or_else(|| self.data_track_edge(true))
    }

    /// The lead-in the reader adds to every track start, and that the disc's
    /// own filesystem does not count. See the trait.
    fn fs_lba(&self, iso_lba: u32) -> u32 {
        iso_lba + 150
    }

    /// Where the lead-out is: the end of the LAST data track, measured from the
    /// start of the first.
    ///
    /// Only the last track is opened. It is the only one whose end can be the
    /// lead-out -- the tracks are in LBA order and the ones in front of it end
    /// where the next one begins -- and opening the others would cost a full
    /// deflate index build on a zipped dump for the low-density track nobody
    /// reads, which is exactly what `Track::source` is lazy to avoid. This runs
    /// inside the TOC syscall, with the title frozen (AGENTS.md 16).
    fn num_sectors(&self) -> u32 {
        let first_start = self.start_sector();
        // The LAST data track, not `boot_sector()`: on a disc whose CDDA is in
        // the high-density area those are different tracks, and the lead-out is
        // behind the last one.
        let last_start = self.data_track_edge(true);
        let mut tracks = self.tracks.borrow_mut();
        let Some(last) = tracks
            .iter()
            .position(|t| t.track_type == 4 && t.start_lba.saturating_add(150) == last_start)
        else {
            return 0;
        };

        let t = &mut tracks[last];
        if t.source.is_none()
            && let Ok(s) = self.container.open(&t.track)
        {
            t.source = Some(s);
        }
        let Some(s) = t.source.as_ref() else {
            return 0;
        };
        let bytes = s.len().saturating_sub(t.offset as u64);
        let track_sectors = (bytes / (t.sector_size as u64)) as u32;
        last_start
            .saturating_add(track_sectors)
            .saturating_sub(first_start)
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
        std::path::Path::new(p)
            .exists()
            .then(|| Gdi::open_path(p).expect("parse gdi"))
    }

    /// A GDI with nothing but a track list. `start_sector`, `boot_sector` and
    /// `data_track_edge` read no bytes, so no track file has to exist -- which
    /// is what lets the layouts below be tested on a machine with no dumps.
    fn tracks_at(spec: &[(u32, u8)]) -> Gdi {
        Gdi {
            tracks: RefCell::new(
                spec.iter()
                    .enumerate()
                    .map(|(i, &(start_lba, track_type))| Track {
                        track_number: i as u8 + 1,
                        start_lba,
                        track_type,
                        sector_size: 2352,
                        track: format!("track{:02}.bin", i + 1),
                        offset: 0,
                        source: None,
                    })
                    .collect(),
            ),
            container: Box::new(DirContainer::new(PathBuf::new())),
        }
    }

    /// Positive control for the index warmer: this list is all it is given, so
    /// an empty one would make it do nothing at all while looking like it
    /// worked, and every track would go back to being indexed inside the first
    /// CD-DA sub-fetch (AGENTS.md 14.9).
    #[test]
    fn the_audio_tracks_are_the_ones_the_warmer_is_given() {
        let g = tracks_at(&[(0, 4), (45000, 4), (60000, 0), (70000, 0)]);
        assert_eq!(
            g.audio_track_files(),
            vec!["track03.bin".to_string(), "track04.bin".to_string()],
            "the audio tracks only, named the way the .gdi names them"
        );
        assert!(
            tracks_at(&[(0, 4), (45000, 4)])
                .audio_track_files()
                .is_empty(),
            "a disc with no audio gives nothing to warm, not its data tracks"
        );
    }

    /// THE BUG THIS LOCKS DOWN. `start_sector()` is the LOWEST data track and
    /// `boot_sector()` the high-density one, and on a GD-ROM they are different
    /// tracks with the same valid header. Getting them the same way round again
    /// would make `--boot-ipbin` execute 32 KB of zeroes, silently.
    #[test]
    fn boot_sector_is_the_high_density_area() {
        let Some(gdi) = sa_gdi() else { return };
        assert_eq!(gdi.start_sector(), 150, "low-density data track");
        assert_eq!(gdi.boot_sector(), 45150, "high-density data track");
    }

    /// AND THE ONE AFTER IT: the high-density area is not always one track.
    ///
    /// A title whose CDDA lives up there is mastered `data / audio / ... /
    /// data`, and the boot track is the FIRST data track of that area, not the
    /// last one on the disc -- which carries no header and no filesystem. This
    /// is the Buzz Lightyear of Star Command PAL layout, the disc that failed
    /// with "the disc does not say which file it boots" while saying so
    /// perfectly clearly 219000 sectors earlier.
    #[test]
    fn cdda_in_the_high_density_area_does_not_move_the_boot_track() {
        let gdi = tracks_at(&[(0, 4), (6986, 0), (45000, 4), (257827, 0), (263852, 4)]);
        assert_eq!(gdi.start_sector(), 150, "low-density data track");
        assert_eq!(gdi.boot_sector(), 45150, "first high-density data track");
        // The lead-out is still measured behind the LAST data track, which is
        // why `num_sectors()` may not go through `boot_sector()`.
        assert_eq!(gdi.data_track_edge(true), 264002, "last data track");
    }

    /// The ordinary three-track GDI, where the two answers coincide, and an
    /// image with no high-density area at all, where the highest data track is
    /// all there is to point at.
    #[test]
    fn the_boot_track_falls_back_to_the_highest_data_track() {
        assert_eq!(tracks_at(&[(0, 4), (600, 0), (45000, 4)]).boot_sector(), 45150);
        assert_eq!(tracks_at(&[(0, 4), (100, 4)]).boot_sector(), 250);
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

    /// The lead-out is the end of the LAST data track, and only that track is
    /// opened to find it.
    ///
    /// This runs inside the TOC syscall with the title frozen, so opening the
    /// low-density track as well -- which on a zipped dump means a full inflate
    /// and index build for bytes nobody reads -- is not a small waste.
    #[test]
    fn the_lead_out_comes_from_the_last_data_track_alone() {
        let Some(gdi) = sa_gdi() else { return };
        let len = std::fs::metadata("test/track03.bin").expect("track03").len();
        // 45000 (+150 lead-in) + its own sectors, measured from the first data
        // track's start at 0 (+150).
        let want = 45150 + (len / 2352) as u32 - 150;
        assert_eq!(gdi.num_sectors(), want);
    }

    /// A track's span runs to the next track's start, and its file can stop
    /// short of it (the next track's pregap is not dumped): what is past the
    /// file is silence, not an error the loader would ask about forever. Past
    /// the LAST track there is no span, and that stays an error.
    #[test]
    fn audio_past_a_short_track_file_is_silence_up_to_the_next_track() {
        let dir = std::env::temp_dir().join(format!("gdi-short-track-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Track 2: 3 sectors in its file, 5 in its span (track 3 starts at 5).
        let body: Vec<u8> = (0..3 * 2352).map(|i| (i % 251) as u8 + 1).collect();
        std::fs::write(dir.join("track02.raw"), &body).unwrap();
        std::fs::write(dir.join("track03.raw"), vec![7u8; 2352]).unwrap();
        let mut g = tracks_at(&[(0, 4), (0, 0), (5, 0)]);
        g.container = Box::new(DirContainer::new(dir.clone()));
        for (i, t) in g.tracks.borrow_mut().iter_mut().enumerate() {
            t.track = format!("track{:02}.raw", i + 1);
        }

        let got = g.read_audio(150, 5).expect("the span reads whole");
        assert_eq!(&got[..3 * 2352], &body[..], "the file's own sectors");
        assert!(got[3 * 2352..].iter().all(|b| *b == 0), "the pregap is silence");
        // The next track begins exactly where the span ends.
        assert_eq!(g.read_audio(155, 1).expect("track 3"), vec![7u8; 2352]);
        // Wholly in the pregap: silence too, whatever the source is.
        assert!(g.read_audio(153, 2).expect("the pregap reads").iter().all(|b| *b == 0));
        // Positive control: the last track has no span to fill.
        assert!(g.read_audio(155, 2).is_err(), "past the last track's file");

        std::fs::remove_dir_all(&dir).ok();
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
