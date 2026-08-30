//! DiscJuggler (`.cdi`) images.
//!
//! # What was here before, and why it could not work
//!
//! This used to sniff the first 16 bytes for a sync header, pick a sector size
//! from that, and then treat the whole file as one flat run of sectors starting
//! at LBA 150 — the same heuristic as the `cdi2iso.c` sitting in the repo root,
//! which is where it came from.
//!
//! A DiscJuggler image is not laid out that way. It is a **descriptor block at
//! the end of the file** followed by nothing, with the track data packed at the
//! front, session by session and track by track. Measured on the three images
//! available here — a retail Sonic Adventure conversion and two mkdcdisc
//! outputs — every one of them begins with an *audio* track, so the old reader
//! answered the Dreamcast's very first sector request with audio samples, or
//! with the middle of a pregap, and reported no error while doing it. That is
//! the worst possible failure for a disc reader: a running title gets plausible
//! bytes that are not its data.
//!
//! # The layout, confirmed arithmetically
//!
//! The last eight bytes are `version` then `header_offset`. For V2/V3 the
//! descriptor is at `header_offset`; for V3.5 it is at `filesize -
//! header_offset`. It holds a session count, then per session a track count,
//! then one variable-length record per track carrying (among much padding) the
//! pregap length, the track length, the mode, the start LBA and a sector-size
//! id (0 → 2048, 1 → 2336, 2 → 2352).
//!
//! Track data occupies the front of the file in descriptor order, each track
//! taking `(pregap + length) * sector_size` bytes. That model is exact: for all
//! three images the sum of those, plus the descriptor block, is the file size to
//! the byte.
//!
//! # Which track is the game, and why the obvious tests are wrong
//!
//! Not the first track: every image here starts with an audio track. Not the
//! last either, and not "the one whose first sector says `SEGA SEGAKATANA`" —
//! both of those pick the wrong track on the Sonic Adventure conversion, which
//! carries a 302-sector second session that begins with a perfectly valid
//! Dreamcast header and contains nothing else. Its real filesystem is in
//! session 0, a 347465-sector track whose first sector is zeros.
//!
//! The test that works on all three images is the **ISO9660 filesystem**: a
//! primary volume descriptor at track-relative sector 16, whose root directory
//! extent lands inside that same track. On the conversion above that is true of
//! session 0 (root at LBA 11725, inside 0..347465) and false of session 1 (same
//! root LBA, nowhere near 358865..359167), which is exactly the distinction
//! needed. Confirmed by reading the root directory out of the winner: it lists
//! `1ST_READ.BIN`, `IP.BIN` and `SONICADV`.
//!
//! A Dreamcast header at sector 0 is kept only as a fallback, and an image that
//! satisfies neither is refused rather than served as though it were fine.

use crate::disc_formats::source::ImageSource;
use crate::disc_formats::iso9660;
use crate::disc_formats::types::{
    DiscFormat, HARDWARE_ID, RAW_SECTOR_SIZE, TocTrack, check_read_len,
};

const V2: u32 = 0x8000_0004;
const V3: u32 = 0x8000_0005;
const V35: u32 = 0x8000_0006;

/// Appears twice at the head of every track record.
const START_MARK: [u8; 10] = [0, 0, 1, 0, 0, 0, 255, 255, 255, 255];

#[derive(Debug, Clone)]
pub struct CdiTrack {
    pub session: u16,
    pub mode: u32,
    pub start_lba: u32,
    pub length: u32,
    pub sector_size: u32,
    /// Bytes to skip inside a raw sector to reach the 2048 user bytes.
    pub data_offset: u32,
    /// Byte offset in the file of this track's FIRST NON-PREGAP sector.
    pub file_offset: u64,
}

impl CdiTrack {
    fn contains(&self, lba: u32) -> bool {
        lba >= self.start_lba && lba < self.start_lba.saturating_add(self.length)
    }
}

pub struct Cdi {
    source: Box<dyn ImageSource>,
    tracks: Vec<CdiTrack>,
    boot: usize,
}

/// A cursor over the descriptor block. Every field is little-endian, and the
/// record is mostly padding whose length depends on the writer's version, so
/// this is deliberately a sequence of explicit reads and skips rather than a
/// struct: the skips ARE the format.
struct Cursor<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Cursor<'a> {
    fn need(&self, n: usize) -> Result<(), String> {
        if self.o + n > self.b.len() {
            Err(format!(
                "CDI descriptor truncated: wanted {n} bytes at {}, have {}",
                self.o,
                self.b.len()
            ))
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8, String> {
        self.need(1)?;
        let v = self.b[self.o];
        self.o += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, String> {
        self.need(2)?;
        let v = u16::from_le_bytes(self.b[self.o..self.o + 2].try_into().unwrap());
        self.o += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, String> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.b[self.o..self.o + 4].try_into().unwrap());
        self.o += 4;
        Ok(v)
    }
    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.need(n)?;
        self.o += n;
        Ok(())
    }
    fn take_mark(&mut self) -> Result<(), String> {
        self.need(START_MARK.len())?;
        if self.b[self.o..self.o + START_MARK.len()] != START_MARK {
            return Err(format!("CDI track start mark missing at offset {}", self.o));
        }
        self.o += START_MARK.len();
        Ok(())
    }
}

/// User bytes into a raw sector, from its size and mode (0 audio, 1 mode1,
/// 2 mode2 form1).
fn data_offset(sector_size: u32, mode: u32) -> u32 {
    match (sector_size, mode) {
        (2048, _) => 0,
        (2336, _) => 8,   // subheader only
        (2352, 1) => 16,  // sync + header
        (2352, _) => 24,  // sync + header + subheader
        _ => 0,
    }
}

impl Cdi {
    pub fn new(source: Box<dyn ImageSource>) -> Result<Self, String> {
        let filename = source.describe();
        let size = source.len();
        if size < 16 {
            return Err(format!("{filename} is too small to be a disc image"));
        }

        let mut tail = [0u8; 8];
        source
            .read_at(size - 8, &mut tail)
            .map_err(|e| e.to_string())?;
        let version = u32::from_le_bytes(tail[0..4].try_into().unwrap());
        let header_offset = u32::from_le_bytes(tail[4..8].try_into().unwrap()) as u64;

        if !matches!(version, V2 | V3 | V35) {
            return Err(format!(
                "{filename} is not a DiscJuggler image (trailer version 0x{version:08x}). \
                 Only .cdi files written by DiscJuggler or mkdcdisc are understood; \
                 convert it, or use the .gdi."
            ));
        }
        let header_pos = if version == V35 {
            size.checked_sub(header_offset)
                .ok_or_else(|| "CDI header offset runs off the front of the file".to_string())?
        } else {
            header_offset
        };
        if header_pos >= size {
            return Err(format!(
                "CDI header at {header_pos} is outside the {size}-byte file"
            ));
        }

        let mut blob = vec![0u8; (size - header_pos) as usize];
        source
            .read_at(header_pos, &mut blob)
            .map_err(|e| e.to_string())?;

        let tracks = parse_tracks(&blob, version)?;
        if tracks.is_empty() {
            return Err(format!("{filename} declares no tracks"));
        }

        // Which one is the game? Position is not a reliable answer and neither
        // is the Dreamcast header -- see the module docs. Ask the filesystem,
        // and only fall back to the header.
        let boot = find_boot_track(source.as_ref(), &tracks).ok_or_else(|| {
            format!(
                "no track of {filename} holds a readable ISO9660 filesystem or a \
                 Dreamcast IP.BIN header ({} track(s) parsed). The descriptor \
                 reads, but nothing in the image looks like a Dreamcast disc.",
                tracks.len()
            )
        })?;

        for (i, t) in tracks.iter().enumerate() {
            debug!(
                "CDI track: session {} mode {} lba {} len {} ss {} @0x{:x}{}",
                t.session,
                t.mode,
                t.start_lba,
                t.length,
                t.sector_size,
                t.file_offset,
                if i == boot { "  <- boot" } else { "" }
            );
        }

        Ok(Cdi {
            source,
            tracks,
            boot,
        })
    }
}

/// Read one track-relative sector's user bytes.
fn read_track_sector(source: &dyn ImageSource, t: &CdiTrack, k: u32) -> Option<[u8; 2048]> {
    let at = t.file_offset + (k as u64) * (t.sector_size as u64) + t.data_offset as u64;
    let mut buf = [0u8; 2048];
    source.read_at(at, &mut buf).ok()?;
    Some(buf)
}

/// The track that actually holds the disc, by the two tests in the module docs.
///
/// Searched from the last track backwards, because a Dreamcast boots the last
/// session — the filesystem test is what stops that preference from picking a
/// trailing stub session.
fn find_boot_track(source: &dyn ImageSource, tracks: &[CdiTrack]) -> Option<usize> {
    // Primary: a real ISO9660 volume whose root directory is in this track.
    for (i, t) in tracks.iter().enumerate().rev() {
        if t.mode == 0 {
            continue;
        }
        let Some(pvd) = read_track_sector(source, t, 16) else {
            continue;
        };
        if !iso9660::is_pvd(&pvd) {
            continue;
        }
        let Some(root_lba) = iso9660::root_extent_lba(&pvd) else {
            continue;
        };
        if root_lba >= t.start_lba && root_lba < t.start_lba.saturating_add(t.length) {
            return Some(i);
        }
    }
    // Fallback: a Dreamcast header at the very start of the track.
    for (i, t) in tracks.iter().enumerate().rev() {
        if t.mode == 0 {
            continue;
        }
        if let Some(s) = read_track_sector(source, t, 0)
            && s.starts_with(HARDWARE_ID)
        {
            return Some(i);
        }
    }
    None
}

fn parse_tracks(blob: &[u8], version: u32) -> Result<Vec<CdiTrack>, String> {
    let mut c = Cursor { b: blob, o: 0 };
    let sessions = c.u16()?;
    let mut tracks = Vec::new();
    // Track data is packed at the front of the file in this order.
    let mut file_pos: u64 = 0;

    for session in 0..sessions {
        let ntracks = c.u16()?;
        for _ in 0..ntracks {
            if c.u32()? != 0 {
                c.skip(8)?; // DiscJuggler 3.00.780 and later
            }
            c.take_mark()?;
            c.take_mark()?;
            c.skip(4)?;
            let name_len = c.u8()? as usize;
            c.skip(name_len)?;
            c.skip(11 + 4 + 4)?;
            if c.u32()? == 0x8000_0000 {
                c.skip(8)?; // DiscJuggler 4
            }
            c.skip(2)?;
            let pregap = c.u32()?;
            let length = c.u32()?;
            c.skip(6)?;
            let mode = c.u32()?;
            c.skip(12)?;
            let start_lba = c.u32()?;
            let total_length = c.u32()?;
            c.skip(16)?;
            let sector_size = match c.u32()? {
                0 => 2048u32,
                1 => 2336,
                2 => 2352,
                other => return Err(format!("unknown CDI sector size id {other}")),
            };
            c.skip(29)?;
            if version != V2 {
                c.skip(5)?;
                if c.u32()? == 0xffff_ffff {
                    c.skip(78)?;
                }
            }

            // pregap + length == total_length on every image checked; trust the
            // descriptor's own total for advancing, so a disc that disagrees
            // still lands its later tracks in the right place.
            tracks.push(CdiTrack {
                session,
                mode,
                start_lba,
                length,
                sector_size,
                data_offset: data_offset(sector_size, mode),
                file_offset: file_pos + (pregap as u64) * (sector_size as u64),
            });
            file_pos += (total_length as u64) * (sector_size as u64);
        }
        c.skip(4 + 8)?;
        if version != V2 {
            c.skip(1)?;
        }
    }
    Ok(tracks)
}

impl DiscFormat for Cdi {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if num_sectors == 0 {
            return Ok(vec![]);
        }
        // BEFORE the allocation: `num_sectors` is what the title's syscall
        // asked for, and the loop below only discovers that an LBA is in no
        // track after `out` has been sized for it.
        check_read_len(num_sectors)?;
        let last = lba.saturating_add(num_sectors - 1);
        let track = self
            .tracks
            .iter()
            .find(|t| t.contains(lba))
            .ok_or_else(|| format!("LBA {lba} is in no track of this CDI"))?;
        let mut out = vec![0u8; (num_sectors as usize) * 2048];

        // Only the user bytes are read: `data_offset` steps over the
        // sync/subheader in front of them, and the ECC behind them is of no
        // interest.
        let at = |want: u32, t: &CdiTrack| {
            t.file_offset
                + ((want - t.start_lba) as u64) * (t.sector_size as u64)
                + t.data_offset as u64
        };

        if track.contains(last) {
            // The whole request is inside one track, which is the case for
            // every read a title actually makes. On a 2048-byte Mode 1 track
            // the sectors are then contiguous in the file and the request is
            // ONE read -- a 128-sector read used to be 128 positioned reads
            // and 128 scans of the track list, with the console frozen.
            if track.sector_size == 2048 && track.data_offset == 0 {
                self.source.read_at(at(lba, track), &mut out)?;
                return Ok(out);
            }
            for (i, chunk) in out.chunks_mut(2048).enumerate() {
                self.source.read_at(at(lba + i as u32, track), chunk)?;
            }
            return Ok(out);
        }

        // Spanning two tracks: rare enough to be worth no cleverness, and the
        // per-sector lookup is what names the LBA that is in none of them.
        for (i, chunk) in out.chunks_mut(2048).enumerate() {
            let want = lba.saturating_add(i as u32);
            let track = self
                .tracks
                .iter()
                .find(|t| t.contains(want))
                .ok_or_else(|| format!("LBA {want} is in no track of this CDI"))?;
            self.source.read_at(at(want, track), chunk)?;
        }
        Ok(out)
    }

    fn start_sector(&self) -> u32 {
        self.tracks[self.boot].start_lba
    }

    /// Every track the descriptor block declares, audio included.
    ///
    /// A CDI track's `mode` is the disc's own: 0 is audio, 1 and 2 are the
    /// data modes. The numbering is positional -- the descriptor stores tracks
    /// in disc order (see `parse_tracks`) -- and `start_lba` already counts the
    /// lead-in, so unlike a `.gdi` there is nothing to add.
    fn toc_tracks(&self) -> Vec<TocTrack> {
        self.tracks
            .iter()
            .enumerate()
            .map(|(i, t)| TocTrack {
                number: (i + 1) as u8,
                start_lba: t.start_lba,
                audio: t.mode == 0,
            })
            .collect()
    }

    /// Raw 2352-byte sectors out of an audio track. See the trait, and the
    /// GDI implementation for why a data track is refused rather than served.
    fn read_audio(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        check_read_len(num_sectors)?;
        if num_sectors == 0 {
            return Ok(vec![]);
        }
        let mut out = vec![0u8; (num_sectors as usize) * RAW_SECTOR_SIZE];
        for (i, chunk) in out.chunks_mut(RAW_SECTOR_SIZE).enumerate() {
            let want = lba.saturating_add(i as u32);
            let track = self
                .tracks
                .iter()
                .find(|t| t.contains(want))
                .ok_or_else(|| format!("CDDA LBA {want} is in no track of this CDI"))?;
            if track.mode != 0 {
                return Err(format!(
                    "CDDA read at LBA {want} lands on a data track (mode {})",
                    track.mode
                )
                .into());
            }
            if track.sector_size as usize != RAW_SECTOR_SIZE {
                return Err(format!(
                    "audio track at LBA {} has {}-byte sectors, not {RAW_SECTOR_SIZE}",
                    track.start_lba, track.sector_size
                )
                .into());
            }
            // No `data_offset`: on an audio track every byte is a sample.
            let at = track.file_offset
                + ((want - track.start_lba) as u64) * (RAW_SECTOR_SIZE as u64);
            self.source.read_at(at, chunk)?;
        }
        Ok(out)
    }

    fn num_sectors(&self) -> u32 {
        self.tracks[self.boot].length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One V2 track record, written by ABSOLUTE OFFSET rather than by calling
    /// the same skip sequence the parser uses.
    ///
    /// That is the whole point of the test. The parser is a run of magic skips
    /// with nothing to check them against, so a test that built its input by
    /// replaying those same skips would agree with any of them, correct or not.
    /// Building the record at fixed offsets means changing a skip breaks this.
    ///
    /// V2 record, with a 4-byte name: 145 bytes.
    fn track_record(pregap: u32, length: u32, mode: u32, lba: u32, total: u32, ssid: u32)
        -> Vec<u8>
    {
        let name = b"trk1";
        let mut r = vec![0u8; 145];
        let put = |r: &mut Vec<u8>, at: usize, v: u32| {
            r[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        put(&mut r, 0, 0); //  0..4    extra-block flag, 0 = no extra block
        r[4..14].copy_from_slice(&START_MARK); //  4..14
        r[14..24].copy_from_slice(&START_MARK); // 14..24
        //  24..28  skipped
        r[28] = name.len() as u8; //             28      filename length
        r[29..33].copy_from_slice(name); //      29..33  filename
        //  33..52  skipped (11 + 4 + 4)
        put(&mut r, 52, 0); //  52..56  DiscJuggler 4 marker (not 0x80000000)
        //  56..58  skipped
        put(&mut r, 58, pregap); //  58..62
        put(&mut r, 62, length); //  62..66
        //  66..72  skipped
        put(&mut r, 72, mode); //    72..76
        //  76..88  skipped
        put(&mut r, 88, lba); //     88..92
        put(&mut r, 92, total); //   92..96
        //  96..112 skipped
        put(&mut r, 112, ssid); //   112..116
        //  116..145 skipped
        r
    }

    fn image(tracks: &[Vec<u8>]) -> Vec<u8> {
        let mut b = 1u16.to_le_bytes().to_vec(); // one session
        b.extend_from_slice(&(tracks.len() as u16).to_le_bytes());
        for t in tracks {
            b.extend_from_slice(t);
        }
        b.extend_from_slice(&[0u8; 12]); // session trailer
        b
    }

    #[test]
    fn parses_a_v2_track() {
        let blob = image(&[track_record(150, 302, 2, 11702, 452, 1)]);
        let tracks = parse_tracks(&blob, V2).expect("parse");
        assert_eq!(tracks.len(), 1);
        let t = &tracks[0];
        assert_eq!(t.start_lba, 11702);
        assert_eq!(t.length, 302);
        assert_eq!(t.mode, 2);
        assert_eq!(t.sector_size, 2336);
        assert_eq!(t.data_offset, 8);
        // The pregap is stored, so the first real sector is past it.
        assert_eq!(t.file_offset, 150 * 2336);
    }

    #[test]
    fn tracks_are_packed_in_order_including_their_pregaps() {
        // The layout that makes the whole reader work: an audio track first,
        // then the data track after ALL of the audio track's sectors. Measured
        // on three real images, where the sum of (pregap+length)*sector_size
        // plus the descriptor is the file size exactly.
        let blob = image(&[
            track_record(150, 302, 0, 0, 452, 2),      // audio, 2352
            track_record(150, 43, 2, 11702, 193, 1),   // data, 2336
        ]);
        let tracks = parse_tracks(&blob, V2).expect("parse");
        assert_eq!(tracks[0].file_offset, 150 * 2352);
        assert_eq!(tracks[1].file_offset, 452 * 2352 + 150 * 2336);
        assert_eq!(tracks[1].sector_size, 2336);
    }

    #[test]
    fn a_missing_start_mark_is_an_error_not_a_guess() {
        let mut rec = track_record(150, 302, 2, 11702, 452, 1);
        rec[4] = 0xAA;
        let blob = image(&[rec]);
        assert!(parse_tracks(&blob, V2).is_err());
    }

    #[test]
    fn user_data_offsets_follow_the_sector_layout() {
        assert_eq!(data_offset(2048, 1), 0);
        assert_eq!(data_offset(2336, 2), 8);
        assert_eq!(data_offset(2352, 1), 16); // sync + header
        assert_eq!(data_offset(2352, 2), 24); // + subheader
    }

    #[test]
    fn lba_lookup_respects_track_bounds() {
        let t = CdiTrack {
            session: 1,
            mode: 2,
            start_lba: 11702,
            length: 43,
            sector_size: 2336,
            data_offset: 8,
            file_offset: 0,
        };
        assert!(!t.contains(11701));
        assert!(t.contains(11702));
        assert!(t.contains(11744));
        assert!(!t.contains(11745));
    }
}
