use crate::disc_formats::types::{HIGH_DENSITY_LBA, TocTrack};

/// The Dreamcast's table of contents: 99 track entries, then first, last and
/// lead-out. Every word is `lba | adr << 24 | ctrl << 28`, except first/last
/// which carry the track number at bit 16 instead of an LBA.
///
/// WHY THE TRACK LIST IS NOT OPTIONAL, when it is available.
///
/// This used to answer a fixed two-entry table built from `start_sector()` and
/// `num_sectors()` alone: one data track, or two when the low-density area was
/// separate, and nothing else. On a `.gdi` that is not an approximation, it is
/// a different disc -- Snow Surfers has nineteen tracks, sixteen of them audio,
/// and was being told it had one. **The TOC is the only place a title ever
/// learns it has music**, so a title handed that table will never ask to play
/// a note, whatever else works.
///
/// The old shape is still what an image that cannot enumerate its tracks gets,
/// byte for byte. A format that does not know its own layout must not have one
/// guessed for it.
pub fn build_dc_toc(
    start_sector: u32,
    num_sectors: u32,
    tracks: &[TocTrack],
    area: u32,
) -> Vec<u8> {
    let mut toc = [u32::MAX; 102];

    let selected = select_area(tracks, area);
    if selected.is_empty() {
        // Exactly what this always returned. See the header.
        if start_sector > 150 {
            toc[0] = make_dc_toc_entry(150, 1, 4);
            toc[1] = make_dc_toc_entry(start_sector, 1, 4);
            toc[100] = make_dc_toc_track(2, 4);
        } else {
            toc[0] = make_dc_toc_entry(start_sector, 1, 4);
            toc[100] = make_dc_toc_track(1, 4);
        }
        toc[99] = make_dc_toc_track(1, 4);
        toc[101] = make_dc_toc_entry(start_sector.saturating_add(num_sectors), 1, 4);
        return pack(&toc);
    }

    for t in &selected {
        // CTRL bit 2 is "data track"; an audio track carries 0. That single bit
        // is what tells a title which tracks it may play.
        let ctrl = if t.audio { 0 } else { 4 };
        if let Some(slot) = (t.number as usize).checked_sub(1)
            && slot < 99
        {
            toc[slot] = make_dc_toc_entry(t.start_lba, 1, ctrl);
        }
    }

    let first = &selected[0];
    let last = &selected[selected.len() - 1];
    toc[99] = make_dc_toc_track(first.number, if first.audio { 0 } else { 4 });
    toc[100] = make_dc_toc_track(last.number, if last.audio { 0 } else { 4 });
    toc[101] = make_dc_toc_entry(leadout(&selected, tracks, start_sector, num_sectors), 1, 4);
    pack(&toc)
}

/// The tracks of one AREA of the disc, because that is what a GETTOC asks for.
///
/// A GD-ROM is two discs in one lens: a CD area (tracks 1-2) and the
/// high-density area (3 onwards), and `param[0]` of the syscall picks between
/// them. A title's CDDA is normally in the high-density area -- Snow Surfers'
/// fifteen audio tracks are tracks 4 to 18 -- so answering the wrong area
/// hands it a table with no music in it, which is the same failure as having
/// no table at all.
///
/// An image with no high-density area (a `.cdi`, a plain ISO) has one area and
/// gives it to whichever is asked for: refusing would mean a disc that reads
/// perfectly having no table of contents.
fn select_area(tracks: &[TocTrack], area: u32) -> Vec<TocTrack> {
    if tracks.is_empty() {
        return vec![];
    }
    // AREA 2 IS THE LOADER'S OWN REQUEST, not a title's: "every track, both
    // areas at once". dcload asks for it once to build the table it resolves
    // CMD_PLAY_TRACKS against (cdda.c), and merging two separate answers on
    // the console would cost a second 408-byte buffer in a loader that counts
    // bytes. A title only ever asks for 0 or 1.
    if area >= 2 {
        return tracks.to_vec();
    }
    let boundary = HIGH_DENSITY_LBA + 150;
    let split = tracks.iter().any(|t| t.start_lba >= boundary)
        && tracks.iter().any(|t| t.start_lba < boundary);
    if !split {
        return tracks.to_vec();
    }
    let want_high = area != 0;
    tracks
        .iter()
        .filter(|t| (t.start_lba >= boundary) == want_high)
        .copied()
        .collect()
}

/// Where the area being reported stops.
///
/// The next track after the last one reported, when there is one -- that is
/// the lead-out of a CD area on a GD-ROM, and it is exact. Otherwise the end
/// of the data the reader knows about, which is what this always answered.
fn leadout(selected: &[TocTrack], all: &[TocTrack], start_sector: u32, num_sectors: u32) -> u32 {
    let last_start = selected[selected.len() - 1].start_lba;
    all.iter()
        .map(|t| t.start_lba)
        .filter(|&lba| lba > last_start)
        .min()
        .unwrap_or_else(|| start_sector.saturating_add(num_sectors))
}

fn pack(toc: &[u32; 102]) -> Vec<u8> {
    let mut out = Vec::with_capacity(toc.len() * 4);
    for val in toc {
        out.extend_from_slice(&val.to_le_bytes());
    }
    out
}

fn make_dc_toc_entry(lba: u32, adr: u32, ctrl: u32) -> u32 {
    lba | (adr << 24) | (ctrl << 28)
}

fn make_dc_toc_track(n: u8, ctrl: u32) -> u32 {
    ((n as u32) << 16) | (1 << 24) | (ctrl << 28)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(blob: &[u8]) -> Vec<u32> {
        blob.chunks(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// An image that cannot enumerate its tracks must get exactly what it used
    /// to get. This is the regression guard for every title that works today.
    #[test]
    fn no_track_list_reproduces_the_old_table() {
        let toc = entries(&build_dc_toc(45150, 500000, &[], 0));
        assert_eq!(toc[0], 150 | (1 << 24) | (4 << 28));
        assert_eq!(toc[1], 45150 | (1 << 24) | (4 << 28));
        assert_eq!(toc[2], u32::MAX);
        assert_eq!(toc[99] >> 16 & 0xff, 1);
        assert_eq!(toc[100] >> 16 & 0xff, 2);
        assert_eq!(toc[101], 545150 | (1 << 24) | (4 << 28));
    }

    fn snow_surfers() -> Vec<TocTrack> {
        // Shape of the real dump: a CD area of one data and one audio track,
        // then a high-density area whose middle is fifteen audio tracks.
        let mut v = vec![
            TocTrack { number: 1, start_lba: 150, audio: false },
            TocTrack { number: 2, start_lba: 900, audio: true },
            TocTrack { number: 3, start_lba: 45150, audio: false },
        ];
        for n in 4..=18u8 {
            v.push(TocTrack {
                number: n,
                start_lba: 200000 + (n as u32 - 4) * 10000,
                audio: true,
            });
        }
        v.push(TocTrack { number: 19, start_lba: 400000, audio: false });
        v
    }

    #[test]
    fn the_high_density_area_carries_the_audio_tracks() {
        let tracks = snow_surfers();
        let toc = entries(&build_dc_toc(150, 549150, &tracks, 1));
        assert_eq!(toc[99] >> 16 & 0xff, 3, "first track of the GD area");
        assert_eq!(toc[100] >> 16 & 0xff, 19, "last track of the GD area");
        // Track 3 is data, track 4 is audio, and the CTRL bit is the whole
        // difference a title can see.
        assert_eq!(toc[2] >> 28, 4);
        assert_eq!(toc[3] >> 28, 0);
        assert_eq!(toc[3] & 0xffffff, 200000);
        // The CD area's tracks are not in this answer.
        assert_eq!(toc[0], u32::MAX);
        assert_eq!(toc[1], u32::MAX);
    }

    #[test]
    fn the_cd_area_stops_at_the_high_density_boundary() {
        let tracks = snow_surfers();
        let toc = entries(&build_dc_toc(150, 549150, &tracks, 0));
        assert_eq!(toc[99] >> 16 & 0xff, 1);
        assert_eq!(toc[100] >> 16 & 0xff, 2);
        assert_eq!(toc[0] & 0xffffff, 150);
        assert_eq!(toc[1] & 0xffffff, 900);
        assert_eq!(toc[2], u32::MAX);
        // Lead-out of the CD area is where the GD area starts.
        assert_eq!(toc[101] & 0xffffff, 45150);
    }

    #[test]
    fn area_two_is_the_whole_disc() {
        let tracks = snow_surfers();
        let toc = entries(&build_dc_toc(150, 549150, &tracks, 2));
        assert_eq!(toc[99] >> 16 & 0xff, 1, "first track of the disc");
        assert_eq!(toc[100] >> 16 & 0xff, 19, "last track of the disc");
        // Both areas present in one table, which is what the loader resolves
        // CMD_PLAY_TRACKS against.
        assert_eq!(toc[0] & 0xffffff, 150);
        assert_eq!(toc[1] >> 28, 0, "track 2 is audio, in the CD area");
        assert_eq!(toc[3] >> 28, 0, "track 4 is audio, in the GD area");
        assert_eq!(toc[18] >> 28, 4, "track 19 is data");
    }

    /// A .cdi has one area, and asking for either must not empty it.
    #[test]
    fn a_single_area_image_answers_both_areas() {
        let tracks = vec![
            TocTrack { number: 1, start_lba: 150, audio: false },
            TocTrack { number: 2, start_lba: 30000, audio: true },
        ];
        for area in [0, 1] {
            let toc = entries(&build_dc_toc(150, 40000, &tracks, area));
            assert_eq!(toc[99] >> 16 & 0xff, 1);
            assert_eq!(toc[100] >> 16 & 0xff, 2);
            assert_eq!(toc[1] >> 28, 0, "track 2 is audio");
        }
    }
}
