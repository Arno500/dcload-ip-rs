pub struct Track {
    #[allow(unused)]
    pub(crate) track_number: u8,
    pub(crate) start_lba: u32,
    #[allow(unused)]
    pub(crate) track_type: u8,
    #[allow(unused)]
    pub(crate) sector_size: u32,
    pub(crate) track: String,
    #[allow(unused)]
    pub(crate) offset: u32,
    /// Opened lazily: a GDI names its audio tracks too, and nothing ever reads
    /// them, so opening one would cost an index build on a zipped dump for
    /// bytes nobody wants.
    pub(crate) source: Option<Box<dyn crate::disc_formats::source::ImageSource>>,
}

/// The largest single `read_sector` a reader will allocate for.
///
/// The count comes off the wire -- it is whatever the title's GD syscall asked
/// for -- and the readers allocate `count * 2048` before they can tell whether
/// the sectors exist. A garbled packet asking for 2^31 sectors is a 4 TiB
/// allocation and an abort instead of an error message. 32 MiB is two thousand
/// times the largest read any title has been seen to make and twice the biggest
/// file `iso9660` will hand back.
pub const MAX_READ_SECTORS: u32 = 16 << 10;

/// The check every reader owes its caller before it sizes a buffer.
///
/// Written once because it is the same invariant three times: `Gdi` and `Cdi`
/// allocate from the count before they can tell whether those sectors exist,
/// and `Iso` is bounded only because its own length check happens to come
/// first. A new format gets it by calling this.
pub fn check_read_len(num_sectors: u32) -> Result<(), String> {
    if num_sectors > MAX_READ_SECTORS {
        return Err(format!(
            "a read of {num_sectors} sectors is past the {MAX_READ_SECTORS} this \
             serves at once"
        ));
    }
    Ok(())
}

/// One entry of the disc's table of contents, as the drive reports it.
///
/// `start_lba` is in the numbering `read_sector` takes, so a caller never has
/// to know whether the format counts the 150-sector lead-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TocTrack {
    pub number: u8,
    pub start_lba: u32,
    pub audio: bool,
}

/// Where the high-density area of a GD-ROM starts, in the lead-in-less
/// numbering a `.gdi` records. A GETTOC asks for one AREA, and on this disc
/// family the two are a different set of tracks: the CD part (1-2) and the GD
/// part (3 onwards), which is where a title's CDDA lives.
pub const HIGH_DENSITY_LBA: u32 = 45000;

/// A raw CD sector. On an audio track all 2352 bytes are signed 16-bit
/// little-endian stereo PCM at 44100 Hz -- 588 frames, exactly 1/75 second.
pub const RAW_SECTOR_SIZE: usize = 2352;

pub trait DiscFormat {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn start_sector(&self) -> u32 {
        150
    }

    /// The sector the disc's BOOTSTRAP lives at, which is not always the one
    /// `start_sector()` returns.
    ///
    /// On a GD-ROM the two differ and it matters. A GDI has a data track in the
    /// low-density area AND one in the high-density area, both opening with a
    /// valid `SEGA SEGAKATANA` header for the same title -- but measured on the
    /// Sonic Adventure 2 PAL dump, the low-density copy is 4096 non-zero bytes
    /// out of 32768: the meta header and nothing else. Its bootstrap region is
    /// all zeroes. The high-density copy carries 14183 and is the one a real
    /// machine executes.
    ///
    /// `start_sector()` deliberately keeps pointing at the low-density track,
    /// because that is the sector DreamShell hashes to name a preset and
    /// changing it would silently repoint the whole game database. This is the
    /// separate question "where is the code", and the default answer -- the
    /// only data track there is -- is right for every single-track format.
    fn boot_sector(&self) -> u32 {
        self.start_sector()
    }

    fn num_sectors(&self) -> u32 {
        0
    }

    /// The disc's tracks, data and AUDIO alike.
    ///
    /// Empty by default, and `build_dc_toc` then answers exactly what it
    /// always did -- a format that cannot enumerate its tracks must not have
    /// its table of contents guessed at. A format that CAN is the only way a
    /// title ever learns it has music: the TOC is where the track numbers,
    /// their start LBAs and their audio/data flag come from, and a title told
    /// there are two data tracks will never ask to play anything.
    fn toc_tracks(&self) -> Vec<TocTrack> {
        vec![]
    }

    /// Read `num_sectors` RAW 2352-byte sectors, for CDDA.
    ///
    /// Separate from `read_sector` because it is a different unit and a
    /// different part of the disc: `read_sector` hands back the 2048 user
    /// bytes of a data sector, which for an audio track is not a thing that
    /// exists -- every one of its 2352 bytes is signed 16-bit stereo PCM.
    fn read_audio(
        &self,
        _lba: u32,
        _num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Err("this image cannot serve CDDA".into())
    }

    /// Where an LBA recorded INSIDE the disc's own ISO9660 structures lands in
    /// the numbering `read_sector` takes.
    ///
    /// THEY ARE NOT ALWAYS THE SAME NUMBER, and the difference is silent: an
    /// extent read at the wrong origin returns a directory full of nothing,
    /// which reads exactly like "this disc has no files on it".
    ///
    /// A `.gdi` records its track starts WITHOUT the 150-sector lead-in and the
    /// reader adds it back, but the filesystem on a GD-ROM is mastered in that
    /// same lead-in-less numbering -- so an extent LBA taken out of it is 150
    /// short of the LBA that reads it. A `.cdi` descriptor counts the lead-in
    /// and so does its filesystem, so there is nothing to add, and the default
    /// is therefore the identity.
    ///
    /// Measured on the Sonic Adventure PAL GDI: track 3 starts at GDI LBA
    /// 45000 (logical 45150), its PVD is at track sector 16, and the root
    /// directory extent is recorded as LBA 45020 -- which is track sector 20,
    /// i.e. logical LBA 45170. `1ST_READ.BIN` is recorded at 545711 and reads
    /// at 545861.
    fn fs_lba(&self, iso_lba: u32) -> u32 {
        iso_lba
    }
}

pub struct StubDisc {}
impl DiscFormat for StubDisc {
    fn read_sector(
        &self,
        _lba: u32,
        _num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Err("CDFS redirection is not enabled, this should never be called from the client".into())
    }
}

pub fn get_disc_format<D: DiscFormat + 'static>(disc: D) -> Box<dyn DiscFormat> {
    Box::new(disc)
}

/// What every Dreamcast disc opens with. The one magic string that decides
/// whether a file is a Dreamcast image at all -- kept here so the readers, the
/// bootstrap loader and the preset matcher all test the same bytes.
pub const HARDWARE_ID: &[u8] = b"SEGA SEGAKATANA";

/// The disc's IP.BIN sector, wherever it actually is.
///
/// Normally it is the first sector of the data track, which is also the sector
/// DreamShell hashes to name its presets, so that is tried first and its bytes
/// are what a caller should hash.
///
/// The fallback exists because one real image demands it: the Sonic Adventure
/// Limited Edition `.cdi` on this machine starts its data track with sixteen
/// blank sectors and carries `IP.BIN` as an ordinary FILE in the ISO9660 root,
/// alongside `1ST_READ.BIN`. Without the fallback such a disc cannot be
/// identified at all, even though it reads perfectly well.
///
/// Returns the 2048-byte sector, or `None` if neither place has a Dreamcast
/// header — which is a real answer, not an error: the caller should then leave
/// the loader alone rather than guess.
pub fn find_ip_bin(disc: &dyn DiscFormat) -> Option<Vec<u8>> {
    ip_bin_at(disc, disc.start_sector())
}

/// The same two places, in a named area.
///
/// `find_ip_bin` asks about `start_sector()` because that is the sector
/// DreamShell hashes. Extracting a boot binary asks about `boot_sector()`
/// instead -- on a GD-ROM those are different tracks (see `boot_sector`) -- and
/// it needs the SAME fallback, or the one image the fallback exists for can be
/// identified and then not booted.
pub fn ip_bin_at(disc: &dyn DiscFormat, base: u32) -> Option<Vec<u8>> {
    let first = disc.read_sector(base, 1).ok()?;
    if first.starts_with(HARDWARE_ID) {
        return Some(first);
    }

    let entry = crate::disc_formats::iso9660::find_in_root(disc, base, "IP.BIN")?;
    let sector = disc.read_sector(entry.lba, 1).ok()?;
    sector.starts_with(HARDWARE_ID).then_some(sector)
}
