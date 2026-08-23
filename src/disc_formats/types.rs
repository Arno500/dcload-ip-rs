#[derive(Debug)]
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
    pub(crate) file: Option<std::fs::File>,
}

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

const HARDWARE_ID: &[u8] = b"SEGA SEGAKATANA";

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
    let base = disc.start_sector();

    let first = disc.read_sector(base, 1).ok()?;
    if first.starts_with(HARDWARE_ID) {
        return Some(first);
    }

    // ISO9660 primary volume descriptor, sixteen sectors in.
    let pvd = disc.read_sector(base + 16, 1).ok()?;
    if pvd.first() != Some(&1) || pvd.get(1..6)? != b"CD001" {
        return None;
    }
    // Root directory record at +156: extent LBA (little-endian half at +2)
    // and data length (little-endian half at +10).
    let root_lba = u32::from_le_bytes(pvd.get(158..162)?.try_into().ok()?);
    let root_len = u32::from_le_bytes(pvd.get(166..170)?.try_into().ok()?);
    if root_len == 0 || root_len > 1 << 20 {
        return None;
    }

    let dir = disc.read_sector(root_lba, root_len.div_ceil(2048)).ok()?;
    let mut o = 0usize;
    while o + 33 <= dir.len() {
        let rec_len = dir[o] as usize;
        if rec_len == 0 {
            // A zero length means "no more records in this sector"; step to
            // the next one rather than stopping, since a directory can span
            // several and the tail of each is padding.
            o = (o / 2048 + 1) * 2048;
            if o >= dir.len() {
                break;
            }
            continue;
        }
        if o + rec_len > dir.len() {
            break;
        }
        let name_len = dir[o + 32] as usize;
        let name = dir.get(o + 33..o + 33 + name_len)?;
        // ISO9660 names carry a ";1" version suffix.
        let bare = name.split(|c| *c == b';').next().unwrap_or(name);
        if bare.eq_ignore_ascii_case(b"IP.BIN") {
            let lba = u32::from_le_bytes(dir.get(o + 2..o + 6)?.try_into().ok()?);
            let sector = disc.read_sector(lba, 1).ok()?;
            return sector.starts_with(HARDWARE_ID).then_some(sector);
        }
        o += rec_len;
    }
    None
}
