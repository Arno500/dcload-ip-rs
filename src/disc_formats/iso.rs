use crate::disc_formats::source::ImageSource;
use crate::disc_formats::types::DiscFormat;

pub struct Iso {
    source: Box<dyn ImageSource>,
    start_sector: u32,
    num_sectors: u32,
}

impl Iso {
    /// An ISO is a flat run of 2048-byte sectors, wherever those bytes come
    /// from -- a file, or a member of an archive read in place.
    pub fn new(source: Box<dyn ImageSource>) -> Result<Self, std::io::Error> {
        let num_sectors = (source.len() / 2048) as u32;
        let start_sector = Self::detect_start_sector(source.as_ref()).unwrap_or(150);
        Ok(Self {
            source,
            start_sector,
            num_sectors,
        })
    }

    /// Where sector 0 of this image really is.
    ///
    /// One read, not five hundred. The descriptors and the root directory all
    /// live in sectors 16..500, so that window is pulled in once and searched
    /// in memory -- the previous version issued a separate 6-byte positioned
    /// read per sector, which on an `.iso` inside a zip meant ~1000 trips
    /// through the deflate cursor to look at 3 KB of bytes.
    fn detect_start_sector(source: &dyn ImageSource) -> Option<u32> {
        const FIRST: u32 = 16;
        const LAST: u32 = 500;

        let start = FIRST as u64 * 2048;
        let end = (LAST as u64 * 2048).min(source.len());
        let whole = end.saturating_sub(start) / 2048;
        if whole == 0 {
            return None;
        }
        let mut area = vec![0u8; (whole * 2048) as usize];
        source.read_at(start, &mut area).ok()?;
        let sector = |sec: u32| -> &[u8] {
            let o = (sec - FIRST) as usize * 2048;
            &area[o..o + 2048]
        };

        let mut pvd_sector = None;
        for sec in FIRST..FIRST + whole as u32 {
            let s = sector(sec);
            if crate::disc_formats::iso9660::is_pvd(s) {
                pvd_sector = Some(sec);
                break;
            }
            // The terminator, with no primary descriptor in front of it: the
            // image starts where a plain image starts.
            if s[0] == 0xff && &s[1..6] == b"CD001" {
                return Some(150);
            }
        }

        // The root directory record, and then the sector that IS that
        // directory: its first record describes itself, so the two match.
        let pvd = pvd_sector?;
        let root_sig = &sector(pvd)[0x9c..0x9c + 0x22];
        for sec in pvd + 1..FIRST + whole as u32 {
            let next = &sector(sec)[..0x22];
            if root_sig[0..0x12] == next[0..0x12] && root_sig[0x19..0x22] == next[0x19..0x22] {
                let root_lba = crate::disc_formats::iso9660::root_extent_lba(sector(pvd))?;
                if root_lba + 150 >= sec {
                    return Some(root_lba + 150 - sec);
                }
                return Some(150);
            }
        }

        Some(150)
    }
}

impl DiscFormat for Iso {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if lba < self.start_sector {
            return Err(format!(
                "Requested LBA {} before start sector {}",
                lba, self.start_sector
            )
            .into());
        }

        let rel_lba = lba - self.start_sector;
        let end = rel_lba.saturating_add(num_sectors);
        if end > self.num_sectors {
            return Err(format!(
                "Requested sectors [{}..{}) past ISO length {}",
                rel_lba, end, self.num_sectors
            )
            .into());
        }

        let mut out = vec![0_u8; (num_sectors as usize) * 2048];
        self.source.read_at((rel_lba as u64) * 2048, &mut out)?;
        Ok(out)
    }

    fn start_sector(&self) -> u32 {
        self.start_sector
    }

    /// The lead-in the reader adds to every track start, and that the disc's
    /// own filesystem does not count. See the trait.
    fn fs_lba(&self, iso_lba: u32) -> u32 {
        iso_lba + 150
    }

    fn num_sectors(&self) -> u32 {
        self.num_sectors
    }
}
