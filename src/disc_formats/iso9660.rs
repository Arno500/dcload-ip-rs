//! Just enough ISO9660 to find a file in a disc image's root directory.
//!
//! This exists for one job: getting `1ST_READ.BIN` out of a disc without
//! anybody having to unpack the image first. It is not a filesystem driver --
//! there is no path walking, no Joliet, no Rock Ridge, no directory recursion --
//! because a Dreamcast title's boot binary is always a file in the root, named
//! by IP.BIN itself.
//!
//! # The one thing that is easy to get wrong
//!
//! WHICH AREA. On a GD-ROM there are two data tracks and both carry a valid
//! ISO9660 volume, but only the high-density one holds the game (see
//! `types::DiscFormat::boot_sector`). Everything here takes the base sector as
//! an argument for that reason -- `boot_sector()` to read the game's files,
//! `start_sector()` only when the low-density area is genuinely what is wanted.

use crate::disc_formats::types::DiscFormat;

/// One entry of a directory extent.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    /// Absolute disc LBA. ISO9660 extents are stored that way, so on a GD-ROM
    /// this is already the 45150-based number a read wants.
    pub lba: u32,
    pub size: u32,
    pub is_dir: bool,
}

/// Is this sector a primary volume descriptor? Type 1, identifier `CD001`.
///
/// Byte-level, and separate from `primary_volume_descriptor`, because the two
/// callers that need it most do not have a `DiscFormat` yet: they are deciding
/// WHICH track or WHICH origin is the filesystem, which is the question a
/// `DiscFormat` answers.
pub fn is_pvd(sector: &[u8]) -> bool {
    sector.first() == Some(&1) && sector.get(1..6) == Some(&b"CD001"[..])
}

/// The root directory's extent LBA, as the PVD records it.
///
/// The root directory record sits at offset 156 of the PVD; its extent LBA is
/// a both-endian pair whose little-endian half starts at +2 of the record.
pub fn root_extent_lba(pvd: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(pvd.get(158..162)?.try_into().ok()?))
}

/// The primary volume descriptor, sixteen sectors into the area.
pub fn primary_volume_descriptor(disc: &dyn DiscFormat, base: u32) -> Option<Vec<u8>> {
    let pvd = disc.read_sector(base + 16, 1).ok()?;
    is_pvd(&pvd).then_some(pvd)
}

/// `(extent LBA, length in bytes)` of the root directory.
pub fn root_directory(disc: &dyn DiscFormat, base: u32) -> Option<(u32, u32)> {
    let pvd = primary_volume_descriptor(disc, base)?;
    // The data length is the other half of the same record, at +10.
    let lba = disc.fs_lba(root_extent_lba(&pvd)?);
    let len = u32::from_le_bytes(pvd.get(166..170)?.try_into().ok()?);
    // A root directory is a handful of sectors. Anything else means the PVD is
    // not what we think it is, and reading megabytes on that assumption is how
    // a bad image turns into an out-of-memory instead of an error message.
    if len == 0 || len > 1 << 20 {
        return None;
    }
    Some((lba, len))
}

/// Every entry of one directory extent.
pub fn list_directory(disc: &dyn DiscFormat, lba: u32, len: u32) -> Vec<DirEntry> {
    let Ok(dir) = disc.read_sector(lba, len.div_ceil(2048)) else {
        return vec![];
    };
    let mut out = vec![];
    let mut o = 0usize;
    while o + 33 <= dir.len() {
        let rec_len = dir[o] as usize;
        if rec_len == 0 {
            // A zero length means "no more records in THIS sector"; step to the
            // next one rather than stopping, since a directory can span several
            // and the tail of each is padding.
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
        let Some(raw) = dir.get(o + 33..o + 33 + name_len) else {
            break;
        };
        // ISO9660 names carry a ";1" version suffix. The two one-byte names
        // 0x00 and 0x01 are "." and "..".
        let bare = raw.split(|c| *c == b';').next().unwrap_or(raw);
        let name = String::from_utf8_lossy(bare).into_owned();
        let flags = dir[o + 25];
        if let (Some(lba_b), Some(size_b)) = (dir.get(o + 2..o + 6), dir.get(o + 10..o + 14))
            && name_len > 1
        {
            out.push(DirEntry {
                name,
                // Converted once, here, so that every `lba` handed out of this
                // module is one `read_sector` can be given directly.
                lba: disc.fs_lba(u32::from_le_bytes(lba_b.try_into().unwrap())),
                size: u32::from_le_bytes(size_b.try_into().unwrap()),
                is_dir: flags & 0x02 != 0,
            });
        }
        o += rec_len;
    }
    out
}

/// Everything in the root directory of the area starting at `base`.
pub fn list_root(disc: &dyn DiscFormat, base: u32) -> Vec<DirEntry> {
    match root_directory(disc, base) {
        Some((lba, len)) => list_directory(disc, lba, len),
        None => vec![],
    }
}

/// One file of the root directory, by name, case-insensitively.
pub fn find_in_root(disc: &dyn DiscFormat, base: u32, name: &str) -> Option<DirEntry> {
    list_root(disc, base)
        .into_iter()
        .find(|e| !e.is_dir && e.name.eq_ignore_ascii_case(name))
}

/// The largest file this module will read into memory.
///
/// The same 16 MiB `dispatch::upload_bytes` refuses to send: the only thing
/// read through here is a boot binary, and one bigger than the console's RAM is
/// a misread directory record rather than a real file. Without the cap a
/// corrupt record carrying 0xffffffff turns into a 4 GiB allocation -- or, on a
/// GDI, into `num_sectors * 2048` overflowing on the way there.
pub const MAX_FILE_BYTES: u32 = crate::types::DREAMCAST_RAM_BYTES as u32;

/// Read a whole file out of the disc.
pub fn read_file(
    disc: &dyn DiscFormat,
    entry: &DirEntry,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if entry.size > MAX_FILE_BYTES {
        return Err(format!(
            "'{}' says it is {} bytes, which is past the {} MiB this reads; the \
             directory record is not what we think it is",
            entry.name,
            entry.size,
            MAX_FILE_BYTES >> 20
        )
        .into());
    }
    let sectors = entry.size.div_ceil(2048);
    let mut data = disc.read_sector(entry.lba, sectors)?;
    // The last sector is padding past the recorded length; a Dreamcast binary
    // is executed from RAM and the tail is harmless, but the size is what the
    // directory says and anything else would make a checksum meaningless.
    data.truncate(entry.size as usize);
    Ok(data)
}

/// The name of the boot binary, as the disc's own IP.BIN gives it.
///
/// IP.BIN carries it at +0x60, sixteen bytes, space-padded -- this is the same
/// field DreamShell reads (`modules/isoldr/module.c`), and it is why the answer
/// is not simply "1ST_READ.BIN": Windows CE titles boot `0WINCEOS.BIN`, and a
/// handful of others use their own name.
///
/// Returns `None` when the field is blank, which is a real answer for a disc
/// that boots some other way.
pub fn boot_file_name(ip_bin: &[u8]) -> Option<String> {
    let field = ip_bin.get(0x60..0x70)?;
    let name: String = field
        .iter()
        .take_while(|b| **b != 0 && **b != b' ')
        .map(|b| *b as char)
        .collect();
    // An ISO9660 filename, or nothing. The field is sixteen raw bytes and a
    // corrupt or hostile image can put anything in them -- separators, `..`,
    // control codes -- and this name reaches a directory lookup, the log, and
    // (as the default output name) a host path. Refusing here makes that true
    // for every consumer rather than for whichever one remembered to check.
    let legal = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !legal {
        warn!("IP.BIN names a boot file this is not: {name:?}");
        return None;
    }
    Some(name)
}
