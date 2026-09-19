//! Reading a disc image out of a `.zip`, in place.
//!
//! Dumps travel zipped, and unpacking a 1.1 GB GDI to run it for thirty seconds
//! is a poor trade. Nothing here unpacks anything: the archive is parsed for
//! where its members are, and each member becomes an [`ImageSource`] that the
//! ordinary `Iso` / `Gdi` / `Cdi` readers seek in exactly as they seek in a
//! file.
//!
//! Two kinds of member, and the difference is worth knowing before you zip a
//! dump:
//!
//! - **Stored** (`zip -0`): the bytes are already there, in order. A read is a
//!   seek. No index, no RAM, no start-up cost -- as good as a loose file, and
//!   the archive still keeps the CRC and the file names together.
//! - **Deflated** (what every zip tool does by default): random access needs
//!   the checkpoint index in [`super::deflate`], which costs one full inflate
//!   pass before the title starts and about 24 MB of RAM afterwards. Reads are
//!   then a few milliseconds at worst.
//!
//! Both work. If you are zipping dumps specifically to run them from here,
//! `-0` is free at run time and costs only disc space.
//!
//! # What is deliberately NOT supported
//!
//! Encrypted members, and any compression method other than stored/deflate
//! (bzip2, LZMA, zstd, xz). Each is refused by name rather than by a generic
//! failure, because "this archive uses zstd" and "this archive is damaged" want
//! completely different things from whoever is reading the log.
//!
//! Spanned/split archives are refused for the same reason. A `.z01` set has
//! bytes we simply do not have.

use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::disc_formats::deflate::{DeflateSource, inflate_all};
use crate::disc_formats::source::{Container, FileSource, ImageSource, MemorySource, SubSource};

const EOCD_SIG: u32 = 0x0605_4b50;
const EOCD64_SIG: u32 = 0x0606_4b50;
const EOCD64_LOCATOR_SIG: u32 = 0x0706_4b50;
const CDFH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// Below this, a deflated member is simply inflated into RAM: building a
/// checkpoint index for a `.gdi` text file or a small homebrew image would cost
/// more than holding the whole thing.
const INLINE_MAX: u64 = 16 << 20;

/// The EOCD record is 22 bytes plus a comment of at most 65535.
const EOCD_SEARCH: u64 = 22 + 65535;

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_header_offset: u64,
}

impl ZipEntry {
    pub fn is_encrypted(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Whether random access to this member costs a deflate index build.
    ///
    /// One place, used both by [`ZipArchive::open_entry`] to choose the reader
    /// and by [`warm_track_indexes`] to choose what to warm: two mirrored
    /// conditions would be free to drift, and the warmer would then build
    /// indexes nobody consults while the read path built them again on the
    /// syscall it must not build them on.
    pub fn needs_index(&self) -> bool {
        self.method == METHOD_DEFLATE && self.uncompressed_size > INLINE_MAX
    }
    /// Directory members are stored as zero-length names ending in `/`.
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

pub struct ZipArchive {
    path: PathBuf,
    entries: Vec<ZipEntry>,
    /// Some archives carry a prefix (a self-extracting stub, or a concatenation)
    /// which shifts every offset the central directory records. Measured once
    /// against where the directory actually is, and applied everywhere.
    offset_shift: i64,
}

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Is this file a zip? By CONTENT, not by extension.
///
/// A dump handed over as `game.zip.bin`, or a `.cdi` that is really an archive,
/// both happen; and the reverse -- deciding from the name and then failing to
/// parse -- produces the least useful error message of the three.
pub fn looks_like_zip(path: &Path) -> bool {
    let Ok(src) = FileSource::open(path) else {
        return false;
    };
    if src.len() < 4 {
        return false;
    }
    let mut magic = [0u8; 4];
    if src.read_at(0, &mut magic).is_err() {
        return false;
    }
    let sig = u32::from_le_bytes(magic);
    if sig == LFH_SIG || sig == EOCD_SIG {
        return true;
    }
    // A PREFIXED archive -- a self-extracting stub, or a concatenation --
    // starts with the prefix, not with the zip. `ZipArchive::open` measures the
    // shift such a file causes and reads it correctly, so answering "no" on the
    // first four bytes alone left that support unreachable: the file fell
    // through to `Iso::new`, which never fails, and the user was told the image
    // carried no Dreamcast header. The end-of-central-directory record is what
    // actually makes a file a zip, and it is at the end.
    locate_eocd(&src).is_some()
}

/// The end-of-central-directory record: where the tail was read from, the tail
/// itself, and the record's offset inside it.
///
/// The EOCD is at the end, behind a comment of unknown length, so it is found
/// by scanning backwards. The comment length is checked against what is
/// actually left, which is what stops a byte pattern inside the comment from
/// being taken for the record.
fn locate_eocd(src: &dyn ImageSource) -> Option<(u64, Vec<u8>, usize)> {
    let size = src.len();
    if size < 22 {
        return None;
    }
    let tail_len = EOCD_SEARCH.min(size);
    let tail_at = size - tail_len;
    let mut tail = vec![0u8; tail_len as usize];
    src.read_at(tail_at, &mut tail).ok()?;

    let mut i = tail.len() - 22;
    loop {
        if u32at(&tail, i) == EOCD_SIG {
            let comment_len = u16at(&tail, i + 20) as usize;
            if i + 22 + comment_len == tail.len() {
                return Some((tail_at, tail, i));
            }
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

impl ZipArchive {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = FileSource::open(path)?;
        let size = file.len();
        if size < 22 {
            return Err(io::Error::other(format!(
                "{}: too small to be a zip archive",
                path.display()
            )));
        }

        let Some((tail_at, tail, eocd)) = locate_eocd(&file) else {
            return Err(io::Error::other(format!(
                "{}: no zip end-of-central-directory record; not a zip archive",
                path.display()
            )));
        };

        let mut entry_count = u16at(&tail, eocd + 10) as u64;
        let mut cd_size = u32at(&tail, eocd + 12) as u64;
        let mut cd_offset = u32at(&tail, eocd + 16) as u64;
        let disk = u16at(&tail, eocd + 4);
        let mut multi_disk = disk != 0 && disk != 0xffff;

        // The zip64 records, when they are there, sit between the central
        // directory and the EOCD: [CD][zip64 EOCD, 56 bytes][locator, 20][EOCD].
        // FINDING THEM BY POSITION, not by the absolute offset the locator
        // carries, is what keeps a prefixed archive working -- that offset is
        // shifted by the prefix, and the shift is the thing being measured
        // below. It also matters for an archive that carries the records
        // without tripping any sentinel (a >4 GiB member in a small archive
        // does that): those 76 bytes still sit in front of the EOCD, and taking
        // the directory to end there is how the whole parse used to slide.
        let has_locator = eocd >= 20 && u32at(&tail, eocd - 20) == EOCD64_LOCATOR_SIG;
        // `None` when the record is not the plain 56 bytes immediately in front
        // of the locator -- a writer that appended an extensible data sector,
        // or a comment long enough to push it out of the tail.
        let eocd64_in_tail =
            (has_locator && eocd >= 76 && u32at(&tail, eocd - 76) == EOCD64_SIG)
                .then_some(eocd - 76);

        // Zip64: any field that overflowed 32 bits reads all-ones and the real
        // value is in that record.
        if (entry_count == 0xffff || cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff)
            && has_locator
        {
            let mut rec = [0u8; 56];
            match eocd64_in_tail {
                Some(at) => rec.copy_from_slice(&tail[at..at + 56]),
                None => {
                    let eocd64_at = u64at(&tail, eocd - 20 + 8);
                    file.read_at(eocd64_at, &mut rec)?;
                    if u32at(&rec, 0) != EOCD64_SIG {
                        return Err(io::Error::other(format!(
                            "{}: the zip64 locator points at {eocd64_at}, which is \
                             not a zip64 end-of-central-directory record",
                            path.display()
                        )));
                    }
                }
            }
            entry_count = u64at(&rec, 32);
            cd_size = u64at(&rec, 40);
            cd_offset = u64at(&rec, 48);
            multi_disk = u32at(&rec, 16) != 0;
        }

        if multi_disk {
            return Err(io::Error::other(format!(
                "{}: this is one part of a split archive; the other parts are not \
                 here. Join it first.",
                path.display()
            )));
        }

        // Where the directory REALLY is, against where it says it is. A
        // self-extracting stub in front of the archive shifts every offset by
        // the size of the stub, and this is the only place the shift can be
        // measured. It ends where the zip64 records begin, or at the EOCD when
        // there are none.
        let cd_end = tail_at + eocd64_in_tail.unwrap_or(eocd) as u64;
        let cd_actual = cd_end
            .checked_sub(cd_size)
            .ok_or_else(|| {
                io::Error::other(format!("{}: central directory size is impossible", path.display()))
            })?;
        let offset_shift = cd_actual as i64 - cd_offset as i64;
        if offset_shift != 0 {
            debug!(
                "{}: archive offsets are shifted by {offset_shift} bytes (a prefix \
                 sits in front of the zip)",
                path.display()
            );
        }

        let mut cd = vec![0u8; cd_size as usize];
        file.read_at(cd_actual, &mut cd)?;

        // Clamped against what the directory can physically hold: the count is
        // a 64-bit field out of the zip64 record, and reserving for an
        // all-ones one is a `capacity overflow` abort instead of the by-name
        // refusal every other malformed archive gets here. 46 bytes is the
        // shortest possible central-directory header.
        let mut entries = Vec::with_capacity(entry_count.min(cd_size / 46) as usize);
        let mut o = 0usize;
        while o + 46 <= cd.len() {
            if u32at(&cd, o) != CDFH_SIG {
                break;
            }
            let flags = u16at(&cd, o + 8);
            let method = u16at(&cd, o + 10);
            let crc32 = u32at(&cd, o + 16);
            let mut compressed_size = u32at(&cd, o + 20) as u64;
            let mut uncompressed_size = u32at(&cd, o + 24) as u64;
            let name_len = u16at(&cd, o + 28) as usize;
            let extra_len = u16at(&cd, o + 30) as usize;
            let comment_len = u16at(&cd, o + 32) as usize;
            let mut local_header_offset = u32at(&cd, o + 42) as u64;
            let name_at = o + 46;
            if name_at + name_len + extra_len + comment_len > cd.len() {
                break;
            }
            let raw_name = &cd[name_at..name_at + name_len];
            // Bit 11 says the name is UTF-8. Otherwise it is CP437, and for the
            // ASCII filenames a disc dump uses the two agree; anything exotic is
            // still shown rather than dropped.
            let name = String::from_utf8_lossy(raw_name).replace('\\', "/");

            // Zip64 extra field: only the fields that read all-ones are present,
            // in this order.
            let extra = &cd[name_at + name_len..name_at + name_len + extra_len];
            let mut e = 0usize;
            while e + 4 <= extra.len() {
                let id = u16at(extra, e);
                let len = u16at(extra, e + 2) as usize;
                if e + 4 + len > extra.len() {
                    break;
                }
                if id == 0x0001 {
                    let mut f = e + 4;
                    if uncompressed_size == 0xffff_ffff && f + 8 <= e + 4 + len {
                        uncompressed_size = u64at(extra, f);
                        f += 8;
                    }
                    if compressed_size == 0xffff_ffff && f + 8 <= e + 4 + len {
                        compressed_size = u64at(extra, f);
                        f += 8;
                    }
                    if local_header_offset == 0xffff_ffff && f + 8 <= e + 4 + len {
                        local_header_offset = u64at(extra, f);
                    }
                }
                e += 4 + len;
            }

            entries.push(ZipEntry {
                name,
                method,
                flags,
                crc32,
                compressed_size,
                uncompressed_size,
                local_header_offset,
            });
            o = name_at + name_len + extra_len + comment_len;
        }

        if entries.is_empty() {
            return Err(io::Error::other(format!(
                "{}: the zip archive holds no files",
                path.display()
            )));
        }
        debug!("{}: {} zip members", path.display(), entries.len());

        Ok(Self {
            path: path.to_path_buf(),
            entries,
            offset_shift,
        })
    }

    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Exact name first, then case-insensitively.
    ///
    /// Deliberately NOT by basename: this is what resolves an explicit
    /// `archive.zip#member`, and answering a mistyped path with a
    /// same-named file from some other directory is worse than the "holds no
    /// member" error that branch exists to give. Track names get that
    /// tolerance through [`Self::find_track`].
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        let wanted = name.replace('\\', "/");
        self.entries
            .iter()
            .find(|e| e.name == wanted)
            .or_else(|| self.entries.iter().find(|e| e.name.eq_ignore_ascii_case(&wanted)))
    }

    /// A name that came out of a `.gdi`, which is a bare filename.
    ///
    /// The basename fallback is what makes a zipped GDI work: the `.gdi` names
    /// its tracks without a directory, and whoever made the archive may well
    /// have put them in one.
    pub fn find_track(&self, name: &str) -> Option<&ZipEntry> {
        if let Some(e) = self.find(name) {
            return Some(e);
        }
        let wanted = name.replace('\\', "/");
        let base = wanted.rsplit('/').next().unwrap_or(&wanted);
        self.entries.iter().find(|e| {
            e.name
                .rsplit('/')
                .next()
                .is_some_and(|b| b.eq_ignore_ascii_case(base))
        })
    }

    /// Where a member's data actually starts.
    ///
    /// The local header has to be read for this: its extra field is allowed to
    /// differ in length from the central directory's, and frequently does
    /// (zip aligns members by padding it).
    fn data_offset(&self, entry: &ZipEntry, file: &dyn ImageSource) -> io::Result<u64> {
        let at = (entry.local_header_offset as i64 + self.offset_shift) as u64;
        let mut lfh = [0u8; 30];
        file.read_at(at, &mut lfh)?;
        if u32at(&lfh, 0) != LFH_SIG {
            return Err(io::Error::other(format!(
                "{}: member '{}' has no local header at {at}; the archive is damaged",
                self.path.display(),
                entry.name
            )));
        }
        let name_len = u16at(&lfh, 26) as u64;
        let extra_len = u16at(&lfh, 28) as u64;
        Ok(at + 30 + name_len + extra_len)
    }

    /// Open one member for random access.
    pub fn open_entry(&self, entry: &ZipEntry) -> io::Result<Box<dyn ImageSource>> {
        if entry.is_encrypted() {
            return Err(io::Error::other(format!(
                "{}: member '{}' is encrypted; unpack it yourself first",
                self.path.display(),
                entry.name
            )));
        }
        let label = format!("{}!{}", self.path.display(), entry.name);
        // One handle, used for the local header and then handed to the
        // member's window: opening the archive twice per member cost a zipped
        // GDI six opens for three tracks.
        let raw = Box::new(FileSource::open(&self.path)?);
        let data_at = self.data_offset(entry, raw.as_ref())?;
        let comp = SubSource::new(raw, data_at, entry.compressed_size, label.clone());

        match entry.method {
            METHOD_STORED => {
                if entry.compressed_size != entry.uncompressed_size {
                    return Err(io::Error::other(format!(
                        "{label}: stored member declares {} compressed and {} \
                         uncompressed bytes; the archive is damaged",
                        entry.compressed_size, entry.uncompressed_size
                    )));
                }
                debug!("{label}: stored, read in place ({} bytes)", entry.uncompressed_size);
                Ok(Box::new(comp))
            }
            METHOD_DEFLATE if !entry.needs_index() => {
                let bytes = inflate_all(&comp, entry.uncompressed_size, entry.crc32, &label)?;
                debug!("{label}: deflated, held in memory ({} bytes)", bytes.len());
                Ok(Box::new(MemorySource::new(bytes, label)))
            }
            METHOD_DEFLATE => {
                let key = format!(
                    "{}\u{0}{}\u{0}{}",
                    self.path.display(),
                    entry.name,
                    entry.local_header_offset
                );
                Ok(Box::new(DeflateSource::new(
                    Box::new(comp),
                    entry.uncompressed_size,
                    entry.crc32,
                    key,
                    label,
                )?))
            }
            other => Err(io::Error::other(format!(
                "{label}: compression method {other} ({}) is not supported; only \
                 stored and deflate are. Re-zip it, or unpack it.",
                method_name(other)
            ))),
        }
    }

    pub fn open_named(&self, name: &str) -> io::Result<Box<dyn ImageSource>> {
        self.open_found(name, self.find(name))
    }

    /// The same, for a name that came out of a `.gdi` -- see
    /// [`Self::find_track`].
    pub fn open_track(&self, name: &str) -> io::Result<Box<dyn ImageSource>> {
        self.open_found(name, self.find_track(name))
    }

    fn open_found(
        &self,
        name: &str,
        found: Option<&ZipEntry>,
    ) -> io::Result<Box<dyn ImageSource>> {
        let entry = found
            .ok_or_else(|| {
                io::Error::other(format!(
                    "{}: no member named '{name}'",
                    self.path.display()
                ))
            })?
            .clone();
        self.open_entry(&entry)
    }
}

fn method_name(method: u16) -> &'static str {
    match method {
        1 => "shrunk",
        6 => "imploded",
        9 => "deflate64",
        12 => "bzip2",
        14 => "LZMA",
        93 => "zstd",
        95 => "xz",
        98 => "PPMd",
        _ => "unknown",
    }
}

/// A `.gdi`'s siblings, when the `.gdi` lives inside an archive.
pub struct ZipContainer {
    archive: Rc<ZipArchive>,
    /// Directory of the chosen image inside the archive, `""` or `"dir/"`.
    prefix: String,
}

impl ZipContainer {
    pub fn new(archive: Rc<ZipArchive>, member: &str) -> Self {
        let prefix = match member.rfind('/') {
            Some(i) => member[..=i].to_string(),
            None => String::new(),
        };
        Self { archive, prefix }
    }
}

impl Container for ZipContainer {
    fn open(&self, name: &str) -> io::Result<Box<dyn ImageSource>> {
        let name = crate::disc_formats::source::plain_track_name(name)?;
        self.archive.open_track(&format!("{}{name}", self.prefix))
    }
    fn read_text(&self, name: &str) -> io::Result<String> {
        let src = self.open(name)?;
        let mut buf = vec![0u8; src.len() as usize];
        src.read_at(0, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
    fn describe(&self) -> String {
        format!("{}!{}", self.archive.path().display(), self.prefix)
    }
}

/// Build these tracks' deflate indexes on a thread, off the read path.
///
/// A deflated member is read through the checkpoint index in [`super::deflate`],
/// and building one costs ~130 ms per 17 MiB. The DATA tracks pay that before
/// the title starts, because identifying the disc and reading its boot binary go
/// through them. An AUDIO track is first touched when the title asks for music,
/// which happens inside a CD-DA sub-fetch -- the title frozen, the loader's
/// 20 ms fetch deadline running. Measured on Snow Surfers (2026-09-12): "CDDA
/// read of LBA 0x0004e352 took 140 ms, past the loader's deadline". The loader's
/// first sub-fetch of the track therefore failed, `cdda_prime()` keyed the
/// channels on with the rest of half 0 as quiet floor, and the music began with
/// 693 ms of silence -- every track, every session, and invisible to every
/// counter on the console (`g_cdda_stale` stayed 0: nothing reached a half that
/// was still being filled).
///
/// Indexing them from a syscall is not open to us either: the TOC syscall has a
/// 500 ms deadline of its own (`CDDA_TOC_DEADLINE_TICKS`) and `Gdi::num_sectors`
/// already runs inside it. So this runs on its own thread, started while the
/// title is still being uploaded, and all it does is fill the process-wide index
/// cache that the read path already consults. Nothing waits on it, and nothing
/// breaks if it loses the race: a track the title reaches first is indexed by
/// the read path exactly as before.
///
/// RAM: one checkpoint table per track, sized by the deflate index budget --
/// about an eighth of the track's size, so ~40 MiB for a 19-track disc.
/// `DCLOAD_ZIP_INDEX_BUDGET` tunes it.
pub fn warm_track_indexes(archive: &ZipArchive, prefix: &str, tracks: &[String]) {
    // Resolved with `find_track`, the same way the read path resolves them, so
    // the index lands under the cache key `open_entry` will look for.
    let names: Vec<String> = tracks
        .iter()
        .map(|t| format!("{prefix}{t}"))
        .filter(|n| {
            archive
                .find_track(n)
                .is_some_and(ZipEntry::needs_index)
        })
        .collect();
    if names.is_empty() {
        return;
    }
    let warmed = names.len();
    let path = archive.path().to_path_buf();
    let started = std::thread::Builder::new()
        .name("warm-zip-index".into())
        .spawn(move || {
            // Re-opened here rather than shared: `ZipArchive` is `Rc`-based. Its
            // central directory is a few hundred bytes to parse again.
            let Ok(archive) = ZipArchive::open(&path) else {
                return;
            };
            for name in &names {
                let Some(entry) = archive.find_track(name) else {
                    continue;
                };
                let t0 = std::time::Instant::now();
                // The source is dropped immediately: what is wanted is the index
                // it leaves behind in the cache.
                match archive.open_entry(entry) {
                    Ok(_) => debug!(
                        "warmed the index of '{name}' in {:.0} ms, off the read path",
                        t0.elapsed().as_secs_f64() * 1000.0
                    ),
                    Err(e) => debug!("could not warm the index of '{name}': {e}"),
                }
            }
        });
    match started {
        Ok(_) => debug!("warming {} deflated track(s) in the background", warmed),
        // Not a failure worth stopping for: without the thread the read path
        // indexes each track itself, as it did before.
        Err(e) => debug!("no index-warming thread ({e}); tracks index on first read"),
    }
}

#[cfg(test)]
mod tests {
    /// The condition that decides both which reader a member gets and which
    /// members the warmer warms. Were it to answer "no index" for a big
    /// deflated track, the warmer would skip it and the read path would build
    /// its index inside a CD-DA sub-fetch again (AGENTS.md 4.13).
    #[test]
    fn only_a_big_deflated_member_needs_an_index() {
        let entry = |method, uncompressed_size| ZipEntry {
            name: "track10.raw".into(),
            method,
            flags: 0,
            crc32: 0,
            compressed_size: 1,
            uncompressed_size,
            local_header_offset: 0,
        };
        assert!(entry(METHOD_DEFLATE, INLINE_MAX + 1).needs_index());
        assert!(
            !entry(METHOD_DEFLATE, INLINE_MAX).needs_index(),
            "at the threshold the member is inflated into RAM instead"
        );
        assert!(
            !entry(METHOD_STORED, INLINE_MAX * 100).needs_index(),
            "a stored member is read in place however large it is"
        );
    }

    use super::*;

    /// A minimal zip built here rather than by a tool, so the parser is tested
    /// against the FORMAT and not against whatever one zipper happens to emit.
    fn build_zip(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, deflate) in members {
            let mut crc = crate::disc_formats::deflate::Crc32::new();
            crc.update(data);
            let crc = crc.finish();
            let payload: Vec<u8> = if *deflate {
                miniz_oxide::deflate::compress_to_vec(data, 6)
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let local_off = out.len() as u32;

            out.extend_from_slice(&LFH_SIG.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // time
            out.extend_from_slice(&0u16.to_le_bytes()); // date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&payload);

            central.extend_from_slice(&CDFH_SIG.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // made by
            central.extend_from_slice(&20u16.to_le_bytes()); // needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk
            central.extend_from_slice(&0u16.to_le_bytes()); // int attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
            central.extend_from_slice(&local_off.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment
        out
    }

    fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, bytes).expect("write temp zip");
        p
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    #[test]
    fn stored_and_deflated_members_read_the_same_bytes() {
        let a = payload(70_000, 1);
        let b = payload(70_000, 2);
        let zip = build_zip(&[("stored.bin", &a, false), ("deflated.bin", &b, true)]);
        let path = write_temp("dcload-zip-test-1.zip", &zip);
        let ar = ZipArchive::open(&path).expect("open");
        assert_eq!(ar.entries().len(), 2);

        for (name, want) in [("stored.bin", &a), ("deflated.bin", &b)] {
            let src = ar.open_named(name).expect("open member");
            assert_eq!(src.len(), want.len() as u64);
            let mut got = vec![0u8; 4096];
            src.read_at(60_000, &mut got).expect("read");
            assert_eq!(&got[..], &want[60_000..64_096], "{name}");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The archive is found by its own trailer, so bytes glued in front of it
    /// (a self-extracting stub) must not shift every member into nonsense.
    #[test]
    fn a_prefixed_archive_still_resolves_its_members() {
        let a = payload(5000, 7);
        let mut zip = vec![0xAAu8; 1234];
        zip.extend_from_slice(&build_zip(&[("a.bin", &a, false)]));
        let path = write_temp("dcload-zip-test-2.zip", &zip);
        let ar = ZipArchive::open(&path).expect("open");
        let src = ar.open_named("a.bin").expect("member");
        let mut got = vec![0u8; 5000];
        src.read_at(0, &mut got).expect("read");
        assert_eq!(got, a);
        let _ = std::fs::remove_file(&path);
    }

    /// The zip64 records, spliced in where a real writer puts them: between the
    /// central directory and the EOCD.
    ///
    /// `sentinels` writes the all-ones markers into the EOCD, as a writer does
    /// when a field genuinely overflowed 32 bits. WITHOUT them is the case that
    /// used to break silently -- a >4 GiB member in an archive whose own fields
    /// still fit, where nothing says "zip64" except those 76 bytes sitting in
    /// front of the EOCD.
    fn add_zip64_records(zip: &[u8], sentinels: bool) -> Vec<u8> {
        let eocd = zip.len() - 22;
        let entries = u16at(zip, eocd + 10) as u64;
        let cd_size = u32at(zip, eocd + 12) as u64;
        let cd_off = u32at(zip, eocd + 16) as u64;

        let mut rec = Vec::new();
        rec.extend_from_slice(&EOCD64_SIG.to_le_bytes());
        rec.extend_from_slice(&44u64.to_le_bytes()); // size of the rest
        rec.extend_from_slice(&45u16.to_le_bytes()); // made by
        rec.extend_from_slice(&45u16.to_le_bytes()); // needed
        rec.extend_from_slice(&0u32.to_le_bytes()); // this disk
        rec.extend_from_slice(&0u32.to_le_bytes()); // disk with the cd
        rec.extend_from_slice(&entries.to_le_bytes());
        rec.extend_from_slice(&entries.to_le_bytes());
        rec.extend_from_slice(&cd_size.to_le_bytes());
        rec.extend_from_slice(&cd_off.to_le_bytes());
        assert_eq!(rec.len(), 56);

        let mut loc = Vec::new();
        loc.extend_from_slice(&EOCD64_LOCATOR_SIG.to_le_bytes());
        loc.extend_from_slice(&0u32.to_le_bytes());
        loc.extend_from_slice(&(eocd as u64).to_le_bytes()); // as the writer saw it
        loc.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(loc.len(), 20);

        let mut out = zip[..eocd].to_vec();
        out.extend_from_slice(&rec);
        out.extend_from_slice(&loc);
        out.extend_from_slice(&zip[eocd..]);
        if sentinels {
            let at = out.len() - 22;
            out[at + 10..at + 12].copy_from_slice(&0xffffu16.to_le_bytes());
            out[at + 12..at + 16].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
            out[at + 16..at + 20].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        out
    }

    /// The 76 bytes of zip64 records sit BETWEEN the central directory and the
    /// EOCD, so "the directory ends where the EOCD begins" is wrong by exactly
    /// that much -- and it is how the shift a prefix causes is measured.
    ///
    /// Getting this wrong is not a wrong answer, it is no answer: the first
    /// central-directory signature check fails and the archive reports holding
    /// no files. It shows up on the big dumps and nowhere else, which is
    /// precisely what this module exists for.
    #[test]
    fn zip64_records_do_not_shift_the_central_directory() {
        let a = payload(5000, 9);
        let plain = build_zip(&[("a.bin", &a, false)]);
        for (i, sentinels) in [false, true].into_iter().enumerate() {
            let zip = add_zip64_records(&plain, sentinels);
            let path = write_temp(&format!("dcload-zip-test-64-{i}.zip"), &zip);
            let ar = ZipArchive::open(&path).expect("open zip64");
            let src = ar.open_named("a.bin").expect("member");
            let mut got = vec![0u8; 5000];
            src.read_at(0, &mut got).expect("read");
            assert_eq!(got, a, "sentinels={sentinels}");
            let _ = std::fs::remove_file(&path);
        }
    }

    /// And the same with a stub in front, which is the case the locator cannot
    /// answer: the offset IT carries was written before the prefix existed, so
    /// the records have to be found by position.
    #[test]
    fn a_prefixed_zip64_archive_reads_too() {
        let a = payload(5000, 11);
        let mut zip = vec![0x5Au8; 999];
        zip.extend_from_slice(&add_zip64_records(&build_zip(&[("a.bin", &a, false)]), true));
        let path = write_temp("dcload-zip-test-64-prefixed.zip", &zip);
        let ar = ZipArchive::open(&path).expect("open");
        let src = ar.open_named("a.bin").expect("member");
        let mut got = vec![0u8; 5000];
        src.read_at(0, &mut got).expect("read");
        assert_eq!(got, a);
        let _ = std::fs::remove_file(&path);
    }

    /// `open_disc` asks this before it asks anything else, so a prefixed
    /// archive that `ZipArchive::open` reads perfectly was still handed to the
    /// ISO reader -- which never fails, and reports the image as carrying no
    /// Dreamcast header.
    #[test]
    fn a_prefixed_archive_is_recognised_as_a_zip() {
        let a = payload(64, 3);
        let mut zip = vec![b'M', b'Z'];
        zip.extend_from_slice(&[0u8; 998]);
        zip.extend_from_slice(&build_zip(&[("a.bin", &a, false)]));
        let path = write_temp("dcload-zip-test-magic.zip", &zip);
        assert!(looks_like_zip(&path));
        let _ = std::fs::remove_file(&path);

        let path = write_temp("dcload-zip-test-notazip.bin", &vec![0u8; 100_000]);
        assert!(!looks_like_zip(&path));
        let _ = std::fs::remove_file(&path);
    }

    /// THE ONE THAT MATTERS: the same disc, loose and zipped, must answer the
    /// same bytes at RANDOM LBAs.
    ///
    /// Sequential agreement proves very little here -- a cursor that never
    /// restarts would pass it. Jumping about is what exercises the checkpoint
    /// table, and a disc reader that hands a running title plausible bytes from
    /// the wrong place is the failure this whole module has to not have.
    ///
    /// Skipped unless the dumps are there. Rebuild the archive with:
    ///   zip test/sa-deflate.zip "test/Sonic Adventure*.gdi" test/track0*
    #[test]
    fn a_zipped_gdi_reads_identically_to_the_loose_one() {
        let loose = "test/Sonic Adventure v1.003 (1999)(Sega)(PAL)(M5)[!].gdi";
        let zipped = "test/sa-deflate.zip";
        if !Path::new(loose).exists() || !Path::new(zipped).exists() {
            return;
        }
        let a = crate::dispatch::open_disc(loose).expect("loose gdi");
        let b = crate::dispatch::open_disc(zipped).expect("zipped gdi");
        assert_eq!(a.boot_sector(), b.boot_sector());

        // Deliberately not in order, and spread over the whole high-density
        // area, so most reads land far from where the last one left off.
        let base = a.boot_sector();
        let span = 500_000u32;
        // Warm-up, OUTSIDE the timing: the first read builds the checkpoint
        // index for the whole member, and folding a one-off 13-second pass into
        // a per-read average would say nothing about what a running title
        // actually waits for.
        b.read_sector(base, 1).expect("warm-up read");
        let mut seed: u32 = 0x5eed_1234;
        let mut worst = std::time::Duration::ZERO;
        let mut total = std::time::Duration::ZERO;
        const N: u32 = 64;
        for _ in 0..N {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let lba = base + (seed >> 8) % span;
            let want = a.read_sector(lba, 8).expect("loose read");
            let t = std::time::Instant::now();
            let got = b.read_sector(lba, 8).expect("zipped read");
            let dt = t.elapsed();
            total += dt;
            worst = worst.max(dt);
            assert_eq!(want, got, "16 KiB at LBA {lba}");
        }
        eprintln!(
            "zipped random 16 KiB read: mean {:?}, worst {:?} over {N} reads",
            total / N,
            worst
        );

        // And the case a running title is actually in most of the time: a file
        // being streamed. The cursor is already there, so this should cost
        // little more than the inflate of the bytes themselves.
        let start = base + 200_000;
        let mut seq = std::time::Duration::ZERO;
        for i in 0..N {
            let lba = start + i * 8;
            let want = a.read_sector(lba, 8).expect("loose read");
            let t = std::time::Instant::now();
            let got = b.read_sector(lba, 8).expect("zipped read");
            seq += t.elapsed();
            assert_eq!(want, got, "sequential 16 KiB at LBA {lba}");
        }
        eprintln!("zipped sequential 16 KiB read: mean {:?}", seq / N);
    }

    /// THE PATTERN A REAL TITLE HAS: several files being read at once.
    ///
    /// A cursor into a deflate stream cannot go backwards, so with a single one
    /// every switch between streams is a restart from a checkpoint -- and a
    /// title loading a level while music streams switches on every read. This
    /// is the case the cursor pool exists for, and a purely random benchmark
    /// cannot show it: random offsets never revisit anything.
    #[test]
    fn three_interleaved_streams_do_not_thrash() {
        let loose = "test/Sonic Adventure v1.003 (1999)(Sega)(PAL)(M5)[!].gdi";
        let zipped = "test/sa-deflate.zip";
        if !Path::new(loose).exists() || !Path::new(zipped).exists() {
            return;
        }
        let a = crate::dispatch::open_disc(loose).expect("loose gdi");
        let b = crate::dispatch::open_disc(zipped).expect("zipped gdi");
        let base = b.boot_sector();

        // Far enough apart that no cursor could serve two of them, and none is
        // within a checkpoint spacing of another.
        let heads = [base + 20_000, base + 200_000, base + 400_000];
        b.read_sector(base, 1).expect("warm-up");

        let mut total = std::time::Duration::ZERO;
        let mut n = 0u32;
        for round in 0..24u32 {
            for head in heads {
                let lba = head + round * 8;
                let want = a.read_sector(lba, 8).expect("loose read");
                let t = std::time::Instant::now();
                let got = b.read_sector(lba, 8).expect("zipped read");
                total += t.elapsed();
                n += 1;
                assert_eq!(want, got, "16 KiB at LBA {lba}");
            }
        }
        eprintln!("zipped interleaved 16 KiB read: mean {:?} over {n} reads", total / n);
    }

    #[test]
    fn a_gdi_inside_an_archive_resolves_its_tracks() {
        use crate::disc_formats::types::DiscFormat;

        let gdi = "2\n1 0 4 2048 track01.bin 0\n2 100 4 2048 track03.bin 0\n";
        let t1: Vec<u8> = (0..32 * 2048).map(|i| (i / 2048) as u8).collect();
        let t3: Vec<u8> = (0..64 * 2048).map(|i| (128 + i / 2048) as u8).collect();
        let zip = build_zip(&[
            ("Game/disc.gdi", gdi.as_bytes(), true),
            ("Game/track01.bin", &t1, true),
            ("Game/track03.bin", &t3, false),
        ]);
        let path = write_temp("dcload-zip-test-gdi.zip", &zip);

        let archive = std::rc::Rc::new(ZipArchive::open(&path).expect("open"));
        let container: Box<dyn Container> =
            Box::new(ZipContainer::new(archive, "Game/disc.gdi"));
        let disc = crate::disc_formats::gdi::Gdi::new(container, "disc.gdi").expect("gdi");

        // Track starts are recorded without the 150-sector lead-in.
        assert_eq!(disc.start_sector(), 150);
        assert_eq!(disc.boot_sector(), 250);
        assert_eq!(disc.read_sector(150, 1).expect("t1 s0")[0], 0);
        assert_eq!(disc.read_sector(181, 1).expect("t1 s31")[0], 31);
        assert_eq!(disc.read_sector(250, 1).expect("t3 s0")[0], 128);
        assert_eq!(disc.read_sector(313, 1).expect("t3 s63")[0], 191);
        // Across a track boundary in one request, which is where an off-by-one
        // in the track lookup shows up.
        let two = disc.read_sector(180, 2).expect("spanning read");
        assert_eq!(two[0], 30);
        assert_eq!(two[2048], 31);

        let _ = std::fs::remove_file(&path);
    }

    /// A `.gdi` names its tracks without a directory, so a track lookup has to
    /// tolerate one. A member the USER named must not: `find` is what resolves
    /// `archive.zip#member`, and quietly answering with a same-named file from
    /// another directory is worse than saying the member is not there.
    #[test]
    fn a_track_is_found_by_basename_but_a_named_member_is_not() {
        let a = payload(64, 3);
        let zip = build_zip(&[("Some Game/track01.bin", &a, false)]);
        let path = write_temp("dcload-zip-test-3.zip", &zip);
        let ar = ZipArchive::open(&path).expect("open");
        assert!(ar.find_track("track01.bin").is_some());
        assert!(ar.find_track("TRACK01.BIN").is_some());
        assert!(ar.find_track("track02.bin").is_none());
        assert!(ar.find("track01.bin").is_none(), "exact lookup, no basename");
        assert!(ar.find("Some Game/track01.bin").is_some());
        let _ = std::fs::remove_file(&path);
    }
}
