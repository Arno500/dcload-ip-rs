//! `.dcp` disc patches: a title's FILES replaced, the image served as it lies.
//!
//! WHY (Skies of Arcadia, 2026-10-11). Some fixes are not a few bytes of the
//! boot binary, which is all a PPF row of the patch library touches
//! (`patchdb`), but hundreds of the disc's files: Riggles' "Perfect 60Hz
//! RGB+VGA (Desync Fix)" puts the US release's cutscene timings and sound
//! effects back into the PAL release, file by file. It ships as a `.dcp`, the
//! Universal Dreamcast Patcher's format: a zip whose members are named by their
//! path in the disc's filesystem -- `<path>.xdelta` for a difference against
//! the file on the disc (`crate::xdelta`), anything else for a file to put
//! there whole.
//!
//! The patcher rebuilds the image. This host serves the image as it lies and
//! lays the patched files over it (`PatchedDisc`), worked out once when the
//! image is opened:
//!
//! - a file whose new content fits the sectors it had stays there, and its
//!   directory record gets the new size;
//! - one that grows, and a new one, goes into a hole of the data track: sectors
//!   that no volume descriptor, path table, directory or file uses, below the
//!   highest one used -- never past the end of the track;
//! - a new file's record is inserted into its directory in ISO 9660 order. The
//!   directory keeps its extent: a patch that would need one moved is refused.
//!
//! **All or nothing.** A member that does not apply -- a file this disc does
//! not have, a delta whose Adler-32 says it was made against another dump --
//! refuses the whole patch, and the image is served unpatched. A half-patched
//! game is worse than either.
//!
//! The boot binary is read through the overlay like everything else, so a
//! `.dcp` that patches `1ST_READ.BIN` changes what is uploaded too. The
//! RetroAchievements hash is taken from the image as it lies
//! (`ra::session` opens it itself): a patched disc is still the game the set
//! was made for.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

use log::{debug, error, info};

use crate::disc_formats::types::{DiscFormat, TocTrack};
use crate::disc_formats::zip::ZipArchive;
use crate::patchdb::{PatchDb, When};

const SECTOR: usize = 2048;
/// The extension a disc patch has in the patch library and on `--ppf`.
pub const EXTENSION: &str = "dcp";
/// Where the Universal Dreamcast Patcher keeps an IP.BIN to replace: not a
/// file of the filesystem, and not served here.
const BOOTSECTOR_DIR: &str = "bootsector/";

/// One member of a `.dcp`.
pub enum Change {
    /// An xdelta3 patch of the file at that path.
    Delta(Vec<u8>),
    /// The file itself, replacing the one at that path or added there.
    Whole(Vec<u8>),
}

pub struct Dcp {
    /// `(path in the disc's filesystem, change)`.
    pub changes: Vec<(String, Change)>,
}

pub fn is_dcp(path: &str) -> bool {
    Path::new(path).extension().is_some_and(|e| e.eq_ignore_ascii_case(EXTENSION))
}

pub fn read_dcp(path: &Path) -> Result<Dcp, String> {
    let name = path.display().to_string();
    let zip = ZipArchive::open(path).map_err(|e| format!("{name}: {e}"))?;
    let mut changes = vec![];
    for e in zip.entries().iter().filter(|e| !e.is_dir()) {
        let member = e.name.replace('\\', "/");
        if member.to_ascii_lowercase().starts_with(BOOTSECTOR_DIR) {
            return Err(format!("{name}: replaces the boot sector ({member}), which is not supported"));
        }
        let bytes = zip.read_whole(e).map_err(|err| err.to_string())?;
        changes.push(match member.strip_suffix(".xdelta") {
            Some(p) => (p.to_string(), Change::Delta(bytes)),
            None => (member, Change::Whole(bytes)),
        });
    }
    if changes.is_empty() {
        return Err(format!("{name}: an empty patch"));
    }
    Ok(Dcp { changes })
}

// ---------------------------------------------------------------------------
// The filesystem, as far as patching it goes.
// ---------------------------------------------------------------------------

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// A both-endian 32-bit field of a directory record.
fn set_both32(rec: &mut [u8], o: usize, v: u32) {
    rec[o..o + 4].copy_from_slice(&v.to_le_bytes());
    rec[o + 4..o + 8].copy_from_slice(&v.to_be_bytes());
}

const REC_EXTENT: usize = 2;
const REC_SIZE: usize = 10;
const REC_FLAGS: usize = 25;
const FLAG_DIR: u8 = 0x02;

fn rec_name(rec: &[u8]) -> &[u8] {
    let n = rec[32] as usize;
    let raw = &rec[33..33 + n];
    raw.split(|c| *c == b';').next().unwrap_or(raw)
}

fn rec_is_dot(rec: &[u8]) -> bool {
    rec[32] == 1 && rec[33] <= 1
}

/// ISO 9660 (9.3) order: the name, then the extension, each as if padded with
/// spaces.
fn iso_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    fn split(n: &[u8]) -> (&[u8], &[u8]) {
        match n.iter().position(|c| *c == b'.') {
            Some(i) => (&n[..i], &n[i + 1..]),
            None => (n, &[][..]),
        }
    }
    fn padded(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        let len = a.len().max(b.len());
        let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(b' ');
        (0..len).map(|i| at(a, i).cmp(&at(b, i))).find(|o| o.is_ne()).unwrap_or(std::cmp::Ordering::Equal)
    }
    let (an, ae) = split(a);
    let (bn, be) = split(b);
    padded(an, bn).then_with(|| padded(ae, be))
}

struct Dir {
    path: String,
    /// ISO LBA and recorded size (whole sectors).
    lba: u32,
    size: u32,
    records: Vec<Vec<u8>>,
    dirty: bool,
}

/// Records of one directory extent, in order. A record never crosses a
/// sector; a zero length ends the records of that sector.
fn parse_records(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![];
    let mut o = 0;
    while o < data.len() {
        let n = data[o] as usize;
        if n == 0 {
            o = (o / SECTOR + 1) * SECTOR;
            continue;
        }
        if n < 34 || o + n > data.len() || (o % SECTOR) + n > SECTOR {
            break;
        }
        out.push(data[o..o + n].to_vec());
        o += n;
    }
    out
}

/// The records laid back into `sectors` sectors, or `None` if they no longer fit.
fn lay_records(records: &[Vec<u8>], sectors: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; sectors * SECTOR];
    let mut o = 0;
    for r in records {
        if (o % SECTOR) + r.len() > SECTOR {
            o = (o / SECTOR + 1) * SECTOR;
        }
        out.get_mut(o..o + r.len())?.copy_from_slice(r);
        o += r.len();
    }
    Some(out)
}

struct Fs {
    /// `read_sector` LBA minus ISO LBA (150 on a GDI).
    shift: u32,
    dirs: Vec<Dir>,
    /// ISO sectors in use, `[start, end)`.
    used: Vec<(u32, u32)>,
}

impl Fs {
    fn read(disc: &dyn DiscFormat) -> Result<Fs, String> {
        let shift = disc.fs_lba(0);
        let base = disc.boot_sector();
        let read = |iso: u32, n: u32| {
            disc.read_sector(iso.wrapping_add(shift), n)
                .map_err(|e| format!("reading LBA {}: {e}", iso.wrapping_add(shift)))
        };
        let base_iso = base.wrapping_sub(shift);
        let pvd = read(base_iso + 16, 1)?;
        if !crate::disc_formats::iso9660::is_pvd(&pvd) {
            return Err("no ISO 9660 volume where the disc boots from".into());
        }
        let mut used = vec![(base_iso, base_iso + 16)];
        // Volume descriptors up to and including the terminator.
        for k in 16..64 {
            used.push((base_iso + k, base_iso + k + 1));
            if read(base_iso + k, 1)?.first() == Some(&255) {
                break;
            }
        }
        let pt_sectors = le32(&pvd, 132).div_ceil(SECTOR as u32);
        for at in [le32(&pvd, 140), le32(&pvd, 144), u32::from_be_bytes(pvd[148..152].try_into().unwrap()),
            u32::from_be_bytes(pvd[152..156].try_into().unwrap())]
        {
            if at != 0 {
                used.push((at, at + pt_sectors));
            }
        }
        let mut fs = Fs { shift, dirs: vec![], used };
        let mut todo = vec![(String::new(), le32(&pvd, 158), le32(&pvd, 166))];
        while let Some((path, lba, size)) = todo.pop() {
            if size == 0 || size > 1 << 20 || fs.dirs.len() > 4096 {
                return Err(format!("directory '{path}' is not what a directory should be"));
            }
            let sectors = size.div_ceil(SECTOR as u32);
            let records = parse_records(&read(lba, sectors)?);
            fs.used.push((lba, lba + sectors));
            for r in records.iter().filter(|r| !rec_is_dot(r)) {
                let (at, len) = (le32(r, REC_EXTENT), le32(r, REC_SIZE));
                let name = String::from_utf8_lossy(rec_name(r)).to_ascii_uppercase();
                let child = if path.is_empty() { name } else { format!("{path}/{name}") };
                if r[REC_FLAGS] & FLAG_DIR != 0 {
                    todo.push((child, at, len));
                } else if len > 0 {
                    fs.used.push((at, at + len.div_ceil(SECTOR as u32)));
                }
            }
            fs.dirs.push(Dir { path, lba, size: sectors * SECTOR as u32, records, dirty: false });
        }
        Ok(fs)
    }

    fn dir(&self, path: &str) -> Option<usize> {
        self.dirs.iter().position(|d| d.path.eq_ignore_ascii_case(path))
    }

    /// `(directory, record)` of a file.
    fn file(&self, path: &str) -> Option<(usize, usize)> {
        let (dir, name) = split_path(path);
        let d = self.dir(dir)?;
        let r = self.dirs[d].records.iter().position(|r| {
            !rec_is_dot(r) && r[REC_FLAGS] & FLAG_DIR == 0 && rec_name(r).eq_ignore_ascii_case(name.as_bytes())
        })?;
        Some((d, r))
    }

    /// `n` free sectors, in the lowest hole that holds them.
    fn allocate(&mut self, n: u32) -> Option<u32> {
        self.used.sort_unstable();
        let mut at = self.used.first()?.0;
        for &(s, e) in &self.used {
            if s >= at + n {
                self.used.push((at, at + n));
                return Some(at);
            }
            at = at.max(e);
        }
        None
    }
}

/// `("SOUND", "M02S.P16")` out of `"SOUND/M02S.P16"`; the root is `""`.
fn split_path(path: &str) -> (&str, &str) {
    let path = path.trim_start_matches('/');
    match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

// ---------------------------------------------------------------------------
// Applying a patch.
// ---------------------------------------------------------------------------

/// What a patch did, for the log.
#[derive(Debug, Default)]
pub struct Summary {
    pub patched: usize,
    pub replaced: usize,
    pub added: Vec<(String, u32)>,
    pub moved: Vec<(String, u32)>,
    pub bytes: usize,
}

/// The sectors to serve instead of the image's: `read_sector` LBA -> whole
/// sectors. Extents never overlap.
type Overlay = BTreeMap<u32, Vec<u8>>;

/// Work out the overlay a patch makes of this disc.
pub fn build(disc: &dyn DiscFormat, dcp: &Dcp) -> Result<(Overlay, Summary), String> {
    let mut fs = Fs::read(disc)?;
    let mut sum = Summary::default();
    // ISO LBA -> content (whole sectors); the records are edited as we go.
    let mut files: Vec<(u32, Vec<u8>)> = vec![];
    for (path, change) in &dcp.changes {
        let found = fs.file(path);
        let content = match (change, found) {
            (Change::Delta(patch), Some((d, r))) => {
                let rec = &fs.dirs[d].records[r];
                let (lba, size) = (le32(rec, REC_EXTENT), le32(rec, REC_SIZE));
                let mut src = disc
                    .read_sector(lba.wrapping_add(fs.shift), size.div_ceil(SECTOR as u32))
                    .map_err(|e| format!("{path}: {e}"))?;
                src.truncate(size as usize);
                sum.patched += 1;
                crate::xdelta::apply(&src, patch).map_err(|e| format!("{path}: {e}"))?
            }
            (Change::Delta(_), None) => return Err(format!("{path}: this disc has no such file")),
            (Change::Whole(bytes), found) => {
                if found.is_some() {
                    sum.replaced += 1;
                }
                bytes.clone()
            }
        };
        let sectors = (content.len() as u32).div_ceil(SECTOR as u32);
        sum.bytes += content.len();
        let lba = match found {
            Some((d, r)) => {
                let rec = &fs.dirs[d].records[r];
                let old = le32(rec, REC_SIZE).div_ceil(SECTOR as u32);
                let lba = if sectors <= old {
                    le32(rec, REC_EXTENT)
                } else {
                    let at = fs.allocate(sectors).ok_or_else(|| no_room(path, sectors))?;
                    sum.moved.push((path.clone(), at.wrapping_add(fs.shift)));
                    at
                };
                let rec = &mut fs.dirs[d].records[r];
                set_both32(rec, REC_EXTENT, lba);
                set_both32(rec, REC_SIZE, content.len() as u32);
                fs.dirs[d].dirty = true;
                lba
            }
            None => {
                let (dir, name) = split_path(path);
                let d = fs.dir(dir).ok_or_else(|| format!("{path}: this disc has no directory '{dir}'"))?;
                let at = if sectors == 0 { 0 } else { fs.allocate(sectors).ok_or_else(|| no_room(path, sectors))? };
                insert_record(&mut fs.dirs[d], name, at, content.len() as u32).map_err(|e| format!("{path}: {e}"))?;
                sum.added.push((path.clone(), at.wrapping_add(fs.shift)));
                at
            }
        };
        if sectors > 0 {
            let mut padded = content;
            padded.resize(sectors as usize * SECTOR, 0);
            files.push((lba, padded));
        }
    }

    let mut overlay = Overlay::new();
    for (lba, data) in files {
        overlay.insert(lba.wrapping_add(fs.shift), data);
    }
    for d in fs.dirs.iter().filter(|d| d.dirty) {
        let laid = lay_records(&d.records, d.size as usize / SECTOR).ok_or_else(|| {
            format!(
                "directory '{}' no longer fits its {} sector(s); moving a directory is not supported",
                d.path,
                d.size as usize / SECTOR
            )
        })?;
        overlay.insert(d.lba.wrapping_add(fs.shift), laid);
    }
    let mut end = 0;
    for (&at, data) in &overlay {
        if at < end {
            return Err(format!("two patched extents overlap at LBA {at}"));
        }
        end = at + (data.len() / SECTOR) as u32;
    }
    Ok((overlay, sum))
}

fn no_room(path: &str, sectors: u32) -> String {
    format!("{path}: no hole of {sectors} sector(s) in the data track to put it in")
}

/// A record for a new file, after the template of a file already in `dir`.
fn insert_record(dir: &mut Dir, name: &str, lba: u32, size: u32) -> Result<(), String> {
    let upper = name.to_ascii_uppercase();
    let template = dir
        .records
        .iter()
        .find(|r| !rec_is_dot(r) && r[REC_FLAGS] & FLAG_DIR == 0)
        .ok_or("its directory has no file to model a record on")?;
    let id = format!("{upper};1");
    let len = (33 + id.len()).next_multiple_of(2);
    let mut rec = vec![0u8; len];
    rec[0] = len as u8;
    set_both32(&mut rec, REC_EXTENT, lba);
    set_both32(&mut rec, REC_SIZE, size);
    rec[18..25].copy_from_slice(&template[18..25]);
    rec[28..32].copy_from_slice(&template[28..32]);
    rec[32] = id.len() as u8;
    rec[33..33 + id.len()].copy_from_slice(id.as_bytes());
    let at = dir
        .records
        .iter()
        .position(|r| !rec_is_dot(r) && iso_cmp(rec_name(r), upper.as_bytes()).is_gt())
        .unwrap_or(dir.records.len());
    if dir.records.iter().any(|r| !rec_is_dot(r) && rec_name(r).eq_ignore_ascii_case(upper.as_bytes())) {
        return Err("already there".into());
    }
    dir.records.insert(at, rec);
    dir.dirty = true;
    Ok(())
}

/// An image with a patch laid over it.
pub struct PatchedDisc {
    inner: Box<dyn DiscFormat>,
    overlay: Overlay,
}

impl DiscFormat for PatchedDisc {
    fn read_sector(&self, lba: u32, num_sectors: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buf = self.inner.read_sector(lba, num_sectors)?;
        let end = lba.saturating_add(num_sectors);
        for (&at, data) in self.overlay.range(..end).rev() {
            let ext_end = at + (data.len() / SECTOR) as u32;
            if ext_end <= lba {
                break;
            }
            let (from, to) = (at.max(lba), ext_end.min(end));
            let dst = (from - lba) as usize * SECTOR..(to - lba) as usize * SECTOR;
            let src = (from - at) as usize * SECTOR..(to - at) as usize * SECTOR;
            if let Some(d) = buf.get_mut(dst) {
                d.copy_from_slice(&data[src]);
            }
        }
        Ok(buf)
    }
    fn start_sector(&self) -> u32 {
        self.inner.start_sector()
    }
    fn boot_sector(&self) -> u32 {
        self.inner.boot_sector()
    }
    fn num_sectors(&self) -> u32 {
        self.inner.num_sectors()
    }
    fn toc_tracks(&self) -> Vec<TocTrack> {
        self.inner.toc_tracks()
    }
    fn read_audio(&self, lba: u32, num_sectors: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.inner.read_audio(lba, num_sectors)
    }
    fn fs_lba(&self, iso_lba: u32) -> u32 {
        self.inner.fs_lba(iso_lba)
    }
}

/// The image back with the reason, when a patch does not apply.
type Refused = (Box<dyn DiscFormat>, String);

/// `disc` with `dcp` laid over it, or the reason it was not.
pub fn patch(disc: Box<dyn DiscFormat>, dcp: &Dcp) -> Result<(Box<dyn DiscFormat>, Summary), Refused> {
    match build(disc.as_ref(), dcp) {
        Ok((overlay, sum)) => Ok((Box::new(PatchedDisc { inner: disc, overlay }), sum)),
        Err(e) => Err((disc, e)),
    }
}

// ---------------------------------------------------------------------------
// The patch library's disc patches (`patches.tsv` rows naming a `.dcp`).
// ---------------------------------------------------------------------------

struct Library {
    db: PatchDb,
    /// `--no-ppf` inverted.
    enabled: bool,
    /// `.dcp` files named with `--ppf`.
    explicit: Vec<String>,
}

static LIBRARY: OnceLock<Library> = OnceLock::new();

/// Set once, before the first image is opened for serving.
pub fn configure(db: PatchDb, enabled: bool, explicit: &[String]) {
    let explicit = explicit.iter().filter(|p| is_dcp(p)).cloned().collect();
    let _ = LIBRARY.set(Library { db, enabled, explicit });
}

/// The image to SERVE: `dispatch::open_disc`, then the disc patches the
/// library has for this dump. A patch that does not apply is reported and the
/// image is served as it lies.
pub fn open_served(spec: &str) -> Result<Box<dyn DiscFormat>, String> {
    Ok(with_library(crate::dispatch::open_disc(spec)?, spec))
}

pub fn with_library(mut disc: Box<dyn DiscFormat>, spec: &str) -> Box<dyn DiscFormat> {
    let Some(lib) = LIBRARY.get() else {
        return disc;
    };
    let md5 = crate::dispatch::identify(disc.as_ref(), spec).ok().map(|i| i.md5);
    let mut chosen: Vec<(String, String)> = lib.explicit.iter().map(|p| (p.clone(), String::new())).collect();
    if let Some(md5) = md5.as_deref() {
        for e in lib.db.disc_rows(md5) {
            let Some(path) = lib.db.path_of(&e.file) else { continue };
            let path = path.display().to_string();
            match (lib.enabled, e.when) {
                (true, When::Auto) => chosen.push((path, e.note.clone())),
                (false, _) => info!("disc patch {path} is listed for this dump; held back by --no-ppf"),
                (true, When::Manual) => {
                    info!("disc patch {path} is AVAILABLE and was not applied -- pass --ppf {path} to use it")
                }
            }
        }
    }
    for (path, note) in chosen {
        let started = Instant::now();
        let dcp = match read_dcp(Path::new(&path)) {
            Ok(d) => d,
            Err(e) => {
                error!("disc patch NOT applied: {e}");
                continue;
            }
        };
        disc = match patch(disc, &dcp) {
            Ok((patched, sum)) => {
                info!(
                    "disc patch {path}: {} file(s) patched, {} replaced, {} added, {} moved \
                     ({:.1} MiB, {:.1} s); served over the image as it lies",
                    sum.patched,
                    sum.replaced,
                    sum.added.len(),
                    sum.moved.len(),
                    sum.bytes as f64 / (1 << 20) as f64,
                    started.elapsed().as_secs_f64()
                );
                if !note.is_empty() {
                    info!("    {note}");
                }
                for (p, lba) in sum.added.iter().map(|a| (a, "added")).chain(sum.moved.iter().map(|m| (m, "moved"))) {
                    debug!("disc patch: {} {lba} to LBA {}", p.0, p.1);
                }
                patched
            }
            Err((unpatched, why)) => {
                error!("disc patch {path} NOT applied: {why}. The image is served as it lies.");
                unpatched
            }
        };
    }
    disc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-track image in memory: ISO LBA = read LBA.
    struct Mem(Vec<u8>);
    impl DiscFormat for Mem {
        fn read_sector(&self, lba: u32, n: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let (a, b) = (lba as usize * SECTOR, (lba + n) as usize * SECTOR);
            Ok(self.0.get(a..b).ok_or("past the end")?.to_vec())
        }
        fn start_sector(&self) -> u32 {
            0
        }
    }

    fn record(name: &str, lba: u32, size: u32, dir: bool) -> Vec<u8> {
        let id = name.as_bytes();
        let len = (33 + id.len()).next_multiple_of(2);
        let mut r = vec![0u8; len];
        r[0] = len as u8;
        set_both32(&mut r, REC_EXTENT, lba);
        set_both32(&mut r, REC_SIZE, size);
        r[18] = 99;
        r[REC_FLAGS] = if dir { FLAG_DIR } else { 0 };
        r[28] = 1;
        r[32] = id.len() as u8;
        r[33..].copy_from_slice(&{
            let mut v = id.to_vec();
            v.resize(len - 33, 0);
            v
        });
        r
    }

    /// PVD at 16, path tables at 18-19, root at 20 ("A.BIN" at 30, 1 sector; dir "SND" at 21),
    /// SND holds "B.P04" (31..33) and "D.P04" (33); a hole at 22..30; data ends at 34.
    fn image() -> Mem {
        let mut img = vec![0u8; 40 * SECTOR];
        let pvd = &mut img[16 * SECTOR..17 * SECTOR];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        // Path tables at 18 (L) and 19 (M), as a real disc has them.
        pvd[132] = 10;
        pvd[140] = 18;
        pvd[151] = 19;
        let root = record("\0", 20, 2048, true);
        pvd[156..156 + root.len()].copy_from_slice(&root);
        img[17 * SECTOR] = 255;
        let put = |img: &mut Vec<u8>, lba: usize, recs: Vec<Vec<u8>>| {
            let laid = lay_records(&recs, 1).unwrap();
            img[lba * SECTOR..(lba + 1) * SECTOR].copy_from_slice(&laid);
        };
        put(&mut img, 20, vec![record("\0", 20, 2048, true), record("\u{1}", 20, 2048, true),
            record("A.BIN;1", 30, 100, false), record("SND", 21, 2048, true)]);
        put(&mut img, 21, vec![record("\0", 21, 2048, true), record("\u{1}", 20, 2048, true),
            record("B.P04;1", 31, 4000, false), record("D.P04;1", 33, 10, false)]);
        img[30 * SECTOR..30 * SECTOR + 100].fill(0xaa);
        img[31 * SECTOR..31 * SECTOR + 4000].fill(0xbb);
        img[33 * SECTOR..33 * SECTOR + 10].fill(0xdd);
        Mem(img)
    }

    fn list(disc: &dyn DiscFormat, lba: u32) -> Vec<(String, u32, u32)> {
        crate::disc_formats::iso9660::list_directory(disc, lba, 2048)
            .into_iter()
            .map(|e| (e.name, e.lba, e.size))
            .collect()
    }

    #[test]
    fn a_shrunk_file_stays_a_grown_one_moves_and_a_new_one_lands_in_order_in_a_hole() {
        let dcp = Dcp {
            changes: vec![
                ("A.BIN".into(), Change::Whole(vec![1; 50])),
                ("SND/D.P04".into(), Change::Whole(vec![2; 5000])),
                ("snd/C.P16".into(), Change::Whole(vec![3; 3000])),
            ],
        };
        let (disc, sum) = patch(Box::new(image()), &dcp).map_err(|e| e.1).unwrap();
        assert_eq!((sum.replaced, sum.added.len(), sum.moved.len()), (2, 1, 1));
        assert_eq!(list(disc.as_ref(), 20)[0], ("A.BIN".into(), 30, 50));
        assert_eq!(
            list(disc.as_ref(), 21),
            vec![("B.P04".into(), 31, 4000), ("C.P16".into(), 25, 3000), ("D.P04".into(), 22, 5000)]
        );
        // In the order the patch lists them: D.P04 first, then C.P16 after it.
        let s = disc.read_sector(22, 5).unwrap();
        assert!(s[..5000].iter().all(|b| *b == 2) && s[5000..3 * SECTOR].iter().all(|b| *b == 0));
        assert!(s[3 * SECTOR..3 * SECTOR + 3000].iter().all(|b| *b == 3));
        assert!(s[3 * SECTOR + 3000..].iter().all(|b| *b == 0));
        // The original beside the overlay is untouched.
        assert!(disc.read_sector(31, 1).unwrap().iter().all(|b| *b == 0xbb));
        assert!(disc.read_sector(30, 1).unwrap()[..50].iter().all(|b| *b == 1));
    }

    #[test]
    fn a_delta_for_a_file_the_disc_lacks_refuses_the_whole_patch() {
        let dcp = Dcp {
            changes: vec![
                ("A.BIN".into(), Change::Whole(vec![1; 50])),
                ("SND/Z.P04".into(), Change::Delta(vec![])),
            ],
        };
        let (disc, why) = patch(Box::new(image()), &dcp).err().unwrap();
        assert!(why.contains("no such file"), "{why}");
        assert!(disc.read_sector(30, 1).unwrap()[..100].iter().all(|b| *b == 0xaa));
    }

    #[test]
    fn no_hole_big_enough_is_a_refusal() {
        let dcp = Dcp { changes: vec![("SND/E.P04".into(), Change::Whole(vec![0; 9 * SECTOR]))] };
        assert!(patch(Box::new(image()), &dcp).err().unwrap().1.contains("no hole"));
    }

    #[test]
    fn iso_order_pads_name_and_extension() {
        use std::cmp::Ordering::*;
        assert_eq!(iso_cmp(b"M02S.P04", b"M02S.P16"), Less);
        assert_eq!(iso_cmp(b"AB.X", b"A.Y"), Greater);
        assert_eq!(iso_cmp(b"A.B", b"A.B"), Equal);
    }
}
