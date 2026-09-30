//! Where a disc image's BYTES come from, kept separate from what they mean.
//!
//! `Iso`, `Gdi` and `Cdi` used to hold a `std::fs::File` each and seek in it.
//! That is the only reason they could not read an image out of a `.zip`: the
//! formats themselves never cared about files, only about "give me these bytes
//! at this offset". `ImageSource` is that operation and nothing else, so a
//! reader written against it works the same on a plain file, on a member of an
//! archive, and on a blob already in memory.
//!
//! `Container` is the second half of the same separation and exists for exactly
//! one format: a `.gdi` is a TEXT FILE that names its track files, so opening
//! one means opening its siblings, and "sibling" means something different in a
//! directory and in an archive. Everything else opens one file and is done.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

/// Random access to the bytes of an image, wherever they physically live.
///
/// `read_at` is all-or-nothing on purpose. A short read on a disc image is
/// never something a caller can do anything sensible with -- the sector it
/// asked for is either there or the image is truncated -- and a `Read`-shaped
/// API would make every reader in this module carry its own retry loop.
pub trait ImageSource: Send {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    fn len(&self) -> u64;
    /// Something a human can put in a log line. Not a path: a zip member has
    /// no path, and the archive it came from is the interesting half.
    fn describe(&self) -> String;

    /// A second, INDEPENDENT handle on the same bytes, for another thread.
    ///
    /// Only the deflate index pass asks for these, and only to stop reading and
    /// inflating from taking turns. Measured on a 1.0 GiB member sitting on a
    /// WSL DrvFs mount: one reader gets 211 MB/s and four get 467 MB/s, so the
    /// read went from being 58 % of the pass to being hidden behind it
    /// entirely.
    ///
    /// `None` -- the default -- means "there is nothing to gain here", which is
    /// the right answer for bytes that are already in memory, and the caller
    /// falls back to reading them itself.
    fn thread_handle(&self) -> Option<Box<dyn ImageSource>> {
        None
    }
}

/// So a `Box<dyn ImageSource>` can be used wherever an `impl ImageSource` is
/// wanted.
///
/// EVERY method has to be forwarded, including the ones with a default body.
/// A default is not deref -- it is a real implementation on this type, and it
/// wins over the boxed value's. Leaving `thread_handle` out of this list made
/// `SubSource`, whose inner source IS a box, report that it could not hand out
/// a thread handle, and the index pass silently fell back to reading on one
/// thread. Nothing failed; it was just half the speed, and the only sign was a
/// "0 reader thread(s)" in a debug line.
impl ImageSource for Box<dyn ImageSource> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(offset, buf)
    }
    fn len(&self) -> u64 {
        (**self).len()
    }
    fn describe(&self) -> String {
        (**self).describe()
    }
    fn thread_handle(&self) -> Option<Box<dyn ImageSource>> {
        (**self).thread_handle()
    }
}

/// A file on disk, read by POSITION rather than by seeking.
///
/// There is no cursor to fight over and no seek syscall in front of each read:
/// `pread`/`ReadFile`-with-offset take the offset themselves. That matters
/// here because a disc read is a burst of small positioned reads -- one per
/// 2048-byte sector in the worst case -- with a Dreamcast frozen at the other
/// end of it.
pub struct FileSource {
    file: File,
    len: u64,
    path: PathBuf,
    name: String,
}

impl FileSource {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            len,
            path: path.to_path_buf(),
            name: path.display().to_string(),
        })
    }

    /// One positioned read. Both platform calls are allowed to come up short,
    /// so the loop in `read_at` is what makes it the all-or-nothing operation
    /// the trait promises.
    fn read_some(&self, buf: &mut [u8], at: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.file.read_at(buf, at)
        }
        #[cfg(windows)]
        {
            self.file.seek_read(buf, at)
        }
    }
}

impl ImageSource for FileSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            match self.read_some(&mut buf[done..], offset + done as u64)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "{}: read of {} bytes at {offset} ran off the end",
                            self.name,
                            buf.len()
                        ),
                    ));
                }
                n => done += n,
            }
        }
        Ok(())
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn describe(&self) -> String {
        self.name.clone()
    }
    /// Another open handle on the same file, with its own cursor.
    fn thread_handle(&self) -> Option<Box<dyn ImageSource>> {
        Self::open(&self.path)
            .map(|f| Box::new(f) as Box<dyn ImageSource>)
            .ok()
    }
}

/// A byte range of another source, addressed from zero.
///
/// This is what a STORED zip member is: the bytes are already there, in order,
/// uncompressed, and reading one is a seek and nothing more. It is also the
/// window a deflated member's compressed bytes are read through.
pub struct SubSource {
    inner: Box<dyn ImageSource>,
    start: u64,
    len: u64,
    name: String,
}

impl SubSource {
    pub fn new(inner: Box<dyn ImageSource>, start: u64, len: u64, name: String) -> Self {
        Self {
            inner,
            start,
            len,
            name,
        }
    }
}

impl ImageSource for SubSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.saturating_add(buf.len() as u64);
        if end > self.len {
            return Err(io::Error::other(format!(
                "{}: read of {} bytes at {offset} runs past the {}-byte member",
                self.name,
                buf.len(),
                self.len
            )));
        }
        self.inner.read_at(self.start + offset, buf)
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn describe(&self) -> String {
        self.name.clone()
    }
    fn thread_handle(&self) -> Option<Box<dyn ImageSource>> {
        self.inner.thread_handle().map(|inner| {
            Box::new(SubSource::new(inner, self.start, self.len, self.name.clone()))
                as Box<dyn ImageSource>
        })
    }
}

/// Bytes already in RAM.
///
/// Used for anything small enough that decompressing it once is cheaper than
/// indexing it -- a `.gdi` text file is a few hundred bytes, and a homebrew
/// `.cdi` is often a few megabytes.
pub struct MemorySource {
    bytes: Vec<u8>,
    name: String,
}

impl MemorySource {
    pub fn new(bytes: Vec<u8>, name: String) -> Self {
        Self { bytes, name }
    }
}

impl ImageSource for MemorySource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let start = offset as usize;
        let end = start.saturating_add(buf.len());
        if end > self.bytes.len() {
            return Err(io::Error::other(format!(
                "{}: read of {} bytes at {offset} runs past the {}-byte image",
                self.name,
                buf.len(),
                self.bytes.len()
            )));
        }
        buf.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn describe(&self) -> String {
        self.name.clone()
    }
}

/// Where a `.gdi`'s track files are looked up.
///
/// A `.gdi` names its tracks as bare filenames and they are expected next to
/// it. "Next to it" is a directory for a loose dump and a prefix inside the
/// archive for a zipped one, and that is the entire difference.
pub trait Container {
    fn open(&self, name: &str) -> io::Result<Box<dyn ImageSource>>;
    fn read_text(&self, name: &str) -> io::Result<String>;
    fn describe(&self) -> String;
}

/// A track name out of a `.gdi`, checked to be what the format says it is.
///
/// THE NAME IS UNTRUSTED: a `.gdi` is text that arrived with a downloaded dump.
/// `Path::join` with an absolute name throws the directory away entirely, so a
/// track line reading `1 0 4 2048 C:\Windows\System32\config\SAM 0` would have
/// the reader open that file and serve its bytes to the running title as disc
/// sectors. A track is a plain filename beside the `.gdi` and nothing else.
///
/// This belongs to the `Container` contract rather than to one implementation:
/// `ZipContainer` cannot reach the filesystem and so cannot be hurt by a bad
/// name, but "the invariant holds because the impl that could be hurt happens
/// to check it" is not a contract.
pub fn plain_track_name(name: &str) -> io::Result<&str> {
    let plain = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', ':'])
        && !Path::new(name).is_absolute();
    if plain {
        Ok(name)
    } else {
        Err(io::Error::other(format!(
            "'{name}' is not a plain filename, so it does not name a file beside \
             the .gdi"
        )))
    }
}

pub struct DirContainer {
    dir: PathBuf,
}

impl DirContainer {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// A track named in a `.gdi` that differs only in case from the file on
    /// disk. Harmless on Windows, fatal on Linux, and common in dumps that
    /// have been round-tripped through a zip.
    ///
    /// The name is checked first -- see [`plain_track_name`]. This is the impl
    /// where a bad one would escape the dump directory.
    fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        let name = plain_track_name(name)?;
        let direct = self.dir.join(name);
        if direct.exists() {
            return Ok(direct);
        }
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(direct);
        };
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().eq_ignore_ascii_case(name) {
                return Ok(e.path());
            }
        }
        Ok(direct)
    }
}

impl Container for DirContainer {
    fn open(&self, name: &str) -> io::Result<Box<dyn ImageSource>> {
        Ok(Box::new(FileSource::open(&self.resolve(name)?)?))
    }
    fn read_text(&self, name: &str) -> io::Result<String> {
        std::fs::read_to_string(self.resolve(name)?)
    }
    fn describe(&self) -> String {
        self.dir.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `.gdi` is text that ARRIVED WITH THE DUMP, and `Path::join` with an
    /// absolute name throws the directory away. A track line naming
    /// `C:\Windows\System32\config\SAM` -- or `../../../../etc/shadow` -- would
    /// otherwise have the reader open that file and serve its bytes to the
    /// running title as disc sectors.
    #[test]
    fn a_track_name_cannot_escape_the_dump_directory() {
        let dir = std::env::temp_dir().join("dcload-container-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("track01.bin"), b"sectors").expect("track");
        let c = DirContainer::new(dir.clone());

        assert!(c.open("track01.bin").is_ok(), "a plain filename still opens");
        for bad in [
            "../track01.bin",
            "..",
            "sub/track01.bin",
            r"sub\track01.bin",
            r"C:\Windows\System32\config\SAM",
            "/etc/shadow",
            "",
        ] {
            assert!(c.open(bad).is_err(), "'{bad}' must be refused");
            assert!(c.read_text(bad).is_err(), "'{bad}' must be refused");
        }
        let _ = std::fs::remove_file(dir.join("track01.bin"));
    }

    /// A play range that runs into the next track's undumped pregap asks for
    /// nothing of the file: a zero-length read past the end. It must not be an
    /// error, or the loader re-asks for the same sectors forever (Shenmue II's
    /// title screen: "read of 0 bytes at 1629936 runs past the 1625232-byte
    /// image").
    #[test]
    fn an_empty_read_past_the_end_of_a_track_in_memory_is_not_an_error() {
        let m = MemorySource::new(vec![1u8; 100], "track05.raw".to_string());
        assert!(m.read_at(1000, &mut []).is_ok(), "empty read, far past the end");
        assert!(m.read_at(100, &mut []).is_ok(), "empty read, exactly at the end");
        // Positive control: a read with bytes in it past the end is still refused.
        assert!(m.read_at(99, &mut [0u8; 2]).is_err());
    }
}
