//! What read pattern this machine's storage actually likes.
//!
//! The index pass in `disc_formats::deflate` reads a whole compressed member
//! before the title starts, and how fast that goes is a property of the
//! FILESYSTEM, not of the decoder: the numbers in `READ_CHUNK` and
//! `READ_THREADS` were measured on a WSL DrvFs mount and there is no reason a
//! Windows SMB share agrees with them.
//!
//! Run it against a big file on the storage in question:
//!
//! ```text
//! cargo run --release --example readbench -- "V:\path\to\track03.bin"
//! ```
//!
//! Each configuration reads a DIFFERENT region of the file, so no run is
//! served out of the cache the previous one filled. That is also why the file
//! has to be big: seven configurations at 128 MiB each want ~900 MiB.

use std::alloc::{Layout, alloc, dealloc};
use std::fs::{File, OpenOptions};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[cfg(windows)]
use std::os::windows::fs::{FileExt, OpenOptionsExt};
#[cfg(unix)]
use std::os::unix::fs::FileExt;

/// Tells the Windows cache manager (and the SMB redirector behind it) that
/// this handle is a streaming read, which is what turns aggressive read-ahead
/// on. It is the flag a copy engine uses and the one we do not.
#[cfg(windows)]
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

/// Bypasses the client cache entirely, so what is measured is the round trip
/// to the server and not what RAM already holds. Every read must then be
/// sector-aligned in offset, in length AND in buffer address -- hence
/// `AlignedBuf`.
#[cfg(windows)]
const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;

const SECTOR: usize = 4096;

/// A buffer whose address is sector-aligned, which unbuffered reads require.
struct AlignedBuf {
    ptr: *mut u8,
    layout: Layout,
}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, SECTOR).expect("layout");
        // SAFETY: non-zero size, valid alignment.
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null(), "out of memory");
        Self { ptr, layout }
    }
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` is a live allocation of `layout.size()` bytes.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: allocated by `alloc` with this same layout.
        unsafe { dealloc(self.ptr, self.layout) }
    }
}

#[derive(Clone, Copy)]
enum Shape {
    /// One handle, one chunk after another. What a copy does.
    Sequential,
    /// Thread `t` takes chunks `t`, `t + N`, `t + 2N`, ... so every handle
    /// jumps `(N - 1) * chunk` bytes after each read. What we do today.
    Strided,
    /// N threads sharing one counter, so the reads in flight are always the
    /// next N CONSECUTIVE chunks. Sequential to the server, N deep.
    Window,
}

struct Config {
    label: &'static str,
    shape: Shape,
    threads: usize,
    chunk: usize,
    seq_scan: bool,
}

fn open(path: &str, seq_scan: bool) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        let mut o = OpenOptions::new();
        o.read(true);
        let mut flags = 0;
        if seq_scan {
            flags |= FILE_FLAG_SEQUENTIAL_SCAN;
        }
        if direct() {
            flags |= FILE_FLAG_NO_BUFFERING;
        }
        if flags != 0 {
            o.custom_flags(flags);
        }
        return o.open(path);
    }
    #[cfg(unix)]
    {
        let _ = seq_scan;
        OpenOptions::new().read(true).open(path)
    }
}

/// Unbuffered, i.e. "measure the network, not this machine's RAM".
fn direct() -> bool {
    std::env::args().any(|a| a == "--direct")
}

fn read_at(file: &File, buf: &mut [u8], at: u64) -> std::io::Result<usize> {
    #[cfg(windows)]
    {
        file.seek_read(buf, at)
    }
    #[cfg(unix)]
    {
        file.read_at(buf, at)
    }
}

/// One positioned read, retried until the buffer is full -- the same
/// all-or-nothing contract `ImageSource::read_at` has.
fn read_exact_at(file: &File, buf: &mut [u8], at: u64) -> std::io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        match read_at(file, &mut buf[done..], at + done as u64)? {
            0 => return Err(std::io::Error::other("short read")),
            n => done += n,
        }
    }
    Ok(())
}

fn run(path: &str, c: &Config, start: u64, span: u64) -> std::io::Result<f64> {
    let chunks = span.div_ceil(c.chunk as u64);
    let t0 = Instant::now();

    match c.shape {
        Shape::Sequential => {
            let file = open(path, c.seq_scan)?;
            let mut buf = AlignedBuf::new(c.chunk);
            let buf = buf.as_mut();
            for k in 0..chunks {
                let at = start + k * c.chunk as u64;
                let n = (c.chunk as u64).min(span - k * c.chunk as u64) as usize;
                read_exact_at(&file, &mut buf[..n], at)?;
            }
        }
        Shape::Strided => {
            std::thread::scope(|s| {
                for t in 0..c.threads {
                    s.spawn(move || {
                        let file = open(path, c.seq_scan).expect("open");
                        let mut buf = AlignedBuf::new(c.chunk);
                        let buf = buf.as_mut();
                        let mut k = t as u64;
                        while k < chunks {
                            let at = start + k * c.chunk as u64;
                            let n = (c.chunk as u64).min(span - k * c.chunk as u64) as usize;
                            read_exact_at(&file, &mut buf[..n], at).expect("read");
                            k += c.threads as u64;
                        }
                    });
                }
            });
        }
        Shape::Window => {
            let next = Arc::new(AtomicU64::new(0));
            std::thread::scope(|s| {
                for _ in 0..c.threads {
                    let next = Arc::clone(&next);
                    s.spawn(move || {
                        let file = open(path, c.seq_scan).expect("open");
                        let mut buf = AlignedBuf::new(c.chunk);
                        let buf = buf.as_mut();
                        loop {
                            let k = next.fetch_add(1, Ordering::Relaxed);
                            if k >= chunks {
                                return;
                            }
                            let at = start + k * c.chunk as u64;
                            let n = (c.chunk as u64).min(span - k * c.chunk as u64) as usize;
                            read_exact_at(&file, &mut buf[..n], at).expect("read");
                        }
                    });
                }
            });
        }
    }

    let secs = t0.elapsed().as_secs_f64();
    Ok(span as f64 / secs / 1_000_000.0)
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: readbench <file> [region-MiB, default 128]");
        std::process::exit(2);
    };
    let region: u64 = args
        .next()
        .and_then(|a| a.parse().ok())
        .unwrap_or(128);
    if direct() {
        println!("(unbuffered: the client cache is out of the picture)");
    }
    let span = region << 20;

    let configs = [
        Config { label: "1 thread   1 MiB", shape: Shape::Sequential, threads: 1, chunk: 1 << 20, seq_scan: false },
        Config { label: "1 thread   4 MiB", shape: Shape::Sequential, threads: 1, chunk: 4 << 20, seq_scan: false },
        Config { label: "1 thread   4 MiB  seq-scan", shape: Shape::Sequential, threads: 1, chunk: 4 << 20, seq_scan: true },
        Config { label: "4 strided  4 MiB  (today)", shape: Shape::Strided, threads: 4, chunk: 4 << 20, seq_scan: false },
        Config { label: "4 window   4 MiB", shape: Shape::Window, threads: 4, chunk: 4 << 20, seq_scan: false },
        Config { label: "4 window   4 MiB  seq-scan", shape: Shape::Window, threads: 4, chunk: 4 << 20, seq_scan: true },
        Config { label: "8 window   1 MiB  seq-scan", shape: Shape::Window, threads: 8, chunk: 1 << 20, seq_scan: true },
        Config { label: "8 window   4 MiB  seq-scan", shape: Shape::Window, threads: 8, chunk: 4 << 20, seq_scan: true },
    ];

    let len = File::open(&path)?.metadata()?.len();
    let want = span * configs.len() as u64;
    if len < want {
        eprintln!(
            "{path} is {} MiB; {} configurations x {region} MiB want {} MiB. \
             Pass a smaller region, or a bigger file.",
            len >> 20,
            configs.len(),
            want >> 20
        );
        std::process::exit(2);
    }

    println!("{path}  ({} MiB)", len >> 20);
    println!("each configuration reads its own cold {region} MiB region\n");
    for (i, c) in configs.iter().enumerate() {
        let at = span * i as u64;
        let mbs = run(&path, c, at, span)?;
        println!("  {:<28} {:7.1} MB/s   {:6.0} Mbps", c.label, mbs, mbs * 8.0);
    }
    Ok(())
}
