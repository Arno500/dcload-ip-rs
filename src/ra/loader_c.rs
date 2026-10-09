//! The loader's own `ra.c`, compiled for the PC (`scripts/ra-sampler-harness` in
//! the loader repo) and run over a scripted RAM: the datagrams it sends are fed
//! to `Mirror`, and at every frame the mirror judges the memory must equal what
//! the script held at that frame. This is the one place the C encoder and the
//! Rust decoder meet. Skipped without gcc or the loader's sources
//! (`DCLOAD_LOADER_REPO`, default /opt/toolchains/dc/dcload-ip).

use std::collections::HashMap;
use std::path::PathBuf;

use super::frames::{Applied, Mirror};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn run_harness(mode: &str) -> Option<String> {
    let repo = PathBuf::from(
        std::env::var("DCLOAD_LOADER_REPO").unwrap_or("/opt/toolchains/dc/dcload-ip".into()),
    );
    let loader = repo.join("target-src/dcload");
    let harness = repo.join("scripts/ra-sampler-harness");
    if !loader.join("ra.c").is_file() || !harness.join("harness.c").is_file() {
        eprintln!("skipped: the loader sources are not at {}", repo.display());
        return None;
    }
    let dir = std::env::temp_dir().join(format!("dcload-ra-harness-{}-{mode}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["ra.c", "ra.h", "commands.h", "packet.h", "bswap.h"] {
        std::fs::copy(loader.join(f), dir.join(f)).unwrap();
    }
    for entry in std::fs::read_dir(harness.join("stub")).unwrap() {
        let p = entry.unwrap().path();
        std::fs::copy(&p, dir.join(p.file_name().unwrap())).unwrap();
    }
    std::fs::copy(harness.join("harness.c"), dir.join("harness.c")).unwrap();
    let exe = dir.join("harness");
    let built = std::process::Command::new("gcc")
        .args(["-std=gnu11", "-O1", "-DWITH_RCHEEVOS=1", "-o"])
        .arg(&exe)
        .arg(dir.join("harness.c"))
        .output();
    match built {
        // No compiler: nothing to compare against, and the test says so.
        Err(_) => {
            eprintln!("skipped: no gcc");
            return None;
        }
        // A compiler that refuses the loader's own source is a failure, not a skip:
        // a test that skips when the code is broken proves nothing.
        Ok(o) if !o.status.success() => {
            panic!("the harness does not build:\n{}", String::from_utf8_lossy(&o.stderr))
        }
        Ok(_) => {}
    }
    let out = std::process::Command::new(&exe).arg(mode).output().ok()?;
    let _ = std::fs::remove_dir_all(&dir);
    Some(String::from_utf8(out.stdout).unwrap())
}

/// What one run of the harness printed, decoded.
struct Run {
    expected: HashMap<u16, Vec<u32>>,
    datagrams: Vec<(u32, Vec<u8>)>,
    /// The answer to each `RACT` part, `None` for a part the loader said nothing to.
    replies: Vec<Option<u32>>,
    limits: Vec<(u32, u32)>,
    words: usize,
    counters: String,
}

fn parse(out: &str) -> Run {
    let mut run = Run {
        expected: HashMap::new(),
        datagrams: Vec::new(),
        replies: Vec::new(),
        limits: Vec::new(),
        words: 0,
        counters: String::new(),
    };
    for line in out.lines() {
        let mut it = line.splitn(3, ' ');
        match (it.next(), it.next(), it.next()) {
            (Some("R"), Some("-"), _) => run.replies.push(None),
            (Some("R"), Some(v), _) => run.replies.push(Some(v.parse::<u32>().unwrap())),
            (Some("T"), Some(v), _) => run.words = v.parse().unwrap(),
            (Some("S"), Some(a), Some(b)) => run.counters = format!("{a} {b}"),
            (Some("E"), Some(frame), Some(words)) => {
                let w: Vec<u32> = hex(words)
                    .chunks(4)
                    .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
                    .collect();
                // printed as %08x of the host value: read back the same way
                run.expected.insert(frame.parse().unwrap(), w);
            }
            (Some("D"), Some(bytes), _) => {
                let b = hex(bytes);
                if &b[..4] == b"RAFR" {
                    let seq = u32::from_be_bytes(b[4..8].try_into().unwrap());
                    let size = u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize;
                    assert_eq!(b.len(), 12 + size, "the size field is the payload");
                    assert!(12 + size <= 1500, "a datagram must fit an Ethernet frame");
                    run.datagrams.push((seq, b[12..].to_vec()));
                } else {
                    assert_eq!(&b[..4], b"RACT", "a command reply");
                    // the reply carries the room for a table: Katana, Windows CE
                    assert_eq!(b.len(), 12 + 8);
                    run.limits.push((
                        u32::from_be_bytes(b[12..16].try_into().unwrap()),
                        u32::from_be_bytes(b[16..20].try_into().unwrap()),
                    ));
                }
            }
            _ => {}
        }
    }
    run
}

fn check(mode: &str) -> Option<Run> {
    let out = run_harness(mode)?;
    let run = parse(&out);
    // refused: 385 ranges, an unaligned offset, a range of 1100 words, ranges out of
    // order, a chain whose parent is not an earlier word, 65 chains. Then the table
    // in parts: a first part of generation 6, generation 7 starting over, a late
    // part of 6 and a part of 7 that skips one -- none answered -- and the last
    // part of 7, which completes it: accepted.
    let no = Some(0xffff_ffff);
    assert_eq!(run.replies, vec![no, no, no, no, no, no, None, None, None, None, Some(0)]);
    assert!(run.datagrams.len() > 10, "{} datagrams", run.datagrams.len());

    let mut m = Mirror::new(7, run.words);
    let mut judged = Vec::new();
    for (seq, payload) in &run.datagrams {
        let res = m.apply(*seq, payload, |frame, mem| {
            assert_eq!(mem.words(), &run.expected[&frame][..], "memory at frame {frame} ({mode})");
            judged.push(frame);
        });
        assert_ne!(res, Applied::Malformed, "datagram {seq}");
    }
    // The harness drops frames while its "network" is busy (frames 200..260)
    // and resumes with a keyframe: frames judged before, and after.
    assert!(judged.len() > 150, "{} frames judged", judged.len());
    assert!(judged.iter().any(|f| *f > 300), "the stream resumed after the busy spell");
    assert!(judged.windows(2).all(|w| w[0] < w[1]), "in order");
    assert_eq!(m.lost, 0, "no datagram was lost, only frames dropped on the console");
    // Only the busy spell's frames (60) may be dropped: reserving a whole keyframe
    // for every frame starved a table near the room's size (230 of 400 dropped).
    let dropped: u32 = run
        .counters
        .split_whitespace()
        .find_map(|f| f.strip_prefix("dropped="))
        .and_then(|v| v.parse().ok())
        .expect("the harness reports dropped frames");
    assert!(dropped <= 60, "{dropped} frames dropped ({mode})");
    Some(run)
}

#[test]
fn the_loaders_datagrams_decode_to_the_memory_it_sampled() {
    let Some(run) = check("katana") else { return };
    // 744 words in a Katana title's room (6 KB: the previous frame, a window and
    // a keyframe); what a Windows CE title has is smaller
    let (katana, ce) = run.limits[0];
    assert_eq!(katana, 744);
    assert!(run.words > 512, "the table is larger than the loader once took: {}", run.words);
    assert!((300..=360).contains(&ce), "Windows CE room: {ce} words");
}

/// Under Windows CE the title's writes sit in dirty lines of a write-back cache,
/// indexed by virtual address, that RAM does not have: the loader must find them
/// by their PHYSICAL tag and put them over what it read. The harness models that,
/// with synonyms; every frame must still equal what the title saw.
#[test]
fn under_windows_ce_dirty_cache_lines_win_over_ram() {
    let Some(run) = check("ce") else { return };
    assert!(run.counters.contains("nofit=0"), "{}", run.counters);
    assert!(!run.counters.contains("oc_words=0 "), "the overlay did nothing: {}", run.counters);
}
