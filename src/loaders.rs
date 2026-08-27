//! Choosing and placing the dcload build a given title needs.
//!
//! The Dreamcast side is built once per base address (`make loaders` in
//! target-src/dcload), one self-contained ELF each, named `dcload-0x8cfe8000.elf`
//! and so on. This module answers three questions about them:
//!
//!   * where is the loader currently running -- from the four bytes dcload
//!     appends to its VERS reply;
//!   * which ELF do we want, and does it exist;
//!   * can it be uploaded straight over the top of the running one, or does the
//!     move need an intermediate hop.
//!
//! # The hop
//!
//! Chainloading is an ordinary upload: the running loader receives PBIN packets
//! and writes them wherever they are addressed, then EXECs the result. That is
//! fine as long as the bytes land somewhere it is not itself using -- and going
//! from 0x8c004000 to 0x8c000100 is exactly the case where they do not. The new
//! image would be written through the running loader's own code while it is
//! executing it.
//!
//! There is no need for a relocating stub to fix that. Every low base is clear
//! of every high one, so the move can be made in two clear steps: load a loader
//! into high RAM, chainload into it, and from up there the low target is
//! untouched ground. It costs one extra 26 KB upload.
//!
//! The 0x8c00f400 vector table is the one region that is always written over a
//! live loader's copy of it, and that is safe by inspection: the running loader
//! only ever jumps there on an exception, the bytes being written are the same
//! bytes, and its own stack is below that address, not above it.

use std::path::{Path, PathBuf};

use elf::{ElfBytes, endian::AnyEndian};

/// The stock base, which is also where the CD image boots the loader.
///
/// It is not just tradition: the loader publishes its magic word at base+4 and
/// its syscall trampoline pointer at base+8, and KOS programs (and everything
/// in dcload-ip's own example-src/) read those two addresses as literals. A
/// loader anywhere else is invisible to them, so nothing moves unless a title's
/// preset actually asks for it.
pub const DEFAULT_BASE: u32 = 0x8c00_4000;

/// Why a base cannot be used, when the answer is known rather than "no ELF".
///
/// A bare "that file is missing" invites someone to go and build it, and for
/// these two that would produce a loader which bricks the session — so the
/// reason belongs here, next to the constant, not only in a Makefile comment.
pub fn known_unsupported(base: u32) -> Option<&'static str> {
    (base < DEFAULT_BASE).then_some(
        "an image based below 0x8c004000 overwrites the BIOS syscall area, and \
         dcload's on-screen display jumps through the font syscall pointer at \
         0x8c0000b4 on every string it draws -- including the \"receiving \
         data...\" it draws while that very area is being overwritten. \
         Supporting this base means giving up the display for it",
    )
}

/// Where to bounce through when the target overlaps the running loader.
///
/// Chosen because its own footprint (0x8ce00000..0x8ce0b000) is clear of every
/// other base in the set, in both directions: no low base can reach it and it
/// cannot reach any of them.
pub const SCRATCH_BASE: u32 = 0x8ce0_0000;

/// Every range a RUNNING loader at `base` is using, and therefore every range
/// an upload must not touch.
///
/// NOT ONE RANGE, AND THE SECOND ONE IS THE INTERESTING HALF. A low loader
/// keeps its two 1536-byte packet buffers and its Maple DMA buffer OUT of its
/// image, in high RAM at 0x8cfe8000 and 0x8cfe9000, precisely so a title's
/// descending stack cannot reach them. Those buffers are the ones an upload
/// arrives in and is answered from -- so uploading a loader over the top of
/// them destroys the machinery doing the uploading.
///
/// Measured, because it is not obvious from the addresses: chainloading
/// straight from 0x8c004000 to 0x8cfe8000 (which is what Sonic Adventure 2's
/// preset asks for) writes the new .text through both buffers. The transfer
/// still reports success, and the new loader does come up and run -- its PC and
/// stack pointer are exactly where they should be -- but it is deaf, and the
/// session is over with no error anywhere.
///
/// The ranges mirror DCLOAD_STACK / DCLOAD_HIRAM / DCLOAD_MAPLE in
/// target-src/dcload/Makefile. If that layout table changes, this changes with
/// it.
pub fn live_footprint(base: u32) -> Vec<(u32, u32)> {
    if base < 0x8c01_0000 {
        vec![
            // Image, BSS, and the stack descending from the BIOS VBR.
            (base, 0x8c00_f400),
            // Maple DMA buffer (0x8cfe8000, 2 KB) and the .hiram packet
            // buffers (0x8cfe9000, 3 KB), as one range.
            (0x8cfe_8000, 0x8cfe_a000),
        ]
    } else {
        // A high loader keeps all of it together: image, stack to base+0xb000,
        // .hiram at +0xc000, Maple at +0xd000.
        vec![(base, base + 0xe000)]
    }
}

/// The image `make loaders` links with `ld -q`, which the host can move to any
/// high base. Deliberately not named `dcload-0x…elf`: `available()` parses that
/// pattern, and this image is not a base.
pub const RELOCATABLE_NAME: &str = "dcload-relocatable.elf";

/// Where a relocated loader may be put, and the step between candidates.
///
/// The floor is `ISOLDR_DEFAULT_ADDR`, which is DreamShell's own answer to
/// "high RAM a title is not using"; below it a loader starts competing with the
/// title's own image, which is loaded at 0x8c010000 and is routinely megabytes
/// long. The ceiling leaves the loader's whole span inside RAM. 64 KB steps
/// give 31 candidates between the two -- far more than the four bases this
/// replaces, and every one of them aligned enough to read in a log.
const FREE_BASE_FLOOR: u32 = 0x8ce0_0000;
const FREE_BASE_STEP: u32 = 0x1_0000;

/// Find a base whose span the title does not address, starting from the one its
/// preset asked for.
///
/// DOWN FIRST, THEN UP. The preset's address is evidence: DreamShell judged
/// that region free for this title, so the nearest thing to it is the least
/// likely to surprise. Downwards first because the collisions seen so far are
/// titles reaching the TOP of RAM (Sonic Adventure 2's Maple DMA list at
/// 0x8cff0000), and moving down is moving away from them.
///
/// `is_clear` answers for one candidate base. It is a closure because what
/// counts as clear is not this module's business -- today it is "the title
/// loads no constant pointing inside the span".
pub fn search_free_base(wanted: u32, is_clear: impl Fn(u32) -> bool) -> Option<u32> {
    if is_clear(wanted) {
        return Some(wanted);
    }
    let ceiling = (0x8d00_0000 - LOADER_SPAN) & !(FREE_BASE_STEP - 1);
    let start = wanted.min(ceiling) & !(FREE_BASE_STEP - 1);
    let down = (FREE_BASE_FLOOR..=start).rev().step_by(FREE_BASE_STEP as usize);
    let up = ((start + FREE_BASE_STEP)..=ceiling).step_by(FREE_BASE_STEP as usize);
    // THE NEIGHBOURS HAVE TO BE CLEAR TOO, which buys a step of margin on each
    // side. What is detected is a constant -- an address the title NAMES -- and
    // what will be written is a buffer of some size around it. Landing 8 KB
    // under a known Maple DMA list satisfies "no constant inside my span" and
    // is still a bad place to be.
    down.chain(up).find(|&b| {
        b != wanted
            && is_clear(b)
            && (b < FREE_BASE_FLOOR + FREE_BASE_STEP || is_clear(b - FREE_BASE_STEP))
            && (b + FREE_BASE_STEP > ceiling || is_clear(b + FREE_BASE_STEP))
    })
}

/// How wide a loader's own span is, from its base. Mirrors the HIGH layout in
/// target-src/dcload/Makefile: stack at +0xb000, .hiram at +0xc000, Maple DMA
/// at +0xd000.
pub const LOADER_SPAN: u32 = 0xe000;

/// Move a relocatable loader image to `to`, without rebuilding it.
///
/// WHY THIS CAN BE A FLAT DELTA, AND HOW THAT IS KNOWN.
///
/// The loader is linked with `ld -q`, which keeps the relocations in the ELF.
/// It emits exactly one type, `R_SH_DIR32`: an absolute 32-bit address in a
/// literal pool or a data word. Everything else in the image -- every branch,
/// every PC-relative load -- is already position-independent. So relocating is
/// "add the delta to each word a relocation names", and nothing more.
///
/// Measured 2026-08-27, by linking the loader natively at several bases and
/// diffing the loadable sections:
///
/// - 833 words differ between two bases, **every one of them by exactly the
///   delta**, and the relocations name exactly those 833 words -- none missed,
///   and none naming a word that does not change. That second half matters as
///   much as the first: it is what proves no relocation points at a hardware
///   register or at the guest vector table, which a delta would corrupt.
/// - Applying this to the image linked at 0x8ce00000 reproduces the native
///   build at 0x8cef8000, at 0x8cc80000 (a negative delta) and at 0x8cd12000
///   (a base nothing had ever been linked at) BYTE FOR BYTE.
///
/// Getting there needed one fix on the DC side: the Maple DMA address used to
/// reach C as a `-D`, i.e. a number, and a number in a literal pool carries no
/// relocation. It is a linker symbol now (maple.c). Nine words, and they were
/// the only ones.
///
/// HIGH BASES ONLY. A flat delta moves the whole layout together, which is true
/// of the HIGH family -- stack, `.hiram` and Maple buffer are all base-relative
/// -- and false of LOW, whose buffers stay at 0x8cfe8000 while its image sits
/// at 0x8c004000. Nothing is lost: the CD always boots the stock base, and the
/// 593 presets that ask for it ask for no move at all.
///
/// `.guestvbr` is deliberately left where it is. It is the vector table handed
/// to the title, linked at 0x8c00f400 for every base (AGENTS.md 4.11 item 2),
/// so it falls outside the span and is not touched.
pub fn relocate(elf: &[u8], to: u32) -> Result<Vec<u8>, String> {
    const SHT_PROGBITS: u32 = 1;
    const SHT_SYMTAB: u32 = 2;
    const SHT_RELA: u32 = 4;
    const SHT_NOBITS: u32 = 8;
    const SHF_ALLOC: u32 = 2;

    if elf.len() < 52 || &elf[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if elf[4] != 1 || elf[5] != 1 {
        return Err("not a 32-bit little-endian ELF".into());
    }
    let rd = |o: usize| -> u32 {
        u32::from_le_bytes([elf[o], elf[o + 1], elf[o + 2], elf[o + 3]])
    };
    let rd16 = |o: usize| -> u16 { u16::from_le_bytes([elf[o], elf[o + 1]]) };

    let from = rd(24); // e_entry: crt0 is first, so this is the base
    if to == from {
        return Ok(elf.to_vec());
    }
    if to % 4 != 0 {
        return Err(format!("0x{to:08x} is not 4-byte aligned"));
    }
    if !plausible_base(to) || to.saturating_add(LOADER_SPAN) > 0x8d00_0000 {
        return Err(format!(
            "0x{to:08x}..0x{:08x} is not inside the Dreamcast's RAM",
            to.saturating_add(LOADER_SPAN)
        ));
    }
    if from < 0x8c01_0000 {
        return Err(format!(
            "this image is linked at 0x{from:08x}, a LOW base: its buffers are at \
             fixed high addresses, so it cannot be moved by a flat delta"
        ));
    }
    let delta = to.wrapping_sub(from);

    let shoff = rd(32) as usize;
    let shentsize = rd16(46) as usize;
    let shnum = rd16(48) as usize;
    if shoff == 0 || shnum == 0 || shoff + shnum * shentsize > elf.len() {
        return Err("section headers are out of range".into());
    }

    // The sections that move: allocated, and inside the loader's own span.
    // `.guestvbr` is allocated too and is deliberately not among them.
    let mut moving: Vec<(u32, u32, usize, u32)> = vec![]; // addr, size, offset, type
    let mut has_rela = false;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let (typ, flags, addr, off, size) = (rd(sh + 4), rd(sh + 8), rd(sh + 12), rd(sh + 16), rd(sh + 20));
        if typ == SHT_RELA {
            has_rela = true;
        }
        if flags & SHF_ALLOC == 0 || size == 0 {
            continue;
        }
        if addr >= from && addr < from.saturating_add(LOADER_SPAN) {
            moving.push((addr, size, off as usize, typ));
        }
    }
    if !has_rela {
        return Err(
            "this loader carries no relocations, so it cannot be moved -- rebuild it with \
             `make loaders`, which links dcload-relocatable.elf with `ld -q`"
                .into(),
        );
    }
    if moving.is_empty() {
        return Err(format!("nothing allocated at 0x{from:08x}; is this a loader ELF?"));
    }

    let mut out = elf.to_vec();
    let mut wr = |o: usize, v: u32| out[o..o + 4].copy_from_slice(&v.to_le_bytes());

    // 1. The words the relocations name. Only those inside a section that is
    //    actually moving -- a relocation against anything else would be a bug,
    //    and silently patching it would be a worse one.
    let mut patched = 0usize;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if rd(sh + 4) != SHT_RELA {
            continue;
        }
        let (off, size, entsize) = (rd(sh + 16) as usize, rd(sh + 20) as usize, rd(sh + 36) as usize);
        if entsize == 0 || off + size > elf.len() {
            return Err("a relocation section is out of range".into());
        }
        for e in (off..off + size).step_by(entsize) {
            let r_offset = rd(e);
            let Some(&(addr, _, foff, typ)) = moving
                .iter()
                .find(|&&(a, sz, _, _)| r_offset >= a && r_offset < a + sz)
            else {
                continue;
            };
            if typ == SHT_NOBITS {
                continue; // nothing on disk to patch
            }
            let at = foff + (r_offset - addr) as usize;
            if at + 4 > elf.len() {
                return Err(format!("relocation at 0x{r_offset:08x} points outside the file"));
            }
            wr(at, rd(at).wrapping_add(delta));
            patched += 1;
        }
    }
    if patched == 0 {
        return Err("no relocation landed inside the loader's own sections".into());
    }

    // 2. Where those sections say they live -- this is what the upload reads.
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let (flags, addr, size) = (rd(sh + 8), rd(sh + 12), rd(sh + 20));
        if flags & SHF_ALLOC != 0 && size != 0 && addr >= from && addr < from + LOADER_SPAN {
            wr(sh + 12, addr.wrapping_add(delta));
        }
    }

    // 3. The entry point.
    wr(24, from.wrapping_add(delta));

    // 4. Program headers, so the file stays self-consistent for any other tool
    //    that reads it (readelf, gdb, objdump).
    let phoff = rd(28) as usize;
    let phentsize = rd16(42) as usize;
    let phnum = rd16(44) as usize;
    if phoff != 0 && phoff + phnum * phentsize <= elf.len() {
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            for field in [8usize, 12] {
                let v = rd(ph + field);
                if v >= from && v < from + LOADER_SPAN {
                    wr(ph + field, v.wrapping_add(delta));
                }
            }
        }
    }

    // 5. The symbol table. Not needed to run the loader -- and needed by every
    //    instrument that resolves a counter by name against this ELF. A symbol
    //    table left at the old base is exactly AGENTS.md 14.19: readings that
    //    come back believable and wrong.
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if rd(sh + 4) != SHT_SYMTAB {
            continue;
        }
        let (off, size, entsize) = (rd(sh + 16) as usize, rd(sh + 20) as usize, rd(sh + 36) as usize);
        if entsize == 0 || off + size > elf.len() {
            continue;
        }
        for e in (off..off + size).step_by(entsize) {
            let v = rd(e + 4);
            if v >= from && v < from + LOADER_SPAN {
                wr(e + 4, v.wrapping_add(delta));
            }
        }
    }
    let _ = SHT_PROGBITS;
    Ok(out)
}

/// The base to fall back to when the one a preset asks for is one the title
/// itself addresses.
///
/// Measured on Sonic Adventure 2 (2026-08-27): its preset asks for 0x8cfe8000,
/// and it puts its Maple DMA list at 0x8cff0000 -- inside the loader's stack
/// and packet buffers at that base. The console goes silent with nothing logged
/// anywhere, because a DMA is written by the hardware and passes through
/// neither dcload nor the host. 0x8cef8000 was confirmed to run it perfectly.
///
/// SAME FAMILY FIRST, THEN NEAREST. A preset that asks for a high base is
/// saying the title uses low RAM (that is the whole reason DreamShell moves the
/// loader up), so answering a high request with a low base would trade this
/// collision for the one the preset exists to avoid. Within the family, nearest
/// is the least opinionated tie-break available: every candidate here has
/// already been shown clear of the title's own constants, so there is nothing
/// better to rank them by, and staying close keeps the loader in the region
/// DreamShell judged free for this title.
pub fn nearest_clear_base(wanted: u32, candidates: &[u32]) -> Option<u32> {
    let high = wanted >= 0x8c01_0000;
    candidates
        .iter()
        .copied()
        .filter(|&b| b != wanted && (b >= 0x8c01_0000) == high)
        .min_by_key(|&b| b.abs_diff(wanted))
}

/// The four bytes dcload appends to its VERS payload, after the NUL that ends
/// the version string. Returns the printable part and the base, when present.
///
/// Absent on any loader built before this existed, which is not an error: the
/// caller then has no basis to move anything and leaves the loader alone.
pub fn parse_version_payload(data: &[u8], size: usize) -> (String, Option<u32>) {
    let size = size.min(data.len());
    let payload = &data[..size];
    let text = String::from_utf8_lossy(payload)
        .trim_end_matches(char::from(0))
        .split('\0')
        .next()
        .unwrap_or("")
        .to_string();

    if size < 4 {
        return (text, None);
    }
    let base = u32::from_be_bytes(payload[size - 4..size].try_into().unwrap());
    // The string and its NUL must actually end before those four bytes,
    // otherwise what we just read is the tail of the adapter name.
    if payload[..size - 4].iter().any(|b| *b == 0) && plausible_base(base) {
        (text, Some(base))
    } else {
        (text, None)
    }
}

/// RAM is 0x8c000000..0x8d000000, and a loader has to leave room for itself.
fn plausible_base(addr: u32) -> bool {
    (0x8c00_0000..0x8cff_0000).contains(&addr) && addr % 4 == 0
}

/// Climb from `start` looking for the directory that holds `Cargo.toml`.
///
/// `target/debug/dcload-ip-rs` is two levels below it, so this finds the same
/// root from a debug build, a release build and `cargo run` alike -- which is
/// the point: the loader set must not move when the profile does. Bounded,
/// because an unbounded walk would happily adopt an unrelated crate's root.
fn project_root_from(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    for _ in 0..6 {
        let d = dir?;
        if d.join("Cargo.toml").is_file() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

/// The project roots this binary can plausibly belong to, most specific first.
///
/// Three sources, because no single one covers every way the tool is run: the
/// executable's own location (`cargo run`, `./target/release/...`), the
/// working directory (a binary invoked from elsewhere in the same checkout),
/// and the manifest path baked in at compile time (the only one that survives
/// `cargo install`). Deduplicated, so the common case where they all agree
/// yields one candidate rather than three.
pub fn project_roots(exe: Option<&Path>, cwd: Option<&Path>, manifest_dir: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    if let Some(root) = exe.and_then(Path::parent).and_then(project_root_from) {
        push(root);
    }
    if let Some(root) = cwd.and_then(project_root_from) {
        push(root);
    }
    push(PathBuf::from(manifest_dir));
    out
}

/// Where `game-presets.tsv` is looked for, in order.
///
/// Same rule as the loaders, and for the same reasons -- outside `target/` so
/// `cargo clean` cannot take it, identical for debug and release. It is
/// searched next to the loaders FIRST so that `--loader-dir` still moves the
/// pair together, which is how a deployed set is normally laid out; then in
/// the project root itself, for a checkout that keeps the table at hand
/// without a loaders directory at all.
pub fn game_db_candidates(
    explicit: Option<String>,
    env_path: Option<String>,
    loader_dir: &Path,
    exe: Option<&Path>,
    cwd: Option<&Path>,
    manifest_dir: &str,
) -> Vec<PathBuf> {
    data_file_candidates(
        "game-presets.tsv",
        explicit,
        env_path,
        loader_dir,
        exe,
        cwd,
        manifest_dir,
    )
}

/// Where the learned memory map lives: beside the preset database, by the same
/// search, so the two travel together and a deployment has both or neither.
pub fn memory_db_candidates(
    explicit: Option<String>,
    env_path: Option<String>,
    loader_dir: &Path,
    exe: Option<&Path>,
    cwd: Option<&Path>,
    manifest_dir: &str,
) -> Vec<PathBuf> {
    data_file_candidates(
        "game-memory.tsv",
        explicit,
        env_path,
        loader_dir,
        exe,
        cwd,
        manifest_dir,
    )
}

fn data_file_candidates(
    db: &str,
    explicit: Option<String>,
    env_path: Option<String>,
    loader_dir: &Path,
    exe: Option<&Path>,
    cwd: Option<&Path>,
    manifest_dir: &str,
) -> Vec<PathBuf> {
    if let Some(p) = explicit {
        return vec![PathBuf::from(p)];
    }
    if let Some(p) = env_path {
        return vec![PathBuf::from(p)];
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };

    push(loader_dir.join(db));
    for root in project_roots(exe, cwd, manifest_dir) {
        push(root.join(db));
        push(root.join("loaders").join(db));
    }
    if let Some(dir) = exe.and_then(Path::parent) {
        push(dir.join(db));
    }
    push(PathBuf::from(db));
    out
}

/// Where a `loaders` directory is looked for, in order.
///
/// THE PROJECT ROOT COMES BEFORE THE EXECUTABLE, ON PURPOSE.
///
/// This used to be "next to the executable" and nothing else, which put the
/// set inside `target/`: `cargo clean` deleted it, and debug and release each
/// needed their own copy. The expensive part is not the copying -- it is that
/// the copy which survives is not necessarily the current one. A stale
/// `target/debug/loaders` chainloads an old loader that answers, runs, and
/// reports its counters at addresses that have since moved; every value comes
/// back believable and wrong. That cost a full session on 2026-08-16.
///
/// So the root wins, and `target/` is kept only as the last resort that lets a
/// distributed binary carry its loaders beside it.
fn loader_dir_candidates(
    explicit: Option<String>,
    env_dir: Option<String>,
    exe: Option<PathBuf>,
    cwd: Option<PathBuf>,
    manifest_dir: &str,
) -> Vec<PathBuf> {
    if let Some(dir) = explicit {
        return vec![PathBuf::from(dir)];
    }
    if let Some(dir) = env_dir {
        return vec![PathBuf::from(dir)];
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };

    let exe_dir = exe.as_deref().and_then(Path::parent);
    for root in project_roots(exe.as_deref(), cwd.as_deref(), manifest_dir) {
        push(root.join("loaders"));
    }
    // Last, the old behaviour: whatever sits beside the binary. Kept so a
    // distributed copy can carry its loaders with it.
    if let Some(dir) = exe_dir {
        push(dir.join("loaders"));
    }
    push(PathBuf::from("loaders"));
    out
}

/// The directory of per-base loader ELFs.
pub struct LoaderSet {
    dir: PathBuf,
    /// Every candidate considered, so a failure can say where it looked
    /// instead of naming one path and leaving the user to guess the rest.
    tried: Vec<PathBuf>,
}

impl LoaderSet {
    pub fn new(dir: PathBuf) -> Self {
        LoaderSet {
            tried: vec![dir.clone()],
            dir,
        }
    }

    /// Search order: explicit argument, then `DCLOAD_LOADER_DIR`, then
    /// `loaders/` in the project root, then the compiled-in manifest
    /// directory, then next to the executable.
    ///
    /// A candidate is taken when it actually HOLDS loaders, not merely when it
    /// exists -- an empty leftover directory must not shadow the real set.
    /// Falling through every candidate still returns a concrete path, so the
    /// caller can report it together with the base it wanted, which is far
    /// more useful than "directory missing" on its own.
    pub fn discover(explicit: Option<String>) -> Self {
        let candidates = loader_dir_candidates(
            explicit,
            std::env::var("DCLOAD_LOADER_DIR").ok(),
            std::env::current_exe().ok(),
            std::env::current_dir().ok(),
            env!("CARGO_MANIFEST_DIR"),
        );
        let chosen = candidates
            .iter()
            .find(|d| !LoaderSet::new((*d).clone()).available().is_empty())
            .or_else(|| candidates.iter().find(|d| d.is_dir()))
            .unwrap_or(&candidates[0])
            .clone();
        LoaderSet {
            dir: chosen,
            tried: candidates,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every directory `discover` considered, for a diagnostic that names them
    /// all rather than only the one it settled on.
    pub fn searched(&self) -> String {
        self.tried
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn path_for(&self, base: u32) -> PathBuf {
        self.dir.join(format!("dcload-0x{:08x}.elf", base))
    }

    pub fn has(&self, base: u32) -> bool {
        self.path_for(base).is_file()
    }

    /// The one image that can become any base, if `make loaders` built it.
    pub fn relocatable(&self) -> Option<PathBuf> {
        let p = self.dir.join(RELOCATABLE_NAME);
        p.is_file().then_some(p)
    }

    /// Can this set produce a loader for `base` at all?
    ///
    /// True for a base with its own pre-linked ELF, and true for ANY high base
    /// once the relocatable image is present -- which is the whole point of it:
    /// the set stops being a menu of addresses someone thought of in advance.
    pub fn can_provide(&self, base: u32) -> bool {
        self.has(base) || (base >= 0x8c01_0000 && self.relocatable().is_some())
    }

    /// The ELF to upload for `base`, and a label for the log.
    ///
    /// A pre-linked ELF wins when there is one: it is what has been tested, and
    /// relocating to a base we already have is work for nothing. Otherwise the
    /// relocatable image is moved in memory -- see `relocate`, which reproduces
    /// a native link byte for byte.
    pub fn image_for(&self, base: u32) -> Result<(Vec<u8>, String), String> {
        if self.has(base) {
            let p = self.path_for(base);
            return std::fs::read(&p)
                .map(|b| (b, p.display().to_string()))
                .map_err(|e| format!("cannot read {}: {e}", p.display()));
        }
        let p = self
            .relocatable()
            .ok_or_else(|| format!("no dcload-0x{base:08x}.elf and no {RELOCATABLE_NAME}"))?;
        let bytes = std::fs::read(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        let moved = relocate(&bytes, base)?;
        Ok((moved, format!("{} relocated to 0x{base:08x}", p.display())))
    }

    /// Which bases are actually on disk, for a diagnostic that tells the user
    /// what to build rather than only what is missing.
    pub fn available(&self) -> Vec<u32> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(rest) = name.strip_prefix("dcload-0x")
                    && let Some(hex) = rest.strip_suffix(".elf")
                    && let Ok(base) = u32::from_str_radix(hex, 16)
                {
                    out.push(base);
                }
            }
        }
        out.sort_unstable();
        out
    }
}

/// The highest address an ELF's loadable sections reach, ignoring the guest
/// vector table.
///
/// `.guestvbr` sits at 0x8c00f400, far from the image, and including it would
/// make every high-base loader look as though it stretched down into low RAM
/// and overlapped everything.
pub fn image_extent_bytes(bytes: &[u8]) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes)?;
    let (headers, strtab) = elf.section_headers_with_strtab()?;
    let headers = headers.ok_or("loader ELF has no section headers")?;
    let strtab = strtab.ok_or("loader ELF has no section name table")?;

    let mut lo = u32::MAX;
    let mut hi = 0u32;
    for sh in headers.iter() {
        if !is_uploadable(&sh) {
            continue;
        }
        let name = strtab.get(sh.sh_name as usize).unwrap_or("");
        if name == ".guestvbr" {
            continue;
        }
        lo = lo.min(sh.sh_addr as u32);
        hi = hi.max((sh.sh_addr + sh.sh_size) as u32);
    }
    if hi == 0 {
        return Err("loader ELF has no loadable sections".into());
    }
    Ok((lo, hi))
}

/// Whether an ELF section is something to send to the Dreamcast.
///
/// SHT_PROGBITS on its own is NOT enough, and getting that wrong is not
/// theoretical: `.symtab`, `.strtab`, `.shstrtab` and `.comment` all carry
/// contents and all sit at address 0, so uploading on type alone writes the
/// symbol table over the bottom of the address map. SHF_ALLOC is the flag that
/// means "occupies memory at run time", and a zero address means the section
/// was never assigned one.
pub fn is_uploadable(sh: &elf::section::SectionHeader) -> bool {
    sh.sh_type == elf::abi::SHT_PROGBITS
        && (sh.sh_flags & elf::abi::SHF_ALLOC as u64) != 0
        && sh.sh_addr != 0
        && sh.sh_size != 0
}

/// The sequence of bases to chainload through to get from `running` to `want`.
///
/// Empty means there is nothing to do.
///
/// EVERY MOVE GOES THROUGH THE SCRATCH BASE, deliberately, even when a direct
/// one looks safe. 0x8ce00000 is chosen once and for all as neutral ground: its
/// span is clear of every other base in the set in both directions, and a
/// pre-linked (non-relocatable) loader is built for it, so the first step never
/// depends on the relocation machinery working. From up there the final move is
/// always the same shape -- high, clear ground, into the address the title
/// actually wants -- instead of a different one per starting point.
///
/// The direct move was conditional on `clashes()` getting it right, and the
/// failure it guards against is silent: uploading a high image through a low
/// loader's packet buffers reports success at both ends and leaves a loader
/// that runs, has the correct PC and stack, and is deaf (AGENTS.md 14.17). One
/// extra 26 KB upload costs 0.04 s, measured; being wrong costs the session.
///
/// The hop is skipped only when it would be a no-op (already there, or that IS
/// the destination) or when it is not possible, in which case a direct move is
/// still attempted rather than giving up.
pub fn plan(running: u32, want: u32, want_image: (u32, u32), scratch_image: (u32, u32)) -> Vec<u32> {
    if running == want {
        return Vec::new();
    }
    if want == SCRATCH_BASE {
        // The neutral ground IS the destination; one move, if it is safe.
        return if clashes(running, want_image) {
            Vec::new()
        } else {
            vec![want]
        };
    }
    if running != SCRATCH_BASE
        && !clashes(running, scratch_image)
        && !clashes(SCRATCH_BASE, want_image)
    {
        return vec![SCRATCH_BASE, want];
    }
    // Either we are already on neutral ground, or it is unusable for this move.
    if !clashes(running, want_image) {
        return vec![want];
    }
    Vec::new()
}

/// Would writing `image` disturb a loader running at `base`?
fn clashes(base: u32, image: (u32, u32)) -> bool {
    overlapping_range(base, image).is_some()
}

/// The SH4 address of a byte of RAM, without its segment.
///
/// P0/P1/P2/P3 are four windows onto the same 16 MB: 0x0c010000, 0x8c010000
/// and 0xac010000 are one address written three ways, and both are in daily
/// use here -- the loader lives at 0x8c004000 while a title is uploaded to
/// 0x0c010000. Comparing the written form would make an overlap between them
/// invisible, which is precisely the collision worth catching.
fn physical(addr: u32) -> u32 {
    addr & 0x1fff_ffff
}

/// Which part of a loader running at `base` an upload of `image` would land
/// on, if any. Returns the offending range so the caller can say WHICH part.
///
/// The guest vector table is deliberately not caught: `live_footprint`'s low
/// range ends AT 0x8c00f400, exclusive, and a `.guestvbr` section starts
/// exactly there. Writing it over a live loader's copy is safe by inspection
/// (same bytes, and only reached on an exception), and every loader ELF
/// carries one, so treating it as a collision would refuse every legitimate
/// chainload.
pub fn overlapping_range(base: u32, image: (u32, u32)) -> Option<(u32, u32)> {
    let (lo, hi) = (physical(image.0), physical(image.1));
    live_footprint(base)
        .into_iter()
        .find(|range| physical(range.0) < hi && lo < physical(range.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Roughly what `make loaders` produces: a ~26 KB image at the base.
    fn image(base: u32) -> (u32, u32) {
        (base, base + 0x6600)
    }

    // A title that names one address: the shape of Sonic Adventure 2's Maple
    // DMA list at 0x8cff0000.
    fn clear_of(hot: u32) -> impl Fn(u32) -> bool {
        move |b: u32| !(b..b + LOADER_SPAN).contains(&hot)
    }

    #[test]
    fn a_free_base_is_found_below_the_one_the_preset_asked_for() {
        // 0x8cfe8000 collides; so does 0x8cfe0000, whose neighbour above still
        // holds the constant. 0x8cfd0000 is the first with a clear step either
        // side -- which is the margin the neighbour rule exists to buy.
        assert_eq!(
            search_free_base(0x8cfe_8000, clear_of(0x8cff_0000)),
            Some(0x8cfd_0000)
        );
    }

    #[test]
    fn a_base_that_is_already_clear_is_kept() {
        assert_eq!(
            search_free_base(0x8ce0_0000, clear_of(0x8cff_0000)),
            Some(0x8ce0_0000)
        );
    }

    #[test]
    fn the_search_never_leaves_high_ram() {
        // Nothing is ever clear: the answer is None, not an address below the
        // floor or a span running off the end of RAM.
        assert_eq!(search_free_base(0x8cfe_8000, |_| false), None);
    }

    #[test]
    fn every_candidate_span_fits_in_ram() {
        let seen = std::cell::Cell::new(0);
        search_free_base(0x8cfe_8000, |b| {
            seen.set(seen.get() + 1);
            assert!(b >= FREE_BASE_FLOOR, "0x{b:08x} is below the floor");
            assert!(
                b.checked_add(LOADER_SPAN).is_some_and(|e| e <= 0x8d00_0000),
                "0x{b:08x}..+span runs off the end of RAM"
            );
            false
        });
        assert!(seen.get() > 8, "only {} candidates were tried", seen.get());
    }

    #[test]
    fn the_fallback_stays_in_the_same_family() {
        // A high preset answered with the stock base would put the loader back
        // in the low RAM the preset moved it out of.
        let built = [0x8c00_4000, 0x8ce0_0000, 0x8cef_8000, 0x8cfe_8000];
        assert_eq!(nearest_clear_base(0x8cfe_8000, &built), Some(0x8cef_8000));
    }

    #[test]
    fn the_fallback_is_the_nearest_of_the_family() {
        let built = [0x8c00_4000, 0x8ce0_0000, 0x8cef_8000];
        // 0x8cef8000 is 0xf8000 away from 0x8cfe8000; 0x8ce00000 is 0x1e8000.
        assert_eq!(nearest_clear_base(0x8cfe_8000, &built), Some(0x8cef_8000));
    }

    #[test]
    fn a_low_preset_never_gets_a_high_fallback() {
        let built = [0x8c00_4000, 0x8ce0_0000, 0x8cef_8000];
        assert_eq!(nearest_clear_base(0x8c00_4000, &built), None);
    }

    #[test]
    fn nothing_built_means_no_fallback() {
        assert_eq!(nearest_clear_base(0x8cfe_8000, &[0x8cfe_8000]), None);
    }

    /// A minimal ELF32-LE executable: one PROGBITS section at `base` holding
    /// one word, and one RELA naming that word.
    fn tiny_elf(base: u32, word: u32) -> Vec<u8> {
        const EH: usize = 52;
        const SH: usize = 40;
        let shoff = EH + 4 + 12; // .text payload, then one Rela entry
        let mut b = vec![0u8; shoff + 3 * SH];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 1; // 32-bit
        b[5] = 1; // little-endian
        b[6] = 1;
        let w = |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let h = |b: &mut Vec<u8>, o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        h(&mut b, 16, 2); // ET_EXEC
        h(&mut b, 18, 42); // EM_SH
        w(&mut b, 20, 1);
        w(&mut b, 24, base); // e_entry
        w(&mut b, 32, shoff as u32);
        h(&mut b, 46, SH as u16);
        h(&mut b, 48, 3);
        h(&mut b, 50, 0);
        // .text contents, and the relocation that names its only word
        w(&mut b, EH, word);
        w(&mut b, EH + 4, base); // r_offset
        w(&mut b, EH + 8, 1); // r_info: R_SH_DIR32
        w(&mut b, EH + 12, 0); // r_addend
        // [1] .text
        let s1 = shoff + SH;
        w(&mut b, s1 + 4, 1); // SHT_PROGBITS
        w(&mut b, s1 + 8, 2 | 4); // ALLOC | EXECINSTR
        w(&mut b, s1 + 12, base);
        w(&mut b, s1 + 16, EH as u32);
        w(&mut b, s1 + 20, 4);
        // [2] .rela.text
        let s2 = shoff + 2 * SH;
        w(&mut b, s2 + 4, 4); // SHT_RELA
        w(&mut b, s2 + 16, (EH + 4) as u32);
        w(&mut b, s2 + 20, 12);
        w(&mut b, s2 + 36, 12); // sh_entsize
        b
    }

    fn word_of(elf: &[u8]) -> u32 {
        u32::from_le_bytes(elf[52..56].try_into().unwrap())
    }

    #[test]
    fn relocating_adds_the_delta_to_every_named_word() {
        let e = tiny_elf(0x8ce0_0000, 0x8ce0_1234);
        let moved = relocate(&e, 0x8cef_8000).unwrap();
        assert_eq!(word_of(&moved), 0x8cef_9234);
        // and the header and section header follow
        assert_eq!(u32::from_le_bytes(moved[24..28].try_into().unwrap()), 0x8cef_8000);
    }

    #[test]
    fn relocating_backwards_works_too() {
        // A negative delta is the case a wrapping bug survives.
        let e = tiny_elf(0x8ce0_0000, 0x8ce0_1234);
        let moved = relocate(&e, 0x8cc8_0000).unwrap();
        assert_eq!(word_of(&moved), 0x8cc8_1234);
    }

    #[test]
    fn relocating_to_the_same_base_changes_nothing() {
        let e = tiny_elf(0x8ce0_0000, 0x8ce0_1234);
        assert_eq!(relocate(&e, 0x8ce0_0000).unwrap(), e);
    }

    #[test]
    fn a_low_image_is_refused_rather_than_mangled() {
        // Its buffers are at fixed high addresses while its image is low, so no
        // single delta describes the move. Refusing beats moving half of it.
        let e = tiny_elf(0x8c00_4000, 0x8c00_5678);
        assert!(relocate(&e, 0x8cef_8000).is_err());
    }

    #[test]
    fn a_target_outside_ram_is_refused() {
        let e = tiny_elf(0x8ce0_0000, 0x8ce0_1234);
        assert!(relocate(&e, 0x8cff_f000).is_err(), "span would run off the end of RAM");
        assert!(relocate(&e, 0x8ce0_0002).is_err(), "unaligned");
    }

    #[test]
    fn an_image_without_relocations_is_refused_with_a_reason() {
        let mut e = tiny_elf(0x8ce0_0000, 0x8ce0_1234);
        // Turn the RELA section into something inert.
        let shoff = u32::from_le_bytes(e[32..36].try_into().unwrap()) as usize;
        e[shoff + 2 * 40 + 4] = 8; // SHT_NOBITS
        let err = relocate(&e, 0x8cef_8000).unwrap_err();
        assert!(err.contains("no relocations"), "unhelpful message: {err}");
    }

    #[test]
    fn same_base_does_nothing() {
        assert!(plan(DEFAULT_BASE, DEFAULT_BASE, image(DEFAULT_BASE), image(SCRATCH_BASE)).is_empty());
    }

    #[test]
    fn moving_to_the_scratch_base_is_one_step() {
        // It is the neutral ground; there is nothing to hop through.
        let plan = plan(DEFAULT_BASE, SCRATCH_BASE, image(SCRATCH_BASE), image(SCRATCH_BASE));
        assert_eq!(plan, vec![SCRATCH_BASE]);
    }

    #[test]
    fn every_other_move_goes_through_the_scratch_base() {
        // Even one that would have been safe directly: the first step is always
        // the same pre-linked loader on the same neutral ground.
        let plan = plan(DEFAULT_BASE, 0x8cef_8000, image(0x8cef_8000), image(SCRATCH_BASE));
        assert_eq!(plan, vec![SCRATCH_BASE, 0x8cef_8000]);
    }

    #[test]
    fn already_on_neutral_ground_does_not_hop_to_itself() {
        let plan = plan(SCRATCH_BASE, 0x8cef_8000, image(0x8cef_8000), image(SCRATCH_BASE));
        assert_eq!(plan, vec![0x8cef_8000]);
    }

    #[test]
    fn low_to_0x8cfe8000_must_not_be_direct() {
        // Sonic Adventure 2's address, and the one that looks safe and is not:
        // a low loader's packet buffers live at 0x8cfe8000/0x8cfe9000, so the
        // new image would be written straight through them.
        let plan = plan(DEFAULT_BASE, 0x8cfe_8000, image(0x8cfe_8000), image(SCRATCH_BASE));
        assert_eq!(plan, vec![SCRATCH_BASE, 0x8cfe_8000]);
    }

    #[test]
    fn low_to_lower_needs_the_hop() {
        // 0x8c000100 + 26 KB runs straight through a loader running at
        // 0x8c004000, so this one cannot be done in place.
        let plan = plan(DEFAULT_BASE, 0x8c00_0100, image(0x8c00_0100), image(SCRATCH_BASE));
        assert_eq!(plan, vec![SCRATCH_BASE, 0x8c00_0100]);
    }

    #[test]
    fn high_to_low_is_direct_from_neutral_ground() {
        let plan = plan(SCRATCH_BASE, 0x8c00_0100, image(0x8c00_0100), image(SCRATCH_BASE));
        assert_eq!(plan, vec![0x8c00_0100]);
    }

    #[test]
    fn a_loader_cannot_be_uploaded_over_itself() {
        // What killed the console on 2026-08-15: refreshing the loader at the
        // address it is already running from.
        assert!(overlapping_range(DEFAULT_BASE, image(DEFAULT_BASE)).is_some());
    }

    #[test]
    fn a_title_at_0x0c010000_is_not_a_collision() {
        // THE ALIAS CASE. A title is uploaded to P0 and the loader lives in
        // P1; they are the same RAM, so the comparison has to be physical --
        // and having made it physical, it must not start refusing the one
        // upload that happens on every single run.
        let sonic_adventure_2 = (0x0c01_0000u32, 0x0c01_0000 + 1_578_116);
        assert_eq!(overlapping_range(DEFAULT_BASE, sonic_adventure_2), None);
        assert_eq!(overlapping_range(SCRATCH_BASE, sonic_adventure_2), None);
    }

    #[test]
    fn a_title_large_enough_to_reach_the_packet_buffers_is_a_collision() {
        // 0x0c010000 + 15.9 MB runs into the buffers at 0x8cfe8000 that the
        // upload is arriving in. Written as P0, caught against a P1 range.
        let huge = (0x0c01_0000u32, 0x0cff_0000);
        assert_eq!(
            overlapping_range(DEFAULT_BASE, huge),
            Some((0x8cfe_8000, 0x8cfe_a000))
        );
    }

    #[test]
    fn the_guest_vector_table_is_never_a_collision() {
        // Every loader ELF carries .guestvbr at 0x8c00f400, and it is always
        // written over the running loader's copy. Catching it would refuse
        // every chainload there is.
        let guestvbr = (0x8c00_f400u32, 0x8c00_fc00);
        assert_eq!(overlapping_range(DEFAULT_BASE, guestvbr), None);
        assert_eq!(overlapping_range(SCRATCH_BASE, guestvbr), None);
    }

    #[test]
    fn the_scratch_base_is_clear_of_a_low_loader_both_ways() {
        assert_eq!(overlapping_range(DEFAULT_BASE, image(SCRATCH_BASE)), None);
        assert_eq!(overlapping_range(SCRATCH_BASE, image(DEFAULT_BASE)), None);
    }

    #[test]
    fn explicit_directory_is_the_only_candidate() {
        let c = loader_dir_candidates(
            Some("/somewhere/else".into()),
            Some("/ignored".into()),
            Some(PathBuf::from("/proj/target/debug/dc")),
            Some(PathBuf::from("/proj")),
            "/proj",
        );
        assert_eq!(c, vec![PathBuf::from("/somewhere/else")]);
    }

    #[test]
    fn env_overrides_everything_but_the_argument() {
        let c = loader_dir_candidates(
            None,
            Some("/from/env".into()),
            Some(PathBuf::from("/proj/target/debug/dc")),
            Some(PathBuf::from("/proj")),
            "/proj",
        );
        assert_eq!(c, vec![PathBuf::from("/from/env")]);
    }

    #[test]
    fn the_project_root_beats_the_target_directory() {
        // What the search sees for a real `cargo run`: the exe lives in
        // target/debug, and the root is what must win -- a stale
        // target/debug/loaders is the failure this ordering exists to prevent.
        let root = std::env::temp_dir().join(format!("dcl-root-{}", std::process::id()));
        let exe = root.join("target").join("debug").join("dc");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[package]").unwrap();

        let c = loader_dir_candidates(None, None, Some(exe.clone()), None, "/elsewhere");
        assert_eq!(c[0], root.join("loaders"));
        assert!(c.contains(&exe.parent().unwrap().join("loaders")));
        assert!(
            c.iter().position(|p| p == &root.join("loaders")).unwrap()
                < c.iter()
                    .position(|p| p == &exe.parent().unwrap().join("loaders"))
                    .unwrap(),
            "the root must be searched before target/"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn debug_and_release_resolve_to_the_same_directory() {
        let root = std::env::temp_dir().join(format!("dcl-prof-{}", std::process::id()));
        std::fs::create_dir_all(root.join("target").join("debug")).unwrap();
        std::fs::create_dir_all(root.join("target").join("release")).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[package]").unwrap();

        let dbg = loader_dir_candidates(
            None,
            None,
            Some(root.join("target").join("debug").join("dc")),
            None,
            "/elsewhere",
        );
        let rel = loader_dir_candidates(
            None,
            None,
            Some(root.join("target").join("release").join("dc")),
            None,
            "/elsewhere",
        );
        assert_eq!(dbg[0], rel[0]);
        assert_eq!(dbg[0], root.join("loaders"));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_installed_binary_falls_back_to_the_manifest_directory() {
        // No Cargo.toml anywhere above ~/.cargo/bin, so the compiled-in path
        // is the only thing left that points at a real checkout.
        let c = loader_dir_candidates(
            None,
            None,
            Some(PathBuf::from("/home/u/.cargo/bin/dcload-ip-rs")),
            None,
            "/src/dcload-ip-rs",
        );
        assert_eq!(c[0], PathBuf::from("/src/dcload-ip-rs/loaders"));
    }

    #[test]
    fn an_empty_directory_does_not_shadow_a_populated_one() {
        let root = std::env::temp_dir().join(format!("dcl-empty-{}", std::process::id()));
        let empty = root.join("empty");
        let full = root.join("full");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::create_dir_all(&full).unwrap();
        std::fs::write(full.join("dcload-0x8c004000.elf"), b"not really an elf").unwrap();

        assert!(LoaderSet::new(empty.clone()).available().is_empty());
        assert_eq!(LoaderSet::new(full.clone()).available(), vec![0x8c00_4000]);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_game_db_follows_an_explicit_loader_dir() {
        // --loader-dir moves the pair: a deployed set keeps the table beside
        // the ELFs, so that directory has to be searched first.
        let c = game_db_candidates(
            None,
            None,
            Path::new("/deployed/loaders"),
            Some(Path::new("/proj/target/debug/dc")),
            None,
            "/proj",
        );
        assert_eq!(c[0], PathBuf::from("/deployed/loaders/game-presets.tsv"));
    }

    #[test]
    fn the_game_db_is_searched_in_the_project_root() {
        let c = game_db_candidates(
            None,
            None,
            Path::new("/proj/loaders"),
            Some(Path::new("/home/u/.cargo/bin/dcload-ip-rs")),
            None,
            "/proj",
        );
        assert!(c.contains(&PathBuf::from("/proj/game-presets.tsv")));
        assert!(c.contains(&PathBuf::from("/proj/loaders/game-presets.tsv")));
        // and never inside target/ before either of those
        let root = c
            .iter()
            .position(|p| p == &PathBuf::from("/proj/game-presets.tsv"))
            .unwrap();
        let beside_exe = c
            .iter()
            .position(|p| p == &PathBuf::from("/home/u/.cargo/bin/game-presets.tsv"))
            .unwrap();
        assert!(root < beside_exe);
    }

    #[test]
    fn an_explicit_game_db_wins_outright() {
        let c = game_db_candidates(
            Some("/tmp/mine.tsv".into()),
            Some("/tmp/env.tsv".into()),
            Path::new("/proj/loaders"),
            None,
            None,
            "/proj",
        );
        assert_eq!(c, vec![PathBuf::from("/tmp/mine.tsv")]);
    }

    #[test]
    fn debug_and_release_find_the_same_game_db() {
        let root = std::env::temp_dir().join(format!("dcl-db-{}", std::process::id()));
        std::fs::create_dir_all(root.join("target").join("debug")).unwrap();
        std::fs::create_dir_all(root.join("target").join("release")).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[package]").unwrap();

        // The loader dir is what discover() would have returned in each case.
        let dbg = game_db_candidates(
            None,
            None,
            &root.join("loaders"),
            Some(&root.join("target").join("debug").join("dc")),
            None,
            "/elsewhere",
        );
        let rel = game_db_candidates(
            None,
            None,
            &root.join("loaders"),
            Some(&root.join("target").join("release").join("dc")),
            None,
            "/elsewhere",
        );
        // The two lists may differ only in their last-resort entry, which is
        // the profile's own output directory -- everything that can actually
        // be found is identical, and the root comes first.
        let strip = |v: Vec<PathBuf>| -> Vec<PathBuf> {
            v.into_iter()
                .filter(|p| !p.starts_with(root.join("target")))
                .collect()
        };
        assert_eq!(strip(dbg.clone()), strip(rel));
        assert_eq!(dbg[1], root.join("game-presets.tsv"));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn version_payload_carries_the_base() {
        let mut payload = b"dcload-ip 2.0.4 using RTL8139\0".to_vec();
        payload.extend_from_slice(&0x8cfe_8000u32.to_be_bytes());
        let size = payload.len();
        payload.resize(1440, 0);
        let (text, base) = parse_version_payload(&payload, size);
        assert_eq!(text, "dcload-ip 2.0.4 using RTL8139");
        assert_eq!(base, Some(0x8cfe_8000));
    }

    #[test]
    fn version_payload_without_a_base_is_not_an_error() {
        // What an older loader sends: string, NUL, nothing else.
        let payload = b"dcload-ip 2.0.3 using RTL8139\0".to_vec();
        let size = payload.len();
        let (text, base) = parse_version_payload(&payload, size);
        assert_eq!(text, "dcload-ip 2.0.3 using RTL8139");
        assert_eq!(base, None);
    }
}
