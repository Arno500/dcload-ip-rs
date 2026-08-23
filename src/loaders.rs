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
    const DB: &str = "game-presets.tsv";

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

    push(loader_dir.join(DB));
    for root in project_roots(exe, cwd, manifest_dir) {
        push(root.join(DB));
        push(root.join("loaders").join(DB));
    }
    if let Some(dir) = exe.and_then(Path::parent) {
        push(dir.join(DB));
    }
    push(PathBuf::from(DB));
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
pub fn image_extent(path: &Path) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes.as_slice())?;
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
/// Empty means there is nothing to do. One element is a direct move. Two means
/// the direct move would have written the new image through the running
/// loader, so it goes up to high RAM first.
pub fn plan(running: u32, want: u32, want_image: (u32, u32), scratch_image: (u32, u32)) -> Vec<u32> {
    if running == want {
        return Vec::new();
    }
    if !clashes(running, want_image) {
        return vec![want];
    }
    // Only worth the hop if the scratch base really is clear at both ends.
    if !clashes(running, scratch_image) && !clashes(SCRATCH_BASE, want_image) {
        return vec![SCRATCH_BASE, want];
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

    #[test]
    fn same_base_does_nothing() {
        assert!(plan(DEFAULT_BASE, DEFAULT_BASE, image(DEFAULT_BASE), image(SCRATCH_BASE)).is_empty());
    }

    #[test]
    fn low_to_high_is_direct_when_it_clears_the_packet_buffers() {
        // 0x8ce00000 is clear of everything a low loader touches.
        let plan = plan(DEFAULT_BASE, SCRATCH_BASE, image(SCRATCH_BASE), image(SCRATCH_BASE));
        assert_eq!(plan, vec![SCRATCH_BASE]);
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
    fn high_to_low_is_direct() {
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
