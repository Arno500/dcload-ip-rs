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
/// Chosen because its own footprint (0x8ce00000..0x8ce0bc00) is clear of every
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
/// The ranges come from `layout()`, which is the one copy of DCLOAD_STACK /
/// DCLOAD_HIRAM / DCLOAD_MAPLE on this side.
pub fn live_footprint(base: u32) -> Vec<(u32, u32)> {
    let l = layout(base);
    if is_high(base) {
        // A high loader keeps all of it together: image, stack, .hiram and the
        // Maple DMA buffer, in that order, from the base.
        vec![(l.image, l.maple + LAYOUT_PAGE)]
    } else {
        vec![
            // Image, BSS, and the stack descending from the BIOS VBR.
            (l.image, l.stack),
            // Maple DMA buffer (2 KB) and the .hiram buffers, in high RAM,
            // as one range. .hiram is 12 KB reserved (packet buffers plus the
            // CDDA staging buffer) -- see the layout table in
            // target-src/dcload/Makefile, which this mirrors.
            (l.maple, l.hiram + HIRAM_RESERVED),
        ]
    }
}

/// The four addresses one loader build is pinned to.
///
/// THIS IS THE LAYOUT TABLE in target-src/dcload/Makefile, and the only copy of
/// it on the host. `live_footprint` and `relocate` both read it, so they cannot
/// come to disagree about where a loader's buffers are -- which they would
/// otherwise, since one of them decides what an upload may overwrite and the
/// other decides what an address in the image is rewritten to.
///
/// The two families exist because 0x8cfe8000 and 0x8cfe9000 are INSIDE the
/// image once the base is 0x8cfe8000. HIGH therefore takes all four relative to
/// the base. LOW keeps the image where every KOS program expects it -- the
/// magic at base+4, the syscall trampoline at base+8 -- with its stack
/// descending from the BIOS VBR directly above it and its two big buffers far
/// away in high RAM, out of reach of a title's descending stack (AGENTS.md 4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// The image: text, rodata, data, bss. The base itself.
    pub image: u32,
    /// The loader's own stack TOP. It descends from here, and for a LOW base it
    /// is the BIOS VBR, which does not follow the image.
    pub stack: u32,
    /// The `.hiram` packet buffers (3 KB).
    pub hiram: u32,
    /// The Maple DMA buffer (2 KB).
    pub maple: u32,
}

/// The width the layout gives the Maple DMA buffer, in both families.
///
/// It is 2 KB, so a page is loose enough to contain `_maple_dma_buffer_end`
/// -- one past the last byte, and named by a relocation like any other symbol
/// -- and tight enough never to reach the neighbouring region.
///
/// NOT `.hiram`, which is `HIRAM_RESERVED` wide and was measured at 4 KB only
/// before CD-DA put a 7 KB staging buffer in it. Classifying `.hiram` by a
/// page meant `__hiram_end` (0x2790 past the start of the section) belonged to
/// no region, and `relocate` refuses what it cannot classify rather than
/// guessing -- so the relocatable loader stopped relocating AT ALL, at every
/// base, the moment that buffer was added. The unit test caught it; nothing on
/// a console would have, because the failure is a message before the upload.
pub const LAYOUT_PAGE: u32 = 0x1000;

/// How much high RAM `.hiram` reserves, whatever the build put in it.
///
/// RESERVED UNCONDITIONALLY, not measured from an ELF. The loader has build
/// flags that change what lands there -- `WITH_CDDA` alone is 7 KB of audio
/// staging -- and this host cannot see which flags a running loader was built
/// with. Reserving the maximum makes the table right for every build; sizing
/// it to one build makes it silently wrong for the others, and being wrong
/// here means placing the next loader on top of the running one's buffers,
/// which reports nothing at either end (AGENTS.md 4.11 item 4).
pub const HIRAM_RESERVED: u32 = 0x3000;

/// dcload's own worst-case stack excursion BELOW the SP a GD syscall is
/// entered with.
///
/// The emulated GD driver runs on the GAME'S stack, on purpose and by design:
/// `cdfs_redir.s` parks the inactive coroutine's frame in `saved_regs[]`
/// instead of giving the loader a second stack, precisely so the network path
/// keeps running where it is known to fit. So every byte dcload's read path
/// uses is a byte taken off the title's own stack, below the deepest point the
/// title ever reaches on its own.
///
/// 1352 bytes, measured over `dcload-0x8c004000.elf` by summing the frame of
/// every function reachable from `gdGdcReqCmd` along the deepest chain
/// (prologue `add #-N,r15` plus each register pushed with `@-r15`). Rounded up
/// to 2 KB, because the number is a property of one build and this constant has
/// to hold for the next one.
pub const GD_STACK_WORST_CASE: u32 = 2048;

/// How much room a LOW base must leave between the loader's `_end` and the
/// lowest SP the title has been seen entering a GD syscall with.
///
/// THIS IS THE THIRD PLACEMENT TEST, and the only one that can see the failure
/// it is named for. The other two -- the constant scan and the learned map --
/// look for an address COLLISION: RAM the title names, or RAM its disc reads
/// have landed in. A stack is neither. It is not named by any constant, no read
/// ever lands in it, and it arrives from above, growing down into whatever the
/// loader left below `0x8c00f400`.
///
/// The two measurements that fix the value, both on Sonic Adventure at the
/// stock base, both from AGENTS.md 4.6:
///
///   margin 5240 bytes (`_end` 0x8c00a558) -- booted and played, 1624 reads
///   margin 2444 bytes (`_end` 0x8c00b044) -- the title corrupted the loader
///
/// The first CD-DA engine is what moved it between the two; the current one
/// costs ~6.8 KB, and with it the default `_end` (0x8c00c58c) is above Sonic
/// Adventure's SP, so that title no longer passes this test at the stock base.
/// 4096 sits between the two measurements, and the reason it is not larger is
/// AGENTS.md 14.9 -- a guard that rejects the one configuration measured to
/// work guards nothing. `GD_STACK_WORST_CASE` is most of what it has to cover;
/// the rest is the title's own frames below the point this can see.
pub const LOW_BASE_MIN_MARGIN: u32 = 4096;

pub fn layout(base: u32) -> Layout {
    if is_high(base) {
        Layout {
            image: base,
            stack: base + 0xbc00,
            hiram: base + 0xc000,
            maple: base + 0xf000,
        }
    } else {
        Layout {
            image: base,
            stack: 0x8c00_f400,
            hiram: 0x8cfe_9000,
            maple: 0x8cfe_8000,
        }
    }
}

/// The part of `live_footprint(base)` NO TITLE HAS BUSINESS ADDRESSING.
///
/// A low loader shares its region with the BIOS work area by construction
/// (AGENTS.md 4.6): 0x8c008000 is where IP.BIN lives, and a title reads its own
/// disc header there as a matter of course. Measured: Sonic Adventure -- which
/// runs perfectly at the stock base -- has eleven constants in
/// 0x8c0080f0..0x8c008208, every one of them legitimate. Reporting those would
/// have the collision check crying wolf on the one title known to work, and a
/// guard that always fires guards nothing (AGENTS.md 14.9).
///
/// The high ranges are different, and a low loader HAS ONE: its packet buffers
/// and Maple DMA buffer live at 0x8cfe8000, in RAM a title owns outright. So
/// this is not "skip the check for low bases" -- it is "check every range the
/// title has no claim on", which for a low base is the buffers alone.
///
/// Both the constant scan and the learned-map check read this, so they cannot
/// come to disagree about which RAM is the loader's.
pub fn exclusive_footprint(base: u32) -> Vec<(u32, u32)> {
    live_footprint(base)
        .into_iter()
        .filter(|&(lo, _)| is_high(lo))
        .collect()
}

/// Which of the two layout families a base belongs to: HIGH keeps stack,
/// `.hiram` and Maple buffer relative to the base, LOW leaves them at
/// 0x8cfe8000 whatever the image's address (AGENTS.md 4.11). `relocate` crosses
/// the line -- it moves each region by its own delta -- but a FALLBACK never
/// does: answering a low request with a high base trades the collision the
/// preset avoids for the one it exists to avoid.
pub fn is_high(base: u32) -> bool {
    base >= 0x8c01_0000
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
const FREE_BASE_FLOOR: u32 = ISOLDR_DEFAULT_ADDR;
const FREE_BASE_STEP: u32 = 0x1_0000;

/// isoldr's own two answers to "the loader must be out of the title's way",
/// and the reason a preset naming NEITHER is information rather than a shrug.
///
/// DreamShell places isoldr at `ISOLDR_DEFAULT_ADDR` by default and at `_HIGH`
/// when that is not enough. A preset that instead asks for `_MIN` (0x8c000100)
/// or `_MIN_GINSU` (0x8c001100) -- 276 of the database's 1026 rows -- is saying
/// that BOTH of these were rejected for that title, and that the loader had to
/// go below the BIOS syscall area, which is the only place left. An unsupported
/// preset is therefore not "no opinion about where the loader goes". It is the
/// strongest opinion in the database, and what it rules out is exactly the two
/// addresses a host with nothing else to go on reaches for first.
///
/// Measured 2026-08-28 on Jet Set Radio, whose preset is 0x8c000100: the host
/// could not honour it, kept the loader where it happened to be -- 0x8ce00000,
/// which is this constant -- and the title both loads that address as a literal
/// (at 0x8c013bde) and read a disc sector onto it 81 reads into the boot.
pub const ISOLDR_DEFAULT_ADDR: u32 = 0x8ce0_0000;
pub const ISOLDR_HIGH_ADDR: u32 = 0x8cfe_8000;

/// Would a loader at `base` sit where isoldr would have, for a title whose
/// preset says isoldr could not?
///
/// Overlap of the spans, not equality: isoldr's build is 13 KB and ours is
/// 0xe000, so "DreamShell could not fit 13 KB here" says nothing good about a
/// 56 KB image starting one step away.
pub fn ruled_out_by_low_preset(base: u32) -> bool {
    [ISOLDR_DEFAULT_ADDR, ISOLDR_HIGH_ADDR]
        .iter()
        .any(|&addr| base.abs_diff(addr) < LOADER_SPAN)
}

/// The same, for a title whose preset cannot be honoured -- floored by where
/// that title's OWN IMAGE ends instead of by a constant.
///
/// `FREE_BASE_FLOOR` exists because "below it a loader starts competing with the
/// title's own image, which is loaded at 0x8c010000 and is routinely megabytes
/// long". That is a guess this host does not have to make: it uploaded the
/// image and knows its length. Jet Set Radio's is 334 KB, and against that the
/// constant floor hides **12.4 MB of RAM no disc read has ever landed in**
/// behind an assumption about a different game -- while the only room left above
/// it is a single 64 KB block with the title's data hard against both sides.
///
/// Only for that path. The normal one keeps the constant, because its ordering
/// is what Sonic Adventure and Sonic Adventure 2 were measured against, and a
/// title whose preset CAN be built has no reason to go looking down here.
///
/// One step of margin above the image, and `search_free_base`'s neighbour rule
/// buys another: a title that allocates immediately after its own image is the
/// obvious hazard down here.
pub fn window_above_image(image_end: u32) -> (u32, u32) {
    let floor = (image_end.max(0x8c01_0000).div_ceil(FREE_BASE_STEP) + 1) * FREE_BASE_STEP;
    (floor, 0x8d00_0000)
}

/// The candidate base furthest from both ends of `[lo, hi)`.
///
/// CENTRED, because the only spans worth handing to this are ones bounded by
/// RAM the title really does use: the middle is then the furthest point from
/// both walls, and the walls are the only evidence there is. Aligned to the
/// same step `search_free_base` uses, so the answer is one it could also have
/// reached and reads the same way in a log.
pub fn base_in_span(lo: u32, hi: u32) -> Option<u32> {
    let first = lo.div_ceil(FREE_BASE_STEP) * FREE_BASE_STEP;
    let last = (hi.checked_sub(LOADER_SPAN)? / FREE_BASE_STEP) * FREE_BASE_STEP;
    (last >= first).then(|| first + ((last - first) / FREE_BASE_STEP / 2) * FREE_BASE_STEP)
}

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
    search_free_base_above(FREE_BASE_FLOOR, wanted, is_clear)
}

/// The same walk, from a floor the caller chose. See `window_above_image` for
/// the one case that does not want the constant.
pub fn search_free_base_above(
    floor: u32,
    wanted: u32,
    is_clear: impl Fn(u32) -> bool,
) -> Option<u32> {
    let free_base_floor = floor;
    let ceiling = (0x8d00_0000 - LOADER_SPAN) & !(FREE_BASE_STEP - 1);
    // A `wanted` OUTSIDE THE WINDOW IS A STARTING POINT, NEVER AN ANSWER.
    // Callers pass the address a preset asked for, and 276 of the 1026 presets
    // ask for one below 0x8c004000 -- an address no relocation can produce.
    // Returning it here, or letting it seed the scan (the old `min(ceiling)`
    // clamped only the top, so a low `wanted` started the upward walk at
    // 0x8c010000), offers a base inside the title's own image.
    if (free_base_floor..=ceiling).contains(&wanted) && is_clear(wanted) {
        return Some(wanted);
    }
    let start = wanted.clamp(free_base_floor, ceiling) & !(FREE_BASE_STEP - 1);
    let down = (free_base_floor..=start).rev().step_by(FREE_BASE_STEP as usize);
    let up = ((start + FREE_BASE_STEP)..=ceiling).step_by(FREE_BASE_STEP as usize);
    // THE NEIGHBOURS HAVE TO BE CLEAR TOO, which buys a step of margin on each
    // side. What is detected is a constant -- an address the title NAMES -- and
    // what will be written is a buffer of some size around it. Landing 8 KB
    // under a known Maple DMA list satisfies "no constant inside my span" and
    // is still a bad place to be.
    down.chain(up).find(|&b| {
        b != wanted
            && is_clear(b)
            && (b < free_base_floor + FREE_BASE_STEP || is_clear(b - FREE_BASE_STEP))
            && (b + FREE_BASE_STEP > ceiling || is_clear(b + FREE_BASE_STEP))
    })
}

/// How wide a loader's own span is, from its base. Mirrors the HIGH layout in
/// target-src/dcload/Makefile: stack at +0xbc00, .hiram at +0xc000, Maple DMA
/// at +0xd000.
pub const LOADER_SPAN: u32 = 0x10000;

/// How big the loader image is allowed to be for the CHEAP feasibility test
/// below. Measured `_end - base = 0x65f8` on the build this was written
/// against, rounded up with room to grow; `relocate` reads the real `_end` out
/// of the ELF and is the authority.
const LOADER_IMAGE_MAX: u32 = 0x8000;

/// Whether `relocate` could put a loader at `base`, decided without reading an
/// ELF: alignment, RAM, and enough room under a stack that for a LOW base does
/// not follow the image down.
///
/// This exists because "can the set answer for this base" is asked before
/// anything has been read from disk -- and answering it with "is it high?", as
/// it was until 2026-08-28, told someone whose title wanted the stock base to
/// go and build a file that was already sitting in the directory.
pub fn could_relocate_to(base: u32) -> bool {
    plausible_base(base)
        && live_footprint(base)
            .iter()
            .all(|&(lo, hi)| lo < hi && hi <= 0x8d00_0000)
        && base.saturating_add(LOADER_IMAGE_MAX).saturating_add(800) < layout(base).stack
}

/// Move a relocatable loader image to `to`, without rebuilding it.
///
/// WHY THIS WORKS, AND HOW THAT IS KNOWN.
///
/// The loader is linked with `ld -q`, which keeps the relocations in the ELF.
/// It emits exactly one type, `R_SH_DIR32`: an absolute 32-bit address in a
/// literal pool or a data word. Everything else in the image -- every branch,
/// every PC-relative load -- is already position-independent. So relocating is
/// "rewrite each word a relocation names", and nothing more.
///
/// NOT ONE DELTA, FOUR. A loader is pinned to four addresses (`Layout`) and
/// only the HIGH family moves them together, which is why this used to refuse
/// every base below 0x8c010000. Each relocation is classified by THE VALUE OF
/// THE SYMBOL IT NAMES -- image, stack, `.hiram` or Maple DMA buffer -- and gets
/// that region's delta. For a move inside one family all four deltas are equal
/// and this is the flat delta it always was; for a move that crosses families
/// they differ, and that difference is the whole of what was missing.
///
/// The symbol's value, not the word's: `commands.c` reaches its own base
/// through the P2 window, so the word reads 0xace00000 where the symbol is
/// 0x8ce00000. Adding the region's delta to the word preserves both the window
/// bits and any addend. (`_dcload_base` is also why classifying by the symbol's
/// SECTION does not work: the linker script PROVIDEs it after `.hiram`, so ld
/// files it there, four words away from the region it actually names.)
///
/// `.guestvbr` is not covered by the relocations and IS base-dependent.
/// exception.S reaches the loader through the fixed jump table at base+0x00..
/// +0x20 that dcload-crt0.s publishes (`.long DCLOAD_BASE + …`), and that image
/// is linked separately, at the guest VBR, then folded in with objcopy -- so
/// its six references arrive as plain literals with nothing naming them. They
/// are patched by content, and then every unmoved section is re-scanned: a word
/// still naming the image at its old base is an error, not a silent miss. Left
/// alone, as it was until 2026-08-28, a relocated loader hands the title a
/// vector table whose handlers jump back to whatever is at the base it was
/// linked for -- and only when the title faults, which is the moment the dump
/// exists for.
///
/// Measured 2026-08-28 against the four natively linked loaders `make loaders`
/// builds: relocating the image linked at 0x8ce00000 reproduces
/// dcload-0x8c004000.elf, dcload-0x8ce00000.elf, dcload-0x8cef8000.elf and
/// dcload-0x8cfe8000.elf BYTE FOR BYTE, `.guestvbr` included. The 833
/// relocations split 824 image / 7 `.hiram` / 1 stack / 1 Maple, and the first
/// of those four bases crosses families.
///
/// (Earlier, 2026-08-27, with a flat delta: 833 words differ between two HIGH
/// bases, every one of them by exactly the delta, and the relocations name
/// exactly those 833 words -- none missed, and none naming a word that does not
/// change. That second half is what proves no relocation points at a hardware
/// register.)
pub fn relocate(elf: &[u8], to: u32) -> Result<Vec<u8>, String> {
    const SHT_SYMTAB: u32 = 2;
    const SHT_RELA: u32 = 4;
    const SHT_NOBITS: u32 = 8;
    const SHF_ALLOC: u32 = 2;
    const STT_SECTION: u8 = 3;

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
    if !plausible_base(to) {
        return Err(format!("0x{to:08x} is not an address in the Dreamcast's RAM"));
    }
    let (src, dst) = (layout(from), layout(to));

    /// Which of the four addresses in `Layout` something belongs to.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Region {
        Image,
        Stack,
        Hiram,
        Maple,
    }
    // Two classifiers, and they differ in one arm ON PURPOSE. A SECTION at the
    // stack top is `.guestvbr` -- at the stock base the guest VBR and the
    // loader's own stack top are the same address, 0x8c00f400 -- while a SYMBOL
    // there is `_stack`. Using one for both would move the guest's vector table
    // whenever the source image was a low one.
    let region_of_section = |a: u32| -> Option<Region> {
        if a >= src.image && a < src.stack {
            Some(Region::Image)
        } else if a >= src.hiram && a < src.hiram + HIRAM_RESERVED {
            Some(Region::Hiram)
        } else if a >= src.maple && a < src.maple + LAYOUT_PAGE {
            Some(Region::Maple)
        } else {
            None
        }
    };
    let region_of_symbol =
        |a: u32| -> Option<Region> { region_of_section(a).or((a == src.stack).then_some(Region::Stack)) };
    let delta_of = |r: Region| -> u32 {
        match r {
            Region::Image => dst.image.wrapping_sub(src.image),
            Region::Stack => dst.stack.wrapping_sub(src.stack),
            Region::Hiram => dst.hiram.wrapping_sub(src.hiram),
            Region::Maple => dst.maple.wrapping_sub(src.maple),
        }
    };

    let shoff = rd(32) as usize;
    let shentsize = rd16(46) as usize;
    let shnum = rd16(48) as usize;
    if shoff == 0 || shnum == 0 || shentsize < 40 || shoff + shnum * shentsize > elf.len() {
        return Err("section headers are out of range".into());
    }

    // The allocated sections, split by whether they move; where the image ends,
    // which is `_end` and is what has to fit under the stack; and the symbol
    // table, without which no relocation can be classified.
    let mut moving: Vec<(u32, u32, usize, u32, Region)> = vec![]; // addr, size, offset, type, region
    let mut fixed: Vec<(u32, usize)> = vec![]; // size and file offset of what stays put
    let mut image_end = from;
    let mut has_rela = false;
    let mut symtab: Option<(usize, usize, usize)> = None; // offset, size, entry size
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let (typ, flags, addr, off, size) =
            (rd(sh + 4), rd(sh + 8), rd(sh + 12), rd(sh + 16), rd(sh + 20));
        if typ == SHT_RELA {
            has_rela = true;
        }
        if typ == SHT_SYMTAB {
            symtab = Some((off as usize, size as usize, rd(sh + 36) as usize));
        }
        if flags & SHF_ALLOC == 0 || size == 0 {
            continue;
        }
        match region_of_section(addr) {
            Some(r) => {
                if r == Region::Image {
                    image_end = image_end.max(addr.saturating_add(size));
                }
                moving.push((addr, size, off as usize, typ, r));
            }
            None if typ != SHT_NOBITS => fixed.push((size, off as usize)),
            None => {}
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
    let Some((symoff, symsize, symentsize)) = symtab else {
        return Err(
            "this loader has no symbol table, so its relocations cannot be told apart -- \
             do not strip dcload-relocatable.elf"
                .into(),
        );
    };
    if symentsize < 16 || symoff + symsize > elf.len() {
        return Err("the symbol table is out of range".into());
    }

    // Everything the loader would occupy has to be in RAM, and the image has to
    // fit under a stack that, for a LOW base, does not come down with it. The
    // rules are the link script's own two ASSERTs, the checks a native link
    // would have made: every allocated section of the image at or under
    // _stack, and (_stack - _end) > 800. `.gdstage` (NOLOAD, above `_end`)
    // lives INSIDE the loader's stack on purpose -- the stack is dead while a
    // title runs, the only time the stage is used (dcload.x.in) -- so the 800
    // bytes are measured from the `_end` symbol, not from the top of the
    // sections. Measured from the sections, every build within 800 bytes of a
    // full stage was refused although it linked.
    let image_len = image_end.wrapping_sub(from);
    if to.saturating_add(image_len) > dst.stack {
        return Err(format!(
            "a {image_len}-byte image at 0x{to:08x} runs past its stack top 0x{:08x}",
            dst.stack
        ));
    }
    let image_len = symbols(elf)
        .ok()
        .and_then(|s| s.get("end").map(|&(v, _)| v))
        .filter(|&e| e >= from && e <= image_end)
        .map_or(image_len, |e| e - from);
    for (lo, hi) in live_footprint(to) {
        if lo >= hi || hi > 0x8d00_0000 {
            return Err(format!(
                "a loader at 0x{to:08x} would need 0x{lo:08x}..0x{hi:08x}, which is not \
                 inside the Dreamcast's RAM"
            ));
        }
    }
    if to.saturating_add(image_len).saturating_add(800) >= dst.stack {
        return Err(format!(
            "a {image_len}-byte image at 0x{to:08x} leaves under 800 bytes of stack \
             below 0x{:08x}, which is the margin the link asserts",
            dst.stack
        ));
    }

    let mut out = elf.to_vec();
    let mut wr = |o: usize, v: u32| out[o..o + 4].copy_from_slice(&v.to_le_bytes());

    // st_value, and whether the entry is a section symbol -- see the two
    // classifiers above.
    let sym_at = |idx: usize| -> Option<(u32, bool)> {
        let e = symoff + idx * symentsize;
        (e + 16 <= symoff + symsize).then(|| (rd(e + 4), elf[e + 12] & 0xf == STT_SECTION))
    };

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
        if entsize < 12 || off + size > elf.len() {
            return Err("a relocation section is out of range".into());
        }
        for e in (off..off + size).step_by(entsize) {
            let r_offset = rd(e);
            let Some(&(addr, _, foff, typ, _)) = moving
                .iter()
                .find(|&&(a, sz, _, _, _)| r_offset >= a && r_offset < a + sz)
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
            let idx = (rd(e + 4) >> 8) as usize;
            let (value, is_section) = sym_at(idx).ok_or_else(|| {
                format!(
                    "the relocation at 0x{r_offset:08x} names symbol {idx}, which is not in \
                     the symbol table"
                )
            })?;
            let region = if is_section {
                region_of_section(value)
            } else {
                region_of_symbol(value)
            }
            .ok_or_else(|| {
                format!(
                    "the relocation at 0x{r_offset:08x} names 0x{value:08x}, which is in none \
                     of this loader's four regions (image 0x{:08x}, stack 0x{:08x}, .hiram \
                     0x{:08x}, Maple 0x{:08x}) -- moving it would be a guess",
                    src.image, src.stack, src.hiram, src.maple
                )
            })?;
            wr(at, rd(at).wrapping_add(delta_of(region)));
            patched += 1;
        }
    }
    if patched == 0 {
        return Err("no relocation landed inside the loader's own sections".into());
    }

    // 2. The base references inside `.guestvbr`, which carries none of its own.
    //    exception.S reaches the loader only through the jump table at the
    //    base, so the window is that table and nothing else; the residual scan
    //    at the end is what says so rather than assuming it.
    const JUMP_TABLE: u32 = 0x20;
    // The same RAM through any of P0/P1/P2/P3: commands.c uses the P2 alias and
    // the vector table could too.
    let window = |a: u32| a & 0x1fff_ffff;
    for &(size, foff) in &fixed {
        for o in (0..(size as usize & !3)).step_by(4) {
            let at = foff + o;
            if at + 4 > elf.len() {
                break;
            }
            let w = rd(at);
            let inside = window(w).wrapping_sub(window(from));
            if inside < JUMP_TABLE {
                wr(at, (w & 0xe000_0000) | window(to.wrapping_add(inside)));
            }
        }
    }

    // 3. Where the moving sections say they live -- this is what the upload
    //    reads, and `.hiram` does not travel with the image across families.
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let (flags, addr, size) = (rd(sh + 8), rd(sh + 12), rd(sh + 20));
        if flags & SHF_ALLOC != 0
            && size != 0
            && let Some(r) = region_of_section(addr)
        {
            wr(sh + 12, addr.wrapping_add(delta_of(r)));
        }
    }

    // 4. The entry point.
    wr(24, to);

    // 5. Program headers, so the file stays self-consistent for any other tool
    //    that reads it (readelf, gdb, objdump). Each LOAD segment holds
    //    sections from one region only -- `.hiram` gets its own -- so the same
    //    per-region rule applies.
    let phoff = rd(28) as usize;
    let phentsize = rd16(42) as usize;
    let phnum = rd16(44) as usize;
    if phoff != 0 && phentsize >= 20 && phoff + phnum * phentsize <= elf.len() {
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            for field in [8usize, 12] {
                let v = rd(ph + field);
                if let Some(r) = region_of_section(v) {
                    wr(ph + field, v.wrapping_add(delta_of(r)));
                }
            }
        }
    }

    // 6. The symbol table. Not needed to run the loader -- and needed by every
    //    instrument that resolves a counter by name against this ELF. A symbol
    //    table left at the old base is exactly AGENTS.md 14.19: readings that
    //    come back believable and wrong.
    for e in (symoff..symoff + symsize).step_by(symentsize) {
        if e + 16 > symoff + symsize {
            break;
        }
        let v = rd(e + 4);
        let r = if elf[e + 12] & 0xf == STT_SECTION {
            region_of_section(v)
        } else {
            region_of_symbol(v)
        };
        if let Some(r) = r {
            wr(e + 4, v.wrapping_add(delta_of(r)));
        }
    }

    // 7. And prove step 2 missed nothing: a word in an unmoved section still
    //    naming the image at its old base would be a jump into whatever the
    //    next title puts there, taken only on a fault.
    for &(size, foff) in &fixed {
        for o in (0..(size as usize & !3)).step_by(4) {
            let at = foff + o;
            if at + 4 > out.len() {
                break;
            }
            let w = u32::from_le_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]);
            if window(w).wrapping_sub(window(from)) < image_len {
                return Err(format!(
                    "a section that does not move still names 0x{w:08x}, inside the image at \
                     its old base 0x{from:08x} -- exception.S has grown a reference to the \
                     loader that is not through the jump table, and this does not know how \
                     to move it"
                ));
            }
        }
    }
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
    let high = is_high(wanted);
    candidates
        .iter()
        .copied()
        .filter(|&b| b != wanted && is_high(b) == high)
        .min_by_key(|&b| b.abs_diff(wanted))
}

/// What the console is plugged into, as dcload read it off PDTRA -- the same
/// two bits the BootROM and every Katana title read, in the same numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cable {
    Vga,
    Rgb,
    Composite,
}

impl Cable {
    /// 1 is not a cable any Dreamcast reports, so it is "no answer" rather
    /// than a guess. Which matters in one direction only: 0 means VGA, so
    /// anything decoded loosely ends up claiming a VGA box that is not there.
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Vga),
            2 => Some(Self::Rgb),
            3 => Some(Self::Composite),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Vga => "VGA box",
            Self::Rgb => "RGB / SCART",
            Self::Composite => "composite or S-video",
        }
    }
}

/// A VERS reply: the printable string, and the fields dcload appends after the
/// NUL that ends it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionReply {
    pub text: String,
    /// Where this loader was linked. `None` on any build from before it was
    /// reported, which is not an error -- the caller then has no basis to move
    /// anything and leaves the loader where it is.
    pub base: Option<u32>,
    /// Which video cable the console is on. `None` likewise on an older build,
    /// and the caller must treat that as "unknown", never as "not VGA".
    pub cable: Option<Cable>,
}

/// The 4-byte fields dcload appends to its VERS payload, in order: the base it
/// was linked at, then the video cable it measured.
///
/// READ FORWARD FROM THE STRING'S NUL, NOT BACKWARDS FROM THE END. Taking the
/// last four bytes as the base was right while there was exactly one field and
/// silently wrong the moment a second appeared: the cable word would be read
/// as the base, judged implausible, and the host would stop relocating
/// anything -- with the log saying only "does not report its load address",
/// which is also what an old loader says. The order here is the loader's, and
/// a field that is not there is simply `None`.
pub fn parse_version_payload(data: &[u8], size: usize) -> VersionReply {
    let size = size.min(data.len());
    let payload = &data[..size];
    let text = String::from_utf8_lossy(payload)
        .trim_end_matches(char::from(0))
        .split('\0')
        .next()
        .unwrap_or("")
        .to_string();

    let Some(nul) = payload.iter().position(|b| *b == 0) else {
        return VersionReply {
            text,
            ..Default::default()
        };
    };
    let fields = &payload[nul + 1..];
    let field = |i: usize| {
        fields
            .get(i * 4..i * 4 + 4)
            .map(|w| u32::from_be_bytes(w.try_into().unwrap()))
    };
    VersionReply {
        text,
        base: field(0).filter(|b| plausible_base(*b)),
        cable: field(1).and_then(Cable::from_code),
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

/// Where the shipped PPF patches live: `patches/`, found by the same search as
/// the two tables, so the loaders, the preset database, the learned memory map
/// and the patches are one deployment rather than four.
///
/// A directory rather than a file, but the rule is identical -- and it has to
/// be, because the failure it prevents is the same one: a set found in
/// `target/` is a set `cargo clean` takes and a set that differs between the
/// debug and release builds. A patch applied from a stale directory is worse
/// than a missing one, since what it produces is a title that runs.
pub fn patch_dir_candidates(
    explicit: Option<String>,
    env_dir: Option<String>,
    loader_dir: &Path,
    exe: Option<&Path>,
    cwd: Option<&Path>,
    manifest_dir: &str,
) -> Vec<PathBuf> {
    data_file_candidates("patches", explicit, env_dir, loader_dir, exe, cwd, manifest_dir)
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
    /// True for a base with its own pre-linked ELF, and true for ANY base the
    /// relocatable image can be moved to once it is present -- which is the
    /// whole point of it: the set stops being a menu of addresses someone
    /// thought of in advance. Both families, since 2026-08-28.
    pub fn can_provide(&self, base: u32) -> bool {
        if self.has(base) {
            return true;
        }
        let Some(path) = self.relocatable() else {
            return false;
        };
        if !could_relocate_to(base) {
            return false;
        }
        // A LOW BASE IS ASKED OF THE IMAGE ITSELF. The cheap test above sizes
        // the image with `LOADER_IMAGE_MAX`, but a low loader's image and its
        // `.gdstage` must fit under the BIOS VBR, and the relocatable set has
        // grown to within bytes of it (2026-09-30: the memory marks and the
        // idle listen put it 576 B past, where it had 136 B to spare). Saying
        // yes here sent the placement to a base `image_for` then refused, and
        // the session stayed on whatever loader was running. A high base has
        // 16 KB between `_end` and its stack and is not in this race.
        is_high(base)
            || std::fs::read(path).is_ok_and(|elf| relocate(&elf, base).is_ok())
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

    /// Where `_end` would fall for a loader at `base`.
    ///
    /// FROM THE IMAGE'S SIZE, not by relocating one and reading it back. Every
    /// address in the image moves with the base by the same delta, so
    /// `_end - _dcload_base` is the same number for every build of the set and
    /// for the relocatable one -- and reading it costs one file and no
    /// relocation, which matters because the caller asks this of candidate
    /// bases it is about to reject.
    ///
    /// `_end` is the SYMBOL, never `image_extent_bytes`: `.hiram` is an
    /// allocated NOLOAD section at 0x8cfe9000 for every LOW build, so the
    /// highest loadable section of a loader based at 0x8c004000 is twelve
    /// megabytes above its image. `_end` is what `dcload.x` puts at the top of
    /// the image and what AGENTS.md 4.6 measures margins against.
    ///
    /// `None` when there is no image to read or it carries no symbols: the
    /// caller must then skip the test rather than assume either answer.
    pub fn image_end_for(&self, base: u32) -> Option<u32> {
        let path = self
            .available()
            .first()
            .map(|&b| self.path_for(b))
            .or_else(|| self.relocatable())?;
        let bytes = std::fs::read(path).ok()?;
        let syms = symbols(&bytes).ok()?;
        let end = syms.get("end")?.0;
        let linked_at = syms.get("dcload_base")?.0;
        base.checked_add(end.checked_sub(linked_at)?)
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

/// `{name: (address, size)}` for an ELF's symbols, with the leading underscore
/// the SH toolchain adds taken off -- so the names here read like the C ones.
///
/// Lives here rather than in `diag`, which was its first caller, because the
/// answer is a property of a loader image and two other things now need it:
/// the stack-headroom test wants `end`, and the stack watch wants
/// `g_gd_sp_min`. One parser, one naming convention.
pub fn symbols(bytes: &[u8]) -> Result<std::collections::HashMap<String, (u32, u32)>, String> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes)
        .map_err(|e| format!("cannot parse the loader ELF: {e}"))?;
    let (symtab, strtab) = elf
        .symbol_table()
        .map_err(|e| format!("cannot read the loader's symbol table: {e}"))?
        .ok_or("the loader ELF carries no symbol table (was it stripped?)")?;
    let mut out = std::collections::HashMap::new();
    for sym in symtab.iter() {
        let Ok(name) = strtab.get(sym.st_name as usize) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let name = name.strip_prefix('_').unwrap_or(name);
        out.insert(name.to_string(), (sym.st_value as u32, sym.st_size as u32));
    }
    Ok(out)
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
/// span is clear of every other base in the set in both directions, and it is
/// the base `dcload-relocatable.elf` is LINKED at, so the first hop is a
/// zero-delta move -- the relocation machinery is exercised but has nothing to
/// change, which is as close to the old pre-linked ELF as makes no difference.
/// (There used to be a pre-linked loader per base; the set is now the
/// relocatable image alone -- see LOADER_BASES in target-src/dcload/Makefile.)
/// From up there the final move is
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
    fn a_preset_below_the_stock_base_never_seeds_a_low_answer() {
        // 276 of the 1026 presets ask for 0x8c000100 or 0x8c001100. The old
        // clamp was `min(ceiling)`, which left `start` at 0x8c000000, so the
        // upward walk began at 0x8c010000 -- where the title's own image is
        // loaded -- and `is_clear` says nothing about low RAM by design.
        let tried = std::cell::RefCell::new(vec![]);
        let answer = search_free_base(0x8c00_0100, |b| {
            tried.borrow_mut().push(b);
            true
        });
        assert!(
            answer.is_some_and(|b| b >= FREE_BASE_FLOOR),
            "answered {answer:x?} for a preset below the stock base"
        );
        assert!(
            tried.borrow().iter().all(|&b| b >= FREE_BASE_FLOOR),
            "the scan considered a base below 0x{FREE_BASE_FLOOR:08x}"
        );
    }

    #[test]
    fn a_base_is_centred_in_the_span_it_is_given() {
        // Jet Set Radio's hole, between the read that killed a run (0x8ce00000)
        // and the sector buffer it keeps at the top of RAM (0x8cff0000).
        assert_eq!(base_in_span(0x8ce1_0000, 0x8cff_0000), Some(0x8cef_0000));
        // The whole window, for a title with no map yet: 31 candidates fit
        // between the floor and the top of RAM, and the 16th is the middle.
        // (It is also the base Sonic Adventure 2 was measured running at --
        // a coincidence, but a reassuring one.)
        assert_eq!(base_in_span(0x8ce0_0000, 0x8d00_0000), Some(0x8cef_0000));
        // Too small to hold a loader at all.
        assert_eq!(base_in_span(0x8ce0_0000, 0x8ce0_8000), None);
        assert_eq!(base_in_span(0x8ce0_0000, 0x8ce0_0000), None);
    }

    #[test]
    fn a_low_preset_rules_out_isoldrs_own_two_addresses() {
        // The point of reading an unsupported preset as information: these are
        // the two DreamShell tried before it gave up and went low.
        assert!(ruled_out_by_low_preset(ISOLDR_DEFAULT_ADDR));
        assert!(ruled_out_by_low_preset(ISOLDR_HIGH_ADDR));
        // Overlap, not equality -- ours is four times isoldr's size.
        assert!(ruled_out_by_low_preset(ISOLDR_DEFAULT_ADDR - LOADER_SPAN + 4));
        assert!(!ruled_out_by_low_preset(ISOLDR_DEFAULT_ADDR - LOADER_SPAN));
        // And it must not condemn the rest of the window.
        assert!(!ruled_out_by_low_preset(0x8cef_0000));
        assert!(!ruled_out_by_low_preset(0x8cf7_0000));
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
    /// one word, one RELA naming that word, and the symbol table `relocate`
    /// classifies it with. `sym` is the value of the symbol the relocation
    /// names -- which is what decides the region, and therefore which of the
    /// four deltas the word gets.
    fn tiny_elf_named(base: u32, word: u32, sym: u32) -> Vec<u8> {
        const EH: usize = 52;
        const SH: usize = 40;
        const SYM: usize = EH + 4 + 12; // after the .text payload and the Rela
        const STR: usize = SYM + 32; // two symbol table entries
        let shoff = STR + 1;
        let mut b = vec![0u8; shoff + 5 * SH];
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
        h(&mut b, 48, 5);
        h(&mut b, 50, 0);
        // .text contents, and the relocation that names its only word
        w(&mut b, EH, word);
        w(&mut b, EH + 4, base); // r_offset
        w(&mut b, EH + 8, (1 << 8) | 1); // r_info: symbol 1, R_SH_DIR32
        w(&mut b, EH + 12, 0); // r_addend
        // symbol 1 (symbol 0 is the reserved null entry, left zeroed)
        w(&mut b, SYM + 16 + 4, sym); // st_value
        h(&mut b, SYM + 16 + 14, 1); // st_shndx: .text
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
        w(&mut b, s2 + 40 - 4, 12); // sh_entsize
        w(&mut b, s2 + 40 - 12, 3); // sh_link: the symbol table
        // [3] .symtab
        let s3 = shoff + 3 * SH;
        w(&mut b, s3 + 4, 2); // SHT_SYMTAB
        w(&mut b, s3 + 16, SYM as u32);
        w(&mut b, s3 + 20, 32);
        w(&mut b, s3 + 24, 4); // sh_link: the string table
        w(&mut b, s3 + 36, 16); // sh_entsize
        // [4] .strtab
        let s4 = shoff + 4 * SH;
        w(&mut b, s4 + 4, 3); // SHT_STRTAB
        w(&mut b, s4 + 16, STR as u32);
        w(&mut b, s4 + 20, 1);
        b
    }

    /// The ordinary case: a word naming an address inside the image.
    fn tiny_elf(base: u32, word: u32) -> Vec<u8> {
        tiny_elf_named(base, word, base)
    }

    fn word_of(elf: &[u8]) -> u32 {
        u32::from_le_bytes(elf[52..56].try_into().unwrap())
    }

    #[test]
    fn a_symbol_at_the_far_end_of_hiram_is_still_hiram() {
        // `__hiram_end` is one past the last byte of a section CD-DA takes to
        // about 10 KB, and `dcload-crt0.s` names it to zero the region. A
        // classifier that gave `.hiram` a single 4 KB page could not place
        // that symbol, and `relocate` refuses what it cannot classify rather
        // than guessing -- so the relocatable image stopped relocating AT ALL,
        // at every base, the moment that buffer was added. Nothing on a
        // console would have found it: the failure is a message before the
        // upload.
        //
        // Low to high on purpose, so `.hiram` moves by a different delta from
        // the image and a misclassification cannot pass by coincidence.
        let (from, to) = (0x8c00_4000u32, 0x8cef_8000u32);
        let sym = layout(from).hiram + 0x2790; // measured, WITH_CDDA=1
        let e = tiny_elf_named(from, sym, sym);
        let moved = relocate(&e, to).expect("a symbol in .hiram must be classifiable");
        assert_eq!(word_of(&moved), layout(to).hiram + 0x2790);
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

    /// THE POINT OF THE FOUR DELTAS. A loader's stack, packet buffers and Maple
    /// DMA buffer do not move with its image when the move crosses families, so
    /// a word naming one of them follows THAT address and not the base.
    #[test]
    fn each_region_follows_its_own_address_across_the_families() {
        let src = layout(SCRATCH_BASE);
        let dst = layout(DEFAULT_BASE);
        for (what, sym, want) in [
            ("image", src.image + 0x1234, dst.image + 0x1234),
            ("stack", src.stack, dst.stack),
            (".hiram", src.hiram + 0x600, dst.hiram + 0x600),
            ("Maple DMA", src.maple, dst.maple),
        ] {
            let e = tiny_elf_named(SCRATCH_BASE, sym, sym);
            let moved = relocate(&e, DEFAULT_BASE).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(word_of(&moved), want, "{what}: 0x{sym:08x}");
        }
    }

    /// A low base is a base like any other now. It was refused outright until
    /// 2026-08-28, which is what sent someone whose title wanted the stock
    /// address off to build an ELF that was already on disk.
    #[test]
    fn a_low_target_is_no_longer_refused() {
        assert!(could_relocate_to(DEFAULT_BASE));
        let e = tiny_elf(SCRATCH_BASE, SCRATCH_BASE + 0x1234);
        let moved = relocate(&e, DEFAULT_BASE).unwrap();
        assert_eq!(word_of(&moved), DEFAULT_BASE + 0x1234);
    }

    /// And the other direction, because the rule is symmetric and a special
    /// case that is not needed is a special case that goes wrong. Nothing builds
    /// a low relocatable image today -- `make loaders` emits relocations for one
    /// high base -- but nothing about this depends on which way it goes.
    #[test]
    fn a_low_image_moves_as_well_as_a_high_one() {
        let low = layout(DEFAULT_BASE);
        let e = tiny_elf_named(DEFAULT_BASE, low.hiram + 0x600, low.hiram + 0x600);
        let moved = relocate(&e, 0x8cef_8000).unwrap();
        assert_eq!(word_of(&moved), layout(0x8cef_8000).hiram + 0x600);
    }

    /// What a low base has that a high one does not: a ceiling. Its stack top
    /// stays at the BIOS VBR whatever the image does, so the image has to fit
    /// underneath it with the margin the link script asserts.
    #[test]
    fn a_low_base_too_close_to_the_bios_vbr_is_refused() {
        assert!(!could_relocate_to(0x8c00_c000), "a real image would not fit");
        // The synthetic image is four bytes, so this one is refused by the
        // 800-byte stack margin alone.
        let e = tiny_elf(SCRATCH_BASE, SCRATCH_BASE + 0x1234);
        assert!(relocate(&e, 0x8c00_f200).is_err());
    }

    /// A relocation naming something in none of the four regions -- a hardware
    /// register, say -- is a case this cannot answer. Guessing at it is what
    /// would corrupt an image with nothing to show for it.
    #[test]
    fn a_relocation_pointing_outside_the_layout_is_refused() {
        let e = tiny_elf_named(SCRATCH_BASE, 0xa05f_8000, 0xa05f_8000);
        let err = relocate(&e, DEFAULT_BASE).unwrap_err();
        assert!(err.contains("four regions"), "unhelpful message: {err}");
    }

    /// THE MEASUREMENT EVERYTHING HERE RESTS ON: relocating reproduces a native
    /// link byte for byte, at every base `make loaders` builds -- the low one
    /// included, which is the move that crosses families.
    ///
    /// Skipped, not failed, when the set is not on disk: it is build output of
    /// the other repository, and the rest of the suite has to stay runnable
    /// without it. When it IS there, this checks whatever is there, so a base
    /// added to LOADER_BASES is covered the day it is deployed.
    #[test]
    fn relocating_reproduces_every_native_link_byte_for_byte() {
        /// Every allocated PROGBITS section, keyed by the address it claims:
        /// exactly what the host uploads, `.guestvbr` included.
        fn loadable(bytes: &[u8]) -> std::collections::BTreeMap<u32, Vec<u8>> {
            let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes).expect("parse");
            let mut m = std::collections::BTreeMap::new();
            for sh in elf.section_headers().expect("sections").iter() {
                if is_uploadable(&sh) {
                    let (d, _) = elf.section_data(&sh).expect("section data");
                    m.insert(sh.sh_addr as u32, d.to_vec());
                }
            }
            m
        }

        let set = LoaderSet::discover(None);
        let (Some(path), bases) = (set.relocatable(), set.available()) else {
            return;
        };
        let Ok(src) = std::fs::read(&path) else { return };
        if bases.is_empty() {
            return;
        }
        for base in bases {
            let native = std::fs::read(set.path_for(base)).expect("read the native link");
            let moved = relocate(&src, base).unwrap_or_else(|e| panic!("0x{base:08x}: {e}"));
            assert_eq!(
                loadable(&moved),
                loadable(&native),
                "relocated to 0x{base:08x} is not the native link"
            );
        }
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
    fn a_stale_build_at_the_scratch_base_can_be_replaced_via_a_relay() {
        // running == want == SCRATCH_BASE, which is what a rebuilt loader set
        // looks like on a console that was not power-cycled. There is no
        // one-hop answer -- a loader cannot be uploaded over itself, and the
        // destination IS the neutral ground -- so ensure_loader_base looks for
        // a base that plans non-empty in BOTH directions and chains the two
        // legs. Assert such a base exists, or that search is dead code and the
        // only remedy is a power cycle.
        let want = SCRATCH_BASE;
        let relay = [DEFAULT_BASE, ISOLDR_HIGH_ADDR].iter().find(|&&alt| {
            !plan(want, alt, image(alt), image(SCRATCH_BASE)).is_empty()
                && !plan(alt, want, image(want), image(SCRATCH_BASE)).is_empty()
        });
        assert!(relay.is_some(), "no relay base for a same-base replacement");
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
        //
        // The range's TOP is the reservation, not what one build happens to
        // put there: .hiram holds the packet buffers and, with WITH_CDDA, the
        // audio staging buffer, and this host cannot see which flags the
        // running loader was built with. See HIRAM_RESERVED.
        let huge = (0x0c01_0000u32, 0x0cff_0000);
        assert_eq!(
            overlapping_range(DEFAULT_BASE, huge),
            Some((0x8cfe_8000, 0x8cfe_9000 + HIRAM_RESERVED))
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
        // The shape of the loader that reported a base and nothing else. It
        // still has to parse, or every such build stops being relocatable the
        // day a second field is added.
        let mut payload = b"dcload-ip 2.0.4 using RTL8139\0".to_vec();
        payload.extend_from_slice(&0x8cfe_8000u32.to_be_bytes());
        let size = payload.len();
        payload.resize(1440, 0);
        let got = parse_version_payload(&payload, size);
        assert_eq!(got.text, "dcload-ip 2.0.4 using RTL8139");
        assert_eq!(got.base, Some(0x8cfe_8000));
        assert_eq!(got.cable, None);
    }

    #[test]
    fn version_payload_carries_the_cable_after_the_base() {
        for (code, want) in [(0u32, Cable::Vga), (2, Cable::Rgb), (3, Cable::Composite)] {
            let mut payload = b"dcload-ip 2.0.4 using RTL8139\0".to_vec();
            payload.extend_from_slice(&0x8c00_4000u32.to_be_bytes());
            payload.extend_from_slice(&code.to_be_bytes());
            let size = payload.len();
            payload.resize(1440, 0);
            let got = parse_version_payload(&payload, size);
            assert_eq!(got.base, Some(0x8c00_4000), "code {code}");
            assert_eq!(got.cable, Some(want), "code {code}");
        }
    }

    #[test]
    fn zero_padding_is_not_read_as_a_vga_box() {
        // `size` is what the loader said it sent; the buffer behind it is 1440
        // bytes of whatever. Reading past `size` would decode a 0 -- which is
        // the code for VGA, i.e. the one wrong answer that would make the host
        // patch a title on a console plugged into a television.
        let mut payload = b"dcload-ip 2.0.4 using RTL8139\0".to_vec();
        payload.extend_from_slice(&0x8c00_4000u32.to_be_bytes());
        let size = payload.len();
        payload.resize(1440, 0);
        assert_eq!(parse_version_payload(&payload, size).cable, None);
    }

    #[test]
    fn version_payload_without_a_base_is_not_an_error() {
        // What an older loader sends: string, NUL, nothing else.
        let payload = b"dcload-ip 2.0.3 using RTL8139\0".to_vec();
        let size = payload.len();
        let got = parse_version_payload(&payload, size);
        assert_eq!(got.text, "dcload-ip 2.0.3 using RTL8139");
        assert_eq!(got.base, None);
        assert_eq!(got.cable, None);
    }
}
