//! Windows CE titles: where the loader may live, and the one change CE's GD
//! driver needs to be servable without interrupts.
//!
//! A CE title is an operating system boot (dcload-ip:
//! docs/wince-investigation.md). Two facts about it drive this module, both
//! read out of Sega Rally 2 PAL's `0WINCEOS.BIN` on 2026-09-27:
//!
//! 1. **CE's kernel owns almost all of RAM.** Its ROM header (`ROMHDR`) says
//!    the page pool is `ulRAMStart..ulRAMEnd` (`0x8c143000..0x8cef0000`) and
//!    driver globals take `ulDrivglobStart..+Len` (`0x8cef0000..0x8d000000`).
//!    It hands pages out from the top: the first ones it used were 352 KB under
//!    `ulRAMEnd`. A loader anywhere in the pool is overwritten once CE's
//!    allocations reach it, with nothing logged. isoldr lives under
//!    `0x8c008000` (13 KB); ours is 32 KB and cannot. So the loader is taken
//!    out of the pool through the header -- data the kernel reads once at
//!    boot, and the one place those numbers are -- at the BOTTOM: it goes at
//!    `ulRAMFree` and the pool is told it starts above it ([`Place`]). Taken
//!    from the top (`ulRAMEnd` lowered, until 2026-10-09), it moved everything
//!    CE hands out by as much: Sega Rally 2's `RALLY2.EXE` loaded at RAM
//!    `0xA85000` instead of `0xA99000`, 0x14000 lower for a 64 KB loader and
//!    16 KB of RetroAchievements room, and its achievement set, which looks for
//!    the program at the seven pages `0xA95000..0xA9B000` an unmodified CE
//!    gives it, matched nothing.
//!
//! 2. **CE chains DMA stream pieces from the G1 DMA-end interrupt**, which a
//!    network transport never raises. Its driver (`wsegacd.dll`, XIP in the
//!    ROM image) reads an aligned request by DMA, and as a DMA *stream* when
//!    the locked pages are not physically contiguous -- which, with pages
//!    handed out top-down, is most of them. Everything else it reads by PIO,
//!    whose pieces are chained from a callback the driver calls itself. So the
//!    one branch that picks DMA for an aligned request is made to pick PIO.
//!    Its single-buffer DMA reads (the driver's own cache, bounce buffers) are
//!    untouched: they complete without an interrupt.

/// Where CE's kernel says its RAM is, read out of the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RomHdr {
    /// Address of the header in RAM (P1).
    pub at: u32,
    pub phys_first: u32,
    pub phys_last: u32,
    pub ram_start: u32,
    pub ram_free: u32,
    pub ram_end: u32,
    pub drivglob_start: u32,
    pub drivglob_len: u32,
}

/// Word offsets of the fields used here, from `ROMHDR` in the CE headers:
/// dllfirst, dlllast, physfirst, physlast, nummods, ulRAMStart, ulRAMFree,
/// ulRAMEnd, ... ulDrivglobStart (15), ulDrivglobLen (16).
const PHYSFIRST: usize = 2;
const PHYSLAST: usize = 3;
const NUMMODS: usize = 4;
const RAMSTART: usize = 5;
const RAMFREE: usize = 6;
const RAMEND: usize = 7;
const DRIVGLOBSTART: usize = 15;
const DRIVGLOBLEN: usize = 16;
const ROMHDR_WORDS: usize = 17;

fn p1(a: u32) -> u32 {
    (a & 0x1fff_ffff) | 0x8000_0000
}

fn word(buf: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]])
}

/// Find the ROM header in a CE boot image loaded at `load`.
///
/// By shape, not by pointer: `physfirst` is the load address, `physlast` lies
/// inside the image, the RAM fields are ordered and in main RAM. On Sega Rally
/// 2 exactly one word position satisfies all of it. More than one is refused:
/// a guess here decides where the loader lives.
pub fn romhdr(payload: &[u8], load: u32) -> Option<RomHdr> {
    let load = p1(load);
    let end = load.wrapping_add(payload.len() as u32);
    let mut found = None;
    for i in (0..payload.len().saturating_sub(ROMHDR_WORDS * 4)).step_by(4) {
        let w = |k: usize| word(payload, i + k * 4);
        if w(PHYSFIRST) != load {
            continue;
        }
        let h = RomHdr {
            at: load.wrapping_add(i as u32),
            phys_first: w(PHYSFIRST),
            phys_last: w(PHYSLAST),
            ram_start: w(RAMSTART),
            ram_free: w(RAMFREE),
            ram_end: w(RAMEND),
            drivglob_start: w(DRIVGLOBSTART),
            drivglob_len: w(DRIVGLOBLEN),
        };
        let plausible = h.phys_last > h.phys_first
            && h.phys_last <= end
            && (1..=1024).contains(&w(NUMMODS))
            && h.ram_start >= h.phys_last
            && h.ram_start <= h.ram_free
            && h.ram_free < h.ram_end
            && h.ram_end <= 0x8d00_0000
            && h.ram_end & 0xfff == 0;
        if !plausible {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(h);
    }
    found
}

/// Which end of CE's page pool the loader is taken from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// At `ulRAMFree`, the pool told it starts above the loader and the
    /// RetroAchievements room: what CE hands out from the top is where an
    /// unmodified CE puts it. The default.
    Bottom,
    /// At the top, the pool told it ends under the room: everything CE hands
    /// out moves down by as much (`--wince-loader-top`, the placement until
    /// 2026-10-09).
    Top,
}

/// CE's pool must keep this much.
const POOL_MIN: u32 = 0x80_0000;

/// Where the loader goes for a CE title: `span` bytes at one end of CE's page
/// pool, which [`take`] then takes out of the pool with up to `RA_ROOM` more.
/// `None` when that would leave CE less than 8 MB.
pub fn loader_base(h: &RomHdr, span: u32, place: Place) -> Option<u32> {
    match place {
        Place::Top => {
            let base = h.ram_end.checked_sub(span)? & !0xffff;
            (base >= h.ram_free.saturating_add(POOL_MIN)).then_some(base)
        }
        Place::Bottom => {
            let base = p1(h.ram_free).checked_add(0xffff)? & !0xffff;
            let top = base.checked_add(span)?.checked_add(RA_ROOM)?;
            (top.saturating_add(POOL_MIN) <= h.ram_end).then_some(base)
        }
    }
}

/// What [`take`] takes out of CE's pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Taken {
    /// The ROMHDR word to write and its value (`ulRAMFree` or `ulRAMEnd`).
    pub patch: (u32, u32),
    /// The RetroAchievements room: P1 address and bytes; `None` for no room.
    pub room: Option<(u32, u32)>,
}

/// Take the loader at `base` (`span` bytes) and `room` more bytes for the
/// RetroAchievements sampler out of CE's page pool, at the end `place` says.
/// `None` when the loader is not inside the pool (nothing to take), or when
/// what is left would reach `ulRAMFree` / `ulRAMEnd`.
pub fn take(h: &RomHdr, base: u32, span: u32, room: u32, place: Place) -> Option<Taken> {
    let base = p1(base);
    if base < h.ram_free || base >= h.ram_end {
        return None;
    }
    let room_at = |a: u32| (room != 0).then_some((a, room));
    match place {
        Place::Top => {
            let end = base.checked_sub(room)? & !0xfff;
            (base > h.ram_free && end > h.ram_free).then(|| Taken {
                patch: (h.at + (RAMEND * 4) as u32, end),
                room: room_at(end),
            })
        }
        Place::Bottom => {
            let above = base.checked_add(span)?;
            let free = above.checked_add(room)?.checked_add(0xfff)? & !0xfff;
            (free < h.ram_end).then(|| Taken {
                patch: (h.at + (RAMFREE * 4) as u32, free),
                room: room_at(above),
            })
        }
    }
}

/// What the RetroAchievements sampler is lent under CE, next to the loader
/// (`g_ra_ce_room`, loader AGENTS.md 4.20): the loader's dead stack holds ~136
/// words of table, Sega Rally 2's achievements need ~430 and more as its
/// pointers move (967 words seen, 2026-10-08). 16 KB holds the loader's largest
/// table (1024 words: previous frame, window, a keyframe); 8 KB held 992.
pub const RA_ROOM: u32 = 0x4000;

/// The branch in CE's GD driver that sends an aligned scatter-gather read to
/// DMA, as it reads in Sega Rally 2's `wsegacd.dll` (`0x8c099f70`):
///
/// ```text
///   f4 52   mov.l  @(16,r15),r2     ; bytes before the first whole sector
///   28 22   tst    r2,r2
///   1e 8b   bf     pio              <- becomes `bra pio` (1e a0)
///   f6 51   mov.l  @(24,r15),r1     ; bytes after the last whole sector
///   18 21   tst    r1,r1
///   1b 8b   bf     pio
///   ..      (the DMA request: DMAREAD, or DMAREAD_STREAM_EX when the pages
///            are not contiguous)
/// ```
///
/// `pio` is the driver's own path for unaligned requests: PIOREAD for one
/// buffer, PIOREAD_STREAM_EX for a list of them, with the next piece asked for
/// from a callback. The delay slot the `bra` gains is the load of the second
/// operand, which `pio` does not read.
const DMA_CHOICE: [u8; 12] = [
    0xf4, 0x52, 0x28, 0x22, 0x1e, 0x8b, 0xf6, 0x51, 0x18, 0x21, 0x1b, 0x8b,
];

/// Make CE's GD driver read aligned requests by PIO (see [`DMA_CHOICE`]).
/// Returned as the aligned word to write. Empty unless the pattern occurs
/// exactly once, halfword-aligned.
pub fn pio_patches(payload: &[u8], load: u32) -> Vec<(u32, u32)> {
    let hits: Vec<usize> = (0..payload.len().saturating_sub(DMA_CHOICE.len()))
        .step_by(2)
        .filter(|&i| payload[i..i + DMA_CHOICE.len()] == DMA_CHOICE)
        .collect();
    let [i] = hits[..] else {
        return vec![];
    };
    // The `bf` is the halfword at i+4; write the aligned word holding it.
    let bf = i + 4;
    let w = bf & !3;
    let mut bytes = [payload[w], payload[w + 1], payload[w + 2], payload[w + 3]];
    bytes[bf - w + 1] = 0xa0;
    vec![(p1(load).wrapping_add(w as u32), u32::from_le_bytes(bytes))]
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOAD: u32 = 0x8c01_0000;

    /// A payload with a ROMHDR shaped like Sega Rally 2's at `off`.
    fn image(off: usize) -> Vec<u8> {
        let mut p = vec![0u8; 0x2000];
        let f = [
            0x01c6_0000, 0x0200_0000, LOAD, LOAD + 0x1f00, 24, LOAD + 0x1f00, LOAD + 0x1f00,
            0x8cef_0000, 1, 0, 0, 0, 2, 1, 0, 0x8cef_0000, 0x0011_0000,
        ];
        for (k, v) in f.iter().enumerate() {
            p[off + k * 4..off + k * 4 + 4].copy_from_slice(&u32::to_le_bytes(*v));
        }
        p
    }

    #[test]
    fn finds_the_rom_header_by_shape() {
        let h = romhdr(&image(0x1000), LOAD).expect("found");
        assert_eq!(h.at, LOAD + 0x1000);
        assert_eq!(h.ram_end, 0x8cef_0000);
        assert_eq!(h.drivglob_start, 0x8cef_0000);
    }

    #[test]
    fn refuses_two_candidates() {
        let mut p = image(0x1000);
        let q = image(0x800);
        p[0x800..0x800 + ROMHDR_WORDS * 4].copy_from_slice(&q[0x800..0x800 + ROMHDR_WORDS * 4]);
        assert_eq!(romhdr(&p, LOAD), None);
    }

    /// Sega Rally 2 PAL's pool, with `ulRAMFree` where it is not 64 KB aligned.
    fn sr2() -> RomHdr {
        RomHdr {
            at: LOAD + 0x1000,
            phys_first: LOAD,
            phys_last: 0x8c14_0000,
            ram_start: 0x8c14_3000,
            ram_free: 0x8c14_8000,
            ram_end: 0x8cef_0000,
            drivglob_start: 0x8cef_0000,
            drivglob_len: 0x0011_0000,
        }
    }

    #[test]
    fn places_the_loader_at_the_bottom_of_the_pool_and_leaves_the_top_alone() {
        let h = sr2();
        let base = loader_base(&h, 0x10000, Place::Bottom).unwrap();
        assert_eq!(base, 0x8c15_0000, "ulRAMFree rounded up to 64 KB");
        // the pool starts above the loader and the room; its end is not touched,
        // so what CE hands out from the top is where an unmodified CE puts it
        assert_eq!(
            take(&h, base, 0x10000, RA_ROOM, Place::Bottom),
            Some(Taken { patch: (h.at + 24, 0x8c16_4000), room: Some((0x8c16_0000, RA_ROOM)) })
        );
        assert_eq!(
            take(&h, base, 0x10000, 0, Place::Bottom),
            Some(Taken { patch: (h.at + 24, 0x8c16_0000), room: None })
        );
        // a pool that would be left under 8 MB: no place
        let small = RomHdr { ram_end: 0x8c95_0000, ..h };
        assert_eq!(loader_base(&small, 0x10000, Place::Bottom), None);
        // a loader outside the pool takes nothing from it
        assert_eq!(take(&h, 0x8c00_4000, 0x10000, RA_ROOM, Place::Bottom), None);
        assert_eq!(take(&h, 0x8cef_0000, 0x10000, 0, Place::Bottom), None);
    }

    #[test]
    fn places_the_loader_at_the_top_of_the_pool_and_takes_it_out() {
        let h = romhdr(&image(0x1000), LOAD).unwrap();
        let base = loader_base(&h, 0x10000, Place::Top).unwrap();
        assert_eq!(base, 0x8cee_0000);
        assert_eq!(
            take(&h, base, 0x10000, 0, Place::Top),
            Some(Taken { patch: (LOAD + 0x1000 + 28, 0x8cee_0000), room: None })
        );
        // RetroAchievements' block is taken out with it, under the loader.
        assert_eq!(
            take(&h, base, 0x10000, RA_ROOM, Place::Top),
            Some(Taken { patch: (LOAD + 0x1000 + 28, 0x8ced_c000), room: Some((0x8ced_c000, RA_ROOM)) })
        );
        // A loader outside the pool takes nothing from it.
        assert_eq!(take(&h, 0x8c00_4000, 0x10000, RA_ROOM, Place::Top), None);
        assert_eq!(take(&h, 0x8cef_0000, 0x10000, 0, Place::Top), None);
    }

    #[test]
    fn turns_the_dma_choice_into_a_branch_to_pio() {
        let mut p = vec![0u8; 64];
        p[16..28].copy_from_slice(&DMA_CHOICE);
        let got = pio_patches(&p, LOAD);
        // The bf at 20 is the low half of the word at 20.
        assert_eq!(got, vec![(LOAD + 20, u32::from_le_bytes([0x1e, 0xa0, 0xf6, 0x51]))]);
        // Odd halfword position: the high half of the word.
        let mut p = vec![0u8; 64];
        p[18..30].copy_from_slice(&DMA_CHOICE);
        let got = pio_patches(&p, LOAD);
        assert_eq!(got, vec![(LOAD + 20, u32::from_le_bytes([0x28, 0x22, 0x1e, 0xa0]))]);
        // Twice: refused.
        let mut p = vec![0u8; 64];
        p[0..12].copy_from_slice(&DMA_CHOICE);
        p[32..44].copy_from_slice(&DMA_CHOICE);
        assert!(pio_patches(&p, LOAD).is_empty());
    }
}
