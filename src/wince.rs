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
//!    `0x8c008000` (13 KB); ours is 32 KB and cannot. So the loader goes at the
//!    top of the pool and the image is told its pool ends there -- the header
//!    is data the kernel reads once at boot, and the one place that number is.
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

/// Where the loader goes for a CE title: the top `span` bytes of CE's page
/// pool, which [`ram_end_patch`] then takes out of the pool. `None` when that
/// would leave CE less than 8 MB above `ulRAMFree`.
pub fn loader_base(h: &RomHdr, span: u32) -> Option<u32> {
    let base = h.ram_end.checked_sub(span)? & !0xffff;
    (base >= h.ram_free.saturating_add(0x80_0000)).then_some(base)
}

/// The word that tells CE its page pool ends at `base`, when a loader at
/// `base` sits inside the pool. `None` when it does not (nothing to take).
pub fn ram_end_patch(h: &RomHdr, base: u32) -> Option<(u32, u32)> {
    let base = p1(base);
    (base > h.ram_free && base < h.ram_end)
        .then(|| (h.at + (RAMEND * 4) as u32, base & !0xfff))
}

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

    #[test]
    fn places_the_loader_at_the_top_of_the_pool_and_takes_it_out() {
        let h = romhdr(&image(0x1000), LOAD).unwrap();
        let base = loader_base(&h, 0x10000).unwrap();
        assert_eq!(base, 0x8cee_0000);
        assert_eq!(ram_end_patch(&h, base), Some((LOAD + 0x1000 + 28, 0x8cee_0000)));
        // A loader outside the pool takes nothing from it.
        assert_eq!(ram_end_patch(&h, 0x8c00_4000), None);
        assert_eq!(ram_end_patch(&h, 0x8cef_0000), None);
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
