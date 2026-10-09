//! A Katana allocator that owns all the RAM a title leaves free, found by its
//! literal pool, and the loader taken out of it. Two of them: Shenmue II's
//! "HLib", and the Katana library's own syMalloc (further down).
//!
//! WHY (Shenmue II, 2026-10-05). Its allocator ("HLib") is set up once from a
//! pool of literals: the heap's start, the first block (start + 0x20), the end,
//! the first block's size (end - (start + 0x20)) and three tags. Everything
//! between the end of the program and a fixed region at the top of RAM is that
//! heap, so no fixed base is free for long: a loader anywhere in it is
//! overwritten when the heap fills (disc 4), and the top is not safe either,
//! because a fixed loading buffer runs over the heap's end there. Taking the
//! loader's 64 KB off the heap's BOTTOM -- moving its start up, and the size
//! with it -- was measured to run the title perfectly.
//!
//! The init writes a "HLib" header at the start, a free block at start + 0x20
//! of the pool's size, and a "HLib" header at the end (32 bytes, so the heap's
//! RAM ends at end + 0x20). Moving the start or the end is three or two words
//! of that pool; the code that reads them is left alone. The words are guarded
//! like the GAPS one: the title reloads its program after a disc swap.

use super::*;

const TAG_FREE: u32 = u32::from_le_bytes(*b"fREe");
const TAG_USED: u32 = u32::from_le_bytes(*b"USE ");
const TAG_LIB: u32 = u32::from_le_bytes(*b"HLib");
/// A block header, and the end sentinel.
const HEADER: u32 = 0x20;
/// How far apart the pool's words may sit, in bytes.
const POOL_SPAN: usize = 0x40;
/// The least heap worth keeping once the loader is out of it.
const MIN_LEFT: u32 = 0x10_0000;

/// One HLib heap: its bounds (P1) and where each pool word is (P1 address of
/// the literal, and the word as the title has it, segment bits included).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HlibHeap {
    pub start: u32,
    pub end: u32,
    start_at: (u32, u32),
    first_at: (u32, u32),
    end_at: (u32, u32),
    size_at: u32,
}

/// The HLib heap a title sets up, if its pool is in the image -- and only if
/// exactly one is (two would leave the choice to chance).
pub fn hlib_heap(buf: &[u8], address: u32) -> Option<HlibHeap> {
    let mut found: Vec<HlibHeap> = vec![];
    for (base, data) in payload_spans(buf, address) {
        let at = |i: usize| p1(base).wrapping_add(i as u32);
        let word = |i: usize| (i + 4 <= data.len()).then(|| le32(data, i));
        for (i, s) in words(data) {
            if !names_ram(s) || word(i + 4) != Some(s.wrapping_add(HEADER)) {
                continue;
            }
            let (lo, hi) = (i.saturating_sub(POOL_SPAN), (i + POOL_SPAN).min(data.len()));
            let near: Vec<(usize, u32)> = (lo..hi.saturating_sub(3))
                .step_by(4)
                .filter_map(|j| word(j).map(|w| (j, w)))
                .collect();
            let has = |tag| near.iter().any(|&(_, w)| w == tag);
            if !(has(TAG_FREE) && has(TAG_USED) && has(TAG_LIB)) {
                continue;
            }
            let start = p1(s);
            for &(j, e) in near.iter().filter(|&&(j, _)| j > i + 4) {
                if !names_ram(e) || p1(e) <= start.wrapping_add(HEADER) {
                    continue;
                }
                let size = p1(e) - (start + HEADER);
                if let Some(&(k, _)) = near.iter().find(|&&(_, w)| w == size) {
                    found.push(HlibHeap {
                        start,
                        end: p1(e),
                        start_at: (at(i), s),
                        first_at: (at(i + 4), word(i + 4).unwrap_or(0)),
                        end_at: (at(j), e),
                        size_at: at(k),
                    });
                    break;
                }
            }
        }
    }
    found.dedup();
    match found.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}

impl HlibHeap {
    /// Where the loader goes: the first 64 KB boundary at or above the heap's
    /// start, if enough heap is left above it.
    pub fn loader_base(&self) -> Option<u32> {
        let base = self.start.checked_add(0xffff)? & !0xffff;
        let left = self.end.checked_sub(base.checked_add(crate::loaders::LOADER_SPAN + HEADER)?)?;
        (crate::loaders::is_high(base) && left >= MIN_LEFT).then_some(base)
    }

    /// The pool words that keep the heap off a loader at `base`: the start
    /// moved above it when it sits at the bottom, the end moved under it when
    /// it sits at the top. Nothing when it is outside the heap; an error when
    /// it is in the middle, where no two words can take it out.
    pub fn patches(&self, base: u32) -> Result<Vec<(u32, u32)>, String> {
        let span = crate::loaders::LOADER_SPAN;
        let (lo, hi) = (p1(base), p1(base) + span);
        let top = self.end + HEADER;
        if hi <= self.start || lo >= top {
            return Ok(vec![]);
        }
        let keep = |raw: u32, to: u32| (to & 0x1fff_ffff) | (raw & 0xe000_0000);
        if lo <= self.start.saturating_add(0xffff) {
            let start = hi;
            if start + HEADER + MIN_LEFT > self.end {
                return Err(format!("only 0x{:x} bytes of heap would be left", self.end.saturating_sub(start)));
            }
            return Ok(vec![
                (self.start_at.0, keep(self.start_at.1, start)),
                (self.first_at.0, keep(self.first_at.1, start + HEADER)),
                (self.size_at, self.end - (start + HEADER)),
            ]);
        }
        if hi >= self.end {
            let end = lo - HEADER;
            if self.start + HEADER + MIN_LEFT > end {
                return Err(format!("only 0x{:x} bytes of heap would be left", end.saturating_sub(self.start)));
            }
            return Ok(vec![
                (self.end_at.0, keep(self.end_at.1, end)),
                (self.size_at, end - (self.start + HEADER)),
            ]);
        }
        Err(format!(
            "it sits in the middle of the heap (0x{:08x}..0x{top:08x}), which only its \
             bottom or its top can be taken out of",
            self.start
        ))
    }

    /// The constants the patches change: a loaded literal naming one of them
    /// is the allocator's own, not a title writing over the loader.
    pub fn names_own_bound(&self, at: u32) -> bool {
        at == self.start || at == self.start + HEADER || at == self.end
    }
}

// ---------------------------------------------------------------------------
// KATANA'S OWN ALLOCATOR: syMalloc, set up by sbInitSystem.
//
// WHY (Jet Set Radio, 2026-10-10). Katana's sbinit.c hands syMallocInit
// everything from the end of the program's BSS to a fixed address:
//
//     mov.l   @r0,r4          ; r0 = &_end (a word of crt0's section table)
//     mov.l   @(disp,pc),r5   ; the heap's end, a literal (0x8c800000 there)
//     mov     #-32,r0
//     or      r2,r4           ; r2 = 0x80000000
//     and     r0,r4
//     add     #32,r4          ; area = (_end | P1) & ~31) + 32
//     sub     r4,r5           ; size = end - area
//
// Jet Set Radio's JET_PAL.BIN does it for 0x8c35d740..0x8c800000, and every
// base the learned memory map offered was in there: 0x8c650000 and 0x8c580000
// were overwritten while a level loaded (the console rebooted, the hook being
// on every interrupt), because the map only knows the blocks a session has
// seen written so far, and a heap fills differently each time. Above the
// heap the title keeps fixed buffers at fixed addresses; there is no hole.
//
// So the loader goes at the heap's TOP and the heap's end literal is lowered
// to the loader's base: one word, unlike the start, which is crt0's own `_end`
// (raising it would make crt0 clear the loader with the BSS).
//
// THE PROGRAM THAT SETS THE HEAP IS NOT ALWAYS THE ONE THIS HOST UPLOADS.
// Jet Set Radio boots a small 1ST_READ.BIN that reads JET_PAL.BIN off the disc
// into a buffer, copies it to 0x8c010000 and runs it. So the programs on the
// disc are scanned too, and the word is patched in the sectors served
// (`DiscPatch`), wherever the read lands.
// ---------------------------------------------------------------------------

/// `mov.l @r0,r4`, `mov.l @(disp,pc),r5` (low byte any), then the rest.
const SBINIT: [u16; 7] = [0x6402, 0xd500, 0xe0e0, 0x242b, 0x2409, 0x7420, 0x3548];
/// Where a Katana program runs, wherever it was read to.
const KATANA_LOAD: u32 = 0x8c01_0000;
/// How far back from the sequence the load of `&_end` into r0 may be.
const SBINIT_LOOKBACK: usize = 32;
/// The reach of `mov.l @(disp,pc)`: a literal is named from at most this far.
const PC_REACH: usize = 1024;
/// How much of a disc file is searched for the sequence: sbinit is linked
/// right after crt0 (0x3dbc and 0x3f50 into Jet Set Radio's two programs).
const SCAN_BYTES: u32 = 0x1_0000;

/// One syMalloc heap, as sbInitSystem sets it up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KatanaHeap {
    /// The area handed to syMallocInit (P1).
    pub start: u32,
    /// Its end (P1), from the literal.
    pub end: u32,
    /// Where that literal is in RAM once the program runs, and as it is.
    pub end_at: u32,
    end_raw: u32,
}

/// The sequence at `i` of `data` (run from `base`), its heap if `_end` can be
/// read: from `data` itself, or through `read_word` for a program read only
/// in part.
fn sbinit_at(data: &[u8], base: u32, i: usize, read_word: &dyn Fn(u32) -> Option<u32>) -> Option<KatanaHeap> {
    let op = |k: usize| (k + 2 <= data.len()).then(|| le16(data, k));
    for (k, want) in SBINIT.iter().enumerate() {
        let got = op(i + 2 * k)?;
        if (k == 1 && got & 0xff00 != *want) || (k != 1 && got != *want) {
            return None;
        }
    }
    let (_, lit) = pc_load(op(i + 2)?, i + 2)?;
    let end_raw = (lit + 4 <= data.len()).then(|| le32(data, lit))?;
    // Nothing else may load that literal: the word is the heap's end only.
    let namers = (lit.saturating_sub(PC_REACH)..lit)
        .step_by(2)
        .filter(|&j| op(j).and_then(|o| pc_load(o, j)).is_some_and(|(_, at)| at == lit))
        .count();
    if namers != 1 {
        return None;
    }
    // r0 = &_end, loaded shortly before.
    let end_ptr = (2..=SBINIT_LOOKBACK).step_by(2).find_map(|b| {
        let j = i.checked_sub(b)?;
        let o = op(j)?;
        match pc_load(o, j) {
            Some((0, at)) if at + 4 <= data.len() => Some(le32(data, at)),
            _ => None,
        }
    })?;
    let bss_end = read_word(end_ptr)?;
    let start = p1(((bss_end | 0x8000_0000) & !31).wrapping_add(32));
    let end = p1(end_raw);
    (names_ram(end_raw) && names_ram(bss_end) && start < end && end - start >= MIN_LEFT).then_some(KatanaHeap {
        start,
        end,
        end_at: p1(base).wrapping_add(lit as u32),
        end_raw,
    })
}

/// The syMalloc heap a program sets up, if exactly one sbInitSystem is in it.
pub fn katana_heap(buf: &[u8], address: u32) -> Option<KatanaHeap> {
    let mut found = vec![];
    for (base, data) in payload_spans(buf, address) {
        let word = |a: u32| {
            let off = p1(a).checked_sub(p1(base))? as usize;
            (a & 3 == 0 && off + 4 <= data.len()).then(|| le32(data, off))
        };
        found.extend((0..data.len()).step_by(2).filter_map(|i| sbinit_at(data, base, i, &word)));
    }
    found.dedup();
    match found.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}

impl KatanaHeap {
    /// Where the loader goes: the highest 64 KB boundary that leaves its span
    /// inside the heap.
    pub fn loader_base(&self) -> Option<u32> {
        let base = self.end.checked_sub(crate::loaders::LOADER_SPAN)? & !0xffff;
        (crate::loaders::is_high(base) && base >= self.start + MIN_LEFT).then_some(base)
    }

    /// The heap's end lowered to a loader at `base`, as (RAM address, word).
    /// Nothing when the loader is outside the heap; an error when it is not
    /// at its top, where lowering the end would throw away the heap above it.
    pub fn patch(&self, base: u32) -> Result<Option<(u32, u32)>, String> {
        let (lo, hi) = (p1(base), p1(base) + crate::loaders::LOADER_SPAN);
        if hi <= self.start || lo >= self.end {
            return Ok(None);
        }
        if self.loader_base() != Some(lo) {
            return Err(format!(
                "it is not at the top of the heap (0x{:08x}..0x{:08x}), the only part of it \
                 the end can be lowered past",
                self.start, self.end
            ));
        }
        Ok(Some((self.end_at, (lo & 0x1fff_ffff) | (self.end_raw & 0xe000_0000))))
    }
}

/// A program on the disc that sets up a syMalloc heap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscHeap {
    pub file: String,
    /// The file's first sector, as `read_sector` takes it, and its length.
    pub lba: u32,
    pub size: u32,
    pub heap: KatanaHeap,
}

/// A word to change in the sectors served, wherever the read lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscPatch {
    pub file: String,
    pub lba: u32,
    /// Byte offset of the word in that sector (4-aligned: never split).
    pub off: usize,
    pub was: u32,
    pub value: u32,
}

/// Every program in the boot area's root that sets up a syMalloc heap, read as
/// Katana runs it: from 0x8c010000. Reads the first `SCAN_BYTES` of each
/// `.BIN` and one sector more for `_end`.
pub fn disc_katana_heaps(disc: &dyn DiscFormat) -> Vec<DiscHeap> {
    let root = crate::disc_formats::iso9660::list_root(disc, disc.boot_sector());
    let mut out = vec![];
    for e in root.iter().filter(|e| {
        !e.is_dir
            && e.name.to_ascii_uppercase().ends_with(".BIN")
            && e.size >= SCAN_BYTES
            && e.size <= crate::disc_formats::iso9660::MAX_FILE_BYTES
    }) {
        let Ok(head) = disc.read_sector(e.lba, SCAN_BYTES / 2048) else {
            continue;
        };
        let word = |a: u32| {
            let off = p1(a).checked_sub(KATANA_LOAD)?;
            if a & 3 != 0 || off + 4 > e.size {
                return None;
            }
            match head.get(off as usize..off as usize + 4) {
                Some(b) => Some(u32::from_le_bytes(b.try_into().ok()?)),
                None => {
                    let s = disc.read_sector(e.lba + off / 2048, 1).ok()?;
                    let o = (off % 2048) as usize;
                    Some(u32::from_le_bytes(s.get(o..o + 4)?.try_into().ok()?))
                }
            }
        };
        let found: Vec<KatanaHeap> = (0..head.len())
            .step_by(2)
            .filter_map(|i| sbinit_at(&head, KATANA_LOAD, i, &word))
            .collect();
        if let [h] = found.as_slice() {
            out.push(DiscHeap { file: e.name.clone(), lba: e.lba, size: e.size, heap: *h });
        }
    }
    out
}

impl DiscHeap {
    /// The constants of this program, run from 0x8c010000, that an instruction
    /// loads and that name RAM a loader at `base` occupies: what the placement
    /// rules check a base against, for a program they never see.
    pub fn literals_in_loader(&self, disc: &dyn DiscFormat, base: u32) -> Result<Vec<(u32, u32)>, String> {
        let mut bytes = disc
            .read_sector(self.lba, self.size.div_ceil(2048))
            .map_err(|e| format!("could not read {}: {e}", self.file))?;
        bytes.truncate(self.size as usize);
        Ok(literals_in_loader_footprint(&bytes, KATANA_LOAD, base))
    }

    /// The sector word that lowers this heap's end to a loader at `base`.
    pub fn patch(&self, base: u32) -> Result<Option<DiscPatch>, String> {
        let Some((at, value)) = self.heap.patch(base)? else {
            return Ok(None);
        };
        let off = at - KATANA_LOAD;
        Ok(Some(DiscPatch {
            file: self.file.clone(),
            lba: self.lba + off / 2048,
            off: (off % 2048) as usize,
            was: self.heap.end_raw,
            value,
        }))
    }
}

/// Where the loader goes when its base would be inside a syMalloc heap: the
/// top of the lowest-ending heap it is in, if every heap it then sits in can
/// be lowered past it.
pub fn katana_loader_base(heaps: &[KatanaHeap], base: u32) -> Option<u32> {
    let inside = |b: u32| heaps.iter().filter(move |h| h.patch(b).map_or(true, |p| p.is_some()));
    let top = inside(base).filter_map(|h| h.loader_base()).min()?;
    inside(top).all(|h| h.patch(top).is_ok()).then_some(top)
}

/// Put the disc patches into a read of `buf.len()` bytes from `start`. Only a
/// word that is still the disc's own is changed. Returns the words changed.
pub fn patch_disc_read(patches: &[DiscPatch], start: u32, buf: &mut [u8]) -> usize {
    let mut n = 0;
    for p in patches {
        let Some(sector) = p.lba.checked_sub(start) else { continue };
        let i = sector as usize * 2048 + p.off;
        if let Some(w) = buf.get_mut(i..i + 4)
            && *w == p.was.to_le_bytes()
        {
            w.copy_from_slice(&p.value.to_le_bytes());
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shenmue II's pool (PAL 1.001, 1ST_READ at 0x8c010000), at 0x8c051968.
    fn shenmue2_like() -> Vec<u8> {
        let mut img = vec![0u8; 0x41a00];
        let pool = 0x41968;
        for (k, w) in [
            0x8c36_0000u32,
            0x8c36_0020,
            0x8ceb_ffe0,
            TAG_FREE,
            0x00b5_ffc0,
            TAG_USED,
            TAG_LIB,
        ]
        .iter()
        .enumerate()
        {
            img[pool + 4 * k..pool + 4 * k + 4].copy_from_slice(&w.to_le_bytes());
        }
        img
    }

    #[test]
    fn the_pool_is_found_and_the_loader_goes_at_the_bottom() {
        let h = hlib_heap(&shenmue2_like(), 0x8c01_0000).expect("pool");
        assert_eq!((h.start, h.end), (0x8c36_0000, 0x8ceb_ffe0));
        assert_eq!(h.loader_base(), Some(0x8c36_0000));
        // What was measured by hand on 2026-10-05.
        assert_eq!(
            h.patches(0x8c36_0000).unwrap(),
            vec![
                (0x8c05_1968, 0x8c37_0000),
                (0x8c05_196c, 0x8c37_0020),
                (0x8c05_1978, 0x00b4_ffc0),
            ]
        );
        assert!(h.names_own_bound(0x8c36_0020));
    }

    #[test]
    fn a_loader_at_the_top_lowers_the_end_and_one_in_the_middle_is_refused() {
        let h = hlib_heap(&shenmue2_like(), 0x8c01_0000).unwrap();
        assert_eq!(
            h.patches(0x8ceb_0000).unwrap(),
            vec![(0x8c05_1970, 0x8cea_ffe0), (0x8c05_1978, 0x00b4_ffc0)]
        );
        assert!(h.patches(0x8c80_0000).is_err());
        assert!(h.patches(0x8cf0_0000).unwrap().is_empty());
        assert!(h.patches(0x8c30_0000).unwrap().is_empty());
    }

    #[test]
    fn an_unaligned_start_gives_the_next_boundary_and_keeps_p2_literals_p2() {
        let mut img = shenmue2_like();
        let pool = 0x41968;
        img[pool..pool + 4].copy_from_slice(&0xac35_8000u32.to_le_bytes());
        img[pool + 4..pool + 8].copy_from_slice(&0xac35_8020u32.to_le_bytes());
        img[pool + 16..pool + 20].copy_from_slice(&(0x8ceb_ffe0u32 - 0x8c35_8020).to_le_bytes());
        let h = hlib_heap(&img, 0x8c01_0000).unwrap();
        assert_eq!(h.loader_base(), Some(0x8c36_0000));
        let p = h.patches(0x8c36_0000).unwrap();
        assert_eq!(p[0], (0x8c05_1968, 0xac37_0000));
        assert_eq!(p[1], (0x8c05_196c, 0xac37_0020));
    }

    /// Jet Set Radio PAL's sbInitSystem (JET_PAL.BIN, run at 0x8c010000): the
    /// sequence at 0x8c013f4c and its literals, with `&_end` pointed at a word
    /// kept inside this smaller image.
    fn jsr_like() -> Vec<u8> {
        let mut img = vec![0u8; 0x4100];
        let code: [u16; 9] = [0xd024, 0xd225, 0x6402, 0xd525, 0xe0e0, 0x242b, 0x2409, 0x7420, 0x3548];
        for (k, op) in code.iter().enumerate() {
            img[0x3f4c + 2 * k..0x3f4e + 2 * k].copy_from_slice(&op.to_le_bytes());
        }
        for (at, w) in [(0x3fe0, 0x8c01_4080u32), (0x3fe4, 0x8000_0000), (0x3fe8, 0x8c80_0000), (0x4080, 0x8c35_d720)] {
            img[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        img
    }

    #[test]
    fn jet_set_radios_heap_is_found_and_the_loader_goes_at_its_top() {
        let h = katana_heap(&jsr_like(), 0x8c01_0000).expect("sbInitSystem");
        assert_eq!((h.start, h.end, h.end_at), (0x8c35_d740, 0x8c80_0000, 0x8c01_3fe8));
        assert_eq!(h.loader_base(), Some(0x8c7f_0000));
        assert_eq!(h.patch(0x8c7f_0000).unwrap(), Some((0x8c01_3fe8, 0x8c7f_0000)));
        // Outside: nothing to do. In the middle: refused.
        assert_eq!(h.patch(0x8c80_0000).unwrap(), None);
        assert_eq!(h.patch(0x8c30_0000).unwrap(), None);
        assert!(h.patch(0x8c65_0000).is_err());
        // The bases the learned map gave move to the top; one above stays.
        assert_eq!(katana_loader_base(&[h], 0x8c65_0000), Some(0x8c7f_0000));
        assert_eq!(katana_loader_base(&[h], 0x8c58_0000), Some(0x8c7f_0000));
        assert_eq!(katana_loader_base(&[h], 0x8cef_0000), None);
    }

    #[test]
    fn a_heap_end_another_instruction_loads_is_not_taken() {
        let mut img = jsr_like();
        // mov.l @(disp,pc),r1 naming the same literal, from 0x3f70.
        img[0x3f70..0x3f72].copy_from_slice(&0xd11du16.to_le_bytes());
        assert_eq!(katana_heap(&img, 0x8c01_0000), None);
    }

    #[test]
    fn the_disc_patch_lands_in_any_read_of_its_sector_and_only_on_the_disc_word() {
        let d = DiscHeap {
            file: "JET_PAL.BIN".into(),
            lba: 0x85fe1,
            size: 0x2f_0ae0,
            heap: katana_heap(&jsr_like(), 0x8c01_0000).unwrap(),
        };
        let p = d.patch(0x8c7f_0000).unwrap().expect("patch");
        assert_eq!((p.lba, p.off), (0x85fe1 + 7, 0x7e8));
        // A read of sectors 6..9 of the file, landing anywhere.
        let mut buf = vec![0u8; 3 * 2048];
        buf[2048 + 0x7e8..2048 + 0x7ec].copy_from_slice(&0x8c80_0000u32.to_le_bytes());
        assert_eq!(patch_disc_read(std::slice::from_ref(&p), 0x85fe1 + 6, &mut buf), 1);
        assert_eq!(&buf[2048 + 0x7e8..2048 + 0x7ec], &0x8c7f_0000u32.to_le_bytes());
        // Other data at that place (another disc): left alone.
        let mut other = vec![0x55u8; 3 * 2048];
        assert_eq!(patch_disc_read(std::slice::from_ref(&p), 0x85fe1 + 6, &mut other), 0);
        // A read that does not reach it.
        assert_eq!(patch_disc_read(std::slice::from_ref(&p), 0x85fe1 + 8, &mut buf), 0);
    }

    #[test]
    fn no_tags_no_heap() {
        let mut img = shenmue2_like();
        img[0x41968 + 24..0x41968 + 28].fill(0);
        assert_eq!(hlib_heap(&img, 0x8c01_0000), None);
    }
}
