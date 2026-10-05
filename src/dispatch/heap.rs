//! A Katana allocator that owns all the RAM a title leaves free, found by its
//! literal pool, and the loader taken out of it.
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

    #[test]
    fn no_tags_no_heap() {
        let mut img = shenmue2_like();
        img[0x41968 + 24..0x41968 + 28].fill(0);
        assert_eq!(hlib_heap(&img, 0x8c01_0000), None);
    }
}
