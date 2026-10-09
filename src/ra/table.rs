//! The table sent to the loader (`RACT`): RAM ranges, then the chains it follows
//! itself (`chains.rs`).

use super::chains::{Chain, Parent};

/// Limits of the loader's build (`RA_RANGES`, `RA_WORDS`, ra.h). The words a
/// table may really have are the loader's room, which its `RACT` answer gives
/// (Katana, Windows CE); `MAX_WORDS` only caps it.
pub const MAX_RANGES: usize = 384;
pub const MAX_WORDS: usize = 1024;
/// `RA_CHAINS` in the loader's ra.h.
pub const MAX_CHAINS: usize = 64;
/// Bytes one `RACT` part may carry: the loader takes no IP fragment, so each
/// part must fit one Ethernet frame (1500 - IP 20 - UDP 8 - command 12). A
/// longer one is fragmented by the PC's stack and never reaches the loader at
/// all (Sonic Adventure 2, 2026-10-07); a table is sent in as many parts as it
/// takes (`parts()`).
pub const MAX_PAYLOAD: usize = 1460;
/// A part's header: ranges and chains in all, then the first range and the
/// number of ranges of this part, then the same for chains.
const PART_HEADER: usize = 24;
/// Two words closer than a gap become one range: a range costs a table entry
/// and a word costs RAM sampled, so the gap is the smallest that fits the loader's
/// range budget (adjacent words only, if that is enough).
const GAPS: [u32; 7] = [0, 4, 8, 16, 32, 64, 128];
/// RAM is 16 MB; the loader refuses anything outside.
const RAM: u32 = 0x0100_0000;

/// One run of 32-bit words, `offset` from the start of RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub offset: u32,
    pub words: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub ranges: Vec<Range>,
    /// Words the loader works out from other words; they follow the ranges'
    /// words in the table's index space.
    pub chains: Vec<Chain>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TableError {
    /// More than the loader can sample: the words and ranges that were asked for.
    TooBig { words: usize, ranges: usize },
}

/// Distinct words `addrs` reads (RAM only), before any merging: what a set
/// asks for, as against what its table carries.
pub fn distinct_words(addrs: impl IntoIterator<Item = u32>) -> usize {
    let mut words: Vec<u32> = addrs.into_iter().filter(|a| *a < RAM).map(|a| a & !3).collect();
    words.sort_unstable();
    words.dedup();
    words.len()
}

impl Table {
    /// The ranges covering `addrs` (RAM offsets of the bytes read, any size
    /// already expanded by the caller): aligned down to a word, sorted,
    /// merged. Addresses outside RAM are dropped: they are not the console's.
    #[cfg(test)]
    pub fn from_addresses(addrs: impl IntoIterator<Item = u32>) -> Result<Table, TableError> {
        Self::from_addresses_within(addrs, MAX_WORDS)
    }

    /// The same, for a loader whose room is `max_words` (Windows CE's is less).
    #[cfg(test)]
    pub fn from_addresses_within(
        addrs: impl IntoIterator<Item = u32>,
        max_words: usize,
    ) -> Result<Table, TableError> {
        Self::build(addrs, &[], max_words)
    }

    /// The ranges covering `addrs`, and `chains` after them. Refused, not
    /// truncated, when it does not fit the loader.
    pub fn build(
        addrs: impl IntoIterator<Item = u32>,
        chains: &[Chain],
        max_words: usize,
    ) -> Result<Table, TableError> {
        let mut words: Vec<u32> = addrs
            .into_iter()
            .filter(|a| *a < RAM)
            .map(|a| a & !3)
            .collect();
        words.sort_unstable();
        words.dedup();

        let merge = |gap: u32| {
            let mut ranges: Vec<Range> = Vec::new();
            for &w in &words {
                match ranges.last_mut() {
                    Some(r) if w <= r.offset + 4 * r.words + gap => {
                        r.words = (w - r.offset) / 4 + 1;
                    }
                    _ => ranges.push(Range { offset: w, words: 1 }),
                }
            }
            ranges
        };
        // the finest merge that fits the range budget (the widest, if none does)
        let budget = MAX_RANGES;
        let mut ranges = merge(GAPS[0]);
        for gap in GAPS {
            ranges = merge(gap);
            if ranges.len() <= budget {
                break;
            }
        }
        let total: usize = ranges.iter().map(|r| r.words as usize).sum::<usize>() + chains.len();
        if ranges.len() > budget || chains.len() > MAX_CHAINS || total > max_words {
            return Err(TableError::TooBig { words: total, ranges: ranges.len() });
        }
        Ok(Table { ranges, chains: chains.to_vec() })
    }

    /// Words in all of the ranges: the ones read from RAM as they are.
    pub fn direct_words(&self) -> usize {
        self.ranges.iter().map(|r| r.words as usize).sum()
    }

    /// Every word of the table: the ranges', then one per chain.
    pub fn words(&self) -> usize {
        self.direct_words() + self.chains.len()
    }

    /// The `RACT` parts (loader ra.h), each at most `MAX_PAYLOAD` bytes: a
    /// header (ranges in all, chains in all, first range of the part, its ranges,
    /// first chain of the part, its chains), then `{offset, words}` per range,
    /// then per chain `parent index << 22 | shift flag << 21 | offset in words`
    /// (the offset signed, 21 bits). Indices are in the table's own word order.
    /// The chains come after the last range; an empty table is one part.
    pub fn parts(&self) -> Vec<Vec<u8>> {
        let nd = self.direct_words();
        let specs: Vec<u32> = self
            .chains
            .iter()
            .map(|c| {
                let parent = match c.parent {
                    Parent::Direct(a) => self.index_of(a).expect("a chain's root is in the table"),
                    Parent::Chain(i) => nd + i,
                };
                (parent as u32) << 22 | c.spec_low()
            })
            .collect();
        let (nr, nc) = (self.ranges.len(), specs.len());
        let mut parts = Vec::new();
        let (mut r0, mut c0) = (0usize, 0usize);
        loop {
            let mut room = MAX_PAYLOAD - PART_HEADER;
            let rc = (room / 8).min(nr - r0);
            room -= 8 * rc;
            // chains only once every range is in
            let cc = if r0 + rc == nr { (room / 4).min(nc - c0) } else { 0 };
            let mut out = Vec::with_capacity(PART_HEADER + 8 * rc + 4 * cc);
            for v in [nr, nc, r0, rc, c0, cc] {
                out.extend_from_slice(&(v as u32).to_be_bytes());
            }
            for r in &self.ranges[r0..r0 + rc] {
                out.extend_from_slice(&r.offset.to_be_bytes());
                out.extend_from_slice(&r.words.to_be_bytes());
            }
            for s in &specs[c0..c0 + cc] {
                out.extend_from_slice(&s.to_be_bytes());
            }
            parts.push(out);
            r0 += rc;
            c0 += cc;
            if r0 == nr && c0 == nc {
                return parts;
            }
        }
    }

    /// Every word address in the table, in table order.
    #[cfg(test)]
    pub fn word_addresses(&self) -> impl Iterator<Item = u32> + '_ {
        self.ranges
            .iter()
            .flat_map(|r| (0..r.words).map(move |i| r.offset + 4 * i))
    }

    /// Index in the sampled words of the word holding `addr`, if it is in the
    /// table. Ranges are sorted, so this is a binary search.
    pub fn index_of(&self, addr: u32) -> Option<usize> {
        let w = addr & !3;
        let mut before = 0usize;
        for r in &self.ranges {
            if w >= r.offset && w < r.offset + 4 * r.words {
                return Some(before + ((w - r.offset) / 4) as usize);
            }
            before += r.words as usize;
        }
        None
    }
}

/// A `RACT` as the loader receives it (ra.c `cmd_ract`), for the fake consoles
/// of the tests: parts in order, a first part starts over, a part that does not
/// follow is ignored. `push` returns the table once a part completes it: the
/// `{offset, words}` ranges and the raw chain words.
#[cfg(test)]
#[derive(Default)]
pub struct Assembler {
    generation: u32,
    totals: (usize, usize),
    ranges: Vec<(u32, u32)>,
    chains: Vec<u32>,
}

#[cfg(test)]
impl Assembler {
    pub fn push(&mut self, generation: u32, data: &[u8]) -> Option<(Vec<(u32, u32)>, Vec<u32>)> {
        let w = |i: usize| u32::from_be_bytes(data[4 * i..4 * i + 4].try_into().unwrap());
        let (nr, nc, r0, rc, c0, cc) =
            (w(0) as usize, w(1) as usize, w(2) as usize, w(3) as usize, w(4) as usize, w(5) as usize);
        assert_eq!(data.len(), PART_HEADER + 8 * rc + 4 * cc, "a part's size");
        assert!(data.len() <= MAX_PAYLOAD, "a part fits one datagram");
        if r0 == 0 && c0 == 0 {
            *self = Assembler { generation, totals: (nr, nc), ..Default::default() };
        } else if generation != self.generation
            || (nr, nc) != self.totals
            || r0 != self.ranges.len()
            || c0 != self.chains.len()
        {
            return None;
        }
        assert!(cc == 0 || r0 + rc == nr, "chains come after the last range");
        self.ranges.extend((0..rc).map(|i| (w(6 + 2 * i), w(7 + 2 * i))));
        self.chains.extend((0..cc).map(|i| w(6 + 2 * rc + i)));
        (self.ranges.len() == nr && self.chains.len() == nc)
            .then(|| (std::mem::take(&mut self.ranges), std::mem::take(&mut self.chains)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_words_merge_and_nothing_else_while_the_budget_allows() {
        let t = Table::from_addresses([0x1000, 0x1004, 0x1010, 0x4000]).unwrap();
        assert_eq!(
            t.ranges,
            vec![
                Range { offset: 0x1000, words: 2 },
                Range { offset: 0x1010, words: 1 },
                Range { offset: 0x4000, words: 1 },
            ],
            "no filler words when ranges are not short"
        );
        assert_eq!(t.words(), 4);
    }

    #[test]
    fn a_wider_gap_is_used_only_when_the_ranges_would_not_fit() {
        // 400 words 16 bytes apart: 400 ranges is too many (384); a 16-byte gap
        // makes one range of 1597 words -- too many words, so the set is refused
        // rather than truncated, but the merge tried the narrowest gap that fits.
        let addrs: Vec<u32> = (0..400u32).map(|i| i * 16).collect();
        assert_eq!(
            Table::from_addresses(addrs),
            Err(TableError::TooBig { words: 1597, ranges: 1 })
        );
        // 350 words 8 bytes apart need no merging at all: 350 ranges fit
        let addrs: Vec<u32> = (0..350u32).map(|i| i * 8).collect();
        let t = Table::from_addresses(addrs).unwrap();
        assert_eq!((t.ranges.len(), t.words()), (350, 350));
        // 400 words 8 bytes apart do not: the gap grows to 4 bytes of space between
        // them, which merges every pair
        let addrs: Vec<u32> = (0..400u32).map(|i| i * 8).collect();
        let t = Table::from_addresses(addrs).unwrap();
        assert!(t.ranges.len() <= MAX_RANGES && t.words() > 400, "{} ranges", t.ranges.len());
    }

    #[test]
    fn distinct_words_count_no_filler() {
        // two words 64 bytes apart, a duplicate, an unaligned byte, outside RAM
        assert_eq!(distinct_words([0x1000, 0x1040, 0x1002, 0x1041, 0x0200_0000]), 2);
    }

    #[test]
    fn unaligned_duplicate_and_outside_ram_addresses() {
        let t = Table::from_addresses([0x1001, 0x1003, 0x1000, 0x0200_0000]).unwrap();
        assert_eq!(t.ranges, vec![Range { offset: 0x1000, words: 1 }]);
    }

    #[test]
    fn too_many_words_is_refused_not_truncated() {
        let addrs = (0..1100u32).map(|i| i * 4);
        assert_eq!(Table::from_addresses(addrs), Err(TableError::TooBig { words: 1100, ranges: 1 }));
    }

    #[test]
    fn a_smaller_room_refuses_what_a_larger_one_takes() {
        let addrs: Vec<u32> = (0..150u32).flat_map(|i| [i * 64, i * 64 + 4]).collect();
        assert!(Table::from_addresses(addrs.clone()).is_ok());
        assert_eq!(
            Table::from_addresses_within(addrs, 248),
            Err(TableError::TooBig { words: 300, ranges: 150 })
        );
    }

    #[test]
    fn a_part_is_big_endian() {
        let t = Table::from_addresses([0x0c00_0000 & 0x00ff_ffff, 0x2004]).unwrap();
        assert_eq!(
            t.parts(),
            vec![vec![
                0, 0, 0, 2, 0, 0, 0, 0, // 2 ranges, no chain in all
                0, 0, 0, 0, 0, 0, 0, 2, // from range 0, 2 ranges
                0, 0, 0, 0, 0, 0, 0, 0, // from chain 0, none
                0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0x20, 0x04, 0, 0, 0, 1
            ]]
        );
        // an empty table is one part, which the loader answers
        let empty = Table { ranges: vec![], chains: vec![] };
        assert_eq!(empty.parts(), vec![vec![0u8; PART_HEADER]]);
    }

    #[test]
    fn chains_follow_the_ranges_in_the_index_space() {
        use crate::ra::chains::{Chain, Parent};
        let chains = [
            Chain { parent: Parent::Direct(0x5000), shift: 0, word_off: 0x2c },
            Chain { parent: Parent::Chain(0), shift: 0, word_off: 0xffff_fff0 },
        ];
        let t = Table::build([0x1000, 0x1004, 0x5000], &chains, 512).unwrap();
        assert_eq!((t.direct_words(), t.words()), (3, 5));
        let parts = t.parts();
        assert_eq!(parts.len(), 1);
        // 2 ranges, 2 words + 1 word, 2 chains; the first's parent is word 2 (0x5000),
        // offset 0x2c / 4 = 11; the second's parent is chain 0 = word 3, offset -4 words
        let (ranges, chains) = Assembler::default().push(1, &parts[0]).unwrap();
        assert_eq!(ranges, vec![(0x1000, 2), (0x5000, 1)]);
        assert_eq!(chains, vec![2 << 22 | 11, 3 << 22 | 0x1f_fffc]);
    }

    #[test]
    fn a_table_too_big_for_one_datagram_goes_in_parts() {
        use crate::ra::chains::{Chain, Parent};
        // Sonic Adventure 2 (2026-10-07): one 1476-byte RACT, fragmented on the wire,
        // never reached the loader; Sega Rally 2 needs 337 ranges (2026-10-08). The
        // most the loader takes: 384 ranges and 64 chains, ~3.4 KB.
        let addrs: Vec<u32> = (0..MAX_RANGES as u32).map(|i| i * 0x100).collect();
        let chains: Vec<Chain> = (0..MAX_CHAINS as u32)
            .map(|i| Chain { parent: Parent::Direct(0x100 * i), shift: 0, word_off: 4 * i })
            .collect();
        let t = Table::build(addrs, &chains, MAX_WORDS).unwrap();
        assert_eq!((t.ranges.len(), t.chains.len()), (MAX_RANGES, MAX_CHAINS));
        let parts = t.parts();
        assert!(parts.len() >= 3, "{} parts", parts.len());
        assert!(parts.iter().all(|p| p.len() <= MAX_PAYLOAD));
        // as the loader takes them: nothing until the last, then the whole table
        let mut a = Assembler::default();
        for p in &parts[..parts.len() - 1] {
            assert_eq!(a.push(3, p), None);
        }
        let (ranges, specs) = a.push(3, parts.last().unwrap()).unwrap();
        assert_eq!(ranges, t.ranges.iter().map(|r| (r.offset, r.words)).collect::<Vec<_>>());
        assert_eq!(specs.len(), MAX_CHAINS);
        assert_eq!(specs[5], 5 << 22 | 5, "chain 5: parent word 5, offset 5 words");
        // a part lost on the way: what follows is ignored, the table is never whole
        let mut a = Assembler::default();
        assert_eq!(a.push(4, &parts[0]), None);
        for p in &parts[2..] {
            assert_eq!(a.push(4, p), None);
        }
    }

    #[test]
    fn chains_count_against_the_room() {
        use crate::ra::chains::{Chain, Parent};
        let chains: Vec<Chain> = (0..10)
            .map(|i| Chain { parent: Parent::Direct(0x1000), shift: 0, word_off: 4 * i })
            .collect();
        assert!(Table::build([0x1000], &chains, 11).is_ok());
        assert_eq!(
            Table::build([0x1000], &chains, 10),
            Err(TableError::TooBig { words: 11, ranges: 1 })
        );
    }

    #[test]
    fn index_counts_words_across_ranges() {
        let t = Table::from_addresses([0x1000, 0x1004, 0x5000]).unwrap();
        assert_eq!(t.index_of(0x1006), Some(1));
        assert_eq!(t.index_of(0x5002), Some(2));
        assert_eq!(t.index_of(0x3000), None);
    }
}
