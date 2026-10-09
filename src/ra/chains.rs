//! Pointers the loader follows itself.
//!
//! A set reads through pointers (`AddAddress`): "the word at the address stored at
//! 0x251278, plus 0x2c". Followed by discovery, every value the pointer ever takes
//! costs the table another word and the console a round trip. Here the SET is
//! walked once (`Probe::walk`, public rcheevos structures only), and each indirect
//! read becomes a CHAIN: a word whose address the loader works out each frame from
//! a word it has just sampled, `(parent & 0xffffff) + offset`. The table stays the
//! same size however the pointer moves, and no frame is lost when it does.
//!
//! What a chain can be: a 24-bit pointer (the Dreamcast sets' `0xW`, which drops
//! the 0x8c of a P1 address) stored in the low three bytes of a word, or in the
//! high three (an address that is 1 mod 4: Shenmue II keeps one there), with a
//! constant offset (negative ones included) that fits 21 bits of words. Anything
//! else is left to discovery, which remains the fallback and makes nothing less
//! correct.

use std::collections::{BTreeSet, HashMap};

/// RAM is 16 MB.
pub const RAM: u32 = 0x0100_0000;

/// Where the value of a chain's parent pointer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Parent {
    /// The table word at this (word-aligned) RAM address.
    Direct(u32),
    /// Another chain's word.
    Chain(usize),
}

/// One word the loader reads at `((parent >> shift) & 0xffffff) + word_off`
/// (wrapping), `shift` being 0 or 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    pub parent: Parent,
    pub shift: u8,
    pub word_off: u32,
}

impl Chain {
    /// What the loader packs: `shift` in bit 21, the offset in words below it
    /// (signed, 21 bits). The parent's index goes above, from bit 22.
    pub fn spec_low(&self) -> u32 {
        (u32::from(self.shift == 8) << 21) | (((self.word_off as i32) >> 2) as u32 & 0x1f_ffff)
    }
}

/// The pointer a node stands for: the word it sits in and where in it.
type Loc = (Parent, u8);

/// What `ra_probe_walk` reports (shim.c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Root { node: i32, addr: u32 },
    Ptr { node: i32, parent: i32, off: u32 },
    Indirect { parent: i32, off: u32, bytes: u32 },
    Direct { addr: u32, bytes: u32 },
    Unsupported,
}

/// What the walk found.
#[derive(Debug, Default, Clone)]
pub struct Walk {
    /// Word-aligned RAM addresses read directly (pointer roots included).
    pub direct: BTreeSet<u32>,
    /// Indirect words, parents before children.
    pub chains: Vec<Chain>,
    /// Constructs not modelled: their reads are left to discovery.
    pub unsupported: usize,
    nodes: HashMap<i32, Option<Loc>>,
    seen: HashMap<(Parent, u8, u32), usize>,
}

/// The largest offset, in bytes, a chain can carry.
const MAX_OFF: i64 = 1 << 22;

impl Walk {
    pub fn from_events(events: impl IntoIterator<Item = Event>) -> Walk {
        let mut w = Walk::default();
        for e in events {
            w.feed(e);
        }
        w
    }

    fn chain(&mut self, (parent, shift): Loc, word_off: u32) -> Option<usize> {
        let off = word_off as i32 as i64;
        if !(-MAX_OFF..MAX_OFF).contains(&off) {
            return None;
        }
        if let Some(i) = self.seen.get(&(parent, shift, word_off)) {
            return Some(*i);
        }
        let i = self.chains.len();
        self.chains.push(Chain { parent, shift, word_off });
        self.seen.insert((parent, shift, word_off), i);
        Some(i)
    }

    /// Where a 24-bit pointer read at byte offset `at` of something lives: in the
    /// word `at & !3`, in its low three bytes (`at` % 4 == 0) or its high three
    /// (`at` % 4 == 1). The other two positions straddle two words.
    fn pointer_slot(at: u32) -> Option<(u32, u8)> {
        match at & 3 {
            0 => Some((at, 0)),
            1 => Some((at & !3, 8)),
            _ => None,
        }
    }

    fn direct_words(&mut self, addr: u32, bytes: u32) {
        let last = addr.wrapping_add(bytes.max(1) - 1);
        let mut a = addr & !3;
        loop {
            if a < RAM {
                self.direct.insert(a);
            }
            if a >= last & !3 {
                break;
            }
            a += 4;
        }
    }

    pub fn feed(&mut self, e: Event) {
        match e {
            Event::Root { node, addr } => {
                match Self::pointer_slot(addr).filter(|(w, _)| *w < RAM) {
                    Some((word, shift)) => {
                        self.direct.insert(word);
                        self.nodes.insert(node, Some((Parent::Direct(word), shift)));
                    }
                    None => {
                        self.nodes.insert(node, None);
                        self.unsupported += 1;
                    }
                }
            }
            Event::Ptr { node, parent, off } => {
                let loc = self.nodes.get(&parent).copied().flatten();
                let made = loc.zip(Self::pointer_slot(off)).and_then(|(p, (word_off, shift))| {
                    self.chain(p, word_off).map(|i| (Parent::Chain(i), shift))
                });
                if made.is_none() {
                    self.unsupported += 1;
                }
                self.nodes.insert(node, made);
            }
            Event::Indirect { parent, off, bytes } => {
                let Some(p) = self.nodes.get(&parent).copied().flatten() else {
                    self.unsupported += 1;
                    return;
                };
                // The bytes at parent + off may straddle two words.
                let first = off & !3;
                let last = off.wrapping_add(bytes.max(1) - 1) & !3;
                let mut w = first;
                loop {
                    if self.chain(p, w).is_none() {
                        self.unsupported += 1;
                        return;
                    }
                    if w == last {
                        break;
                    }
                    w = w.wrapping_add(4);
                }
            }
            Event::Direct { addr, bytes } => self.direct_words(addr, bytes),
            Event::Unsupported => self.unsupported += 1,
        }
    }
}

/// The address of each chain's word under `words` (the table's words, direct then
/// chains): `None` when it falls outside RAM, where rcheevos reads nothing.
pub fn resolve(
    chains: &[Chain],
    direct_index: impl Fn(u32) -> Option<usize>,
    ndirect: usize,
    words: &[u32],
) -> Vec<Option<u32>> {
    chains
        .iter()
        .map(|c| {
            let pv = (match c.parent {
                Parent::Direct(a) => words.get(direct_index(a)?)?,
                Parent::Chain(i) => words.get(ndirect + i)?,
            } >> c.shift)
                & 0x00ff_ffff;
            let a = pv.wrapping_add(c.word_off);
            (a < RAM).then_some(a)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_two_level_chain_and_its_reads() {
        // I:0xW251278 _ I:0xW000004 _ 0xH00002c : a pointer, a pointer inside it,
        // a byte past that.
        let w = Walk::from_events([
            Event::Root { node: 0, addr: 0x251278 },
            Event::Ptr { node: 1, parent: 0, off: 4 },
            Event::Indirect { parent: 1, off: 0x2c, bytes: 1 },
        ]);
        assert_eq!(w.direct.iter().copied().collect::<Vec<_>>(), vec![0x251278]);
        assert_eq!(
            w.chains,
            vec![
                Chain { parent: Parent::Direct(0x251278), shift: 0, word_off: 4 },
                Chain { parent: Parent::Chain(0), shift: 0, word_off: 0x2c },
            ]
        );
    }

    #[test]
    fn a_read_across_two_words_takes_both() {
        let w = Walk::from_events([
            Event::Root { node: 0, addr: 0x1000 },
            Event::Indirect { parent: 0, off: 0x2e, bytes: 4 },
        ]);
        assert_eq!(w.chains.len(), 2);
        assert_eq!((w.chains[0].word_off, w.chains[1].word_off), (0x2c, 0x30));
    }

    #[test]
    fn the_same_chain_from_two_achievements_is_one_word() {
        let w = Walk::from_events([
            Event::Root { node: 0, addr: 0x1000 },
            Event::Indirect { parent: 0, off: 0x10, bytes: 1 },
            Event::Root { node: 5, addr: 0x1000 },
            Event::Indirect { parent: 5, off: 0x11, bytes: 1 },
            Event::Indirect { parent: 5, off: 0x14, bytes: 1 },
        ]);
        assert_eq!(w.chains.len(), 2, "0x10 and 0x14, the second read shares 0x10");
    }

    #[test]
    fn a_negative_offset_wraps_like_the_address_does() {
        let w = Walk::from_events([
            Event::Root { node: 0, addr: 0x1000 },
            Event::Indirect { parent: 0, off: 0xffff_fc18, bytes: 1 },
        ]);
        assert_eq!(w.chains[0].word_off, 0xffff_fc18);
        assert_eq!(w.chains[0].spec_low(), 0x1f_ff06, "-1000 bytes = -250 words, 21 bits, no shift");
        let a = resolve(&w.chains, |a| (a == 0x1000).then_some(0), 1, &[0x0012_3456]);
        assert_eq!(a, vec![Some(0x0012_3456 - 1000)], "pointer 0x123456 - 0x3e8");
    }

    #[test]
    fn what_cannot_be_a_chain_is_left_to_discovery() {
        let w = Walk::from_events([
            Event::Root { node: 0, addr: 0x1002 },   // a pointer that straddles two words
            Event::Indirect { parent: 0, off: 4, bytes: 1 },
            Event::Root { node: 1, addr: 0x2000 },
            Event::Ptr { node: 2, parent: 1, off: 6 }, // ... at an offset that does
            Event::Indirect { parent: 2, off: 4, bytes: 1 },
            Event::Root { node: 3, addr: 0x2000 },
            Event::Indirect { parent: 3, off: 0x4000_0000, bytes: 1 }, // too far
            Event::Unsupported,
        ]);
        assert!(w.chains.is_empty());
        assert_eq!(w.unsupported, 6);
    }

    #[test]
    fn a_pointer_in_the_high_three_bytes_of_a_word_is_a_chain_with_a_shift() {
        // Shenmue II: I:0xW531719 -- bytes 1..3 of the word at 0x531718
        let w = Walk::from_events([
            Event::Root { node: 0, addr: 0x531719 },
            Event::Indirect { parent: 0, off: 0xffff_fc18, bytes: 1 },
        ]);
        assert!(w.direct.contains(&0x531718));
        assert_eq!(
            w.chains,
            vec![Chain { parent: Parent::Direct(0x531718), shift: 8, word_off: 0xffff_fc18 }]
        );
        assert_eq!(w.chains[0].spec_low() >> 21, 1, "the shift flag");
        // the word holds 0x12 in its low byte and the pointer 0x345678 above it
        let a = resolve(&w.chains, |a| (a == 0x531718).then_some(0), 1, &[0x3456_7812]);
        assert_eq!(a, vec![Some(0x34_5678 - 1000)]);
    }

    #[test]
    fn an_address_outside_ram_resolves_to_nothing() {
        let c = [Chain { parent: Parent::Direct(0x1000), shift: 0, word_off: 0xffff_fff0 }];
        assert_eq!(resolve(&c, |_| Some(0), 1, &[0x8]), vec![None], "0x8 - 0x10 wraps to 0xfffffff8");
        assert_eq!(resolve(&c, |_| Some(0), 1, &[0x10]), vec![Some(0)], "0x10 - 0x10 is address 0");
    }

    #[test]
    fn direct_reads_cover_their_bytes() {
        let w = Walk::from_events([Event::Direct { addr: 0x1ffe, bytes: 4 }]);
        assert_eq!(w.direct.iter().copied().collect::<Vec<_>>(), vec![0x1ffc, 0x2000]);
    }
}
