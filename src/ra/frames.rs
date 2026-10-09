//! `RAFR`: the loader's frames, put back into a memory image.
//!
//! Layout (loader AGENTS.md 4.20), every word big-endian: generation, record
//! count, then records. A record is one window of the table (`WIN` words):
//! a header (`frame << 16 | 0x8000 key | 0x4000 last | window << 9 | changed`),
//! a bitmap of `WIN_MAP` words, one word per set bit. A frame is one or more
//! records and is complete at the one flagged `last`; a keyframe sets every bit
//! of every window and may be cut across datagrams.

/// Words per window, and words of its bitmap: `RA_WIN`, `RA_WIN_MAP` in ra.h.
pub const WIN: usize = 128;
pub const WIN_MAP: usize = WIN / 32;

const KEY: u32 = 0x8000;
const LAST: u32 = 0x4000;

/// What `Mirror::apply` found in a datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// This many frames were completed and reported to the caller.
    Frames(usize),
    /// The table has changed since these frames were sampled: ignored.
    OldGeneration,
    /// A datagram was lost (or frames dropped on the console): memory could
    /// be stale until the next keyframe, and the caller must not evaluate.
    Lost,
    /// Truncated or inconsistent: ignored.
    Malformed,
}

/// The console's memory as last reported, in table order.
pub struct Mirror {
    generation: u32,
    words: Vec<u32>,
    windows: u32,
    next_seq: Option<u32>,
    /// False from a gap, or before the first complete keyframe.
    trusted: bool,
    /// The frame whose records have started and not finished.
    open: Option<u16>,
    /// Windows of the keyframe in progress that have arrived.
    key_mask: u32,
    /// Datagrams known lost.
    pub lost: u32,
}

impl Mirror {
    pub fn new(generation: u32, words: usize) -> Self {
        Mirror {
            generation,
            words: vec![0; words],
            windows: words.div_ceil(WIN) as u32,
            next_seq: None,
            trusted: false,
            open: None,
            key_mask: 0,
            lost: 0,
        }
    }

    #[cfg(test)]
    pub fn trusted(&self) -> bool {
        self.trusted
    }

    /// The word at `index` of the table (`Table::index_of`).
    #[cfg(test)]
    pub fn word(&self, index: usize) -> u32 {
        self.words[index]
    }

    /// Every word, in table order.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// Apply one datagram: `seq` is the command's address field, `payload` the
    /// bytes after the 12-byte header. `on_frame` is called when a frame that
    /// may be trusted is complete, with the loader's frame number and the memory
    /// as of that frame -- the achievement logic runs there, one frame at a time.
    pub fn apply(
        &mut self,
        seq: u32,
        payload: &[u8],
        mut on_frame: impl FnMut(u16, &Mirror),
    ) -> Applied {
        let mut r = Reader { data: payload, at: 0 };
        let (Some(gen_), Some(count)) = (r.word(), r.word()) else {
            return Applied::Malformed;
        };
        if gen_ != self.generation {
            // Frames of the previous table: the next generation starts with a
            // keyframe anyway.
            self.next_seq = None;
            return Applied::OldGeneration;
        }
        if self.next_seq.is_some_and(|n| n != seq) {
            self.trusted = false;
            self.open = None;
            self.lost += 1;
        }
        self.next_seq = Some(seq.wrapping_add(1));

        let mut frames = 0usize;
        for _ in 0..count {
            let Some(hdr) = r.word() else { return Applied::Malformed };
            let (frame, key, last) = ((hdr >> 16) as u16, hdr & KEY != 0, hdr & LAST != 0);
            let win = (hdr >> 9 & 0x1f) as usize;
            let changed = (hdr & 0x1ff) as usize;
            let mut map = [0u32; WIN_MAP];
            for m in map.iter_mut() {
                let Some(w) = r.word() else { return Applied::Malformed };
                *m = w;
            }
            if map.iter().map(|m| m.count_ones() as usize).sum::<usize>() != changed {
                return Applied::Malformed;
            }

            if self.open != Some(frame) {
                // A frame that never reached its last record leaves the memory
                // half updated.
                if self.open.is_some() {
                    self.trusted = false;
                }
                self.open = Some(frame);
                self.key_mask = 0;
            }
            if key {
                self.key_mask |= 1 << win;
            }
            // A delta over a hole is not applied: it would be a value against a
            // base the console has moved on from. A keyframe is its own base.
            let apply = key || self.trusted;
            for i in 0..WIN {
                if map[i / 32] & (1 << (i % 32)) == 0 {
                    continue;
                }
                let Some(v) = r.word() else { return Applied::Malformed };
                let at = win * WIN + i;
                if at >= self.words.len() {
                    return Applied::Malformed;
                }
                if apply {
                    self.words[at] = v;
                }
            }

            if last {
                self.open = None;
                if key {
                    self.trusted = self.key_mask == (1u32 << self.windows) - 1;
                }
                if self.trusted {
                    frames += 1;
                    on_frame(frame, self);
                }
            }
        }
        if frames == 0 && !self.trusted { Applied::Lost } else { Applied::Frames(frames) }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn word(&mut self) -> Option<u32> {
        let b = self.data.get(self.at..self.at + 4)?;
        self.at += 4;
        Some(u32::from_be_bytes(b.try_into().unwrap()))
    }
}

#[cfg(test)]
pub(super) mod build {
    //! What the loader's `ra_sample`/`ra_send_one` write, for the tests.
    use super::*;

    /// The records of one frame over `n` table words: `changes` are
    /// (index, value) pairs; a keyframe sends every word of `all`.
    pub fn frame(no: u16, key: bool, n: usize, changes: &[(usize, u32)]) -> Vec<Vec<u8>> {
        let mut recs: Vec<(usize, Vec<(usize, u32)>)> = Vec::new();
        for w in 0..n.div_ceil(WIN) {
            let mine: Vec<(usize, u32)> = changes
                .iter()
                .copied()
                .filter(|(i, _)| i / WIN == w)
                .map(|(i, v)| (i % WIN, v))
                .collect();
            if !mine.is_empty() {
                recs.push((w, mine));
            }
        }
        if recs.is_empty() {
            recs.push((0, vec![]));
        }
        let total = recs.len();
        recs.into_iter()
            .enumerate()
            .map(|(k, (w, mut mine))| {
                mine.sort();
                let mut map = [0u32; WIN_MAP];
                for (i, _) in &mine {
                    map[i / 32] |= 1 << (i % 32);
                }
                let hdr = (no as u32) << 16
                    | if key { KEY } else { 0 }
                    | if k + 1 == total { LAST } else { 0 }
                    | (w as u32) << 9
                    | mine.len() as u32;
                let mut out = hdr.to_be_bytes().to_vec();
                for m in map {
                    out.extend_from_slice(&m.to_be_bytes());
                }
                for (_, v) in mine {
                    out.extend_from_slice(&v.to_be_bytes());
                }
                out
            })
            .collect()
    }

    /// A keyframe of `words`.
    pub fn keyframe(no: u16, words: &[u32]) -> Vec<Vec<u8>> {
        let all: Vec<(usize, u32)> = words.iter().copied().enumerate().collect();
        frame(no, true, words.len(), &all)
    }

    pub fn datagram(gen_: u32, records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = gen_.to_be_bytes().to_vec();
        out.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn keyframe_then_delta() {
        let mut m = Mirror::new(1, 4);
        let key = datagram(1, &keyframe(1, &[10, 11, 12, 13]));
        assert_eq!(m.apply(0, &key, |_, _| {}), Applied::Frames(1));
        let mut recs = frame(2, false, 4, &[(2, 99)]);
        recs.extend(frame(3, false, 4, &[(0, 7)]));
        let mut seen = Vec::new();
        assert_eq!(
            m.apply(1, &datagram(1, &recs), |no, m| seen.push((no, m.word(0), m.word(2)))),
            Applied::Frames(2)
        );
        // each frame is reported with the memory as of THAT frame
        assert_eq!(seen, vec![(2, 10, 99), (3, 7, 99)]);
        assert_eq!((m.word(0), m.word(1), m.word(2)), (7, 11, 99));
    }

    #[test]
    fn a_frame_with_no_change_still_counts() {
        let mut m = Mirror::new(1, 4);
        m.apply(0, &datagram(1, &keyframe(1, &[1, 2, 3, 4])), |_, _| {});
        let mut seen = 0;
        m.apply(1, &datagram(1, &frame(2, false, 4, &[])), |_, _| seen += 1);
        assert_eq!(seen, 1, "hit counts run on frames, changed or not");
    }

    #[test]
    fn a_keyframe_cut_across_two_datagrams_is_trusted_only_when_whole() {
        let n = 300; // three windows
        let words: Vec<u32> = (0..n as u32).map(|i| i * 3).collect();
        let recs = keyframe(1, &words);
        assert_eq!(recs.len(), 3);
        let mut m = Mirror::new(1, n);
        assert_eq!(m.apply(0, &datagram(1, &recs[..2]), |_, _| {}), Applied::Lost);
        assert!(!m.trusted(), "half a keyframe is not a base");
        let mut seen = Vec::new();
        assert_eq!(
            m.apply(1, &datagram(1, &recs[2..]), |no, m| seen.push((no, m.word(299)))),
            Applied::Frames(1)
        );
        assert_eq!(seen, vec![(1, 897)]);
        assert!(m.trusted());
        assert_eq!(m.word(130), 390);
    }

    #[test]
    fn the_second_datagram_of_a_keyframe_lost_leaves_it_untrusted() {
        let n = 300;
        let words = vec![5u32; n];
        let recs = keyframe(1, &words);
        let mut m = Mirror::new(1, n);
        m.apply(0, &datagram(1, &recs[..2]), |_, _| {});
        // datagram 1 never arrives; a delta frame follows in datagram 2
        let delta = datagram(1, &frame(2, false, n, &[(0, 9)]));
        assert_eq!(m.apply(2, &delta, |_, _| panic!("judged")), Applied::Lost);
        assert!(!m.trusted());
        assert_eq!(m.word(0), 5);
    }

    #[test]
    fn a_lost_datagram_blocks_deltas_until_a_keyframe() {
        let mut m = Mirror::new(1, 2);
        m.apply(0, &datagram(1, &keyframe(1, &[1, 2])), |_, _| {});
        // sequence 1 never arrives
        let delta = datagram(1, &frame(5, false, 2, &[(0, 50)]));
        assert_eq!(m.apply(2, &delta, |_, _| {}), Applied::Lost);
        assert!(!m.trusted());
        assert_eq!(m.word(0), 1, "a delta over a hole must not be applied");
        assert_eq!(m.apply(3, &datagram(1, &keyframe(6, &[60, 61])), |_, _| {}), Applied::Frames(1));
        assert!(m.trusted());
        assert_eq!(m.lost, 1);
    }

    #[test]
    fn frames_of_an_old_table_are_ignored() {
        let mut m = Mirror::new(2, 1);
        let old = datagram(1, &keyframe(1, &[5]));
        assert_eq!(m.apply(0, &old, |_, _| {}), Applied::OldGeneration);
        assert_eq!(m.word(0), 0);
    }

    #[test]
    fn truncated_and_inconsistent_datagrams() {
        let mut m = Mirror::new(1, 1);
        let mut d = datagram(1, &keyframe(1, &[5]));
        d.truncate(d.len() - 2);
        assert_eq!(m.apply(0, &d, |_, _| {}), Applied::Malformed);
        let mut bad = datagram(1, &keyframe(1, &[5]));
        bad[11] ^= 1; // header says 0 changed words, bitmap has one bit
        assert_eq!(m.apply(0, &bad, |_, _| {}), Applied::Malformed);
        // a bit past the end of the table
        let mut m = Mirror::new(1, 1);
        let beyond = datagram(1, &frame(1, true, 2, &[(0, 1), (1, 2)]));
        assert_eq!(m.apply(0, &beyond, |_, _| {}), Applied::Malformed);
    }
}
