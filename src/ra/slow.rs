//! The slow path: memory the loader's table has no room for, read with `SBIQ`.
//!
//! WHY. A set can read more than the loader samples (512 words). Sega Rally 2's
//! reads 1775, ~900 of them for its rich presence alone (2026-10-08). The rich
//! presence is the one part that does not need every frame: the site gets it at
//! rc_client's ping every 2 minutes, Discord every 15 s, and it seldom compares
//! a value with the previous frame. So when the set does not fit, the probe
//! builds the table without it (`session::Keep`), and every word the real client
//! reads that the table lacks is read here instead, a cycle at a time, and the
//! client sees the last cycle's value (`Env::read`). Achievements and
//! leaderboards stay in the table: they are judged frame by frame.
//!
//! HOW. The wanted words are grouped into pieces (neighbours within `GAP` read
//! together, at most `PIECE` bytes) and asked `IN_FLIGHT` at a time: the loader
//! answers `SBIQ` only while it listens (the hook's idle listen, at most 1 ms
//! every 50 ms, and the GD waits), and answers every request waiting in its ring
//! then. Sega Rally 2's rich presence is ~900 words in ~300 pieces, so one at a
//! time would take ~15 s a cycle. A piece is asked again after `RETRY` without
//! its last byte (a datagram can be lost). A cycle starts at most every `EVERY`
//! (5 s);
//! each piece's words are handed over as it completes.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Bytes of one `SBIQ`: four of the loader's 1440-byte replies, back to back.
pub const PIECE: u32 = 4 * 1440;
/// Two wanted words this close are read in one piece, with what lies between.
const GAP: u32 = 256;
/// Pieces asked at once, and the bytes they may come to.
const IN_FLIGHT: usize = 8;
const IN_FLIGHT_BYTES: u32 = 2 * PIECE;
/// A cycle starts at most this often. Each read is a request and an answer the
/// loader sends from its listen windows, inside a disc read's wait too (as
/// `--diag`'s are): ~600 datagrams a cycle for Sega Rally 2. What it feeds is
/// shown every 15 s at best (Discord) and sent every 2 minutes (the site).
const EVERY: Duration = Duration::from_secs(5);
/// A piece is asked again after this long without its last byte.
const RETRY: Duration = Duration::from_millis(300);

struct Piece {
    lo: u32,
    len: u32,
    buf: Vec<u8>,
    have: Vec<bool>,
    asked: Option<Instant>,
    done: bool,
}

#[derive(Default)]
pub struct Slow {
    /// RAM offsets of the words wanted (word-aligned).
    want: BTreeSet<u32>,
    /// The cycle in progress, by RAM offset.
    pieces: Vec<Piece>,
    left: usize,
    started: Option<Instant>,
    /// For the log: completed cycles, and how long the last one took.
    pub cycles: u64,
    pub last_took: Duration,
}

impl Slow {
    /// Read this word from the next cycle on. True when it is new.
    pub fn want(&mut self, word: u32) -> bool {
        self.want.insert(word & !3)
    }

    /// The pieces to ask for now, `(RAM offset, bytes)`: the cycle's next ones
    /// up to `IN_FLIGHT`, again those unanswered after `RETRY`, or the first of
    /// a new cycle once `EVERY` has passed since the last began.
    pub fn poll(&mut self, now: Instant) -> Vec<(u32, u32)> {
        if self.left == 0 {
            if self.want.is_empty() || self.started.is_some_and(|t| now.duration_since(t) < EVERY) {
                return vec![];
            }
            self.pieces = plan(&self.want)
                .into_iter()
                .map(|(lo, len)| Piece {
                    lo,
                    len,
                    buf: vec![0; len as usize],
                    have: vec![false; len as usize],
                    asked: None,
                    done: false,
                })
                .collect();
            self.left = self.pieces.len();
            self.started = Some(now);
        }
        let mut out = vec![];
        let mut bytes = 0;
        for p in self.pieces.iter_mut().filter(|p| !p.done).take(IN_FLIGHT) {
            bytes += p.len;
            if bytes > IN_FLIGHT_BYTES && !out.is_empty() {
                break;
            }
            if p.asked.is_none_or(|t| now.duration_since(t) >= RETRY) {
                p.asked = Some(now);
                out.push((p.lo, p.len));
            }
        }
        out
    }

    /// The pieces asked and not complete: what a reply must fall in.
    pub fn in_flight(&self) -> Vec<(u32, u32)> {
        self.pieces.iter().filter(|p| !p.done && p.asked.is_some()).map(|p| (p.lo, p.len)).collect()
    }

    /// Bytes read at RAM offset `off`. Returns the words of the piece this
    /// completed, if it did.
    pub fn on_data(&mut self, off: u32, data: &[u8], now: Instant) -> Option<BTreeMap<u32, u32>> {
        let i = self.pieces.partition_point(|p| p.lo <= off).checked_sub(1)?;
        let p = &mut self.pieces[i];
        let start = (off - p.lo) as usize;
        let n = data.len().min((p.len as usize).saturating_sub(start));
        if p.done || n == 0 {
            return None;
        }
        p.buf[start..start + n].copy_from_slice(&data[..n]);
        p.have[start..start + n].fill(true);
        if !p.have.iter().all(|h| *h) {
            return None;
        }
        p.done = true;
        let words: BTreeMap<u32, u32> = self
            .want
            .range(p.lo..p.lo + p.len)
            .filter(|&&w| ((w - p.lo) as usize) + 4 <= p.buf.len())
            .map(|&w| {
                let k = (w - p.lo) as usize;
                (w, u32::from_le_bytes(p.buf[k..k + 4].try_into().unwrap()))
            })
            .collect();
        self.left -= 1;
        if self.left == 0 {
            self.cycles += 1;
            self.last_took = self.started.map_or(Duration::ZERO, |t| now.duration_since(t));
        }
        Some(words)
    }

    /// Whether the last `on_data` ended a cycle (no piece left).
    pub fn cycle_done(&self) -> bool {
        self.left == 0 && !self.pieces.is_empty()
    }

    /// Pieces of the cycle in progress (for the log).
    pub fn pieces(&self) -> usize {
        self.pieces.len()
    }
}

/// The wanted words as pieces: neighbours within `GAP` together, `PIECE` at most.
fn plan(want: &BTreeSet<u32>) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for &w in want {
        match out.last_mut() {
            Some((lo, len)) if w + 4 - *lo <= PIECE && w <= *lo + *len + GAP => *len = w + 4 - *lo,
            _ => out.push((w, 4)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(words: &[(u32, u32)], lo: u32, len: u32) -> Vec<u8> {
        let mut b = vec![0xeeu8; len as usize];
        for &(a, v) in words {
            if (lo..lo + len).contains(&a) {
                let i = (a - lo) as usize;
                b[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn neighbours_share_a_piece_and_a_piece_has_a_limit() {
        let want: BTreeSet<u32> = [0x1000, 0x1008, 0x1100, 0x2000].into_iter().collect();
        assert_eq!(plan(&want), vec![(0x1000, 0x104), (0x2000, 4)]);
        let far: BTreeSet<u32> = (0..2000u32).map(|i| 0x10_0000 + 4 * i).collect();
        let p = plan(&far);
        assert!(p.iter().all(|&(_, len)| len <= PIECE), "{p:x?}");
        assert_eq!(p.iter().map(|p| p.1).sum::<u32>(), 8000, "every word, once");
    }

    /// A cycle of ten pieces: eight asked at once, the rest as those land; a
    /// piece arriving in two halves, one lost and asked again; each piece's words
    /// handed over as it completes, and the next cycle waits for its second.
    #[test]
    fn a_cycle_reads_every_piece_eight_at_a_time_and_waits_its_turn() {
        let mem: Vec<(u32, u32)> = (0..10u32).map(|i| (0x1000 * (i + 1), 0x1111_1111 * (i + 1))).collect();
        let mut s = Slow::default();
        for &(a, _) in &mem {
            s.want(a);
        }
        let t0 = Instant::now();
        let first = s.poll(t0);
        assert_eq!(first.len(), IN_FLIGHT);
        assert_eq!(s.poll(t0 + Duration::from_millis(100)), vec![], "eight in flight");
        let mut got = BTreeMap::new();
        // the first piece in two halves
        let whole = le(&mem, 0x1000, 4);
        assert!(s.on_data(0x1000, &whole[..2], t0).is_none(), "half a piece");
        got.extend(s.on_data(0x1002, &whole[2..], t0).expect("the piece is complete"));
        assert_eq!(s.on_data(0x0800, &whole, t0), None, "not ours");
        // the second is lost; the others land
        for &(lo, len) in &first[2..] {
            got.extend(s.on_data(lo, &le(&mem, lo, len), t0).unwrap());
        }
        let next = s.poll(t0 + Duration::from_millis(100));
        assert_eq!(next, vec![(0x9000, 4), (0xa000, 4)], "the rest, as room frees");
        assert_eq!(s.poll(t0 + RETRY), vec![(0x2000, 4)], "the lost one, again");
        for (lo, len) in [(0x2000, 4), (0x9000, 4), (0xa000, 4)] {
            got.extend(s.on_data(lo, &le(&mem, lo, len), t0).unwrap());
        }
        assert!(s.cycle_done());
        assert_eq!(got.into_iter().collect::<Vec<_>>(), mem);
        assert_eq!(s.cycles, 1);
        assert_eq!(s.poll(t0 + Duration::from_millis(500)), vec![], "a cycle every EVERY");
        assert_eq!(s.poll(t0 + EVERY).len(), IN_FLIGHT);
    }
}
