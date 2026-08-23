//! Sega's boot-binary scrambling, and how to tell whether it was used.
//!
//! # What it is
//!
//! A binary burned on a CD-R that boots through IP.BIN is stored SCRAMBLED: its
//! 32-byte slices are permuted by a tiny PRNG seeded with the file's own size,
//! and the bootstrap unpermutes them while loading. A binary on a real GD-ROM
//! is not -- the GD bootstrap loads it as it lies. So whether the
//! `1ST_READ.BIN` inside an image is scrambled depends on how that image was
//! made, not on the game:
//!
//! - a `.gdi` dumped from a GD-ROM: plain, always;
//! - a `.cdi` self-boot conversion: usually scrambled, because that is what
//!   makes it boot from a CD-R at all.
//!
//! It matters here because this host does what DreamShell's isoldr does -- it
//! jumps straight into the binary and never runs the bootstrap that would have
//! unscrambled it. Uploading a scrambled binary produces a title that is
//! uploaded correctly, verified correctly, and executes noise.
//!
//! # Detecting it, and the limit of the detection
//!
//! `descramble()` is a permutation, so "was this scrambled" cannot be answered
//! by looking at entropy or at byte statistics -- both are identical either way.
//! What CAN be answered, with certainty, is "does unscrambling it produce a
//! binary that starts with a header we recognise". [`assess`] does exactly that
//! and nothing more: it reports `Scrambled` only on a positive match, and
//! `Unknown` when it cannot tell, rather than guessing on a running title's
//! behalf. The recognised headers are DreamShell's list
//! (`modules/isoldr/module.c`), which covers KOS and a couple of other
//! homebrew toolchains.
//!
//! Retail Katana binaries have no such fixed header, so a scrambled retail
//! conversion lands in `Unknown` -- the caller says so, and `--descramble`
//! forces the issue. isoldr has exactly the same gap and answers it the same
//! way (it descrambles only for `BIN_TYPE_KOS`).
//!
//! # Verified against a third-party scrambler
//!
//! Round-tripped through `mkdcdisc`: a 256 KiB binary opening with `kos_hdr`,
//! written to a `.cdi`, read back out and unscrambled here, comes back with the
//! same MD5 -- and the same again through a zipped copy of that `.cdi`, stored
//! and deflated.
//!
//! **`mkdcdisc`'s two flags name the format of the file you HAND it, not what
//! it writes.** `-b/--unscrambled-binary` takes a plain binary and scrambles it
//! onto the disc; `-B/--scrambled-binary` takes one that is already scrambled
//! and writes it as it lies. So the disc built with `-b` is the one this module
//! finds scrambled, which is the opposite of what the flag name suggests on
//! first reading.

/// The largest window the scrambler permutes within.
const MAX_CHUNK: usize = 0x200000;

/// Openings of a binary that is definitely NOT scrambled.
///
/// From DreamShell's `modules/isoldr/module.c` (`kos_hdr`, `kos_hdr_2`,
/// `kos_hdr_3`, `ron_hdr`): the first instructions of the standard homebrew
/// start-up stubs. Eight bytes is far too much to match by chance out of a
/// permuted slice, which is what makes the test one-sided and safe.
const PLAIN_HEADS: &[[u8; 8]] = &[
    [0x2D, 0xD0, 0x02, 0x01, 0x12, 0x20, 0x2B, 0xD0],
    [0x38, 0xD0, 0x02, 0x01, 0x12, 0x20, 0x36, 0xD0],
    [0x37, 0xD0, 0x02, 0x01, 0x12, 0x20, 0x35, 0xD0],
    [0x1B, 0xD0, 0x1A, 0xD1, 0x1B, 0x20, 0x2B, 0x40],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scrambling {
    /// The binary opens with a header we know belongs to a plain image.
    Plain,
    /// Unscrambling it produces such a header. It was scrambled.
    Scrambled,
    /// Neither -- which is the normal answer for a retail Katana title, whose
    /// binaries have no fixed opening.
    Unknown,
}

fn has_plain_head(data: &[u8]) -> bool {
    data.len() >= 8 && PLAIN_HEADS.iter().any(|h| &data[..8] == h)
}

/// Decide, without guessing.
pub fn assess(data: &[u8]) -> Scrambling {
    if has_plain_head(data) {
        return Scrambling::Plain;
    }
    // Only the first chunk has to be unscrambled to see the first slice, but
    // the permutation depends on the WHOLE size, so the cheap shortcut does not
    // exist. This runs once per upload on a file that is about to be sent over
    // a 100 Mbit link, which puts it comfortably below the noise.
    if has_plain_head(&descramble(data)) {
        return Scrambling::Scrambled;
    }
    Scrambling::Unknown
}

struct Rand(u32);

impl Rand {
    fn new(size: usize) -> Self {
        Self(size as u32 & 0xffff)
    }
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(2109).wrapping_add(9273) & 0x7fff;
        (self.0 + 0xc000) & 0xffff
    }
}

/// Undo the scrambling, transcribed from DreamShell's
/// `firmware/isoldr/loader/descramble.c` (itself Sega's algorithm).
///
/// The source is read strictly forwards; the destination is written in the
/// permuted order the PRNG produces. Window sizes step down from 2 MB to 32
/// bytes, and whatever is left over at the end is copied straight across.
pub fn descramble(src: &[u8]) -> Vec<u8> {
    let size = src.len();
    let mut dest = vec![0u8; size];
    let mut rng = Rand::new(size);
    let mut src_pos = 0usize;
    let mut dst_base = 0usize;
    let mut remaining = size;
    let mut idx: Vec<usize> = Vec::with_capacity(MAX_CHUNK / 32);

    let mut chunk = MAX_CHUNK;
    while chunk >= 32 {
        while remaining >= chunk {
            let slices = chunk / 32;
            idx.clear();
            idx.extend(0..slices);
            for i in (0..slices).rev() {
                let x = ((rng.next() as usize) * i) >> 16;
                idx.swap(i, x);
                let to = dst_base + 32 * idx[i];
                dest[to..to + 32].copy_from_slice(&src[src_pos..src_pos + 32]);
                src_pos += 32;
            }
            remaining -= chunk;
            dst_base += chunk;
        }
        chunk >>= 1;
    }
    if remaining > 0 {
        dest[dst_base..dst_base + remaining]
            .copy_from_slice(&src[src_pos..src_pos + remaining]);
    }
    dest
}

/// Apply the scrambling. Only used to test that `descramble` inverts it.
#[cfg(test)]
fn scramble(src: &[u8]) -> Vec<u8> {
    let size = src.len();
    let mut dest = vec![0u8; size];
    let mut rng = Rand::new(size);
    let mut dst_pos = 0usize;
    let mut src_base = 0usize;
    let mut remaining = size;
    let mut idx: Vec<usize> = Vec::with_capacity(MAX_CHUNK / 32);

    let mut chunk = MAX_CHUNK;
    while chunk >= 32 {
        while remaining >= chunk {
            let slices = chunk / 32;
            idx.clear();
            idx.extend(0..slices);
            for i in (0..slices).rev() {
                let x = ((rng.next() as usize) * i) >> 16;
                idx.swap(i, x);
                let from = src_base + 32 * idx[i];
                dest[dst_pos..dst_pos + 32].copy_from_slice(&src[from..from + 32]);
                dst_pos += 32;
            }
            remaining -= chunk;
            src_base += chunk;
        }
        chunk >>= 1;
    }
    if remaining > 0 {
        dest[dst_pos..dst_pos + remaining]
            .copy_from_slice(&src[src_base..src_base + remaining]);
    }
    dest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
    }

    /// The pair has to round-trip at sizes that exercise every window step and
    /// the leftover tail, because the window schedule is the part of the
    /// algorithm that is easy to transcribe one shift wrong.
    #[test]
    fn descramble_inverts_scramble() {
        for len in [32usize, 33, 64, 1000, 32 * 1024 + 17, 3 * 1024 * 1024 + 5] {
            let data = sample(len);
            let round = descramble(&scramble(&data));
            assert_eq!(round, data, "round trip at {len} bytes");
        }
    }

    #[test]
    fn a_plain_homebrew_head_is_recognised() {
        let mut data = sample(64 * 1024);
        data[..8].copy_from_slice(&PLAIN_HEADS[0]);
        assert_eq!(assess(&data), Scrambling::Plain);
    }

    #[test]
    fn a_scrambled_homebrew_head_is_recognised() {
        let mut data = sample(64 * 1024);
        data[..8].copy_from_slice(&PLAIN_HEADS[1]);
        assert_eq!(assess(&scramble(&data)), Scrambling::Scrambled);
    }

    /// A retail binary has no known opening, and the honest answer is "cannot
    /// tell" -- NOT a guess that would mangle a perfectly good image.
    #[test]
    fn an_unrecognised_binary_is_reported_as_unknown() {
        assert_eq!(assess(&sample(64 * 1024)), Scrambling::Unknown);
    }
}
