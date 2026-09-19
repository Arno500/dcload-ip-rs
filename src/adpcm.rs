//! 4-bit Yamaha ADPCM for the AICA, encoded as one continuous stream.
//!
//! # Why
//!
//! The loader copies every CD-DA byte twice over the G2 bus -- out of the BBA,
//! then into sound RAM -- while the title waits, and those copies cost far more
//! than this host's work or the network (measured 2026-09-01: ~2.2 ms of G2
//! time per 7056-byte PCM fetch, against 0.11 ms to serve it). 4 bits a sample
//! instead of 16 is a quarter of the bytes. The loader asks for it with `DC24`
//! (`CDDA_ADPCM`, the default); `DC23` PCM is still served.
//!
//! # The codec: `oxideav-adpcm`
//!
//! [`oxideav_adpcm::yamaha`] implements the Y8950 recurrence and distinguishes
//! the AICA's step constants (`{230,..,614} >> 8`) from the YM2608's
//! (`{57,..,153} >> 6`). The two differ slightly, and a stream encoded with one
//! and decoded with the other does not sound wrong at once: it drifts. The test
//! `the_crate_still_decodes_like_the_aica` pins the recurrence against the
//! crate, and is the spec if the dependency ever has to go.
//!
//! # The contract with the loader
//!
//! ADPCM is differential: the encoder here and the AICA's decoder share one
//! state (predictor and step), living on two machines. The AICA plays the ring
//! in long-stream mode, which keeps that state across the loop back to the
//! ring's start. So:
//!
//! - the encoder continues from one request to the next and never resets on a
//!   seek or a loop, because the decoder does not;
//! - it resets only when the request has bit 31 set, which the loader sets on
//!   the first request after keying the channels on (the only event that resets
//!   the decoder);
//! - a re-asked request (the loader timed out) gets back exactly the bytes sent
//!   the first time, from a history of the last `RECENT` requests.
//!
//! # The one step the decoders disagree on
//!
//! A nibble moves the predictor by `((2m+1) * step) >> 3`, which reaches 46080
//! at the step ceiling. flycast (`sgc_if.cpp`, `DecodeADPCM`) clamps that
//! contribution to `0x7fff` before applying it, and so does Sega's own AICA
//! encoder (superctr's note in `ymz_codec.c`); the crate and MAME do not.
//! Nobody has measured the silicon. The two readings part only when the
//! contribution is above `0x7fff` *and* the predictor starts on the far side of
//! zero (a near full-scale swing in one sample) -- and then by up to 13 000,
//! which never heals by itself: the recurrence has no leak, so the offset stays
//! until the predictor hits a rail. Simulated on Snow Surfers (2026-09-16), the
//! crate's encoder produced such a nibble twice in the intro track (4-9 dB SNR
//! for ~0.5 s at 12 s and 46 s) and 14 260 times in one in-game track.
//!
//! So [`pick_nibble`] never emits one: it takes the nearest magnitude whose
//! result is the same under both readings, and the stream decodes identically
//! whichever the AICA does. Lowering the magnitude is always possible (4 and
//! below stay under `0x7fff`), and it costs ~0.5 dB of rms error against an
//! encoder that assumes the clamp, on the loudest tracks only.

use oxideav_adpcm::yamaha::{Channel, Chip, decode_nibble};

/// The largest contribution every AICA decoder model applies as is.
const CONTRIBUTION_CLAMP: i32 = 0x7fff;

/// True if `nibble` decodes to different predictors with and without the clamp
/// on its contribution. Unclamped, a contribution past `0x7fff` always carries
/// the predictor to the rail it points at; clamped, it does so only from that
/// rail's side of zero.
fn ambiguous(state: &Channel, nibble: u8) -> bool {
    let mag = i32::from(nibble & 7);
    let diff = ((2 * mag + 1) * state.step) >> 3;
    diff > CONTRIBUTION_CLAMP
        && if nibble & 8 != 0 {
            state.predictor >= 0
        } else {
            state.predictor < 0
        }
}

/// The nibble for `target`: the crate's nearest-magnitude choice (the threshold
/// ladder `4|d| >= k * step`), lowered while it is [`ambiguous`]. The
/// reconstructions grow with the magnitude, so the largest unambiguous one below
/// the choice is the nearest unambiguous one.
fn pick_nibble(state: &Channel, target: i16) -> u8 {
    let dn = i32::from(target) - state.predictor;
    let sign = if dn < 0 { 8u8 } else { 0 };
    let four_abs = i64::from(dn.unsigned_abs()) * 4;
    let step = i64::from(state.step);
    let mut mag = (1..=7u8)
        .rev()
        .find(|&k| four_abs >= i64::from(k) * step)
        .unwrap_or(0);
    while mag > 0 && ambiguous(state, sign | mag) {
        mag -= 1;
    }
    sign | mag
}

/// One mono stream, two nibbles to the byte, low nibble first, a lone final
/// nibble padded with 0 -- the crate's `encode_packet` layout for one channel.
fn encode_mono(samples: &[i16], state: &mut Channel) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples.len().div_ceil(2));
    for pair in samples.chunks(2) {
        let mut byte = 0u8;
        for (i, &s) in pair.iter().enumerate() {
            let nibble = pick_nibble(state, s);
            decode_nibble(state, nibble);
            byte |= nibble << (4 * i);
        }
        out.push(byte);
    }
    out
}

/// The two channels' encoder state, plus the bytes sent for recent requests.
///
/// A re-ask is answered from that history, not re-encoded: the coder state has
/// already moved past the request, and re-encoding would hand the decoder bytes
/// from the wrong state -- per channel, so one ear goes wrong.
#[derive(Clone, Debug)]
pub struct Stream {
    left: Channel,
    right: Channel,
    /// Newest last: (lba, frames, the bytes that were sent).
    recent: std::collections::VecDeque<(u32, usize, Vec<u8>)>,
    /// Re-asks served from the history, and those among them that were not
    /// for the newest entry.
    pub replays: u64,
    pub out_of_order: u64,
    /// Re-asks older than the history holds. There is no correct answer to one
    /// (the decoder is at a state the encoder has left), so it is counted and
    /// must stay 0.
    pub lost_replay: u64,
}

/// Requests kept for re-asks. It must cover the largest run of requests the
/// loader can have outstanding before one is re-asked: at every PLAY,
/// `cdda_prime()` sends a whole half (13 sub-fetches) back to back, so a failure
/// early in it is re-asked 13 requests later. With 8 such re-asks missed the
/// history and were heard as glitches with every loader counter clean.
///
/// 48 covers both halves of the ring with margin, for 48 x 2352 = 113 KB.
pub const RECENT: usize = 48;

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream {
    pub fn new() -> Self {
        Stream {
            left: Channel::for_chip(Chip::Aica),
            right: Channel::for_chip(Chip::Aica),
            recent: std::collections::VecDeque::with_capacity(RECENT),
            replays: 0,
            out_of_order: 0,
            lost_replay: 0,
        }
    }

    /// The bytes already sent for this request, if it is a re-ask the history
    /// still holds. Counted like any replay.
    ///
    /// CALL THIS BEFORE READING THE DISC. The loader re-asks when an answer did
    /// not arrive within its deadline, and the usual reason is that producing
    /// it was slow -- a disc read that stalled. Reading the disc again before
    /// looking here repeats the stall on every re-ask, and each is dropped in
    /// turn: measured 2026-09-16, 19 consecutive failures on one LBA, ended only
    /// by the loader restarting the stream. The history answers in microseconds.
    pub fn replay(&mut self, lba: u32, frames: usize) -> Option<Vec<u8>> {
        let pos = self
            .recent
            .iter()
            .position(|(l, f, _)| *l == lba && *f == frames)?;
        self.replays += 1;
        if pos + 1 != self.recent.len() {
            self.out_of_order += 1;
        }
        Some(self.recent[pos].2.clone())
    }

    /// Encode one request's worth of interleaved 16-bit stereo.
    ///
    /// `pcm` is raw CD audio: signed 16-bit little-endian, left then right.
    /// The answer is the left channel's nibbles followed by the right
    /// channel's, each a contiguous mono stream, because that is what an AICA
    /// channel plays and the console is the side that cannot afford the split.
    ///
    /// Two nibbles to the byte, **low nibble first**: the AICA's order, and the
    /// crate's (its `decode_packet` reads the low half of each byte first).
    ///
    /// `restart` resets both coders first: the loader sets it when it keys the
    /// channels on, which is the only event that resets the AICA's decoder.
    pub fn encode_request(&mut self, lba: u32, pcm: &[u8], restart: bool) -> Vec<u8> {
        if restart {
            self.left = Channel::for_chip(Chip::Aica);
            self.right = Channel::for_chip(Chip::Aica);
            self.recent.clear();
        }

        let frames = pcm.len() / 4;

        // A re-ask: hand back exactly what was sent, and leave the coder state
        // alone.
        if let Some(bytes) = self.replay(lba, frames) {
            return bytes;
        }

        // A request behind the newest kept one that is not in the history: a
        // re-ask older than RECENT. (`restart` clears the history, so a seek or
        // track change after a key-on cannot land here.) Counted; it is then
        // encoded from the current state, which is wrong but all there is.
        // A jump further back than the history could ever span is the loader
        // looping a repeating range back to its start, which is not a re-ask.
        if let Some((newest, newest_frames, _)) = self.recent.back()
            && lba < *newest
            && *newest - lba <= (RECENT * newest_frames.div_ceil(588)) as u32
        {
            self.lost_replay += 1;
        }

        // Anything else -- the next block, a seek, a track loop -- continues
        // without a reset, because the decoder does not reset either. The step
        // size adapts to new material within a few milliseconds.
        let mut ls = Vec::with_capacity(frames);
        let mut rs = Vec::with_capacity(frames);
        for f in pcm.chunks_exact(4) {
            ls.push(i16::from_le_bytes([f[0], f[1]]));
            rs.push(i16::from_le_bytes([f[2], f[3]]));
        }

        // One channel per call, so each output is a mono stream.
        let mut out = encode_mono(&ls, &mut self.left);
        out.extend_from_slice(&encode_mono(&rs, &mut self.right));

        if self.recent.len() == RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back((lba, frames, out.clone()));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_adpcm::yamaha::encode_packet;

    const SCALE: [i32; 8] = [230, 230, 230, 230, 307, 409, 512, 614];

    /// flycast's `DecodeADPCM`: the contribution is clamped to 0x7fff before
    /// it is applied.
    fn decode_clamped(nibbles: &[u8]) -> Vec<i16> {
        let (mut pred, mut step) = (0i32, 127i32);
        let mut out = Vec::new();
        for b in nibbles {
            for nib in [b & 0xf, b >> 4] {
                let mag = (nib & 7) as usize;
                let diff = (((1 + 2 * mag as i32) * step) >> 3).min(0x7fff);
                pred = (pred + if nib & 8 != 0 { -diff } else { diff }).clamp(-32768, 32767);
                step = ((step * SCALE[mag]) >> 8).clamp(127, 24576);
                out.push(pred as i16);
            }
        }
        out
    }

    /// Full-scale material that drives the step to its ceiling and swings the
    /// predictor across zero in one sample, which is what the clamp needs.
    fn slams(n: usize) -> Vec<i16> {
        let mut lcg: u32 = 0x9e37_79b9;
        (0..n)
            .map(|i| {
                lcg = lcg.wrapping_mul(1664525).wrapping_add(1013904223);
                let level = 20000 + (lcg >> 20) as i32 % 12000;
                (if (i / 3) % 2 == 0 { level } else { -level }) as i16
            })
            .collect()
    }

    fn decode(nibbles: &[u8]) -> Vec<i16> {
        let mut c = Channel::for_chip(Chip::Aica);
        let mut out = Vec::new();
        for b in nibbles {
            out.push(decode_nibble(&mut c, b & 0xf));
            out.push(decode_nibble(&mut c, b >> 4));
        }
        out
    }

    fn stereo(n: u32, fl: impl Fn(f64) -> f64, fr: impl Fn(f64) -> f64) -> Vec<u8> {
        (0..n)
            .flat_map(|i| {
                let l = fl(i as f64) as i16;
                let r = fr(i as f64) as i16;
                let mut v = l.to_le_bytes().to_vec();
                v.extend_from_slice(&r.to_le_bytes());
                v
            })
            .collect()
    }

    /// THE DEPENDENCY, PINNED. The AICA recurrence written out, from MAME's
    /// `aica.cpp` and KOS's `utils/wav2adpcm` (superctr's `ymz_codec.c`), and
    /// asserted against the crate over every nibble at a spread of step sizes.
    ///
    /// Its whole job is to fail if a version bump swaps the AICA constants for
    /// the OPNA ones, or changes a clamp: those produce audio that is not
    /// obviously wrong, only slowly wrong, and the only other place it could be
    /// noticed is a Dreamcast three minutes into a track.
    ///
    /// The recurrence here has no clamp on the per-sample contribution, and
    /// `wav2adpcm`, Sega's encoder and flycast's decoder do. That disagreement
    /// is not settled here but avoided: see `pick_nibble` and
    /// `no_nibble_decodes_two_ways`.
    #[test]
    fn the_crate_still_decodes_like_the_aica() {
        let mut theirs = Channel::for_chip(Chip::Aica);
        let (mut pred, mut step) = (0i32, 127i32);
        // A walk that visits the whole step range: repeated large magnitudes
        // drive it to the 24576 ceiling, repeated small ones back to 127.
        let mut lcg: u32 = 0x1234_5678;
        for _ in 0..20000 {
            lcg = lcg.wrapping_mul(1664525).wrapping_add(1013904223);
            let nib = ((lcg >> 19) & 0xf) as u8;
            let mag = (nib & 7) as usize;

            let diff = ((1 + 2 * mag as i32) * step) >> 3;
            pred += if nib & 8 != 0 { -diff } else { diff };
            pred = pred.clamp(-32768, 32767);
            step = ((step * SCALE[mag]) >> 8).clamp(127, 24576);

            assert_eq!(decode_nibble(&mut theirs, nib) as i32, pred, "nibble {nib:#x}");
            assert_eq!(theirs.step, step);
        }
        // And the walk really did exercise the range, or the assertions above
        // proved nothing about the clamps.
        assert!(step > 127, "the step never left its floor: the walk is not a test");
    }

    /// The encoder picks the NEAREST reconstruction, which is what makes it the
    /// right encoder and not merely a working one. Reconstruction for magnitude
    /// k is `(2k+1)*step/8`, so the boundary between k and k+1 sits at
    /// `4*|d| = (k+1)*step` -- the crate's threshold ladder, and also exactly
    /// what KOS's `floor(4*|d| / step)` computes.
    /// ...to within one LSB, and the one LSB is the floor in the recurrence.
    /// The threshold ladder is derived from the exact reconstruction
    /// `(2k+1)*step/8`, but the hardware computes `((2k+1)*step) >> 3`, so at a
    /// boundary the truncated value can land a unit nearer on the other side.
    /// Measured over 8000 samples of a full-scale sweep: it happens, and the
    /// worst disagreement is 1 of 32768. Asserting `<= 1` rather than `== 0`
    /// records that rather than hiding it behind a looser sine test.
    ///
    /// "Nearest" among the nibbles that are not `ambiguous`; the slams make
    /// sure that restriction is exercised, not just compiled.
    #[test]
    fn the_encoder_picks_the_nearest_magnitude() {
        // Walk the encoder over real material so `step` takes many values, and
        // check its choice against an exhaustive search at each one.
        let mut src: Vec<i16> = (0..8000)
            .map(|i| ((i as f64 * 0.031).sin() * 24000.0) as i16)
            .collect();
        src.extend(slams(8000));
        let mut state = Channel::for_chip(Chip::Aica);
        let mut restricted = 0;

        for &s in &src {
            let before = state;
            let best = (0..16u8)
                .filter(|&n| !ambiguous(&before, n))
                .min_by_key(|&n| {
                    let mut t = before;
                    (decode_nibble(&mut t, n) as i32 - s as i32).abs()
                })
                .unwrap();
            if (0..16u8).any(|n| ambiguous(&before, n)) {
                restricted += 1;
            }

            let chosen = pick_nibble(&before, s);
            decode_nibble(&mut state, chosen);

            // Compare the RECONSTRUCTIONS, not the nibbles: two magnitudes can
            // tie at a threshold and either answer is equally right.
            let recon = |n: u8| {
                let mut t = before;
                decode_nibble(&mut t, n) as i32
            };
            let slack = (recon(chosen) - s as i32).abs() - (recon(best) - s as i32).abs();
            assert!(
                (0..=1).contains(&slack),
                "sample {s} at step {}: crate chose {chosen:#x}, search {best:#x}, \
                 {slack} worse",
                before.step
            );
        }
        assert!(restricted > 100, "only {restricted} samples met the clamp: the slams are not");
    }

    /// THE CLAMP HAZARD, AND THAT IT IS GONE. On material that meets it, the
    /// crate's own encoder produces a stream that decodes differently with and
    /// without the clamp (so this test can fail), and this encoder's stream
    /// decodes identically -- and still follows the signal.
    #[test]
    fn no_nibble_decodes_two_ways() {
        let src = slams(20000);

        let mut plain = Channel::for_chip(Chip::Aica);
        let theirs = encode_packet(&src, std::slice::from_mut(&mut plain));
        assert_ne!(
            decode(&theirs),
            decode_clamped(&theirs),
            "the material never reached the clamp: this test proves nothing"
        );

        let mut state = Channel::for_chip(Chip::Aica);
        let ours = encode_mono(&src, &mut state);
        let back = decode(&ours);
        assert_eq!(back, decode_clamped(&ours), "a nibble still decodes two ways");

        let err = src
            .iter()
            .zip(&back)
            .map(|(a, b)| ((*a as f64) - (*b as f64)).powi(2))
            .sum::<f64>()
            / src.len() as f64;
        assert!(err.sqrt() < 12000.0, "rms error {} on +-32000 slams", err.sqrt());
    }

    /// Below the clamp this is the crate's encoder, byte for byte: the only
    /// change is the ambiguous nibble.
    #[test]
    fn below_the_clamp_the_bytes_are_the_crates() {
        let src: Vec<i16> = (0..20000)
            .map(|i| ((i as f64 * 0.013).sin() * 16000.0 + (i as f64 * 0.21).sin() * 6000.0) as i16)
            .collect();
        let mut a = Channel::for_chip(Chip::Aica);
        let mut b = Channel::for_chip(Chip::Aica);
        assert_eq!(
            encode_mono(&src, &mut a),
            encode_packet(&src, std::slice::from_mut(&mut b))
        );
        // An odd count pads the same way.
        assert_eq!(
            encode_mono(&src[..7], &mut a),
            encode_packet(&src[..7], std::slice::from_mut(&mut b))
        );
    }

    /// A sine at a level a CD actually reaches, round-tripped. The bar is the
    /// format's, not ours: 4-bit ADPCM is worth roughly 8-9 bits of accuracy on
    /// material like this, so a few percent of full scale is a pass and an
    /// order of magnitude more would mean the two states have parted company.
    #[test]
    fn a_sine_survives_the_round_trip() {
        let src: Vec<i16> = (0..4096)
            .map(|i| ((i as f64 * 0.07).sin() * 20000.0) as i16)
            .collect();
        let mut enc = Channel::for_chip(Chip::Aica);
        let packed = encode_mono(&src, &mut enc);
        let back = decode(&packed);

        assert_eq!(back.len(), src.len());
        // Skip the attack: the step size starts at its floor and needs a few
        // samples to reach the signal, which is the format and not a defect.
        let err: f64 = src[64..]
            .iter()
            .zip(&back[64..])
            .map(|(a, b)| ((*a as f64) - (*b as f64)).powi(2))
            .sum::<f64>()
            / (src.len() - 64) as f64;
        assert!(err.sqrt() < 1200.0, "rms error {} of 20000", err.sqrt());
    }

    /// THE PROPERTY THE WHOLE DESIGN RESTS ON. Encoding a run in one go and
    /// encoding it as a sequence of requests must produce the same bytes --
    /// otherwise the AICA, which never resets, hears a seam at every fetch.
    #[test]
    fn requests_concatenate_into_one_stream() {
        let pcm = stereo(
            8192,
            |i| (i * 0.03).sin() * 15000.0,
            |i| (i * 0.05).cos() * 9000.0,
        );

        let mut whole = Stream::new();
        let one = whole.encode_request(100, &pcm, true);

        let mut split = Stream::new();
        let half = pcm.len() / 2;
        let a = split.encode_request(100, &pcm[..half], true);
        let b = split.encode_request(200, &pcm[half..], false);

        // Each request is left-then-right, so the two halves interleave rather
        // than concatenate: rebuild the whole-stream layout from them.
        let (a_l, a_r) = a.split_at(a.len() / 2);
        let (b_l, b_r) = b.split_at(b.len() / 2);
        let mut rebuilt = Vec::new();
        rebuilt.extend_from_slice(a_l);
        rebuilt.extend_from_slice(b_l);
        rebuilt.extend_from_slice(a_r);
        rebuilt.extend_from_slice(b_r);

        assert_eq!(one, rebuilt);
    }

    /// A re-ask with another request in between still gets the original
    /// bytes, and is counted as out of order.
    #[test]
    fn a_re_ask_one_step_back_is_still_byte_identical() {
        let mut s = Stream::new();
        let a = stereo(1176, |t| (t * 0.05).sin() * 20000.0, |t| (t * 0.07).sin() * 9000.0);
        let b = stereo(1176, |t| (t * 0.11).sin() * 17000.0, |t| (t * 0.03).sin() * 5000.0);

        let first = s.encode_request(100, &a, true);
        let _second = s.encode_request(101, &b, false);
        let again = s.encode_request(100, &a, false);

        assert_eq!(first, again, "a re-ask one step back changed the bytes");
        assert_eq!(s.replays, 1);
        assert_eq!(
            s.out_of_order, 1,
            "asking for something older than the newest entry must be counted"
        );
    }

    /// Positive control for `lost_replay`: a re-ask past the history is
    /// counted, and one inside it is served and not counted.
    #[test]
    fn a_re_ask_older_than_the_history_is_counted_and_one_inside_it_is_not() {
        let mut s = Stream::new();
        let pcm = vec![0u8; 588 * 4];
        for i in 0..=(RECENT as u32) {
            s.encode_request(1000 + i, &pcm, i == 0);
        }
        // Still inside: the newest RECENT entries, so the bytes come back.
        let before = s.lost_replay;
        s.encode_request(1000 + RECENT as u32, &pcm, false);
        assert_eq!(s.replays, 1, "a re-ask inside the history must be served");
        assert_eq!(s.lost_replay, before, "and must not be counted as lost");

        // LBA 1000 was evicted by the RECENT+1'th request.
        s.encode_request(1000, &pcm, false);
        assert_eq!(s.lost_replay, before + 1, "a re-ask past the history is lost");
    }

    /// A repeating range loops back to its start, further behind than the
    /// history could ever span: the loader is not re-asking, so it is not
    /// counted (the count used to name every loop an audible glitch).
    #[test]
    fn a_loop_back_to_the_start_of_the_range_is_not_a_lost_re_ask() {
        let mut s = Stream::new();
        let pcm = vec![0u8; 2352 * 4]; // one 4-sector sub-fetch
        for i in 0..200u32 {
            s.encode_request(320338 + 4 * i, &pcm, i == 0);
        }
        s.encode_request(320338, &pcm, false);
        assert_eq!(s.lost_replay, 0, "a loop is not a lost re-ask");
        assert_eq!(s.replays, 0, "and is encoded, not replayed");
    }

    /// A re-ask is answered without the PCM, so without touching the disc, and
    /// with the very bytes encode_request sent; a request never sent is not.
    #[test]
    fn a_re_ask_is_answered_without_the_disc() {
        let mut s = Stream::new();
        let a = stereo(2352, |t| (t * 0.05).sin() * 20000.0, |t| (t * 0.07).sin() * 9000.0);
        let sent = s.encode_request(100, &a, true);
        assert_eq!(s.replay(100, 2352), Some(sent));
        assert_eq!(s.replay(104, 2352), None, "never sent: must be read and encoded");
        assert_eq!(s.replay(100, 1176), None, "same LBA, other size: not the same request");
        assert_eq!(s.replays, 1);
    }

    /// The ordinary re-ask (the newest request again) is not out of order.
    #[test]
    fn an_immediate_re_ask_is_not_out_of_order() {
        let mut s = Stream::new();
        let a = stereo(1176, |t| (t * 0.05).sin() * 20000.0, |t| (t * 0.07).sin() * 9000.0);
        let first = s.encode_request(100, &a, true);
        let again = s.encode_request(100, &a, false);
        assert_eq!(first, again);
        assert_eq!(s.replays, 1);
        assert_eq!(s.out_of_order, 0);
    }

    /// A repeated request is byte-identical, and the stream carries on from
    /// where it was, not from before the repeat.
    #[test]
    fn a_repeated_lba_re_encodes_identically() {
        let pcm = stereo(2048, |i| (i * 0.02).sin() * 12000.0, |i| (i * 0.02).sin() * 12000.0);

        let mut s = Stream::new();
        let _ = s.encode_request(10, &pcm, true);
        let first = s.encode_request(20, &pcm, false);
        let again = s.encode_request(20, &pcm, false);
        assert_eq!(first, again);

        // And the stream carries on from the retry, not from before it.
        let mut fresh = Stream::new();
        let _ = fresh.encode_request(10, &pcm, true);
        let _ = fresh.encode_request(20, &pcm, false);
        assert_eq!(fresh.encode_request(30, &pcm, false), s.encode_request(30, &pcm, false));
    }

    /// The two channels are independent mono streams, one after the other --
    /// NOT nibble-interleaved, which is what the crate's `encode_packet` does
    /// when handed two channels at once and what an AICA channel cannot play.
    #[test]
    fn the_channels_come_out_split_not_interleaved() {
        let pcm = stereo(1024, |i| (i * 0.02).sin() * 12000.0, |_| -8000.0);
        let mut s = Stream::new();
        let out = s.encode_request(1, &pcm, true);
        assert_eq!(out.len(), 1024);

        let (left, right) = out.split_at(512);
        // The right channel is a constant, so after the step has settled its
        // nibbles are the two that bracket zero movement -- nothing like the
        // left channel's sweep. Decoding it must give back the constant.
        let back = decode(right);
        assert!(
            back[64..].iter().all(|s| (*s as i32 + 8000).abs() < 400),
            "right channel did not decode to its constant: {:?}",
            &back[64..70]
        );
        assert_ne!(left, right);
    }

    /// Silence must encode to something that stays silent. The step size
    /// bottoms out at 127, so the residual is +-15 LSB -- 66 dB down.
    #[test]
    fn silence_stays_quiet() {
        let src = vec![0i16; 2048];
        let mut enc = Channel::for_chip(Chip::Aica);
        let packed = encode_mono(&src, &mut enc);
        let back = decode(&packed);
        assert!(
            back.iter().all(|s| s.abs() <= 16),
            "max {}",
            back.iter().map(|s| s.abs()).max().unwrap()
        );
    }

    /// The idle byte the loader fills a fresh ring with (`RING_IDLE_BYTE` in
    /// cdda.c, 0x80) decodes to near-silence; an all-zero ring would not, since
    /// a zero nibble is a positive step and runs to full scale.
    #[test]
    fn the_idle_byte_is_the_quiet_one() {
        // 2048 bytes is 4096 samples, well past the ~2185 a zero-nibble ramp
        // needs to reach the clamp.
        let ramp = decode(&[0x00u8; 2048]);
        let idle = decode(&[0x80u8; 2048]);
        assert_eq!(ramp.iter().map(|s| s.abs()).max().unwrap(), 32767);
        assert!(idle.iter().map(|s| s.abs()).max().unwrap() <= 16);
    }
}
