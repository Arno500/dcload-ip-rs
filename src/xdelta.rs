//! xdelta3 patches (VCDIFF, RFC 3284), as a `.dcp` carries one per file.
//!
//! WHY HERE (Skies of Arcadia, 2026-10-11). The Universal Dreamcast Patcher's
//! `.dcp` is a zip of `<path>.xdelta` files, each the difference between a file
//! of the disc's filesystem and its replacement. Only decoding is needed, and
//! only what xdelta3 writes: the default code table, a source window from the
//! file being patched or from the target so far, Adler-32 per window, and
//! LZMA as the secondary compressor of each section.
//!
//! **xdelta3's LZMA sections are not complete `.xz` files.** Each is an xz
//! stream header, one block header (LZMA2, no check) and LZMA2 chunks flushed
//! with LZMA_SYNC_FLUSH: no end-of-stream byte, no index, no footer. So the
//! container is stripped by hand and the LZMA2 chunks are given the end byte
//! (`0x00`) they lack. The Adler-32 of every window says whether that worked.

use std::io::Cursor;

/// VCDIFF's magic, then version 0 (xdelta3 writes 0).
const MAGIC: [u8; 3] = [0xd6, 0xc3, 0xc4];
/// Header indicator: a secondary compressor id follows.
const VCD_DECOMPRESS: u8 = 0x01;
/// Header indicator: a code table follows (not supported: xdelta3 never writes one).
const VCD_CODETABLE: u8 = 0x02;
/// Header indicator: application data follows (xdelta3's file names).
const VCD_APPHEADER: u8 = 0x04;
/// Window indicator: the copy window is in the source / in the target so far.
const VCD_SOURCE: u8 = 0x01;
const VCD_TARGET: u8 = 0x02;
/// Window indicator: xdelta3's Adler-32 of the target window follows.
const VCD_ADLER32: u8 = 0x04;
/// xdelta3's secondary compressor ids.
const SEC_LZMA: u8 = 2;

const NOOP: u8 = 0;
const ADD: u8 = 1;
const RUN: u8 = 2;
const COPY: u8 = 3;

/// One half of a code table entry: (kind, size (0 = read it), mode).
type Half = (u8, u8, u8);

/// The RFC 3284 default code table (section 5.6).
fn code_table() -> Vec<(Half, Half)> {
    let none = (NOOP, 0, 0);
    let mut t = vec![((RUN, 0, 0), none), ((ADD, 0, 0), none)];
    t.extend((1..=17).map(|s| ((ADD, s, 0), none)));
    for m in 0..9 {
        t.push(((COPY, 0, m), none));
        t.extend((4..=18).map(|s| ((COPY, s, m), none)));
    }
    for m in 0..6 {
        for s in 1..=4 {
            t.extend((4..=6).map(|c| ((ADD, s, 0), (COPY, c, m))));
        }
    }
    for m in 6..9 {
        t.extend((1..=4).map(|s| ((ADD, s, 0), (COPY, 4, m))));
    }
    t.extend((0..9).map(|m| ((COPY, 4, m), (ADD, 1, 0))));
    debug_assert_eq!(t.len(), 256);
    t
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0 }
    }
    fn done(&self) -> bool {
        self.i >= self.b.len()
    }
    fn byte(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.i).ok_or("truncated")?;
        self.i += 1;
        Ok(v)
    }
    /// A VCDIFF integer: 7 bits a byte, most significant first.
    fn int(&mut self) -> Result<usize, String> {
        let mut v: usize = 0;
        for _ in 0..10 {
            let c = self.byte()?;
            v = v.checked_mul(128).ok_or("integer overflow")? | (c & 0x7f) as usize;
            if c & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("integer too long".into())
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let s = self.b.get(self.i..self.i.checked_add(n).ok_or("truncated")?).ok_or("truncated")?;
        self.i += n;
        Ok(s)
    }
}

/// One LZMA-compressed section: its decoded size, then xdelta3's xz stream.
fn unlzma(section: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(section);
    let size = r.int()?;
    let xz = &section[r.i..];
    // Stream header: magic, flags (check type), CRC32 -- 12 bytes.
    if xz.len() < 13 || &xz[..6] != b"\xfd7zXZ\0" {
        return Err("LZMA section is not an xz stream".into());
    }
    // Block header: its size is (first byte + 1) * 4.
    let block = (xz[12] as usize + 1) * 4;
    let body = xz.get(12 + block..).ok_or("xz block header runs past the section")?;
    let mut lzma2 = Vec::with_capacity(body.len() + 1);
    lzma2.extend_from_slice(body);
    lzma2.push(0x00);
    let mut out = Vec::with_capacity(size);
    lzma_rs::lzma2_decompress(&mut Cursor::new(lzma2), &mut out).map_err(|e| format!("LZMA2: {e}"))?;
    if out.len() != size {
        return Err(format!("LZMA section decoded to {} bytes, its header says {size}", out.len()));
    }
    Ok(out)
}

/// Apply an xdelta3 patch to `source`, the file it was made against.
pub fn apply(source: &[u8], patch: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(patch);
    if r.take(3)? != MAGIC {
        return Err("not a VCDIFF (xdelta3) patch".into());
    }
    r.byte()?; // version
    let hi = r.byte()?;
    let secondary = if hi & VCD_DECOMPRESS != 0 { Some(r.byte()?) } else { None };
    if hi & VCD_CODETABLE != 0 {
        return Err("the patch carries its own code table, which xdelta3 never writes".into());
    }
    if hi & VCD_APPHEADER != 0 {
        let n = r.int()?;
        r.take(n)?;
    }
    let table = code_table();
    let mut out: Vec<u8> = Vec::new();
    while !r.done() {
        let wi = r.byte()?;
        let (src_len, src_pos) = if wi & (VCD_SOURCE | VCD_TARGET) != 0 { (r.int()?, r.int()?) } else { (0, 0) };
        let delta_len = r.int()?;
        let delta_start = r.i;
        let target_len = r.int()?;
        let di = r.byte()?;
        let (n_data, n_inst, n_addr) = (r.int()?, r.int()?, r.int()?);
        let adler = if wi & VCD_ADLER32 != 0 { Some(u32::from_be_bytes(r.take(4)?.try_into().unwrap())) } else { None };
        let mut sections = [r.take(n_data)?.to_vec(), r.take(n_inst)?.to_vec(), r.take(n_addr)?.to_vec()];
        if r.i != delta_start + delta_len {
            return Err("a window's length does not match its sections".into());
        }
        for (k, s) in sections.iter_mut().enumerate() {
            if di & (1 << k) != 0 {
                match secondary {
                    Some(SEC_LZMA) => *s = unlzma(s)?,
                    Some(id) => return Err(format!("secondary compressor {id} is not supported (only LZMA)")),
                    None => return Err("a compressed section, but no compressor named".into()),
                }
            }
        }
        let [data, inst, addr] = sections;
        let segment: &[u8] = if wi & VCD_SOURCE != 0 {
            source.get(src_pos..src_pos + src_len).ok_or("the copy window runs past the source file")?
        } else if wi & VCD_TARGET != 0 {
            out.get(src_pos..src_pos + src_len).ok_or("the copy window runs past the target")?
        } else {
            &[]
        };
        let window = decode_window(&table, segment, &data, &inst, &addr, target_len)?;
        if let Some(want) = adler
            && adler32(&window) != want
        {
            return Err(format!("window {} fails its Adler-32: not the file this patch was made for", out.len()));
        }
        out.extend_from_slice(&window);
    }
    Ok(out)
}

fn decode_window(
    table: &[(Half, Half)],
    segment: &[u8],
    data: &[u8],
    inst: &[u8],
    addr: &[u8],
    target_len: usize,
) -> Result<Vec<u8>, String> {
    let (mut data, mut inst, mut addr) = (Reader::new(data), Reader::new(inst), Reader::new(addr));
    let mut t: Vec<u8> = Vec::with_capacity(target_len);
    let mut near = [0usize; 4];
    let mut next_near = 0;
    let mut same = [0usize; 3 * 256];
    while !inst.done() {
        let (a, b) = table[inst.byte()? as usize];
        for (kind, size, mode) in [a, b] {
            if kind == NOOP {
                continue;
            }
            let size = if size == 0 { inst.int()? } else { size as usize };
            match kind {
                ADD => t.extend_from_slice(data.take(size)?),
                RUN => {
                    let v = data.byte()?;
                    t.resize(t.len() + size, v);
                }
                _ => {
                    let here = segment.len() + t.len();
                    let at = match mode {
                        0 => addr.int()?,
                        1 => here.checked_sub(addr.int()?).ok_or("bad HERE address")?,
                        2..=5 => near[mode as usize - 2] + addr.int()?,
                        _ => same[(mode as usize - 6) * 256 + addr.byte()? as usize],
                    };
                    near[next_near] = at;
                    next_near = (next_near + 1) % 4;
                    same[at % (3 * 256)] = at;
                    if at >= here {
                        return Err("a copy from beyond the current position".into());
                    }
                    for k in 0..size {
                        let p = at + k;
                        let v = if p < segment.len() { segment[p] } else { t[p - segment.len()] };
                        t.push(v);
                    }
                }
            }
        }
    }
    if t.len() != target_len {
        return Err(format!("window decoded to {} bytes, its header says {target_len}", t.len()));
    }
    Ok(t)
}

fn adler32(b: &[u8]) -> u32 {
    let (mut a, mut s) = (1u32, 0u32);
    for chunk in b.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            s += a;
        }
        a %= 65521;
        s %= 65521;
    }
    (s << 16) | a
}
