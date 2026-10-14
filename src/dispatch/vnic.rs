//! A network title's own Ethernet driver, served by the loader (2026-10-11;
//! loader AGENTS.md 4.21, dcload-ip `vnic.c`).
//!
//! WHY. A title that plays online carries Sega's ETD library, a complete
//! RTL8139 driver: its init powers the GAPS bridge down and up, clears the
//! adapter's SRAM -- the loader's RX ring -- and resets the chip, after which
//! the loader, whose disc reads go through that chip, hears nothing. The
//! GAPS guard (`gaps_probe_patches`) prevents that by letting the title find
//! no adapter: its offline path. Two drivers cannot share one RTL8139 (one RX
//! read pointer, four TX descriptors taken in turn), so instead the loader
//! keeps the chip and the title's driver is replaced by the loader's: each
//! ETD entry point it calls gets a stub that jumps to `_vnic_etd` with the
//! function's index. The library's API is the boundary, not the chip's
//! registers, which a title without an MMU touches where it likes.
//!
//! FOUND BY CONTENT, AND ONLY EXACTLY. ETD is a precompiled library, so a title
//! that links the same version carries the same machine code: the entry
//! points are recognised by their first instructions at their offsets from
//! `ETD_Init`, and the library is recognised by its error strings, which its
//! literal pools name at known offsets too. Anything that differs by one byte
//! is another version, and is left to the GAPS guard: a stub written over a
//! function that is not the one `vnic_call()` expects would run the loader on
//! the wrong arguments. Known: Unreal Tournament PAL (boot md5 7d4a0918...).

use super::*;

/// The entry points the loader serves, in `vnic_call()`'s order (the index in
/// each stub): their offset from `ETD_Init` and their first instructions, as
/// Unreal Tournament PAL's copy has them. Every stub fits inside them (12
/// bytes at most).
const ENTRIES: [(&str, u32, &[u8]); 8] = [
    ("ETD_Init", 0x000, &[0xe6, 0x2f, 0xd6, 0x2f, 0xc6, 0x2f, 0xb6, 0x2f, 0xa6, 0x2f, 0x22, 0x4f, 0x7d, 0xd1, 0x7c, 0xd3]),
    ("ETD_Stop", 0x0ca, &[0x22, 0x4f, 0x4d, 0xd3, 0x4c, 0xd1, 0x32, 0x60, 0x10, 0x30, 0x0b, 0x8b]),
    ("ETD_GetEthAddr", 0x162, &[0xe6, 0x2f, 0x22, 0x4f, 0x27, 0xd1, 0x25, 0xd3, 0x47, 0xd5, 0x12, 0x62]),
    ("ETD_SetCtlPrm", 0x1d0, &[0xe6, 0x2f, 0xd6, 0x2f, 0x22, 0x4f, 0x0a, 0xd3, 0x0a, 0xd1, 0x0f, 0xdd]),
    ("link", 0x332, &[0xe6, 0x2f, 0x43, 0x6e, 0xd6, 0x2f, 0xc6, 0x2f, 0x22, 0x4f, 0x19, 0xd3]),
    ("ETD_CtlXmit", 0x3e4, &[0xe6, 0x2f, 0xd6, 0x2f, 0x22, 0x4f, 0x4e, 0xd3, 0x4e, 0xd1, 0x4b, 0xdd]),
    ("ETD_SetRecvBuf", 0x4ac, &[0x22, 0x4f, 0x1e, 0xd1, 0x1c, 0xd3, 0x12, 0x62, 0x30, 0x32, 0x07, 0x89]),
    ("ETD_SetSendBuf", 0x4d4, &[0xe6, 0x2f, 0xd6, 0x2f, 0x22, 0x4f, 0xfc, 0x7f, 0x11, 0xd3, 0x12, 0xd1]),
];

/// The four callback setters, in `g_vnic_slot`'s order (RX, TX, unused,
/// link): `mov.l @(cb,PC),Rn ; mov.l @(ctx,PC),Rm ; mov.l r4,@Rn ; rts ;
/// mov.l r5,@Rm`. Not replaced: the loader reads the words they write.
const SETTERS: [(u32, &[u8]); 4] = [
    (0x0f4, &[0x50, 0xd1, 0x5c, 0xd3, 0x42, 0x21, 0x0b, 0x00, 0x52, 0x23]),
    (0x0fe, &[0x4f, 0xd2, 0x5a, 0xd3, 0x42, 0x22, 0x0b, 0x00, 0x52, 0x23]),
    (0x108, &[0x4d, 0xd2, 0x59, 0xd3, 0x42, 0x22, 0x0b, 0x00, 0x52, 0x23]),
    (0x112, &[0x4c, 0xd2, 0x57, 0xd3, 0x42, 0x22, 0x0b, 0x00, 0x52, 0x23]),
];

/// Literal pool words that name the library's error strings, by offset from
/// `ETD_Init`: the proof that this is ETD and that the offsets above are its.
const NAMES: [(u32, &str); 6] = [
    (0x214, "ETD_Init():"),
    (0x288, "ETD_GetEthAddr():"),
    (0x29c, "ETD_SetCtlPrm():"),
    (0x520, "ETD_CtlXmit():"),
    (0x584, "ETD_SetRecvBuf():"),
    (0x58c, "ETD_SetSendBuf():"),
];

/// Sega's ETD driver, found in a title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Etd {
    /// The entry points the loader replaces (P1), in `vnic_call()`'s order.
    pub entries: [u32; 8],
    /// The driver's own callback words (RX, TX, unused, link), then their
    /// contexts (P1): what the loader is told (`g_vnic_slot`).
    pub slots: [u32; 8],
}

/// Find ETD in `buf` (uploaded at `address`), only if every entry point and
/// every name is exactly where this version keeps them.
pub fn find_etd(buf: &[u8], address: u32) -> Option<Etd> {
    for (base, data) in payload_spans(buf, address) {
        let base = p1(base);
        // The NUL-terminated string at `w`, inside this span.
        let names_string = |w: u32, s: &str| -> bool {
            let Some(off) = phys(w).checked_sub(phys(base)) else {
                return false;
            };
            data.get(off as usize..off as usize + s.len() + 1)
                .is_some_and(|b| &b[..s.len()] == s.as_bytes() && b[s.len()] == 0)
        };
        let word_at = |off: u32| -> Option<u32> {
            let o = off as usize;
            (o % 4 == 0).then(|| data.get(o..o + 4).map(|_| le32(data, o))).flatten()
        };
        let needle = b"ETD_Init():\0";
        for at in (0..data.len().saturating_sub(needle.len())).filter(|&i| data[i..].starts_with(needle)) {
            let s = base + at as u32;
            for (l, _) in words(data).filter(|&(_, w)| phys(w) == phys(s)) {
                let Some(init) = (l as u32).checked_sub(NAMES[0].0) else { continue };
                let ok = ENTRIES.iter().all(|(_, off, pro)| {
                    data.get((init + off) as usize..(init + off) as usize + pro.len()) == Some(*pro)
                }) && SETTERS.iter().all(|(off, pro)| {
                    data.get((init + off) as usize..(init + off) as usize + pro.len()) == Some(*pro)
                }) && NAMES.iter().all(|(off, name)| word_at(init + off).is_some_and(|w| names_string(w, name)));
                if !ok {
                    continue;
                }
                let mut slots = [0u32; 8];
                for (i, (off, _)) in SETTERS.iter().enumerate() {
                    for (j, half) in [0usize, 2].into_iter().enumerate() {
                        let at = (init + off) as usize + half;
                        let (_, lit) = pc_load(le16(data, at), at)?;
                        slots[i + 4 * j] = p1(word_at(lit as u32)?);
                    }
                }
                let entries = ENTRIES.map(|(_, off, _)| base + init + off);
                return Some(Etd { entries, slots });
            }
        }
    }
    None
}

/// The stub written over entry point `index` at `at`: `r1` gets `target`
/// (`_vnic_etd`), `r0` the index, in the jump's delay slot. The literal must be
/// 4-aligned, so an entry at a multiple of 4 gets a `nop` before it.
fn stub(at: u32, index: u8, target: u32) -> Vec<u8> {
    let mut halves = vec![0xd101u16, 0x412b, 0xe000 | index as u16];
    if at % 4 == 0 {
        halves.push(0x0009);
    }
    let mut out: Vec<u8> = halves.iter().flat_map(|h| h.to_le_bytes()).collect();
    out.extend_from_slice(&target.to_le_bytes());
    out
}

/// The words of the title to change: a stub over every entry point of `etd`,
/// as whole aligned words, the bytes around each stub kept as `buf` has them.
pub fn etd_patches(buf: &[u8], address: u32, etd: &Etd, target: u32) -> Vec<(u32, u32)> {
    let mut bytes: Vec<(u32, u8)> = vec![];
    for (i, &at) in etd.entries.iter().enumerate() {
        bytes.extend(stub(at, i as u8, target).into_iter().enumerate().map(|(k, b)| (at + k as u32, b)));
    }
    let mut out: Vec<(u32, u32)> = vec![];
    for (base, data) in payload_spans(buf, address) {
        let base = p1(base);
        let mut changed: Vec<u32> = bytes.iter().map(|&(a, _)| a & !3).collect();
        changed.dedup();
        for w in changed {
            let Some(off) = w.checked_sub(base).map(|o| o as usize).filter(|&o| o + 4 <= data.len()) else {
                continue;
            };
            let mut word: [u8; 4] = data[off..off + 4].try_into().expect("four bytes");
            for &(a, b) in bytes.iter().filter(|&&(a, _)| a & !3 == w) {
                word[(a - w) as usize] = b;
            }
            out.push((w, u32::from_le_bytes(word)));
        }
    }
    out
}

/// Phantasy Star Online v2.011 PAL's driver (2026-10-11): ETD's core behind
/// another API. Its network layer fills a table of seven functions from one
/// literal pool -- init, info, open, close, send, terminate, getmac -- by
/// device (the modem's otherwise), and calls a link test by its own literal.
/// Offsets from init and first instructions, as that copy has them, in the
/// pool's order; `true` for the ones the loader replaces (the others touch no
/// hardware: `open` keeps one callback per frame type, ARP and IP, in two words
/// the loader reads).
const PSO_TABLE: [(&str, u32, bool, &[u8]); 7] = [
    ("init", 0x000, true, &[0xe6, 0x2f, 0xd6, 0x2f, 0xc6, 0x2f, 0xb6, 0x2f, 0x31, 0xd3, 0x32, 0xd2, 0xa6, 0x2f, 0x96, 0x2f]),
    ("info", 0x132, false, &[0x01, 0xe4, 0x94, 0xd2, 0x43, 0x60, 0x42, 0x25, 0x54, 0x80, 0x34, 0xe0]),
    ("open", 0x150, false, &[0x70, 0x60, 0x8e, 0xd5, 0xf1, 0x54, 0x08, 0x88, 0x1c, 0x8b, 0x71, 0x84]),
    ("close", 0x19a, false, &[0x7d, 0xd6, 0x62, 0x63, 0x30, 0x34, 0x04, 0x8d, 0x00, 0xe5, 0x7b, 0xd6]),
    ("send", 0x1b8, true, &[0xe6, 0x2f, 0xd6, 0x2f, 0xc6, 0x2f, 0xb6, 0x2f, 0xa6, 0x2f, 0x96, 0x2f, 0x22, 0x4f, 0xf4, 0x7f]),
    ("terminate", 0x09e, true, &[0x1c, 0xd2, 0x22, 0x4f, 0x22, 0x63, 0x38, 0x23, 0x03, 0x8b, 0x1a, 0xd3]),
    ("getmac", 0x30a, true, &[0xe6, 0x2f, 0x22, 0x4f, 0xfc, 0x7f, 0x2f, 0xd3, 0x53, 0x6e, 0x2d, 0xd4]),
];
/// The link test (reads the PHY's status), called by its own literal.
const PSO_LINK: (u32, &[u8]) = (0x19c6, &[0x22, 0x4f, 0x17, 0xd4, 0x53, 0xb0, 0x09, 0x00, 0x03, 0x64, 0x4c, 0x60]);
/// Where `open` loads the addresses of its two callback words (ARP, IP).
const PSO_OPEN_SLOTS: [u32; 2] = [0x10, 0x2c];

/// Phantasy Star Online's driver, found in a title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsoNet {
    /// The pool word naming its init (P1); the table's other words follow.
    pub pool: u32,
    /// The literal words naming its link test (P1).
    pub links: Vec<u32>,
    /// What the loader is told (`g_vnic_slot`): the ARP and IP callback words,
    /// which the title also passes as their handles (contexts 4 and 5).
    pub slots: [u32; 8],
}

/// Find PSO's driver in `buf` (uploaded at `address`), only exactly.
pub fn find_pso_net(buf: &[u8], address: u32) -> Option<PsoNet> {
    for (base, data) in payload_spans(buf, address) {
        let base = p1(base);
        let at = |a: u32| a.checked_sub(base).map(|o| o as usize).filter(|&o| o < data.len());
        let code_is = |a: u32, pro: &[u8]| at(a).and_then(|o| data.get(o..o + pro.len())) == Some(pro);
        for (p, w0) in words(data) {
            let init = p1(w0);
            if !names_ram(w0) || at(init).is_none() {
                continue;
            }
            let table_ok = PSO_TABLE.iter().enumerate().all(|(k, (_, off, _, pro))| {
                data.get(p + 4 * k..p + 4 * k + 4).is_some_and(|_| p1(le32(data, p + 4 * k)) == init + off)
                    && code_is(init + off, pro)
            });
            if !table_ok || !code_is(init + PSO_LINK.0, PSO_LINK.1) {
                continue;
            }
            let open = init + PSO_TABLE[2].1;
            let mut slots = [0u32; 8];
            for (k, off) in PSO_OPEN_SLOTS.iter().enumerate() {
                let o = at(open + off)?;
                let (_, lit) = pc_load(le16(data, o), o)?;
                let w = p1(data.get(lit..lit + 4).map(|_| le32(data, lit))?);
                slots[k] = w;
                slots[4 + k] = w;
            }
            let link = init + PSO_LINK.0;
            let links = words(data).filter(|&(_, w)| names_ram(w) && p1(w) == link).map(|(i, _)| base + i as u32).collect();
            return Some(PsoNet { pool: base + p as u32, links, slots });
        }
    }
    None
}

/// The words to change for PSO: the table's replaced entries and every link
/// literal, pointed at `_vnic_pso + 4 * n` (`entry`, vnic_entry.S).
pub fn pso_patches(net: &PsoNet, entry: u32) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = PSO_TABLE
        .iter()
        .enumerate()
        .filter(|(_, t)| t.2)
        .enumerate()
        .map(|(n, (k, _))| (net.pool + 4 * k as u32, entry + 4 * n as u32))
        .collect();
    out.extend(net.links.iter().map(|&l| (l, entry + 16)));
    out
}

/// PHANTASY STAR ONLINE VER.2 (2026-10-11). Its 1ST_READ.BIN is a bootstrap
/// that loads IWASHI.SEA (to 0x8c004000), KATSUO.SEA (to 0x8c008400) and
/// DP_ADDRESS.JPN (to 0x8c800000), then enters IWASHI, which decrypts the last
/// with PSO's subtractive generator, overwrites words of the result from its
/// own table at offsets KATSUO's table gives, decompresses it (PRS) to
/// 0x8c010000 and calls KATSUO, which enters the program through the word at
/// 0x8c01002c. Nothing on the disc holds the program in clear, so the host
/// decodes it the same way to find the driver (PSO v2.011's, moved), and the
/// loader writes the words when KATSUO jumps (vnic.c, "LATE PATCHES").
pub const PSO_V2_FILES: [&str; 3] = ["IWASHI.SEA", "KATSUO.SEA", "DP_ADDRESS.JPN"];
const IWASHI_LOAD: u32 = 0x8c00_4000;
const KATSUO_LOAD: u32 = 0x8c00_8400;
/// The word of a Katana program's header that holds its entry point.
const KATANA_ENTRY_WORD: u32 = 0x8c01_002c;
/// KATSUO's last instructions after the load of the literal it jumps through:
/// `mov r2,r3 ; mov.l r2,@r15 ; mov.l @r3,r2 ; mov r2,r3 ; mov.l r2,@r15 ;
/// add #4,r15 ; jmp @r3 ; lds.l @r15+,pr`.
const KATSUO_JUMP: [u8; 16] = [
    0x23, 0x63, 0x22, 0x2f, 0x32, 0x62, 0x23, 0x63, 0x22, 0x2f, 0x04, 0x7f, 0x2b, 0x43, 0x26, 0x4f,
];

/// PSO's subtractive generator (Knuth's, 55 words), as IWASHI.SEA runs it.
struct PsoRng {
    w: [u32; 58],
}

impl PsoRng {
    fn new(seed: u32) -> Self {
        let mut w = [0u32; 58];
        w[57] = seed;
        w[56] = seed;
        let (mut esi, mut ebx) = (1u32, seed);
        let mut edi = 21;
        while edi <= 0x46e {
            let r = edi % 55;
            w[1 + r] = esi;
            (esi, ebx) = (ebx.wrapping_sub(esi), w[1 + r]);
            edi += 21;
        }
        let mut rng = PsoRng { w };
        for _ in 0..4 {
            rng.update();
        }
        rng.w[0] = 55;
        rng
    }

    fn update(&mut self) {
        let w = &mut self.w;
        for i in 0..24 {
            w[2 + i] = w[2 + i].wrapping_sub(w[33 + i]);
        }
        for i in 0..31 {
            w[26 + i] = w[26 + i].wrapping_sub(w[2 + i]);
        }
    }

    fn next(&mut self) -> u32 {
        self.w[0] += 1;
        if self.w[0] > 55 {
            self.update();
            self.w[0] = 1;
        }
        self.w[1 + self.w[0] as usize]
    }
}

/// Sega's PRS, as IWASHI.SEA decompresses it. `None` on a stream that reads
/// outside itself or names bytes not yet written.
fn prs_decompress(src: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let (mut i, mut cmd, mut bits) = (0usize, 0u8, 0u32);
    let mut bit = |i: &mut usize| -> Option<u8> {
        if bits == 0 {
            cmd = *src.get(*i)?;
            *i += 1;
            bits = 8;
        }
        let b = cmd & 1;
        cmd >>= 1;
        bits -= 1;
        Some(b)
    };
    loop {
        if bit(&mut i)? == 1 {
            out.push(*src.get(i)?);
            i += 1;
            continue;
        }
        let (off, len) = if bit(&mut i)? == 0 {
            let len = ((bit(&mut i)? << 1) | bit(&mut i)?) as usize + 2;
            let off = *src.get(i)? as isize - 256;
            i += 1;
            (off, len)
        } else {
            let v = *src.get(i)? as usize | (*src.get(i + 1)? as usize) << 8;
            i += 2;
            if v == 0 {
                return Some(out);
            }
            let off = (v >> 3) as isize - 8192;
            let len = match v & 7 {
                0 => {
                    let n = *src.get(i)? as usize + 1;
                    i += 1;
                    n
                }
                n => n + 2,
            };
            (off, len)
        };
        for _ in 0..len {
            let at = (out.len() as isize + off).try_into().ok()?;
            out.push(*out.get::<usize>(at)?);
        }
        if out.len() > limit {
            return None;
        }
    }
}

/// PSO Ver.2's program, decoded from its three files as IWASHI.SEA does it,
/// for loading at 0x8c010000. `None` if any of them is not what it should be:
/// the decompressed size must come out as the file's first word says.
pub fn pso_v2_decode(iwashi: &[u8], katsuo: &[u8], dp: &[u8]) -> Option<Vec<u8>> {
    let (size, seed) = (le32(dp.get(..4)?, 0), le32(dp.get(4..8)?, 0));
    let mut data = dp.get(8..)?.to_vec();
    data.resize(data.len().div_ceil(4) * 4, 0);
    let mut rng = PsoRng::new(seed);
    for word in data.chunks_exact_mut(4) {
        let w = u32::from_le_bytes(word.try_into().ok()?) ^ rng.next();
        word.copy_from_slice(&w.to_le_bytes());
    }
    // IWASHI's table of words, put at the word indices KATSUO's deltas give.
    let mut p5 = (le32(iwashi, iwashi.len().checked_sub(4)?).checked_sub(IWASHI_LOAD)?) as usize;
    let mut p6 = (le32(katsuo, katsuo.len().checked_sub(4)?).checked_sub(KATSUO_LOAD)?) as usize;
    let mut index = 0usize;
    while *katsuo.get(p6)? != 0 {
        index += katsuo[p6] as usize;
        p6 += 2;
        let w = iwashi.get(p5..p5 + 4)?;
        data.get_mut(index * 4..index * 4 + 4)?.copy_from_slice(w);
        p5 += 4;
    }
    let out = prs_decompress(&data, crate::types::DREAMCAST_RAM_BYTES as usize)?;
    (out.len() == size as usize).then_some(out)
}

/// What the host prepares for PSO Ver.2: the driver in the decoded program,
/// and the word of KATSUO.SEA to point at the loader while it is served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsoLate {
    pub net: PsoNet,
    /// Where KATSUO's literal lands in RAM, and what it holds (the entry word).
    pub katsuo_at: u32,
    pub entry_word: u32,
    /// The heaps the decoded program sets up (`program_heaps`): its syMalloc
    /// heap runs to the top of RAM, where the loader goes, and its end is a
    /// word of the decoded program -- lowered with the other late words.
    pub heaps: Vec<KatanaHeap>,
    /// Its Katana expansion probe's G2 write, pointed at a function returning
    /// 0 (`gaps_power_down_redirect`): left alone, the probe switched the
    /// adapter off as the program started (console, 2026-10-12).
    pub gaps_off: Option<(u32, u32)>,
    /// Its serial-number checks, answered "valid" (`pso_serial_check_patches`).
    pub serial_checks: Vec<(u32, u32)>,
    /// The decoded program, for the constants a placement is checked against.
    program: Vec<u8>,
}

impl PsoLate {
    /// The decoded program's constants naming RAM a loader at `base` occupies.
    pub fn literals_in_loader(&self, base: u32) -> Vec<(u32, u32)> {
        literals_in_loader_footprint(&self.program, KATANA_PROGRAM, base)
    }
}

/// Where the decoded program runs from.
const KATANA_PROGRAM: u32 = 0x8c01_0000;
/// The flash block PSO Ver.2 keeps its serial number and access key in
/// (partition 2, logical block 7: its record is written by 0x8c2326f4, PAL,
/// through the Katana flash library). The loader lets writes of this block
/// reach the console's flash (`g_vnic_flash_keep`, vnic.c), so that what was
/// typed is not asked again next session; the host carries no number.
pub const PSO_V2_SERIAL_BLOCK: u32 = 7;
/// How many (address, value) pairs the loader's `g_vnic_late` holds
/// (`VNIC_LATE_MAX`, vnic.c).
pub const VNIC_LATE_MAX: usize = 10;

/// PSO Ver.2's late patching, from its three files; `None` unless the
/// program decodes, carries PSO's driver, and KATSUO jumps as known.
pub fn find_pso_v2(iwashi: &[u8], katsuo: &[u8], dp: &[u8]) -> Option<PsoLate> {
    let program = pso_v2_decode(iwashi, katsuo, dp)?;
    let net = find_pso_net(&program, KATANA_PROGRAM)?;
    let tail = (0..katsuo.len().saturating_sub(KATSUO_JUMP.len() + 2))
        .step_by(2)
        .find(|&i| katsuo[i + 2..].starts_with(&KATSUO_JUMP))?;
    let (_, lit) = pc_load(le16(katsuo, tail), tail)?;
    let entry_word = le32(katsuo.get(lit..lit + 4)?, 0);
    (entry_word == KATANA_ENTRY_WORD).then(|| PsoLate {
        net,
        katsuo_at: KATSUO_LOAD + lit as u32,
        entry_word,
        heaps: program_heaps(&program, KATANA_PROGRAM),
        gaps_off: gaps_power_down_redirect(&program, KATANA_PROGRAM),
        serial_checks: pso_serial_check_patches(&program, KATANA_PROGRAM),
        program,
    })
}

/// PSO Ver.2's serial-number checks (console, 2026-10-14). The program loads
/// PRIME.PRS (`"prime.prs"`: three validators, a product of three primes) and
/// keeps the module in one word; each check loads that word and calls one of
/// its functions (`mov.l @r0,r0 ; mov.l @(4|8,r0),r0 ; jsr @r0`), and the
/// entry screen refuses the number on 0. Each `jsr` becomes `mov #1,r0` (its
/// delay slot then runs as an ordinary instruction): whatever is typed is
/// accepted, and no number is carried by the host. Two pairs on PSO Ver.2 PAL.
pub fn pso_serial_check_patches(program: &[u8], base: u32) -> Vec<(u32, u32)> {
    let h = |i: usize| (i + 1 < program.len()).then(|| le16(program, i));
    let lit = |at: usize| program.get(at..at + 4).map(|b| le32(b, 0));
    let Some(name) = program.windows(10).position(|w| w == b"prime.prs\0") else {
        return vec![];
    };
    let name = base + name as u32;
    // The loader of the module: a load of the name, then, within a few
    // instructions, `mov.l @(disp,PC),Rn ; mov.l r0,@Rn` storing the module.
    let mut module = None;
    for i in (0..program.len().saturating_sub(1)).step_by(2) {
        let Some((_, at)) = pc_load(le16(program, i), i) else { continue };
        if lit(at) != Some(name) {
            continue;
        }
        module = (i + 2..i + 26).step_by(2).find_map(|j| {
            let (rn, at) = pc_load(h(j)?, j)?;
            (h(j + 2)? == 0x2002 | rn << 8).then(|| lit(at)).flatten().filter(|&w| names_ram(w))
        });
        if module.is_some() {
            break;
        }
    }
    let Some(module) = module else { return vec![] };
    let mut out = vec![];
    for j in (0..program.len().saturating_sub(9)).step_by(2) {
        let Some((0, at)) = pc_load(le16(program, j), j) else { continue };
        if lit(at) != Some(module)
            || le16(program, j + 2) != 0x6002
            || !matches!(le16(program, j + 4), 0x5001 | 0x5002)
            || le16(program, j + 6) != 0x400b
        {
            continue;
        }
        // The 4-aligned word holding the `jsr`.
        out.push(if (j + 4) % 4 == 0 {
            (base + j as u32 + 4, 0x0009 | 0xe001 << 16) // nop ; mov #1,r0
        } else {
            (base + j as u32 + 6, 0xe001 | (le16(program, j + 8) as u32) << 16)
        });
    }
    out
}

/// The loader's `g_vnic_late`: count, the entry word, then the pairs -- the
/// driver's, then `more` (a heap end lowered under the loader). An error if
/// they outnumber what the loader holds.
pub fn pso_v2_late_words(late: &PsoLate, pso_entry: u32, more: &[(u32, u32)]) -> Result<Vec<u32>, String> {
    let mut pairs = pso_patches(&late.net, pso_entry);
    pairs.extend_from_slice(more);
    if pairs.len() > VNIC_LATE_MAX {
        return Err(format!("{} words to write, the loader holds {VNIC_LATE_MAX}", pairs.len()));
    }
    let mut out = vec![pairs.len() as u32, late.entry_word];
    out.extend(pairs.iter().flat_map(|&(a, v)| [a, v]));
    Ok(out)
}

/// A network driver the loader can serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetDriver {
    Etd(Etd),
    Pso(PsoNet),
}

impl NetDriver {
    pub fn name(&self) -> &'static str {
        match self {
            NetDriver::Etd(_) => "Sega's ETD Ethernet driver",
            NetDriver::Pso(_) => "Phantasy Star Online's Ethernet driver",
        }
    }

    /// What the loader is told before EXEC (`g_vnic_slot`).
    pub fn slots(&self) -> [u32; 8] {
        match self {
            NetDriver::Etd(e) => e.slots,
            NetDriver::Pso(p) => p.slots,
        }
    }
}

/// Either driver, if `buf` carries one exactly as known.
pub fn find_net_driver(buf: &[u8], address: u32) -> Option<NetDriver> {
    find_etd(buf, address).map(NetDriver::Etd).or_else(|| find_pso_net(buf, address).map(NetDriver::Pso))
}

/// The title's words to change: `etd` and `pso` are the loader's two ways in
/// (`_vnic_etd`, `_vnic_pso`).
pub fn net_driver_patches(buf: &[u8], address: u32, d: &NetDriver, etd: u32, pso: u32) -> Vec<(u32, u32)> {
    match d {
        NetDriver::Etd(e) => etd_patches(buf, address, e, etd),
        NetDriver::Pso(p) => pso_patches(p, pso),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PSO v2.011's driver laid out as its 1ST_READ.BIN has it: init at
    /// 0x8c371ff4, the table's pool at 0x8c36c074, the link literal at
    /// 0x8c030a70, open's callback words at 0x8c58dec0/4.
    fn pso_net_like() -> Vec<u8> {
        const INIT: usize = 0x361ff4;
        let mut img = vec![0u8; 0x37_0000];
        for (k, (_, off, _, pro)) in PSO_TABLE.iter().enumerate() {
            img[INIT + *off as usize..][..pro.len()].copy_from_slice(pro);
            img[0x35_c074 + 4 * k..][..4].copy_from_slice(&(0x8c37_1ff4 + off).to_le_bytes());
        }
        img[INIT + PSO_LINK.0 as usize..][..PSO_LINK.1.len()].copy_from_slice(PSO_LINK.1);
        img[0x2_0a70..0x2_0a74].copy_from_slice(&0x8c37_39bau32.to_le_bytes());
        for (k, off) in PSO_OPEN_SLOTS.iter().enumerate() {
            let at = INIT + PSO_TABLE[2].1 as usize + *off as usize;
            // mov.l @(disp,PC),r6 aimed at a pool word of our own.
            let lit = 0x36_2400 + 4 * k;
            let disp = (lit - ((at + 4) & !3)) / 4;
            img[at..at + 2].copy_from_slice(&(0xd600u16 | disp as u16).to_le_bytes());
            img[lit..lit + 4].copy_from_slice(&(0x8c58_dec0u32 + 4 * k as u32).to_le_bytes());
        }
        img
    }

    #[test]
    fn psos_driver_is_found_by_its_table_and_its_link_literal() {
        let img = pso_net_like();
        let NetDriver::Pso(n) = find_net_driver(&img, 0x8c01_0000).expect("PSO") else {
            panic!("not PSO's")
        };
        assert_eq!(n.pool, 0x8c36_c074);
        assert_eq!(n.links, vec![0x8c03_0a70]);
        assert_eq!(n.slots, [0x8c58_dec0, 0x8c58_dec4, 0, 0, 0x8c58_dec0, 0x8c58_dec4, 0, 0]);
        assert_eq!(
            pso_patches(&n, 0x8cfc_0870),
            vec![
                (0x8c36_c074, 0x8cfc_0870),
                (0x8c36_c084, 0x8cfc_0874),
                (0x8c36_c088, 0x8cfc_0878),
                (0x8c36_c08c, 0x8cfc_087c),
                (0x8c03_0a70, 0x8cfc_0880),
            ]
        );
        let mut img = pso_net_like();
        img[0x361ff4 + 0x1b8 + 14] ^= 1; // send's prologue
        assert_eq!(find_pso_net(&img, 0x8c01_0000), None);
    }

    /// ETD laid out as Unreal Tournament PAL has it in 1ST_READ.BIN (loaded at
    /// 0x8c010000): ETD_Init at 0x8c1c4a74, its strings at 0x8c27e840..., the
    /// callback words at 0x8c2ceb78... Only the bytes the recogniser reads.
    fn ut_etd_like() -> Vec<u8> {
        const INIT: usize = 0x1b_4a74;
        let mut img = vec![0u8; 0x1c_0000];
        for (_, off, pro) in ENTRIES {
            img[INIT + off as usize..][..pro.len()].copy_from_slice(pro);
        }
        for (off, pro) in SETTERS {
            img[INIT + off as usize..][..pro.len()].copy_from_slice(pro);
        }
        let mut s = 0x1b_8000usize;
        for (off, name) in NAMES {
            img[s..s + name.len()].copy_from_slice(name.as_bytes());
            img[INIT + off as usize..][..4].copy_from_slice(&(0x8c01_0000 + s as u32).to_le_bytes());
            s += name.len() + 1;
        }
        // The setters' literals, where their `mov.l @(disp,PC)` point.
        for (i, (off, _)) in SETTERS.iter().enumerate() {
            for (j, half) in [0usize, 2].into_iter().enumerate() {
                let at = INIT + *off as usize + half;
                let (_, lit) = pc_load(le16(&img, at), at).unwrap();
                let slot = 0x8c2c_eb78u32 + 4 * i as u32 + 0x10 * j as u32;
                img[lit..lit + 4].copy_from_slice(&slot.to_le_bytes());
            }
        }
        img
    }

    #[test]
    fn unreal_tournaments_etd_is_found_with_its_entry_points_and_callback_words() {
        let etd = find_etd(&ut_etd_like(), 0x0c01_0000).expect("ETD");
        assert_eq!(
            etd.entries,
            [0x8c1c_4a74, 0x8c1c_4b3e, 0x8c1c_4bd6, 0x8c1c_4c44, 0x8c1c_4da6, 0x8c1c_4e58, 0x8c1c_4f20, 0x8c1c_4f48]
        );
        assert_eq!(
            etd.slots,
            [0x8c2c_eb78, 0x8c2c_eb7c, 0x8c2c_eb80, 0x8c2c_eb84, 0x8c2c_eb88, 0x8c2c_eb8c, 0x8c2c_eb90, 0x8c2c_eb94]
        );
    }

    /// With `DCLOAD_ETD_BIN` naming a real boot binary (Unreal Tournament PAL's
    /// 1ST_READ.BIN, `dcload-ip-rs extract`): ETD is found where it is.
    #[test]
    fn a_real_boot_binary_with_etd_is_recognised() {
        let Ok(path) = std::env::var("DCLOAD_ETD_BIN") else {
            return;
        };
        let img = std::fs::read(path).expect("DCLOAD_ETD_BIN");
        let etd = find_etd(&img, 0x8c01_0000).expect("ETD in this binary");
        assert_eq!(etd.entries[0], 0x8c1c_4a74);
        assert_eq!(etd.slots, [0x8c2c_eb78, 0x8c2c_eb7c, 0x8c2c_eb80, 0x8c2c_eb84, 0x8c2c_eb88, 0x8c2c_eb8c, 0x8c2c_eb90, 0x8c2c_eb94]);
    }

    /// With `DCLOAD_PSO_BIN` naming PSO v2.011 PAL's 1ST_READ.BIN.
    #[test]
    fn psos_real_boot_binary_is_recognised() {
        let Ok(path) = std::env::var("DCLOAD_PSO_BIN") else {
            return;
        };
        let img = std::fs::read(path).expect("DCLOAD_PSO_BIN");
        let Some(NetDriver::Pso(n)) = find_net_driver(&img, 0x8c01_0000) else {
            panic!("PSO's driver not found")
        };
        assert_eq!(n.pool, 0x8c36_c074);
        // Two literals name the link test: the game's (its status, 0x8c030a4e)
        // and the driver's own interrupt handler's, dead once init is the
        // loader's -- pointed at the loader too, which changes nothing.
        assert_eq!(n.links, vec![0x8c03_0a70, 0x8c37_24e8]);
        assert_eq!(&n.slots[..2], &[0x8c58_dec0, 0x8c58_dec4]);
    }

    /// With `DCLOAD_PSO2_DIR` naming a directory holding PSO Ver.2 PAL's
    /// IWASHI.SEA, KATSUO.SEA and DP_ADDRESS.JPN.
    #[test]
    fn pso_ver2s_program_is_decoded_and_its_driver_found() {
        let Ok(dir) = std::env::var("DCLOAD_PSO2_DIR") else {
            return;
        };
        let [iw, ka, dp] = PSO_V2_FILES.map(|n| std::fs::read(std::path::Path::new(&dir).join(n)).expect(n));
        let program = pso_v2_decode(&iw, &ka, &dp).expect("decodes");
        assert_eq!(program.len(), 0x3f_8560);
        assert_eq!(le32(&program, 0x2c), 0x8c34_0848); // its entry, KATSUO's target
        let late = find_pso_v2(&iw, &ka, &dp).expect("PSO's driver in it");
        assert_eq!(late.katsuo_at, 0x8c00_8478);
        assert_eq!(late.entry_word, 0x8c01_002c);
        assert_eq!(late.net.pool, 0x8c3c_8bb4); // in the table's filler, 0x8c3c89f0
        // Its syMalloc heap runs to the top of RAM: the loader goes near its top
        // (0x8cff0000 is named by its constants) and the end, a word of the
        // decoded program, is lowered under it.
        let top = late.heaps.iter().find(|h| h.end == 0x8d00_0000).expect("a heap to the top of RAM");
        assert_eq!((top.start, top.end_at), (0x8c5c_6880, 0x8c03_0820));
        let free = |b: u32| late.literals_in_loader(b).is_empty();
        assert_eq!(katana_loader_base(&late.heaps, 0x8ce0_0000, &free), Some(0x8cfe_0000));
        let lowered = top.patch(0x8cfe_0000).unwrap().expect("the loader inside it");
        assert_eq!(lowered, (0x8c03_0820, 0x0cfe_0000));
        // Its expansion probe (0x8c37a37e) switches the adapter off: its G2
        // write is pointed at the program's first `rts ; mov #0,r0`.
        assert_eq!(late.gaps_off, Some((0x8c37_a3e0, 0x8c01_0510)));
        let more = [late.gaps_off.unwrap(), lowered];
        let words = pso_v2_late_words(&late, 0x8cfc_0870, &more).unwrap();
        assert_eq!(words[..2], [words.len() as u32 / 2 - 1, 0x8c01_002c]);
        assert_eq!(words[0], 8);
        assert_eq!(words[words.len() - 4..], [0x8c37_a3e0, 0x8c01_0510, 0x8c03_0820, 0x0cfe_0000]);
        // Its two serial-number checks (the screen before going online) call
        // PRIME.PRS's validators; each `jsr` is answered 1.
        assert_eq!(late.serial_checks, vec![(0x8c23_28c8, 0xe001_0009), (0x8c23_2958, 0xe001_0009)]);
        let all: Vec<(u32, u32)> = more.iter().chain(&late.serial_checks).copied().collect();
        let words = pso_v2_late_words(&late, 0x8cfc_0870, &all).unwrap();
        assert_eq!(words[0] as usize, VNIC_LATE_MAX);
        assert!(pso_v2_late_words(&late, 0x8cfc_0870, &[lowered; 5]).is_err());
    }

    #[test]
    fn a_serial_number_check_is_answered_valid() {
        let mut p = vec![0u8; 0x200];
        let put16 = |p: &mut Vec<u8>, at: usize, v: u16| p[at..at + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |p: &mut Vec<u8>, at: usize, v: u32| p[at..at + 4].copy_from_slice(&v.to_le_bytes());
        p[0x100..0x10a].copy_from_slice(b"prime.prs\0");
        // Its loader: the name in r4, a call, the module stored through r1.
        for (at, op) in [(0x10, 0xd40b), (0x12, 0x400b), (0x14, 0x0009), (0x16, 0xd10b), (0x18, 0x2102)] {
            put16(&mut p, at, op);
        }
        put32(&mut p, 0x40, 0x8c01_0100);
        put32(&mut p, 0x44, 0x8c51_0900);
        // Two checks, the `jsr` 4-aligned in the first and not in the second.
        for (at, op) in [(0x60, 0xd007), (0x62, 0x6002), (0x64, 0x5001), (0x66, 0x400b), (0x68, 0x64d3)] {
            put16(&mut p, at, op);
        }
        put32(&mut p, 0x80, 0x8c51_0900);
        for (at, op) in [(0x92, 0xd003), (0x94, 0x6002), (0x96, 0x5002), (0x98, 0x400b), (0x9a, 0x6543)] {
            put16(&mut p, at, op);
        }
        put32(&mut p, 0xa0, 0x8c51_0900);
        assert_eq!(
            pso_serial_check_patches(&p, 0x8c01_0000),
            vec![(0x8c01_0064, 0xe001_0009), (0x8c01_0098, 0x6543_e001)]
        );
        // Without the module's name, nothing.
        p[0x100] = b'P';
        assert!(pso_serial_check_patches(&p, 0x8c01_0000).is_empty());
    }

    #[test]
    fn one_byte_of_another_version_is_not_etd() {
        let mut img = ut_etd_like();
        img[0x1b_4a74 + 0x4d4 + 6] ^= 1; // ETD_SetSendBuf's prologue
        assert_eq!(find_etd(&img, 0x0c01_0000), None);
        let mut img = ut_etd_like();
        img[0x1b_8000 + 4] = b'X'; // "ETD_Init():" no longer
        assert_eq!(find_etd(&img, 0x0c01_0000), None);
    }

    #[test]
    fn a_stub_jumps_to_the_loader_with_its_index_and_keeps_the_neighbouring_bytes() {
        let img = ut_etd_like();
        let etd = find_etd(&img, 0x0c01_0000).unwrap();
        let p = etd_patches(&img, 0x0c01_0000, &etd, 0x8cfc_0870);
        // ETD_Stop at 0x8c1c4b3e (2 mod 4): the word before it keeps its first
        // half, then mov.l @(1,PC),r1 ; jmp @r1 ; mov #1,r0 ; .long target.
        assert!(p.contains(&(0x8c1c_4b3c, 0xd101_0000 | le16(&img, 0x1b_4b3c) as u32)));
        assert!(p.contains(&(0x8c1c_4b40, 0xe001_412b)));
        assert!(p.contains(&(0x8c1c_4b44, 0x8cfc_0870)));
        // ETD_SetSendBuf at 0x8c1c4f48 (0 mod 4): a nop before the literal.
        assert!(p.contains(&(0x8c1c_4f48, 0x412b_d101)));
        assert!(p.contains(&(0x8c1c_4f4c, 0x0009_e007)));
        assert!(p.contains(&(0x8c1c_4f50, 0x8cfc_0870)));
        // Eight stubs of 10 or 12 bytes: three or four words each, no more.
        assert!(p.len() <= 8 * 4 && p.len() >= 8 * 3);
    }
}
