//! Scans of a title's code and the patches they lead to: GAPS, the VGA
//! cable check, direct GD driver calls, constants naming the loader, fill loops,
//! KOS, and applying and verifying patches on the console.

use super::*;

/// The bytes that will be in RAM and where each run lands: a raw binary whole
/// at `address`, an ELF section by section. Every scan goes through this.
fn payload_spans(buf: &[u8], address: u32) -> Vec<(u32, &[u8])> {
    let mut spans: Vec<(u32, &[u8])> = vec![];
    if let Ok(elf) = ElfBytes::<AnyEndian>::minimal_parse(buf) {
        if let Some(headers) = elf.section_headers() {
            for sh in headers.iter() {
                if crate::loaders::is_uploadable(&sh)
                    && let Ok((data, _)) = elf.section_data(&sh)
                {
                    spans.push((sh.sh_addr as u32, data));
                }
            }
        }
    } else {
        spans.push((address, buf));
    }
    spans
}

fn le16(data: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([data[i], data[i + 1]])
}

fn le32(data: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
}

/// The 4-aligned words of `data`, with their offsets.
fn words(data: &[u8]) -> impl Iterator<Item = (usize, u32)> + '_ {
    (0..data.len().saturating_sub(3)).step_by(4).map(move |i| (i, le32(data, i)))
}

/// Whether `w` names main RAM, through any of its three windows.
fn names_ram(w: u32) -> bool {
    matches!(w & 0xff00_0000, 0x0c00_0000 | 0x8c00_0000 | 0xac00_0000)
}

/// If `op` at offset `at` is `mov.l @(disp,PC),Rn`: `Rn` and the offset it
/// loads from (PC + 4, rounded down to 4, plus disp * 4).
fn pc_load(op: u16, at: usize) -> Option<(u16, usize)> {
    (op & 0xf000 == 0xd000).then(|| ((op >> 8) & 0xf, ((at + 4) & !3) + (op & 0xff) as usize * 4))
}

/// A disc read's ReturnValue carries `READ_RETVAL_TAG | LBA`, so the loader can
/// refuse a late answer to another read into the same buffer (`GD_READ_TAG` in
/// the loader). Bit 31 stays clear for older loaders.
pub(super) const READ_RETVAL_TAG: u32 = 0x4000_0000;

/// The four G2 slot windows a Katana title probes for an expansion device.
const GAPS_SLOT_WINDOWS: [u32; 4] = [0xa100_0400, 0xa100_0800, 0xa100_1400, 0xa100_1800];
/// `"GAPS"` as a little-endian word, the signature the probe compares against.
const GAPS_SIGNATURE: u32 = 0x5350_4147;
/// How far from the signature a slot-window literal may sit to corroborate it.
const GAPS_CORROBORATION_SPAN: usize = 4096;

/// Stop a title from switching the Broadband Adapter off (loader AGENTS.md 4.12).
///
/// A title that probes the G2 slots for `"GAPS"` powers down whatever answers,
/// and the loader goes deaf. Replacing the comparison constant makes every
/// probe fail, which is the empty-port path every title supports. The constant
/// only counts when a slot-window literal sits near it.
pub fn gaps_probe_patches(buf: &[u8], address: u32) -> Vec<(u32, u32)> {
    let spans = payload_spans(buf, address);

    let mut out = vec![];
    for (base, data) in spans {
        let slots: Vec<usize> = words(data)
            .filter(|(_, w)| GAPS_SLOT_WINDOWS.contains(w))
            .map(|(i, _)| i)
            .collect();
        for (i, w) in words(data) {
            let corroborated = slots.iter().any(|&s| s.abs_diff(i) <= GAPS_CORROBORATION_SPAN);
            if w != GAPS_SIGNATURE || !corroborated {
                continue;
            }
            let at = p1(base) + i as u32;
            info!(
                "this title probes the expansion port for the GAPS bridge \
                 (signature at 0x{at:08x}); neutralising it so it cannot switch \
                 the adapter off"
            );
            out.push((at, 0xffff_ffff));
        }
    }
    out
}

/// The SH4 port data register; bits 8-9 are the video cable (0 VGA, 2 RGB,
/// 3 composite).
const PDTRA: u32 = 0xff80_0030;

/// How many instructions past the load the port read may sit.
const CABLE_READ_WINDOW: usize = 8;

/// The BIOS GD driver body the syscall vectors point at, cached and uncached.
const GD_DRIVER_BODY: [u32; 2] = [0x8c00_10f0, 0xac00_10f0];

/// Redirect a title's direct calls to the BIOS GD driver body to the loader's
/// `_gd_bios_entry` (`entry`), as isoldr's `gdc_syscall_patch` does. Windows CE
/// calls the body by address; the BIOS copy stays intact for the loader's own
/// use. Word-aligned literals only; a P2 literal stays P2.
pub fn gd_body_patches(buf: &[u8], address: u32, entry: u32) -> Vec<(u32, u32)> {
    let mut out = vec![];
    for (base, data) in payload_spans(buf, address) {
        for (i, w) in words(data) {
            if GD_DRIVER_BODY.contains(&w) {
                let redirected = (entry & 0x1fff_ffff) | (w & 0xe000_0000);
                out.push((p1(base).wrapping_add(i as u32), redirected));
            }
        }
    }
    out
}

/// Make a title read "VGA" from the cable check: the port read becomes `mov #0`.
///
/// Found by content: a `mov.l @(disp,PC),Rn` loading `PDTRA`, then a read
/// through `Rn` within a few instructions:
///
/// ```text
///   d3 03   mov.l  @(3,PC),r3   ; 0xff800030
///   92 03   mov.w  @(3,PC),r2   ; 0x0300
///   64 31   mov.w  @r3,r4       <- becomes `mov #0,r4` (e4 00)
/// ```
///
/// Patching the read covers however the caller masks it. It cannot add a 480p
/// mode the title does not have.
pub fn vga_cable_patches(buf: &[u8], address: u32) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = vec![];
    for (span_base, data) in payload_spans(buf, address) {
        let pool: Vec<usize> = words(data).filter(|&(_, w)| w == PDTRA).map(|(i, _)| i).collect();
        if pool.is_empty() {
            continue;
        }
        let at_of = |i: usize| p1(span_base).wrapping_add(i as u32);
        for i in (0..data.len().saturating_sub(1)).step_by(2) {
            let Some((reg, target)) = pc_load(le16(data, i), i) else {
                continue;
            };
            if !pool.contains(&target) {
                continue;
            }
            let mut done = false;
            // Stop after an `rts` and its delay slot.
            let mut last = CABLE_READ_WINDOW;
            for k in 1..=CABLE_READ_WINDOW {
                let at = i + k * 2;
                if at + 1 >= data.len() || k > last {
                    break;
                }
                let op = le16(data, at);
                // `mov.w @Rm,Rn` (0x6mn1) or `mov.l @Rm,Rn` (0x6mn2).
                if matches!(op & 0xf00f, 0x6001 | 0x6002) && (op >> 4) & 0xf == reg {
                    let dst = (op >> 8) & 0xf;
                    let mov_imm0 = 0xe000u16 | (dst << 8);
                    let aligned = at & !3;
                    let before = le32(data, aligned);
                    let after = if at & 2 == 0 {
                        (before & 0xffff_0000) | mov_imm0 as u32
                    } else {
                        (before & 0x0000_ffff) | ((mov_imm0 as u32) << 16)
                    };
                    info!(
                        "this title reads the cable type at 0x{:08x} (0x{PDTRA:08x} loaded \
                         into r{reg} at 0x{:08x}); it will read 0 -- VGA",
                        at_of(at),
                        at_of(i)
                    );
                    out.push((at_of(aligned), after));
                    done = true;
                    break;
                }
                if op == 0x000b {
                    last = k + 1;
                }
            }
            if !done {
                warn!(
                    "this title loads the cable-type register 0x{PDTRA:08x} at 0x{:08x} and \
                     then reads it in a shape this host does not recognise -- NOTHING was \
                     patched there, so it will see the cable that is really plugged in",
                    at_of(i)
                );
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// IP.BIN's peripheral field: ASCII hex at +0x38, bit 4 meaning "VGA box".
const IP_BIN_PERIPHERALS: std::ops::Range<usize> = 0x38..0x40;

/// Bit 4 of that word: "supports the VGA box".
pub const PERIPHERAL_VGA: u32 = 0x10;

/// The header's peripheral word, or `None` if the field is not hex.
pub fn ip_bin_peripherals(header: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(header.get(IP_BIN_PERIPHERALS)?).ok()?;
    u32::from_str_radix(text.trim(), 16).ok()
}

/// Set the VGA bit in an IP.BIN header, keeping the field's width. Read by
/// IP.BIN's own bootstrap and by titles that read the header back from RAM.
/// Returns the word before and after.
pub fn declare_vga_in_ip_bin(header: &mut [u8]) -> Option<(u32, u32)> {
    let before = ip_bin_peripherals(header)?;
    let after = before | PERIPHERAL_VGA;
    let width = std::str::from_utf8(&header[IP_BIN_PERIPHERALS])
        .ok()?
        .trim()
        .len();
    let text = format!("{after:0width$X}");
    if text.len() > IP_BIN_PERIPHERALS.len() {
        return None;
    }
    let mut field = [b' '; IP_BIN_PERIPHERALS.end - IP_BIN_PERIPHERALS.start];
    field[..text.len()].copy_from_slice(text.as_bytes());
    header[IP_BIN_PERIPHERALS].copy_from_slice(&field);
    Some((before, after))
}

/// `declare_vga_in_ip_bin`, logged.
pub(super) fn declare_vga_and_say_so(header: &mut [u8]) {
    match declare_vga_in_ip_bin(header) {
        Some((before, after)) if before != after => info!(
            "--vga: IP.BIN peripherals 0x{before:07X} -> 0x{after:07X}, declaring VGA box support"
        ),
        Some((before, _)) => {
            info!("--vga: IP.BIN already declares VGA box support (peripherals 0x{before:07X})")
        }
        None => warn!(
            "--vga: IP.BIN's peripheral field is not the hex string it should be; \
             leaving it as it is"
        ),
    }
}

/// Constants the title loads that name the part of the loader at `base` no
/// title should touch: `(address named, loading site)`.
///
/// A title can aim DMA (Maple, say) at an address it holds as a constant, which
/// overwrites the loader with nothing reported anywhere, so this is checked
/// before the title runs. A literal counts only when a `mov.l @(disp,PC)` loads it.
pub fn literals_in_loader_footprint(buf: &[u8], address: u32, base: u32) -> Vec<(u32, u32)> {
    loaded_literals_in(buf, address, &crate::loaders::exclusive_footprint(base))
}

/// Constants naming RAM inside `ranges` (P1, `hi` exclusive) that an
/// instruction loads: `(address named, loading site)`.
pub fn loaded_literals_in(buf: &[u8], address: u32, ranges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let spans = payload_spans(buf, address);
    if ranges.is_empty() {
        return vec![];
    }

    let mut out: Vec<(u32, u32)> = vec![];
    for (span_base, data) in spans {
        // Every aligned word naming RAM inside the ranges...
        let pool: HashMap<usize, u32> = words(data)
            .filter(|&(_, raw)| names_ram(raw))
            .map(|(i, raw)| (i, p1(raw)))
            .filter(|&(_, at)| ranges.iter().any(|&(lo, hi)| at >= lo && at < hi))
            .collect();
        if pool.is_empty() {
            continue;
        }
        // ...that a `mov.l @(disp,PC),Rn` loads.
        for i in (0..data.len().saturating_sub(1)).step_by(2) {
            if let Some((_, target)) = pc_load(le16(data, i), i)
                && let Some(&at) = pool.get(&target)
            {
                out.push((at, p1(span_base.wrapping_add(i as u32))));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// 64 KB-aligned RAM addresses above the load address that the image names
/// anywhere, as data or literals: where the title's own regions start (P1,
/// sorted). Not corroborated by a load, because titles keep region tables as
/// plain words (Shenmue II). Cached per image.
pub fn region_starts(buf: &[u8], address: u32) -> Vec<u32> {
    // Keyed by identity and a hash of the ends: a freed buffer's address can
    // be reused by the next image.
    type Key = (usize, usize, u32, u64);
    static CACHE: std::sync::Mutex<Option<(Key, Vec<u32>)>> = std::sync::Mutex::new(None);
    let tail = &buf[buf.len().saturating_sub(64)..];
    let taste = buf[..buf.len().min(64)]
        .iter()
        .chain(tail)
        .fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
    let key = (buf.as_ptr() as usize, buf.len(), address, taste);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((k, v)) = cache.as_ref()
        && *k == key
    {
        return v.clone();
    }
    let floor = p1(address);
    let mut out: Vec<u32> = payload_spans(buf, address)
        .into_iter()
        .flat_map(|(_, data)| words(data))
        .filter(|&(_, raw)| raw & 0xffff == 0 && names_ram(raw))
        .map(|(_, raw)| p1(raw))
        .filter(|&at| at > floor)
        .collect();
    out.sort_unstable();
    out.dedup();
    *cache = Some((key, out.clone()));
    out
}

/// RAM the title fills in a loop whose bounds are constants: `(lo, hi, site)`,
/// `hi` exclusive, P1, `site` the loop's first instruction.
///
/// The Katana crt0 paints 0x8c00c000..0x8c00f400 with "SEGA" before anything
/// else, which wipes a low loader. The shape matched, and nothing looser:
///
/// ```text
///     mov.l  @(disp,PC),Rx     up to four loads, immediately before the loop
/// L:  mov.{b,w,l} Rv,@Rp
///     add    #1|2|4,Rp         the store's size
///     cmp/hs Rend,Rp           (cmp/hi makes the bound inclusive)
///     bf     L
/// ```
///
/// A bound loaded and then dereferenced is a variable, not a range (how crt0
/// clears `.bss`), so the loads must be contiguous with the loop.
pub fn constant_range_fills(buf: &[u8], address: u32) -> Vec<(u32, u32, u32)> {
    let mut out = vec![];
    for (span_base, data) in payload_spans(buf, address) {
        let op = |i: usize| le16(data, i);
        for at in (0..data.len().saturating_sub(7)).step_by(2) {
            let store = op(at);
            let size = match store & 0xf00f {
                0x2000 => 1,
                0x2001 => 2,
                0x2002 => 4,
                _ => continue,
            };
            let rp = (store >> 8) & 0xf;
            let cmp = op(at + 4);
            let inclusive = match cmp & 0xf00f {
                0x3002 => false,
                0x3006 => true,
                _ => continue,
            };
            // add #size,Rp; cmp against Rp; bf back to the store.
            if op(at + 2) != 0x7000 | (rp << 8) | size
                || (cmp >> 8) & 0xf != rp
                || op(at + 6) != 0x8bfb
            {
                continue;
            }
            let rend = (cmp >> 4) & 0xf;
            let (mut lo, mut hi) = (None, None);
            for k in (1..=4).filter_map(|n| at.checked_sub(2 * n)) {
                let Some((reg, pool)) = pc_load(op(k), k) else {
                    break;
                };
                if pool + 4 > data.len() {
                    break;
                }
                let v = le32(data, pool);
                // Walking backwards, the first load of a register is the one
                // the loop sees.
                match reg {
                    r if r == rp && lo.is_none() => lo = Some(v),
                    r if r == rend && hi.is_none() => hi = Some(v),
                    _ => {}
                }
            }
            let (Some(lo), Some(hi)) = (lo, hi) else {
                continue;
            };
            if !names_ram(lo) || !names_ram(hi) {
                continue;
            }
            let (lo, hi) = (p1(lo), p1(hi) + if inclusive { size as u32 } else { 0 });
            if lo < hi {
                out.push((lo, hi, p1(span_base.wrapping_add(at as u32))));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Poke 32-bit words (little-endian) into the uploaded title, reading each one
/// back: a patch that cannot be shown to have landed is reported, loudly.
pub fn apply_patches(
    conn: &mut impl ExternalDcIo,
    patches: &[(u32, u32)],
) -> DcResult<()> {
    for &(addr, value) in patches {
        // Physical, never P2: P2 transfers longer than 8 bytes come back wrong
        // (see `selftest_readback`).
        let addr = phys(addr);
        let before = read_word(conn, addr);
        send_data(conn, &value.to_le_bytes(), addr, None)?;
        let after = read_word(conn, addr);

        match (before, after) {
            (_, Some(got)) if got == value => info!(
                "patch: 0x{addr:08x} = 0x{value:08x}, verified (was {})",
                before.map_or("unreadable".to_string(), |b| format!("0x{b:08x}"))
            ),
            (_, Some(got)) => error!(
                "PATCH DID NOT LAND: 0x{addr:08x} reads 0x{got:08x}, wanted 0x{value:08x}. \
                 Anything you conclude from this run is about an unpatched title."
            ),
            (_, None) => error!(
                "PATCH UNVERIFIABLE: 0x{addr:08x} could not be read back. \
                 Do not conclude anything from this run."
            ),
        }
    }
    Ok(())
}

/// KOS's `arch_stack_16m` and `arch_stack_32m` (`stack.c`), which `startup.S`
/// names through two consecutive pointers in its literal pool.
const KOS_STACK_16M: u32 = 0x8d00_0000;
const KOS_STACK_32M: u32 = 0x8e00_0000;

/// The two words that lower a KOS binary's top of RAM to `top`, keeping its
/// heap and stacks below a high loader. `arch_stack_32m` becomes the 16 MB
/// mirror of `top`, so the memory size test still answers 16 MB. `load` is
/// where `boot` is loaded (P1).
pub fn kos_mem_top_patches(boot: &[u8], load: u32, top: u32) -> Result<Vec<(u32, u32)>, String> {
    let word = |at: usize| boot.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    // The word a pointer names, if it names one inside the image.
    let named = |p: u32| {
        let off = p.wrapping_sub(load) as usize;
        (p & 3 == 0 && off < boot.len()).then(|| word(off)).flatten()
    };
    let found: Vec<(u32, u32)> = (0..boot.len().saturating_sub(7))
        .step_by(4)
        .filter_map(|at| {
            let (p16, p32) = (word(at)?, word(at + 4)?);
            (named(p16)? == KOS_STACK_16M && named(p32)? == KOS_STACK_32M).then_some((p16, p32))
        })
        .collect();
    match found[..] {
        [(p16, p32)] => Ok(vec![(p16, top), (p32, top.wrapping_add(0x0100_0000))]),
        [] => Err("no arch_stack_16m/arch_stack_32m pair in the literal pool".into()),
        _ => Err(format!("{} candidate arch_stack pairs, refusing to guess", found.len())),
    }
}

/// A KOS binary, recognised by the three consecutive aligned words `startup.S`
/// uses to look for dcload: `0x8c004004`, `0xdeadbeef`, `0x8c004008`.
pub fn is_kos_binary(boot: &[u8]) -> bool {
    let probe = [0x8c00_4004u32, DCLOAD_MAGIC, 0x8c00_4008];
    let all: Vec<u32> = words(boot).map(|(_, w)| w).collect();
    all.windows(3).any(|w| w == probe)
}

/// What a program tests at `DEFAULT_BASE + 4` to find dcload; `DEFAULT_BASE + 8`
/// holds the syscall pointer it then calls.
const DCLOAD_MAGIC: u32 = 0xdead_beef;

/// Make the dcload magic at `DEFAULT_BASE + 4` true for the loader at `base`.
///
/// Once the loader has moved, those words belong to the dead image the CD
/// booted. With `point_at_loader` they are pointed at the live loader (a
/// program without a disc, or a KOS title once the loader knows it is KOS);
/// otherwise the magic is cleared, as on a real boot.
pub fn update_dcload_magic(
    conn: &mut impl ExternalDcIo,
    base: u32,
    point_at_loader: bool,
) -> DcResult<()> {
    let stock = crate::loaders::DEFAULT_BASE;
    if (base & 0x1fff_ffff) == (stock & 0x1fff_ffff) {
        return Ok(());
    }
    let magic_at = stock + 4;
    if point_at_loader {
        let span = (base & 0x1fff_ffff)..(base & 0x1fff_ffff) + crate::loaders::LOADER_SPAN;
        match read_word(conn, phys(base + 8)) {
            Some(syscall) if span.contains(&(syscall & 0x1fff_ffff)) => {
                info!(
                    "dcload magic at 0x{magic_at:08x} pointed at the loader at 0x{base:08x} \
                     (syscalls -> 0x{syscall:08x}), not at the dead image the CD booted"
                );
                return apply_patches(conn, &[(magic_at + 4, syscall), (magic_at, DCLOAD_MAGIC)]);
            }
            got => warn!(
                "the loader at 0x{base:08x} does not report a syscall entry inside \
                 itself (read {}); clearing the dcload magic instead",
                got.map_or("nothing".to_string(), |w| format!("0x{w:08x}"))
            ),
        }
    }
    info!(
        "dcload magic at 0x{magic_at:08x} cleared: the loader is at 0x{base:08x}, and what \
         is left at 0x{stock:08x} is the dead image the CD booted"
    );
    apply_patches(conn, &[(magic_at, 0)])
}

/// One word read back from the console, `None` if it could not be read.
fn read_word(conn: &mut impl ExternalDcIo, addr: u32) -> Option<u32> {
    match receive_data(conn, Some(Duration::from_millis(500)), addr, 4, true) {
        Ok(b) if b.len() == 4 => Some(le32(&b, 0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kos_binary_is_known_by_its_dcload_probe() {
        let words = |ws: &[u32]| ws.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        let mut boot = words(&[0x0009_0009, 0x8c00_4004, 0xdead_beef, 0x8c00_4008, 0]);
        assert!(is_kos_binary(&boot));
        boot.insert(0, 0);
        assert!(!is_kos_binary(&boot), "unaligned");
        assert!(!is_kos_binary(&words(&[0x8c00_4004, 0xdead_beef])));
        assert!(!is_kos_binary(&words(&[0xdead_beef, 0x8c00_4004, 0x8c00_4008])));
        assert!(!is_kos_binary(&[]));
    }

    /// Both pool pointers are rewritten, the 32 MB one to the mirror of the new
    /// top; a lone pointer to 0x8d000000 is not the pair.
    #[test]
    fn a_kos_top_of_ram_is_found_through_startups_literal_pool() {
        let load = 0x8c01_0000;
        let words = |ws: &[u32]| ws.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        // 0: the pool (16m, 32m); 8: a lone pointer; 12, 16: the variables.
        let boot = words(&[load + 16, load + 12, load + 16, KOS_STACK_32M, KOS_STACK_16M]);
        let got = kos_mem_top_patches(&boot, load, 0x8cfe_8000).expect("found");
        assert_eq!(got, vec![(load + 16, 0x8cfe_8000), (load + 12, 0x8dfe_8000)]);
        assert!(kos_mem_top_patches(&words(&[load + 4, KOS_STACK_16M]), load, 0x8cfe_8000).is_err());
    }

    /// Needs `DCLOAD_TEST_KOS_BIN`: an unscrambled KOS binary loaded at 0x8c010000.
    #[test]
    fn a_real_kos_binary_has_one_top_of_ram() {
        let Ok(p) = std::env::var("DCLOAD_TEST_KOS_BIN") else { return };
        let boot = std::fs::read(p).expect("read");
        assert!(is_kos_binary(&boot));
        let got = kos_mem_top_patches(&boot, 0x8c01_0000, 0x8cfe_8000).expect("found");
        println!("{got:x?}");
        assert_eq!(got.len(), 2);
    }

    /// A raw image of `len` zero bytes with the given words set.
    fn raw(len: usize, words: &[(usize, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; len];
        for &(at, w) in words {
            b[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    #[test]
    fn signature_with_a_nearby_slot_window_is_neutralised() {
        let p = raw(0x1000, &[(0x100, 0xa100_1400), (0x348, GAPS_SIGNATURE)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c01_0000 + 0x348, 0xffff_ffff)]);
    }

    #[test]
    fn the_four_bytes_alone_are_not_enough() {
        let p = raw(0x1000, &[(0x348, GAPS_SIGNATURE)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched on the signature alone: {got:?}");
    }

    #[test]
    fn corroboration_must_be_near() {
        let p = raw(
            0x8000,
            &[(0x100, 0xa100_1400), (0x100 + GAPS_CORROBORATION_SPAN + 4, GAPS_SIGNATURE)],
        );
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "corroborated across {GAPS_CORROBORATION_SPAN}+ bytes: {got:?}");
    }

    #[test]
    fn a_slot_window_without_the_signature_is_left_alone() {
        let p = raw(0x1000, &[(0x100, 0xa100_1400)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty());
    }

    #[test]
    fn the_signature_must_be_aligned() {
        let p = raw(0x1000, &[(0x100, 0xa100_1400), (0x34a, GAPS_SIGNATURE)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "matched an unaligned occurrence: {got:?}");
    }

    /// A high base: image at 0x8cfe8000, stack top 0x8cff3000, `.hiram`
    /// 0x8cff4000, Maple 0x8cff5000.
    const HIGH_BASE: u32 = 0x8cfe_8000;

    /// `mov.l @(disp,PC),Rn` at `at`, reading the long at `pool`.
    fn mov_l_pc(at: usize, pool: usize, rn: u16) -> (usize, u16) {
        let disp = (pool - ((at + 4) & !3)) / 4;
        assert!(disp <= 0xff, "displacement out of range for a real load");
        (at, 0xd000 | (rn << 8) | disp as u16)
    }

    fn raw_ops(len: usize, words: &[(usize, u32)], ops: &[(usize, u16)]) -> Vec<u8> {
        let mut b = raw(len, words);
        for &(at, op) in ops {
            b[at..at + 2].copy_from_slice(&op.to_le_bytes());
        }
        b
    }

    #[test]
    fn a_constant_the_title_loads_into_the_loader_is_reported() {
        let p = raw_ops(
            0x1000,
            &[(0x200, 0x0cff_0000)],
            &[mov_l_pc(0x100, 0x200, 1)],
        );
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
        assert_eq!(got, vec![(0x8cff_0000, 0x8c01_0000 + 0x100)]);
    }

    #[test]
    fn a_constant_nothing_loads_is_ignored() {
        let p = raw(0x1000, &[(0x200, 0x0cff_0000)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
        assert!(got.is_empty(), "reported a literal nothing loads: {got:?}");
    }

    #[test]
    fn a_constant_outside_the_footprint_is_ignored() {
        let p = raw_ops(
            0x1000,
            &[(0x200, 0x0c80_0000)],
            &[mov_l_pc(0x100, 0x200, 1)],
        );
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
        assert!(got.is_empty(), "reported an address outside the loader: {got:?}");
    }

    #[test]
    fn the_same_address_is_seen_through_every_window() {
        for w in [0x0cff_0000u32, 0x8cff_0000, 0xacff_0000] {
            let p = raw_ops(0x1000, &[(0x200, w)], &[mov_l_pc(0x100, 0x200, 1)]);
            let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
            assert_eq!(got, vec![(0x8cff_0000, 0x8c01_0000 + 0x100)], "window 0x{w:08x}");
        }
    }

    /// At the stock base the loader shares the BIOS work area with every title.
    #[test]
    fn the_bios_work_area_a_low_loader_shares_is_not_reported() {
        let p = raw_ops(0x1000, &[(0x200, 0x8c00_8200)], &[mov_l_pc(0x100, 0x200, 1)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, 0x8c00_4000);
        assert!(got.is_empty(), "reported the shared BIOS work area: {got:?}");
    }

    /// ...but its high buffers are its own.
    #[test]
    fn a_low_loaders_high_buffers_are_still_reported() {
        let p = raw_ops(0x1000, &[(0x200, 0x0cfe_8800)], &[mov_l_pc(0x100, 0x200, 1)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, 0x8c00_4000);
        assert_eq!(got, vec![(0x8cfe_8800, 0x8c01_0000 + 0x100)]);
    }

    #[test]
    fn the_stock_low_base_does_not_see_sonic_adventure_2s_maple_buffer() {
        let p = raw_ops(0x1000, &[(0x200, 0x0cff_0000)], &[mov_l_pc(0x100, 0x200, 1)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, 0x8c00_4000);
        assert!(got.is_empty(), "the low base reported a high-RAM constant: {got:?}");
    }

    /// The Katana crt0's first loop: r5 = hi, r6 = "SEGA", r4 = lo, then
    /// `mov.l r6,@r4; add #4,r4; cmp/hs r5,r4; bf`. `between` breaks the
    /// contiguity of the loads.
    fn stack_paint(lo: u32, hi: u32, cmp: u16, between: Option<u16>) -> Vec<u8> {
        let loop_at = if between.is_some() { 0x108 } else { 0x106 };
        let mut ops = vec![
            mov_l_pc(0x100, 0x208, 5),
            mov_l_pc(0x102, 0x204, 6),
            mov_l_pc(0x104, 0x200, 4),
            (loop_at, 0x2462),
            (loop_at + 2, 0x7404),
            (loop_at + 4, cmp),
            (loop_at + 6, 0x8bfb),
        ];
        if let Some(op) = between {
            ops.push((0x106, op));
        }
        raw_ops(0x1000, &[(0x200, lo), (0x204, 0x4147_4553), (0x208, hi)], &ops)
    }

    #[test]
    fn the_katana_stack_paint_is_found() {
        let p = stack_paint(0x8c00_c000, 0x8c00_f400, 0x3452, None);
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c00_c000, 0x8c00_f400, 0x8c01_0106)]);
    }

    #[test]
    fn an_inclusive_bound_covers_the_last_store() {
        let p = stack_paint(0x8c00_c000, 0x8c00_f3fc, 0x3456, None);
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c00_c000, 0x8c00_f400, 0x8c01_0106)]);
    }

    #[test]
    fn a_bound_read_through_a_pointer_is_not_a_range() {
        let p = stack_paint(0x8c00_c000, 0x8c00_f400, 0x3452, Some(0x6442));
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert!(got.is_empty(), "reported a range held in a variable: {got:?}");
    }

    #[test]
    fn a_fill_outside_ram_is_ignored() {
        let p = stack_paint(0xa05f_8000, 0xa05f_8100, 0x3452, None);
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert!(got.is_empty(), "reported a fill of hardware registers: {got:?}");
    }

    /// The cable check as Katana titles carry it, at any 2-aligned `at`.
    fn cable_check(len: usize, at: usize) -> Vec<u8> {
        let pool = ((at + 4) & !3) + 12;
        let (_, load) = mov_l_pc(at, pool, 3);
        raw_ops(
            len,
            &[(pool, PDTRA)],
            &[
                (at, load),        // mov.l  @(3,PC),r3
                (at + 2, 0x9203),  // mov.w  @(3,PC),r2   ; 0x0300
                (at + 4, 0x6431),  // mov.w  @r3,r4
                (at + 6, 0x604d),  // extu.w r4,r0
                (at + 8, 0x000b),  // rts
                (at + 10, 0x2029), // and    r2,r0
            ],
        )
    }

    #[test]
    fn the_cable_read_becomes_mov_zero() {
        let p = cable_check(0x1000, 0x100);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c01_0104, 0x604d_e400)]);
    }

    #[test]
    fn a_read_in_the_high_half_of_a_word_keeps_the_low_one() {
        let p = cable_check(0x1000, 0x102);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c01_0104, 0xe400_9203)]);
    }

    #[test]
    fn a_port_address_nothing_loads_is_left_alone() {
        let p = raw(0x1000, &[(0x200, PDTRA)]);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched on the literal alone: {got:?}");
    }

    #[test]
    fn a_load_with_no_read_after_it_patches_nothing() {
        let pool = 0x110;
        let p = raw_ops(0x1000, &[(pool, PDTRA)], &[mov_l_pc(0x100, pool, 3)]);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched without finding the read: {got:?}");
    }

    #[test]
    fn the_read_must_use_the_register_the_address_went_into() {
        let mut p = cable_check(0x1000, 0x100);
        p[0x104..0x106].copy_from_slice(&0x6451u16.to_le_bytes()); // mov.w @r5,r4
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched a read of another register: {got:?}");
    }

    /// An IP.BIN header whose peripheral field reads `text`.
    fn header_with(text: &[u8]) -> Vec<u8> {
        let mut h = vec![b' '; 0x100];
        h[..16].copy_from_slice(b"SEGA SEGAKATANA ");
        h[0x38..0x38 + text.len()].copy_from_slice(text);
        h
    }

    #[test]
    fn the_vga_bit_is_set_and_the_field_keeps_its_width() {
        let mut h = header_with(b"0799A00");
        assert_eq!(declare_vga_in_ip_bin(&mut h), Some((0x0079_9A00, 0x0079_9A10)));
        assert_eq!(&h[0x38..0x40], b"0799A10 ");
    }

    #[test]
    fn a_title_that_already_declares_vga_is_unchanged() {
        let mut h = header_with(b"0601A10");
        let before = h[0x38..0x40].to_vec();
        assert_eq!(declare_vga_in_ip_bin(&mut h), Some((0x0060_1A10, 0x0060_1A10)));
        assert_eq!(h[0x38..0x40], before[..]);
    }

    #[test]
    fn a_field_that_is_not_hex_is_refused() {
        let mut h = header_with(b"NOT HEX");
        assert_eq!(ip_bin_peripherals(&h), None);
        assert_eq!(declare_vga_in_ip_bin(&mut h), None);
        assert_eq!(&h[0x38..0x40], b"NOT HEX ");
    }

    #[test]
    fn direct_driver_calls_are_redirected_and_keep_their_segment() {
        let mut p = vec![0u8; 64];
        p[8..12].copy_from_slice(&0x8c00_10f0u32.to_le_bytes());
        p[20..24].copy_from_slice(&0xac00_10f0u32.to_le_bytes());
        // Unaligned: code, not a literal.
        p[34..38].copy_from_slice(&0x8c00_10f0u32.to_le_bytes());
        let got = gd_body_patches(&p, 0x0c01_0000, 0x8c8a_4400);
        assert_eq!(got, vec![(0x8c01_0008, 0x8c8a_4400), (0x8c01_0014, 0xac8a_4400)]);
    }

    #[test]
    fn a_title_without_the_literal_is_left_alone() {
        let mut p = vec![0u8; 64];
        p[8..12].copy_from_slice(&0x8c00_00bcu32.to_le_bytes());
        assert!(gd_body_patches(&p, 0x0c01_0000, 0x8c8a_4400).is_empty());
    }
}
