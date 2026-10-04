//! Loader variants and the footprint of a running loader.
//!
//! `make loaders` (target-src/dcload, AGENTS.md 4.18) builds, next to the
//! universal `dcload-relocatable.elf`, one image per network driver, kind of
//! title and CD-DA -- `dcload-{bba,lan}-{katana,kos,wince}-{cdda,nocdda}.elf`
//! (RESIDENT: no screen, no DHCP) -- and two CORE images,
//! `dcload-core-{bba,lan}-katana.elf`, pinned at 0x8c004000 with everything in
//! the system hole under 0x8c00c000 (4.19). This module names them, reads which
//! one is running from the VERS reply's variant word, chooses one for a title
//! and works out the RAM a running loader owns from its own ELF.

use std::sync::Mutex;

use crate::loaders;

/// The network driver the console has, from VERS's `address` field
/// (`installed_adapter`: the octal 0300 / 0400 of dcload.h).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Driver {
    Bba,
    Lan,
}

impl Driver {
    pub fn from_installed(code: u32) -> Option<Self> {
        match code {
            0o400 => Some(Self::Bba),
            0o300 => Some(Self::Lan),
            _ => None,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Bba => "bba",
            Self::Lan => "lan",
        }
    }
}

/// The kind of title a variant serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Os {
    Katana,
    Kos,
    Wince,
}

impl Os {
    fn tag(self) -> &'static str {
        match self {
            Self::Katana => "katana",
            Self::Kos => "kos",
            Self::Wince => "wince",
        }
    }
}

/// One loader image of the variant set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Variant {
    pub driver: Driver,
    pub os: Os,
    pub cdda: bool,
    /// The CORE image: pinned at 0x8c004000, Katana only, never relocated.
    pub core: bool,
}

impl Variant {
    pub fn file_name(&self) -> String {
        if self.core {
            format!("dcload-core-{}-{}.elf", self.driver.tag(), self.os.tag())
        } else {
            format!(
                "dcload-{}-{}-{}.elf",
                self.driver.tag(),
                self.os.tag(),
                if self.cdda { "cdda" } else { "nocdda" }
            )
        }
    }

    /// For the log.
    pub fn label(&self) -> String {
        self.file_name().trim_end_matches(".elf").to_string()
    }

    /// The inverse of `file_name`.
    #[cfg(test)]
    pub fn parse(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("dcload-")?.strip_suffix(".elf")?;
        let mut it = rest.split('-');
        let first = it.next()?;
        let (core, driver) = if first == "core" {
            (true, it.next()?)
        } else {
            (false, first)
        };
        let driver = match driver {
            "bba" => Driver::Bba,
            "lan" => Driver::Lan,
            _ => return None,
        };
        let os = match it.next()? {
            "katana" => Os::Katana,
            "kos" => Os::Kos,
            "wince" => Os::Wince,
            _ => return None,
        };
        let cdda = if core {
            false
        } else {
            match it.next()? {
                "cdda" => true,
                "nocdda" => false,
                _ => return None,
            }
        };
        it.next().is_none().then_some(Variant { driver, os, cdda, core })
    }
}

/// What VERS's variant word says about the running build (cmd_version).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VariantWord {
    /// 0 LOW, 1 HIGH, 2 CORE.
    pub layout: u8,
    /// 0 all, 1 Katana, 2 KOS, 3 Windows CE.
    pub os: u8,
    pub cdda: bool,
    pub bba: bool,
    pub lan: bool,
    pub mark: bool,
    pub disc: bool,
    pub resident: bool,
}

impl VariantWord {
    /// `None` when the marker byte is not there: an older loader.
    pub fn from_word(w: u32) -> Option<Self> {
        if w >> 24 != 0xA5 {
            return None;
        }
        let bit = |n: u32| w >> n & 1 != 0;
        Some(VariantWord {
            layout: (w & 15) as u8,
            os: (w >> 4 & 15) as u8,
            cdda: bit(8),
            bba: bit(9),
            lan: bit(10),
            mark: bit(11),
            disc: bit(12),
            resident: bit(13),
        })
    }

    pub fn is_core(&self) -> bool {
        self.layout == 2
    }
}

/// What the host knows about the title when it picks a loader.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TitleFacts {
    pub kos: bool,
    pub wince: bool,
    /// The disc has audio tracks, and CD-DA was not switched off.
    pub audio: bool,
}

impl TitleFacts {
    pub fn os(&self) -> Os {
        if self.wince {
            Os::Wince
        } else if self.kos {
            Os::Kos
        } else {
            Os::Katana
        }
    }
}

/// The variant for a title: the matching image of the set. `core` asks for the
/// CORE image (Katana only; the caller has decided it is eligible).
pub fn pick_variant(driver: Driver, facts: &TitleFacts, core: bool) -> Variant {
    if core {
        Variant { driver, os: Os::Katana, cdda: false, core: true }
    } else {
        Variant { driver, os: facts.os(), cdda: facts.audio, core: false }
    }
}

/// Which family a footprint belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Low,
    High,
    Core,
}

/// The RAM one loader image owns, read off the image's own symbols so the host
/// does not carry a table that a new layout would leave stale.
///
/// For the LOW and HIGH families this is exactly `loaders::live_footprint` of
/// the image's base (a test holds the two together); for the CORE family it is
/// the resident core, minus the IP.BIN hole, plus the pre-EXEC buffer and
/// stack under the system area a title paints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Footprint {
    pub family: Family,
    pub base: u32,
    /// What survives under a running title.
    pub resident: Vec<(u32, u32)>,
    /// What only the loader's own start-up uses (the CORE's Maple buffer and
    /// main-loop stack): free for the title once it runs.
    pub pre_exec: Vec<(u32, u32)>,
    /// The part no title has business addressing (see `exclusive_footprint`).
    pub exclusive: Vec<(u32, u32)>,
    /// The top of everything resident (`_end`).
    pub resident_end: u32,
    /// Bytes at 0x8c008000 the host may write (the IP.BIN header): 0 when the
    /// loader's image covers them, 2048 for a loader that is out of the hole.
    pub ipbin_room: u32,
}

impl Footprint {
    /// Everything an upload must not touch while this loader runs.
    pub fn live(&self) -> Vec<(u32, u32)> {
        let mut v = self.resident.clone();
        v.extend(self.pre_exec.iter().copied());
        v
    }

    pub fn is_core(&self) -> bool {
        self.family == Family::Core
    }
}

/// The footprint of a loader image (relocated or pinned).
pub fn footprint_from_elf(bytes: &[u8]) -> Result<Footprint, String> {
    let syms = loaders::symbols(bytes)?;
    let val = |n: &str| {
        syms.get(n)
            .map(|&(v, _)| v)
            .ok_or_else(|| format!("the loader ELF has no `{n}` symbol"))
    };
    let base = val("dcload_base")?;
    let end = val("end")?;
    if syms.get("dcload_layout").map(|&(v, _)| v) == Some(2) {
        let (hole_lo, hole_hi) = (val("_ipbin_hole_start")?, val("_ipbin_hole_end")?);
        let (maple, stack) = (val("maple_dma_buffer")?, val("stack")?);
        return Ok(Footprint {
            family: Family::Core,
            base,
            resident: vec![(base, hole_lo), (hole_hi, end)],
            pre_exec: vec![(maple, stack)],
            exclusive: Vec::new(),
            resident_end: end,
            ipbin_room: hole_hi - hole_lo,
        });
    }
    Ok(Footprint {
        family: if loaders::is_high(base) { Family::High } else { Family::Low },
        base,
        resident: loaders::live_footprint(base),
        pre_exec: Vec::new(),
        exclusive: loaders::exclusive_footprint(base),
        resident_end: end,
        ipbin_room: if loaders::is_high(base) { 2048 } else { 0 },
    })
}

/// Is this ELF a CORE image?
pub fn is_core_image(bytes: &[u8]) -> bool {
    loaders::symbols(bytes)
        .ok()
        .and_then(|s| s.get("dcload_layout").map(|&(v, _)| v))
        == Some(2)
}

/// The loader now in control, when it is a CORE (the only case where the
/// footprint is not the one `loaders::layout()` describes): set once after a
/// chainload (or recognised from VERS), read by every check that used
/// `live_footprint(base)` at run time -- the disc-read destination test, the
/// memory marks, the IP.BIN write, the hop planner.
static ACTIVE: Mutex<Option<Footprint>> = Mutex::new(None);

pub fn set_active(fp: Option<Footprint>) {
    *ACTIVE.lock().unwrap() = fp.filter(Footprint::is_core);
}

fn active_for(base: u32) -> Option<Footprint> {
    ACTIVE.lock().unwrap().clone().filter(|f| f.base == base)
}

/// A core is running at `base`.
pub fn core_running(base: u32) -> bool {
    active_for(base).is_some()
}

/// `loaders::live_footprint`, but true to a CORE running at `base`.
pub fn live_ranges(base: u32) -> Vec<(u32, u32)> {
    active_for(base).map_or_else(|| loaders::live_footprint(base), |f| f.live())
}

/// What survives under the running title (the disc-read destination test).
pub fn under_title_ranges(base: u32) -> Vec<(u32, u32)> {
    active_for(base).map_or_else(|| loaders::live_footprint(base), |f| f.resident)
}

/// `loaders::exclusive_footprint`, empty for a CORE (nothing of it is in RAM
/// a title owns outright).
pub fn exclusive_ranges(base: u32) -> Vec<(u32, u32)> {
    active_for(base).map_or_else(|| loaders::exclusive_footprint(base), |f| f.exclusive)
}

/// How much of the IP.BIN header sector the running loader leaves room for.
pub fn ipbin_room(base: u32) -> u32 {
    match active_for(base) {
        Some(f) => f.ipbin_room,
        None if loaders::is_high(base) => 2048,
        None => 0,
    }
}

/// Write the loader's own address and syscall port into the image, where its
/// `.data` keeps them (`our_ip`, `dcload_syscall_port`): a resident loader has
/// no DHCP and no start-up screen, and the host knows both numbers.
///
/// `our_ip` holds the address as the number a.b.c.d (what `ntohl` of a
/// packet's destination gives), and `set_ip_from_file` leaves an address whose
/// top octet is set alone. The port is the host's view of the loader's own.
pub fn patch_resident(bytes: &mut [u8], ip: [u8; 4], port: u16) -> Result<(), String> {
    let syms = loaders::symbols(bytes)?;
    let mut put = |name: &str, value: &[u8]| -> Result<(), String> {
        let (addr, _) = *syms
            .get(name)
            .ok_or_else(|| format!("the loader ELF has no `{name}` symbol"))?;
        let off = file_offset(bytes, addr)
            .ok_or_else(|| format!("`{name}` (0x{addr:08x}) is not in an uploaded section"))?;
        bytes[off..off + value.len()].copy_from_slice(value);
        Ok(())
    };
    put("our_ip", &u32::from_be_bytes(ip).to_le_bytes())?;
    put("dcload_syscall_port", &port.to_le_bytes())?;
    Ok(())
}

/// Where a loaded (PROGBITS) address sits in the ELF file.
fn file_offset(bytes: &[u8], addr: u32) -> Option<usize> {
    use elf::{ElfBytes, endian::AnyEndian};
    let elf = ElfBytes::<AnyEndian>::minimal_parse(bytes).ok()?;
    let (headers, _) = elf.section_headers_with_strtab().ok()?;
    headers?.iter().find_map(|sh| {
        (loaders::is_uploadable(&sh)
            && (sh.sh_addr as u32..(sh.sh_addr + sh.sh_size) as u32).contains(&addr))
        .then(|| (sh.sh_offset as u32 + (addr - sh.sh_addr as u32)) as usize)
    })
}

/// CORE choice for a title, with the reason either way (logged by the caller).
///
/// The core is where a title that fills high RAM cannot reach it, and the
/// price is the stack: a Katana title uses the BIOS work area as a stack
/// (AGENTS.md 4.6), and a core ends at `resident_end`. So it is only chosen on
/// evidence, as the stock base is: a stack depth recorded by an earlier session
/// (`sp_min`) that clears the core, and a startup that does not paint it.
#[allow(clippy::too_many_arguments)]
pub fn core_verdict(
    facts: &TitleFacts,
    resident_end: u32,
    sp_min: Option<u32>,
    painted: Option<String>,
    high_busy: Option<u32>,
    forced: bool,
) -> Result<(), String> {
    if facts.kos || facts.wince {
        return Err("the core serves Katana titles only".into());
    }
    if facts.audio && !forced {
        return Err("the disc has audio tracks and the core has no CD-DA (--loader-core forces it)".into());
    }
    if let Some(why) = painted {
        return Err(why);
    }
    match sp_min {
        None if !forced => {
            return Err(
                "no stack depth recorded for this title yet: a core is only chosen once a \
                 session has read one back (--loader-core forces it)"
                    .into(),
            );
        }
        Some(sp) if !stack_clears(resident_end, sp) => {
            return Err(format!(
                "this title has been seen entering GD syscalls with SP 0x{sp:08x}, under \
                 4 KB above the core's top 0x{resident_end:08x}"
            ));
        }
        _ => {}
    }
    if !forced {
        match high_busy {
            Some(blocks) if blocks >= HIGH_BUSY_BLOCKS => {}
            Some(blocks) => {
                return Err(format!(
                    "its learned map uses only {blocks} of the top 64 blocks of RAM \
                     (needs {HIGH_BUSY_BLOCKS}): a high loader is safe enough"
                ));
            }
            None => {
                return Err("no memory map recorded for this title: a high loader stands".into());
            }
        }
    }
    Ok(())
}

/// How many of the top 64 blocks (64 KB each, 0x8cc00000..0x8d000000) a title's
/// learned map has to use before the core is preferred to a high loader.
pub const HIGH_BUSY_BLOCKS: u32 = 24;

/// Does a stack seen as low as `sp` clear a core ending at `end` by the margin
/// the LOW base uses? Addresses in physical form: a title's stack may be seen
/// in P0 (0x0cb06ca4: Shenmue II keeps it in high RAM) or P1.
pub fn stack_clears(end: u32, sp: u32) -> bool {
    let phys = |a: u32| a & 0x1fff_ffff;
    let (sp, end) = (phys(sp), phys(end));
    sp >= 0x0c01_0000 || sp.saturating_sub(end) >= loaders::LOW_BASE_MIN_MARGIN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_names_round_trip() {
        for driver in [Driver::Bba, Driver::Lan] {
            for os in [Os::Katana, Os::Kos, Os::Wince] {
                for cdda in [true, false] {
                    let v = Variant { driver, os, cdda, core: false };
                    assert_eq!(Variant::parse(&v.file_name()), Some(v), "{}", v.file_name());
                }
            }
            let c = Variant { driver, os: Os::Katana, cdda: false, core: true };
            assert_eq!(c.file_name(), format!("dcload-core-{}-katana.elf", driver.tag()));
            assert_eq!(Variant::parse(&c.file_name()), Some(c));
        }
        assert_eq!(Variant::parse("dcload-relocatable.elf"), None);
        assert_eq!(Variant::parse("dcload-0x8c004000.elf"), None);
    }

    #[test]
    fn the_variant_word_reads_what_the_loader_builds() {
        // HIGH, Katana, no CD-DA, BBA, MARK, DISC, resident.
        let w = 0xA500_0000u32 | 1 | (1 << 4) | 1 << 9 | 1 << 11 | 1 << 12 | 1 << 13;
        let v = VariantWord::from_word(w).unwrap();
        assert_eq!((v.layout, v.os), (1, 1));
        assert!(v.bba && !v.lan && !v.cdda && v.mark && v.disc && v.resident);
        assert!(!v.is_core());
        assert!(VariantWord::from_word(0xA500_0002).unwrap().is_core());
        assert_eq!(VariantWord::from_word(0x0000_0102), None);
    }

    #[test]
    fn the_adapter_comes_from_the_octal_models() {
        assert_eq!(Driver::from_installed(0o400), Some(Driver::Bba));
        assert_eq!(Driver::from_installed(0o300), Some(Driver::Lan));
        assert_eq!(Driver::from_installed(0), None);
    }

    #[test]
    fn a_variant_follows_the_title() {
        let f = TitleFacts { kos: true, ..Default::default() };
        assert_eq!(pick_variant(Driver::Lan, &f, false).file_name(), "dcload-lan-kos-nocdda.elf");
        let f = TitleFacts { wince: true, audio: true, ..Default::default() };
        assert_eq!(pick_variant(Driver::Bba, &f, false).file_name(), "dcload-bba-wince-cdda.elf");
        assert_eq!(
            pick_variant(Driver::Bba, &TitleFacts::default(), true).file_name(),
            "dcload-core-bba-katana.elf"
        );
    }

    #[test]
    fn a_stack_in_high_ram_clears_a_core_and_sonic_adventures_does_not() {
        // Shenmue II: seen in P0 high RAM. Crazy Taxi 2 likewise.
        assert!(stack_clears(0x8c00_b960, 0x0cb0_6ca4));
        assert!(stack_clears(0x8c00_b960, 0x0c17_50ec));
        // Snow Surfers: 0x8c00e460 over a core ending 0x8c00b960.
        assert!(stack_clears(0x8c00_b960, 0x8c00_e460));
        // Sonic Adventure: 0x8c00b91c, under the core's own end.
        assert!(!stack_clears(0x8c00_b960, 0x8c00_b91c));
        assert!(!stack_clears(0x8c00_b960, 0x8c00_acac));
    }

    #[test]
    fn the_core_needs_evidence_unless_it_is_forced() {
        let katana = TitleFacts::default();
        let ok = |sp, high, forced| core_verdict(&katana, 0x8c00_b960, sp, None, high, forced);
        assert!(ok(Some(0x0cb0_6ca4), Some(40), false).is_ok());
        assert!(ok(None, Some(40), false).is_err(), "no recorded stack depth");
        assert!(ok(Some(0x0cb0_6ca4), Some(3), false).is_err(), "a quiet title stays high");
        assert!(ok(Some(0x0cb0_6ca4), None, false).is_err(), "no map recorded");
        assert!(ok(None, None, true).is_ok(), "forced");
        assert!(ok(Some(0x8c00_b91c), Some(60), true).is_err(), "even forced, a stack under the core");
        let audio = TitleFacts { audio: true, ..Default::default() };
        assert!(core_verdict(&audio, 0x8c00_b960, Some(0x0cb0_6ca4), None, Some(40), false).is_err());
        let kos = TitleFacts { kos: true, ..Default::default() };
        assert!(core_verdict(&kos, 0x8c00_b960, Some(0x0cb0_6ca4), None, Some(40), true).is_err());
    }

    #[test]
    fn a_core_footprint_leaves_the_ipbin_hole_alone() {
        set_active(Some(Footprint {
            family: Family::Core,
            base: 0x8c00_4000,
            resident: vec![(0x8c00_4000, 0x8c00_8000), (0x8c00_8200, 0x8c00_b960)],
            pre_exec: vec![(0x8c00_c000, 0x8c00_f400)],
            exclusive: vec![],
            resident_end: 0x8c00_b960,
            ipbin_room: 0x200,
        }));
        let hits = |lo: u32, hi: u32| {
            under_title_ranges(0x8c00_4000)
                .iter()
                .any(|&(a, b)| lo < b && a < hi)
        };
        assert!(!hits(0x8c00_8000, 0x8c00_8200), "the header's room");
        assert!(hits(0x8c00_8000, 0x8c00_8800), "past the room");
        assert!(!hits(0x8cfe_8000, 0x8d00_0000), "nothing in high RAM");
        assert!(!hits(0x8c01_0000, 0x8ce0_0000), "the title's own ground");
        assert_eq!(ipbin_room(0x8c00_4000), 0x200);
        assert!(live_ranges(0x8c00_4000).contains(&(0x8c00_c000, 0x8c00_f400)));
        set_active(None);
        assert_eq!(ipbin_room(0x8c00_4000), 0);
        assert!(under_title_ranges(0x8c00_4000).contains(&(0x8cfe_8000, 0x8cfe_9000 + loaders::HIRAM_RESERVED)));
    }

    /// With `DCLOAD_LOADER_DIR` naming a freshly built set: every variant
    /// relocates to the bases it is for, its footprint equals what `layout()`
    /// says, and the core is the hole-aware one.
    #[test]
    fn the_built_variants_have_the_footprints_the_host_assumes() {
        let Ok(dir) = std::env::var("DCLOAD_LOADER_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let mut seen = 0;
        for driver in [Driver::Bba, Driver::Lan] {
            for os in [Os::Katana, Os::Kos, Os::Wince] {
                for cdda in [true, false] {
                    let v = Variant { driver, os, cdda, core: false };
                    let Ok(bytes) = std::fs::read(dir.join(v.file_name())) else {
                        continue;
                    };
                    seen += 1;
                    for base in [0x8ce0_0000u32, 0x8cee_0000, 0x8cfe_0000] {
                        let moved = loaders::relocate(&bytes, base).unwrap();
                        let fp = footprint_from_elf(&moved).unwrap();
                        assert_eq!(fp.family, Family::High);
                        assert_eq!(fp.resident, loaders::live_footprint(base), "{}", v.label());
                        assert!(fp.resident_end > base && fp.resident_end < loaders::layout(base).stack);
                    }
                }
            }
            let c = Variant { driver, os: Os::Katana, cdda: false, core: true };
            let Ok(bytes) = std::fs::read(dir.join(c.file_name())) else {
                continue;
            };
            seen += 1;
            let fp = footprint_from_elf(&bytes).unwrap();
            assert_eq!(fp.family, Family::Core);
            assert_eq!(fp.base, 0x8c00_4000);
            assert_eq!(fp.resident[0], (0x8c00_4000, 0x8c00_8000));
            assert_eq!(fp.resident[1].0, 0x8c00_8200);
            assert!(fp.resident_end <= 0x8c00_c000, "0x{:08x}", fp.resident_end);
            assert_eq!(fp.pre_exec, vec![(0x8c00_c000, 0x8c00_f400)]);
            assert_eq!(fp.ipbin_room, 0x200);
            // pinned: it does not move, and "moving" it to where it is changes nothing
            assert!(loaders::relocate(&bytes, 0x8ce0_0000).is_err());
            assert_eq!(loaders::relocate(&bytes, 0x8c00_4000).unwrap(), bytes);
        }
        let mut patched = std::fs::read(dir.join(
            Variant { driver: Driver::Bba, os: Os::Katana, cdda: false, core: false }.file_name(),
        ))
        .unwrap_or_default();
        if !patched.is_empty() {
            patch_resident(&mut patched, [192, 168, 1, 64], 53535).unwrap();
            let syms = loaders::symbols(&patched).unwrap();
            let at = file_offset(&patched, syms["our_ip"].0).unwrap();
            assert_eq!(&patched[at..at + 4], &0xc0a8_0140u32.to_le_bytes());
            let at = file_offset(&patched, syms["dcload_syscall_port"].0).unwrap();
            assert_eq!(&patched[at..at + 2], &53535u16.to_le_bytes());
        }
        assert!(seen > 0, "DCLOAD_LOADER_DIR holds no variants");
    }
}
