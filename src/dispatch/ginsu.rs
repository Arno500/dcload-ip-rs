//! Ginsu: a boot loader that is not the title.
//!
//! Some titles boot a small 1ST_READ.BIN of Sega's "Ginsu" library (Pro Pinball
//! Trilogy, Unreal Tournament NTSC): it reads GINSU.INI, loads the program the
//! `[GINSU]` section's `FirstApp` names off the disc, copies it to 0x8c010000
//! (through GINXFER.BIN) and runs it. Everything this host learns from a boot
//! binary -- the title's network driver, its expansion-port probe, its heap --
//! is then in that program, which it never uploads.
//!
//! Unreal Tournament NTSC (2026-10-12): its 1ST_READ.BIN is 166 KB, its
//! program UTDC.BIN 2.6 MB, stored plain, linked at 0x8c010000, carrying the
//! same ETD driver as the PAL 1ST_READ.BIN. Served as it was, its driver reset
//! the adapter under the loader the moment the program started: silence after
//! the last read of UTDC.BIN.
//!
//! So the program is read here, examined as a boot binary is, and its words are
//! changed in the sectors served (`DiscPatch`): the copy GINXFER makes carries
//! them, wherever Ginsu reads the file to first.
//!
//! WHERE GINSU READS THEM DECIDES WHERE THE LOADER GOES. Its file system works
//! at `GINSU_TOP` (0x8cfe0000, with its directory at 0x8cff0000); it reads
//! GINXFER.BIN to the 64 KB boundary under that minus its size, and the program
//! to the 64 KB boundary under GINXFER minus the program's (1ST_READ.BIN
//! 0x8c010794, measured: UTDC.BIN's 2609020 bytes at 0x8cd50000..0x8cfcd000,
//! GINXFER at 0x8cfd0000). Everything from the program up is Ginsu's while it
//! runs. Placed at the top of UTDC.BIN's heap (0x8cfc0000) the loader refused
//! the program's read and Ginsu went back to the BIOS menu; at 0x8cfd0000 it
//! refused GINXFER's. So the loader goes at the bottom of the program's heap,
//! the heap started above it (`GinsuApp::heap_bottom`), or failing that right
//! under the program (`GinsuApp::loader_base`), the heap ending there.
//!
//! A CONFIGURATION IN THE BOOT LOADER (NBA 2K2 PAL, 2026-10-15). No GINSU.INI:
//! the 1ST_READ.BIN carries a `SNIG` block (0x8c06fb00) naming
//! `\manifest.bin` and `\ginxfer.bin`, neither on the disc; Ginsu falls back
//! to JOHNNIE.BIN, a name in its code (0x8c062cac), and the program is chosen
//! in code by the console's language among MAIN.BIN, MAINF.BIN, MAING.BIN and
//! MAINS.BIN (a table at 0x8c068530), each 7.3 MB. Measured on the console:
//! MAIN.BIN read to 0x8c8d0000..0x8cfc8dc4, then nothing with the loader at
//! 0x8cfd0000 (JOHNNIE.BIN's read refused), a reset at Start with it at
//! 0x8cfe0000 (the file system's work area). So the programs are the `.BIN`
//! files the boot loader names that set up a heap, all of them patched; the
//! transfer program, when the one named is missing, is taken to fit the 64 KB
//! under `GINSU_TOP`.

use super::DiscPatch;
use crate::disc_formats::{iso9660, types::DiscFormat};

/// Where Katana programs, and so the program Ginsu runs, are linked.
pub const GINSU_APP_LOAD: u32 = 0x8c01_0000;

/// What Ginsu reads its programs under: its file system's work area.
pub const GINSU_TOP: u32 = 0x8cfe_0000;

/// The transfer program `Ginsu.XferExecutable` names when it names none.
const GINSU_XFER_DEFAULT: &str = "GINXFER.BIN";

/// A Ginsu configuration built into the boot loader, when the disc has no
/// GINSU.INI: its magic, and where in it the transfer program's path is.
const SNIG: &[u8; 8] = b"SNIG\x01\0\0\0";
const SNIG_XFER: usize = 0x80;
/// A path field of that block.
const SNIG_PATH: usize = 0x40;

/// The transfer program's size when the one named is not on the disc: Ginsu
/// then runs one of its own choosing (NBA 2K2's JOHNNIE.BIN, 8436 bytes),
/// read to the 64 KB under `GINSU_TOP` like any that fits there.
const GINSU_XFER_UNKNOWN: u32 = 0x1_0000;

/// The program a Ginsu boot loader runs, as it is on the disc.
#[derive(Clone, Debug)]
pub struct GinsuApp {
    /// Its file name in the root directory.
    pub name: String,
    /// Its first sector, as `read_sector` takes it.
    pub lba: u32,
    pub bytes: Vec<u8>,
    /// GINXFER.BIN's size: Ginsu reads it above the program.
    pub xfer_size: u32,
    /// The other programs Ginsu may run instead, chosen at run time (NBA
    /// 2K2: one per language); each is patched like this one.
    pub variants: Vec<GinsuApp>,
}

/// The file the `[GINSU]` section's `FirstApp` runs: the `Command` of the
/// section that names, without its leading `\`. `None` for anything else.
pub fn first_app_command(ini: &str) -> Option<String> {
    let mut section = String::new();
    let mut first: Option<String> = None;
    let mut commands: Vec<(String, String)> = vec![];
    for line in ini.lines() {
        let line = line.trim();
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.trim().to_ascii_uppercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let (key, value) = (key.trim(), value.trim());
        if section == "GINSU" && key.eq_ignore_ascii_case("Ginsu.FirstApp") {
            first = Some(value.to_ascii_uppercase());
        } else if key.eq_ignore_ascii_case("Ginsu.Command") {
            commands.push((section.clone(), value.trim_start_matches('\\').to_string()));
        }
    }
    let first = first?;
    commands.into_iter().find(|(s, _)| *s == first).map(|(_, c)| c).filter(|c| !c.is_empty())
}

/// The `[GINSU]` section's `Ginsu.XferExecutable`, without its leading `\`.
pub fn xfer_command(ini: &str) -> Option<String> {
    let mut section = String::new();
    for line in ini.lines() {
        let line = line.trim();
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.trim().to_ascii_uppercase();
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && section == "GINSU"
            && key.trim().eq_ignore_ascii_case("Ginsu.XferExecutable")
        {
            return Some(value.trim().trim_start_matches('\\').to_string()).filter(|v| !v.is_empty());
        }
    }
    None
}

fn ginsu_ini(disc: &dyn DiscFormat) -> Option<String> {
    let ini = iso9660::find_in_root(disc, disc.boot_sector(), "GINSU.INI")?;
    let text = iso9660::read_file(disc, &ini).ok()?;
    Some(String::from_utf8_lossy(&text).into_owned())
}

/// The name of the program a Ginsu boot runs, if this disc boots one.
pub fn ginsu_app_name(disc: &dyn DiscFormat) -> Option<String> {
    match ginsu_ini(disc) {
        Some(ini) => first_app_command(&ini),
        None => built_in_ginsu(disc).map(|a| a.name),
    }
}

/// The program a Ginsu boot runs, read off the disc.
pub fn ginsu_app(disc: &dyn DiscFormat) -> Option<GinsuApp> {
    let Some(ini) = ginsu_ini(disc) else {
        return built_in_ginsu(disc);
    };
    let name = first_app_command(&ini)?;
    let xfer = xfer_command(&ini).unwrap_or_else(|| GINSU_XFER_DEFAULT.to_string());
    let xfer_size = iso9660::find_in_root(disc, disc.boot_sector(), &xfer)?.size;
    let e = iso9660::find_in_root(disc, disc.boot_sector(), &name)?;
    let bytes = iso9660::read_file(disc, &e).ok()?;
    Some(GinsuApp { name: e.name, lba: e.lba, bytes, xfer_size, variants: vec![] })
}

/// The transfer program a `SNIG` block in `boot` names, if `boot` carries one.
pub fn snig_xfer(boot: &[u8]) -> Option<String> {
    let at = (0..boot.len().saturating_sub(SNIG_XFER + SNIG_PATH))
        .step_by(4)
        .find(|&i| boot[i..].starts_with(SNIG))?;
    let field = &boot[at + SNIG_XFER..at + SNIG_XFER + SNIG_PATH];
    let path = &field[..field.iter().position(|&b| b == 0)?];
    let name = std::str::from_utf8(path).ok()?.trim_start_matches('\\');
    (!name.is_empty() && name.is_ascii()).then(|| name.to_string())
}

/// The names `boot` holds as NUL-ended strings, in order, each once, a
/// leading `\` dropped: what a boot loader may run.
pub fn named_files(boot: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for run in boot.split(|&b| !(0x21..0x7f).contains(&b)) {
        let Ok(s) = std::str::from_utf8(run) else { continue };
        let s = s.trim_start_matches('\\');
        if (5..=16).contains(&s.len()) && !out.iter().any(|o| o.eq_ignore_ascii_case(s)) {
            out.push(s.to_string());
        }
    }
    out
}

/// A Ginsu boot whose configuration is built into the boot loader (above):
/// the programs are the `.BIN` files of the root it names that set up a heap,
/// the first named the one reported.
fn built_in_ginsu(disc: &dyn DiscFormat) -> Option<GinsuApp> {
    let ip = crate::disc_formats::types::ip_bin_at(disc, disc.boot_sector())?;
    let boot_name = iso9660::boot_file_name(&ip)?;
    let boot_entry = iso9660::find_in_root(disc, disc.boot_sector(), &boot_name)?;
    let boot = iso9660::read_file(disc, &boot_entry).ok()?;
    let xfer = snig_xfer(&boot)?;
    let root = iso9660::list_root(disc, disc.boot_sector());
    let xfer_size = root
        .iter()
        .find(|e| !e.is_dir && e.name.eq_ignore_ascii_case(&xfer))
        .map_or(GINSU_XFER_UNKNOWN, |e| e.size);
    let mut programs: Vec<GinsuApp> = vec![];
    for n in named_files(&boot) {
        let Some(e) = root.iter().find(|e| {
            !e.is_dir
                && e.name.eq_ignore_ascii_case(&n)
                && e.name.to_ascii_uppercase().ends_with(".BIN")
                && !e.name.eq_ignore_ascii_case(&boot_name)
                && !e.name.eq_ignore_ascii_case(&xfer)
                && e.size >= 0x1_0000
                && e.size <= iso9660::MAX_FILE_BYTES
        }) else {
            continue;
        };
        let Ok(bytes) = iso9660::read_file(disc, e) else { continue };
        if super::program_heaps(&bytes, GINSU_APP_LOAD).is_empty() {
            continue;
        }
        programs.push(GinsuApp { name: e.name.clone(), lba: e.lba, bytes, xfer_size, variants: vec![] });
    }
    let mut first = (!programs.is_empty()).then(|| programs.remove(0))?;
    first.variants = programs;
    Some(first)
}

impl GinsuApp {
    /// This program and the ones Ginsu may run instead.
    pub fn programs(&self) -> impl Iterator<Item = &GinsuApp> {
        std::iter::once(self).chain(self.variants.iter())
    }

    /// Where Ginsu reads the program and GINXFER.BIN: each at the 64 KB
    /// boundary under what is above it minus its size (the largest program's,
    /// when it may run several).
    pub fn ginsu_reads(&self) -> (u32, u32) {
        let xfer = GINSU_TOP.wrapping_sub(self.xfer_size) & !0xffff;
        let len = self.programs().map(|p| p.bytes.len()).max().unwrap_or(0);
        (xfer.wrapping_sub(len as u32) & !0xffff, xfer)
    }

    /// The highest loader base nothing Ginsu reads lands on: right under the
    /// program.
    pub fn loader_base(&self) -> u32 {
        self.ginsu_reads().0 - crate::loaders::LOADER_SPAN
    }

    /// The loader at the BOTTOM of the program's heap instead, and the sector
    /// words that start the heap above it (`heap_start_raise`). Right under
    /// the program, Unreal Tournament NTSC's heap lost 2.6 MB (0x8cd40000..
    /// 0x8cfdd000); here it loses the 64 KB boundary over its BSS and the
    /// loader's span (0x8c312ca0..0x8c330000). Ginsu's own heap, which runs to
    /// the top of RAM from under 0x8c050000, ends under the loader as any heap
    /// does. Run on the console (2026-10-12): Ginsu and UT boot.
    ///
    /// With several programs (NBA 2K2's four languages) the base is over the
    /// highest heap start of them all, and every one is raised above it.
    pub fn heap_bottom(&self) -> Result<(u32, Vec<DiscPatch>), String> {
        let span = crate::loaders::LOADER_SPAN;
        let mut base = 0;
        for p in self.programs() {
            let start = super::program_heaps(&p.bytes, GINSU_APP_LOAD)
                .iter()
                .map(|h| h.start)
                .min()
                .ok_or_else(|| format!("no heap found in {}", p.name))?;
            base = base.max(start.checked_add(0xffff).ok_or("heap past RAM")? & !0xffff);
        }
        if base + span > self.ginsu_reads().0 {
            return Err(format!("0x{base:08x} is not under where Ginsu reads the program"));
        }
        let mut patches = vec![];
        for p in self.programs() {
            let hits = super::literals_in_loader_footprint(&p.bytes, GINSU_APP_LOAD, base);
            if let Some((at, v)) = hits.first() {
                return Err(format!("{} names 0x{v:08x} (at 0x{at:08x}), inside a loader at 0x{base:08x}", p.name));
            }
            let words = super::heap_start_raise(&p.bytes, GINSU_APP_LOAD, base + span)
                .map_err(|e| format!("{}: {e}", p.name))?;
            patches.extend(p.disc_patches(&words).map_err(|(at, _)| format!("the word at 0x{at:08x} is outside {}", p.name))?);
        }
        Ok((base, patches))
    }

    /// Words of the running program (`(address, value)`, as the patch finders
    /// return them) as changes to the sectors served. A word outside the file,
    /// or not 4-aligned, cannot be one, and is returned in the error.
    pub fn disc_patches(&self, words: &[(u32, u32)]) -> Result<Vec<DiscPatch>, (u32, u32)> {
        words
            .iter()
            .map(|&(at, value)| {
                let off = ((at & 0x1fff_ffff) | 0x8c00_0000)
                    .checked_sub(GINSU_APP_LOAD)
                    .filter(|o| at & 3 == 0 && (*o as usize) + 4 <= self.bytes.len())
                    .ok_or((at, value))?;
                let o = off as usize;
                Ok(DiscPatch {
                    file: self.name.clone(),
                    lba: self.lba + off / 2048,
                    off: o % 2048,
                    was: u32::from_le_bytes(self.bytes[o..o + 4].try_into().expect("4 bytes")),
                    value,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unreal Tournament NTSC's GINSU.INI, as on the disc.
    const UT_NTSC: &str = "[GINSU]\r\nGinsu.FirstApp                  = UTDC\r\n\
        Ginsu.DefaultApp                = UTDC\r\nGinsu.XferExecutable            = \\GINXFER.BIN\r\n\r\n\
        [PWBROWSER]\r\nGinsu.Path\t\t\t= \\\r\nGinsu.Command\t\t\t= \\2_DP.BIN\r\nGinsu.FirstGDDA                 = 4\r\n\r\n\
        [UTDC]\r\nGinsu.Path                      = \\\r\nGinsu.Command                   = \\UTDC.BIN\r\n\
        Ginsu.FirstGDDA                 = 4\r\n";

    #[test]
    fn the_first_app_is_the_command_of_the_section_it_names() {
        assert_eq!(first_app_command(UT_NTSC).as_deref(), Some("UTDC.BIN"));
        // Not the browser, whose section comes first.
        assert_eq!(first_app_command(&UT_NTSC.replace("= UTDC\r\nGinsu.Def", "= PWBROWSER\r\nGinsu.Def")).as_deref(), Some("2_DP.BIN"));
        assert_eq!(first_app_command("[GINSU]\nGinsu.FirstApp = NONE\n"), None);
        assert_eq!(first_app_command("not an ini"), None);
    }

    /// With `DCLOAD_GINSU_APP` naming Unreal Tournament NTSC's UTDC.BIN: what
    /// a boot binary would show is all there, and lands in the file's sectors.
    #[test]
    fn unreal_tournament_ntscs_program_is_examined_like_a_boot_binary() {
        let Ok(path) = std::env::var("DCLOAD_GINSU_APP") else {
            return;
        };
        let bytes = std::fs::read(path).expect("DCLOAD_GINSU_APP");
        let app = GinsuApp { name: "UTDC.BIN".into(), lba: 447_448, bytes, xfer_size: 8436, variants: vec![] };
        let Some(driver) = super::super::find_net_driver(&app.bytes, GINSU_APP_LOAD) else {
            panic!("ETD not found")
        };
        let stubs = super::super::net_driver_patches(&app.bytes, GINSU_APP_LOAD, &driver, 0x8cfc_0800, 0x8cfc_0900);
        assert!(!stubs.is_empty());
        assert_eq!(app.disc_patches(&stubs).expect("all in the file").len(), stubs.len());
        let off = super::super::gaps_power_down_patches(&app.bytes, GINSU_APP_LOAD);
        assert_eq!(off.len(), 12);
        let heaps = super::super::program_heaps(&app.bytes, GINSU_APP_LOAD);
        assert!(heaps.iter().any(|h| h.end >= 0x8cfd_0000), "{heaps:?}");
        // The loader under what Ginsu reads: the heap ends there, and nothing
        // of the program names that RAM.
        let base = app.loader_base();
        assert_eq!(base, 0x8cd4_0000);
        assert!(heaps.iter().all(|h| h.patch_deep(base).is_ok_and(|p| p.is_some())), "{heaps:?}");
        assert_eq!(super::super::literals_in_loader_footprint(&app.bytes, GINSU_APP_LOAD, base), vec![]);
        // Or at the bottom of the heap (0x8c312ca0..): its three reads of
        // `_end` through `&_end` (0x8c05b06e, 0x8c05b12a, 0x8c05b1ee) become
        // moves, and both literals naming `&_end` hold the new start.
        let mut words = super::super::heap_start_raise(&app.bytes, GINSU_APP_LOAD, 0x8c33_0000).expect("raised");
        words.sort();
        assert_eq!(
            words,
            vec![
                (0x8c05_b06c, 0x65b3_d141),
                (0x8c05_b128, 0x62c3_d111),
                (0x8c05_b16c, 0x8c33_0000),
                (0x8c05_b1ec, 0x6513_d40a),
                (0x8c05_b214, 0x8c33_0000),
            ]
        );
        let (bottom, patches) = app.heap_bottom().expect("at the bottom");
        assert_eq!((bottom, patches.len()), (0x8c32_0000, 5));
    }

    /// A boot loader carrying its configuration: the `SNIG` block names the
    /// transfer program, and the names it holds are what it may run.
    #[test]
    fn a_built_in_configuration_names_the_transfer_program() {
        let mut boot = vec![0u8; 0x400];
        boot[0x10..0x1e].copy_from_slice(b"D\0\0\0MAIN.BIN\0\0");
        boot[0x20..0x2e].copy_from_slice(b"\\1ST_READ.BIN\0");
        boot[0x100..0x108].copy_from_slice(SNIG);
        boot[0x180..0x18c].copy_from_slice(b"\\ginxfer.bin");
        assert_eq!(snig_xfer(&boot).as_deref(), Some("ginxfer.bin"));
        assert_eq!(named_files(&boot), vec!["MAIN.BIN", "1ST_READ.BIN", "ginxfer.bin"]);
        // Not at a 4-byte boundary: not the block.
        boot.copy_within(0x100..0x190, 0x102);
        boot[0x100..0x102].fill(0);
        assert_eq!(snig_xfer(&boot), None);
    }

    /// With `DCLOAD_NBA2K2_DIR` holding NBA 2K2 PAL's 1ST_READ.BIN, MAIN.BIN,
    /// MAINF.BIN, MAING.BIN and MAINS.BIN: the four programs keep their heap's
    /// bounds in two words of .data, and the loader goes at the bottom of the
    /// heap, every program's start raised above it.
    #[test]
    fn nba_2k2s_programs_start_their_heap_above_the_loader() {
        let Ok(dir) = std::env::var("DCLOAD_NBA2K2_DIR") else {
            return;
        };
        let read = |n: &str| std::fs::read(std::path::Path::new(&dir).join(n)).expect(n);
        let boot = read("1ST_READ.BIN");
        assert_eq!(snig_xfer(&boot).as_deref(), Some("ginxfer.bin"));
        let names = named_files(&boot);
        for n in ["MAIN.BIN", "MAINF.BIN", "MAING.BIN", "MAINS.BIN", "JOHNNIE.BIN"] {
            assert!(names.iter().any(|m| m == n), "{n}");
        }
        let main = read("MAIN.BIN");
        let heaps = super::super::program_heaps(&main, GINSU_APP_LOAD);
        assert!(heaps.iter().any(|h| (h.start, h.end, h.end_at) == (0x8c7f_5040, 0x8d00_0000, 0x8c70_8b48)), "{heaps:?}");
        let words = super::super::heap_start_raise(&main, GINSU_APP_LOAD, 0x8c81_0000).expect("raised");
        assert_eq!(words, vec![(0x8c70_8b44, 0x0c81_0000)]);
        let prog = |n: &str, lba: u32| GinsuApp { name: n.into(), lba, bytes: read(n), xfer_size: GINSU_XFER_UNKNOWN, variants: vec![] };
        let mut app = prog("MAIN.BIN", 536_823);
        app.variants = vec![prog("MAINF.BIN", 543_964), prog("MAING.BIN", 533_252), prog("MAINS.BIN", 540_393)];
        // Measured on the console: MAIN.BIN read to 0x8c8d0000.
        assert_eq!(app.ginsu_reads(), (0x8c8d_0000, 0x8cfd_0000));
        let (base, patches) = app.heap_bottom().expect("at the bottom");
        assert_eq!(base, 0x8c80_0000);
        assert_eq!(patches.len(), 4, "{patches:?}");
        assert!(patches.iter().all(|p| p.value == 0x0c81_0000 && p.was & 0x1fff_ffff < 0x0c80_0000), "{patches:?}");
        let main_patch = patches.iter().find(|p| p.file == "MAIN.BIN").expect("MAIN.BIN");
        assert_eq!((main_patch.lba, main_patch.off, main_patch.was), (536_823 + 0x6f8b44 / 2048, 0x6f8b44 % 2048, 0x0c7f_5040));
        // 1ST_READ.BIN's own heap (its end at 0x8c05f1a4) is still found.
        let first = super::super::program_heaps(&boot, GINSU_APP_LOAD);
        assert!(first.iter().any(|h| h.end_at == 0x8c05_f1a4 && h.patch_deep(base).is_ok_and(|p| p.is_some())), "{first:?}");
        // And nothing it loads names the loader's RAM there.
        assert_eq!(super::super::literals_in_loader_footprint(&boot, GINSU_APP_LOAD, base), vec![]);
        // Its VCCD layer calls the BIOS GD driver body by address (no
        // 0x8c0000bc anywhere): 13 literals in each program, pointed at the
        // loader's _gd_bios_entry as served. Unpatched, MAIN.BIN rendered its
        // frames and never asked the host for a sector (flycast, 2026-10-17).
        for p in app.programs() {
            let words = super::super::gd_body_patches(&p.bytes, GINSU_APP_LOAD, 0x8c80_049c);
            assert_eq!(words.len(), 13, "{}", p.name);
            let served = p.disc_patches(&words).expect("in the file");
            assert!(served.iter().all(|d| d.was == 0x8c00_10f0 && d.value == 0x8c80_049c), "{served:?}");
        }
        assert!(super::super::gd_body_patches(&boot, GINSU_APP_LOAD, 0x8c80_049c).is_empty());
        // And it streams one sector a piece, moving on in its GD DMA-end
        // handler (0x8c24af20): the continuation in VCCD's state + 44.
        for p in app.programs() {
            assert!(super::super::gd_dma_end_slot(&p.bytes, GINSU_APP_LOAD).is_some(), "{}", p.name);
        }
        assert_eq!(super::super::gd_dma_end_slot(&main, GINSU_APP_LOAD), Some((0x8c7c_6894, 0)));
        assert_eq!(super::super::gd_dma_end_slot(&boot, GINSU_APP_LOAD), None);
    }

    #[test]
    fn the_transfer_program_is_named_in_the_ginsu_section() {
        assert_eq!(xfer_command(UT_NTSC).as_deref(), Some("GINXFER.BIN"));
        assert_eq!(xfer_command("[UTDC]\nGinsu.XferExecutable = \\X.BIN\n"), None);
    }

    /// Measured on the console (2026-10-12): UTDC.BIN read to
    /// 0x8cd50000..0x8cfcd000, so GINXFER.BIN at 0x8cfd0000.
    #[test]
    fn the_loader_goes_under_what_ginsu_reads() {
        let app = GinsuApp { name: "UTDC.BIN".into(), lba: 0, bytes: vec![0; 2_609_020], xfer_size: 8436, variants: vec![] };
        assert_eq!(app.ginsu_reads(), (0x8cd5_0000, 0x8cfd_0000));
        assert_eq!(app.loader_base(), 0x8cd4_0000);
    }

    #[test]
    fn a_word_of_the_program_lands_in_its_sector() {
        let mut bytes = vec![0u8; 0x2000];
        bytes[0x1804..0x1808].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let app = GinsuApp { name: "UTDC.BIN".into(), lba: 447_598, bytes, xfer_size: 8436, variants: vec![] };
        let p = app.disc_patches(&[(0x8c01_1804, 9), (0x0c01_0000, 7)]).unwrap();
        assert_eq!((p[0].lba, p[0].off, p[0].was, p[0].value), (447_598 + 3, 4, 0x1234_5678, 9));
        assert_eq!((p[1].lba, p[1].off, p[1].was), (447_598, 0, 0));
        assert_eq!(app.disc_patches(&[(0x8c01_2000, 1)]), Err((0x8c01_2000, 1)));
        assert_eq!(app.disc_patches(&[(0x8c00_fffc, 1)]), Err((0x8c00_fffc, 1)));
        assert_eq!(app.disc_patches(&[(0x8c01_0002, 1)]), Err((0x8c01_0002, 1)));
    }
}
