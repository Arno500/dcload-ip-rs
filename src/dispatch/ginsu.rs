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

use super::DiscPatch;
use crate::disc_formats::{iso9660, types::DiscFormat};

/// Where Katana programs, and so the program Ginsu runs, are linked.
pub const GINSU_APP_LOAD: u32 = 0x8c01_0000;

/// What Ginsu reads its programs under: its file system's work area.
pub const GINSU_TOP: u32 = 0x8cfe_0000;

/// The transfer program `Ginsu.XferExecutable` names when it names none.
const GINSU_XFER_DEFAULT: &str = "GINXFER.BIN";

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
    first_app_command(&ginsu_ini(disc)?)
}

/// The program a Ginsu boot runs, read off the disc.
pub fn ginsu_app(disc: &dyn DiscFormat) -> Option<GinsuApp> {
    let ini = ginsu_ini(disc)?;
    let name = first_app_command(&ini)?;
    let xfer = xfer_command(&ini).unwrap_or_else(|| GINSU_XFER_DEFAULT.to_string());
    let xfer_size = iso9660::find_in_root(disc, disc.boot_sector(), &xfer)?.size;
    let e = iso9660::find_in_root(disc, disc.boot_sector(), &name)?;
    let bytes = iso9660::read_file(disc, &e).ok()?;
    Some(GinsuApp { name: e.name, lba: e.lba, bytes, xfer_size })
}

impl GinsuApp {
    /// Where Ginsu reads the program and GINXFER.BIN: each at the 64 KB
    /// boundary under what is above it minus its size.
    pub fn ginsu_reads(&self) -> (u32, u32) {
        let xfer = GINSU_TOP.wrapping_sub(self.xfer_size) & !0xffff;
        (xfer.wrapping_sub(self.bytes.len() as u32) & !0xffff, xfer)
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
    pub fn heap_bottom(&self) -> Result<(u32, Vec<DiscPatch>), String> {
        let span = crate::loaders::LOADER_SPAN;
        let start = super::program_heaps(&self.bytes, GINSU_APP_LOAD)
            .iter()
            .map(|h| h.start)
            .min()
            .ok_or("no heap found in the program")?;
        let base = start.checked_add(0xffff).ok_or("heap past RAM")? & !0xffff;
        if base + span > self.ginsu_reads().0 {
            return Err(format!("0x{base:08x} is not under where Ginsu reads the program"));
        }
        let hits = super::literals_in_loader_footprint(&self.bytes, GINSU_APP_LOAD, base);
        if let Some((at, v)) = hits.first() {
            return Err(format!("the program names 0x{v:08x} (at 0x{at:08x}), inside a loader at 0x{base:08x}"));
        }
        let words = super::heap_start_raise(&self.bytes, GINSU_APP_LOAD, base + span)?;
        let patches = self
            .disc_patches(&words)
            .map_err(|(at, _)| format!("the word at 0x{at:08x} is outside {}", self.name))?;
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
        let app = GinsuApp { name: "UTDC.BIN".into(), lba: 447_448, bytes, xfer_size: 8436 };
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

    #[test]
    fn the_transfer_program_is_named_in_the_ginsu_section() {
        assert_eq!(xfer_command(UT_NTSC).as_deref(), Some("GINXFER.BIN"));
        assert_eq!(xfer_command("[UTDC]\nGinsu.XferExecutable = \\X.BIN\n"), None);
    }

    /// Measured on the console (2026-10-12): UTDC.BIN read to
    /// 0x8cd50000..0x8cfcd000, so GINXFER.BIN at 0x8cfd0000.
    #[test]
    fn the_loader_goes_under_what_ginsu_reads() {
        let app = GinsuApp { name: "UTDC.BIN".into(), lba: 0, bytes: vec![0; 2_609_020], xfer_size: 8436 };
        assert_eq!(app.ginsu_reads(), (0x8cd5_0000, 0x8cfd_0000));
        assert_eq!(app.loader_base(), 0x8cd4_0000);
    }

    #[test]
    fn a_word_of_the_program_lands_in_its_sector() {
        let mut bytes = vec![0u8; 0x2000];
        bytes[0x1804..0x1808].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let app = GinsuApp { name: "UTDC.BIN".into(), lba: 447_598, bytes, xfer_size: 8436 };
        let p = app.disc_patches(&[(0x8c01_1804, 9), (0x0c01_0000, 7)]).unwrap();
        assert_eq!((p[0].lba, p[0].off, p[0].was, p[0].value), (447_598 + 3, 4, 0x1234_5678, 9));
        assert_eq!((p[1].lba, p[1].off, p[1].was), (447_598, 0, 0));
        assert_eq!(app.disc_patches(&[(0x8c01_2000, 1)]), Err((0x8c01_2000, 1)));
        assert_eq!(app.disc_patches(&[(0x8c00_fffc, 1)]), Err((0x8c00_fffc, 1)));
        assert_eq!(app.disc_patches(&[(0x8c01_0002, 1)]), Err((0x8c01_0002, 1)));
    }
}
