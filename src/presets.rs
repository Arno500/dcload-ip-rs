//! Per-game settings, and the disc identity used to look them up.
//!
//! # Why the host has to care where the loader lives
//!
//! dcload is not a debugger attached to a title, it is a program that stays
//! resident in the Dreamcast's RAM while the title runs, answering the GD-ROM
//! syscalls the title makes. A retail title decides for itself which parts of
//! RAM are free, and several of them treat the hole the loader occupies as
//! exactly that -- Sonic Adventure puts a descending stack through it, which is
//! how it once ended up overwriting the loader's adapter pointer.
//!
//! DreamShell's isoldr solves this per title, with a database of presets whose
//! `memory` field is the address its loader must be linked at to stay out of
//! that title's way. This module carries that database over: the host reads the
//! disc, identifies it, and looks up the address. `dispatch::ensure_loader_base`
//! then uploads a dcload relinked for that address and chainloads into it before
//! the title is uploaded at all.
//!
//! # Identification, and why it is two-tier
//!
//! DreamShell names each preset file after the MD5 of the disc's boot sector --
//! 2048 bytes at the first sector of the data track, i.e. IP.BIN sector 0. That
//! is a hash of one *dump*, not of a game, and coverage is partial: neither of
//! the two Sonic Adventure dumps this was developed against is in the database,
//! even though both games are.
//!
//! So there is a second tier. IP.BIN carries the title as text at offset 0x80,
//! and the database rows carry it too, so a disc with no hash match can still be
//! recognised by name. That is weaker on purpose and is reported as such: 24
//! titles are shared by presets that disagree about `memory`, and for those the
//! majority value is used.
//!
//! Anything with no match at all keeps whatever base the loader is already
//! running at, which is the stock 0x8c004000.

use std::collections::HashMap;
use std::path::Path;

use crate::loaders::DEFAULT_BASE;

/// One row of the database: a game, and what isoldr needs to do for it.
#[derive(Debug, Clone)]
pub struct Preset {
    pub md5: String,
    pub title: String,
    /// The address the loader must be linked at. This is the field that does
    /// the work; everything below is carried so the host can say out loud what
    /// it is not honouring.
    pub memory: u32,
    pub emu_async: u32,
    pub dma: u32,
    pub irq: u32,
    pub cdda: u32,
    pub heap: u32,
    pub low: u32,
    pub fastboot: u32,
    pub bin_type: u32,
    pub boot_mode: u32,
    pub altread: u32,
    pub patches: [(u32, u32); 2],
}

/// How confident the lookup is. A caller that only logs still wants to say
/// which one it was, because the two have very different failure modes: a hash
/// match is the exact dump somebody tested, a title match is a guess that the
/// regional variant in hand behaves like the one that was tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// The disc's boot sector hashes to a preset. Exact.
    BootSectorMd5,
    /// Same title text, different dump. Approximate.
    Title,
}

impl Preset {
    /// The settings in this row that this host does not act on, in words.
    ///
    /// The point is not completeness for its own sake: when a title misbehaves,
    /// the first useful question is whether its preset asked for something that
    /// was quietly dropped. Printing that at load time turns a silent
    /// incompatibility into a line in the log.
    pub fn unsupported(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.irq != 0 {
            out.push("irq=1 (the title expects the loader to hook interrupts; \
                      dcload's VBR leaves the interrupt vector as nop;rte;nop. \
                      Its CDDA engine does not need it -- it writes sound RAM \
                      with the CPU, so it raises no AICA DMA interrupt to \
                      arbitrate, and it is driven from the GD syscalls)"
                .to_string());
        }
        // `cdda` is SERVED now (dcload's cdda.c), so what is worth reporting
        // is which of isoldr's options this loader answers differently -- not
        // that the feature is missing. The source and destination bits pick
        // between an IDE/SD device and DMA/SQ/PIO, none of which describe a
        // loader reading over UDP and writing sound RAM with the CPU; the
        // position bits pick an SH4 timer, and this engine reads the AICA's
        // own play position instead. See target-src/dcload/cdda.h.
        if self.cdda != 0 {
            const CDDA_CH_FIXED: u32 = 0x0002_0000;
            if self.cdda & CDDA_CH_FIXED == 0 {
                out.push(format!(
                    "cdda={:08x} asks for adaptive AICA channels; this loader always \
                     uses the fixed pair (62/63)",
                    self.cdda
                ));
            }
        }
        if self.bin_type != 0 {
            let name = match self.bin_type {
                1 => "KOS",
                2 => "KATANA",
                3 => "WINCE",
                4 => "NAOMI",
                _ => "unknown",
            };
            out.push(format!(
                "type={} ({}); the binary is uploaded and entered as-is",
                self.bin_type, name
            ));
        }
        if self.boot_mode != 0 {
            out.push(format!(
                "mode={} (boot through IP.BIN); the host enters 1ST_READ.BIN directly",
                self.boot_mode
            ));
        }
        if self.low != 0 {
            out.push("low=1 (low syscall area relocation)".to_string());
        }
        if self.heap != 0 {
            out.push(format!("heap={:08x} (heap placement)", self.heap));
        }
        if self.altread != 0 {
            out.push("altread=1 (alternate read path)".to_string());
        }
        for (addr, value) in self.patches {
            if addr != 0 {
                out.push(format!(
                    "patch {value:08x} -> {addr:08x} (a fix-up poked into RAM before boot)"
                ));
            }
        }
        // dma is about the LOADER's own storage device (SD/IDE). On a network
        // transport there is no device DMA at all, so `dma` is not something
        // that could be honoured or dropped -- it does not apply. Same for
        // fastboot, which skips DreamShell's own UI.
        out
    }
}

/// The whole table, plus the title index used for the fallback tier.
pub struct PresetDb {
    by_md5: HashMap<String, Preset>,
    /// Title -> the row whose `memory` is the majority among presets sharing
    /// that title. Built once, so the answer does not depend on file order.
    by_title: HashMap<String, Preset>,
    /// Titles whose presets disagree about `memory`, and the addresses they
    /// disagree over. THE ADDRESSES, not just how many: a disagreement in which
    /// one of the votes is below the BIOS syscall area is a different statement
    /// from one between two high addresses, and only the votes themselves can
    /// tell them apart. See `title_addresses`.
    ambiguous_titles: HashMap<String, Vec<u32>>,
}

impl PresetDb {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut by_md5: HashMap<String, Preset> = HashMap::new();
        // Collect every row per title first: the majority vote needs all of
        // them before it can pick one.
        let mut per_title: HashMap<String, Vec<Preset>> = HashMap::new();

        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 17 {
                continue;
            }
            let hex = |s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0);
            let dec = |s: &str| s.parse::<u32>().unwrap_or(0);
            let preset = Preset {
                md5: f[0].to_string(),
                title: f[1].to_string(),
                memory: hex(f[2]),
                emu_async: dec(f[3]),
                dma: dec(f[4]),
                irq: dec(f[5]),
                cdda: hex(f[6]),
                heap: hex(f[7]),
                low: dec(f[8]),
                fastboot: dec(f[9]),
                bin_type: dec(f[10]),
                boot_mode: dec(f[11]),
                altread: dec(f[12]),
                patches: [(hex(f[13]), hex(f[14])), (hex(f[15]), hex(f[16]))],
            };
            per_title
                .entry(normalise_title(&preset.title))
                .or_default()
                .push(preset.clone());
            by_md5.insert(preset.md5.clone(), preset);
        }

        // How often each address appears across the whole database, for the
        // tie-break below.
        let mut overall: HashMap<u32, usize> = HashMap::new();
        for r in by_md5.values() {
            *overall.entry(r.memory).or_insert(0) += 1;
        }

        let mut by_title = HashMap::new();
        let mut ambiguous_titles = HashMap::new();
        for (title, rows) in per_title {
            if title.is_empty() {
                continue;
            }
            let mut votes: HashMap<u32, usize> = HashMap::new();
            for r in &rows {
                *votes.entry(r.memory).or_insert(0) += 1;
            }
            if votes.len() > 1 {
                let mut addrs: Vec<u32> = votes.keys().copied().collect();
                addrs.sort_unstable();
                ambiguous_titles.insert(title.clone(), addrs);
            }
            // Most votes wins. A TIE BREAKS TOWARDS NOT MOVING: the stock base
            // first, then whatever the database as a whole prefers, then the
            // lowest address so the result cannot depend on hash order.
            //
            // The tie is not hypothetical, and neither is the direction. Two
            // presets are titled "SONIC ADVENTURE", one at 0x8c004000 and one
            // at 0x8c000100, so a dump matched by title alone lands on that
            // one-all split -- and Sonic Adventure is a title known to run at
            // the stock base here. Relocating it on the strength of a tie
            // would be trading something that works for a coin toss.
            let winner = votes
                .iter()
                .max_by_key(|(addr, n)| {
                    (
                        **n,
                        **addr == DEFAULT_BASE,
                        *overall.get(addr).unwrap_or(&0),
                        std::cmp::Reverse(**addr),
                    )
                })
                .map(|(addr, _)| *addr)
                .unwrap_or(0);
            if let Some(row) = rows.into_iter().find(|r| r.memory == winner) {
                by_title.insert(title, row);
            }
        }

        PresetDb {
            by_md5,
            by_title,
            ambiguous_titles,
        }
    }

    pub fn len(&self) -> usize {
        self.by_md5.len()
    }

    /// Exact first, then by title. `None` means "no opinion", which the caller
    /// must treat as "leave the loader where it is" and not as an error.
    pub fn lookup(&self, disc: &DiscIdentity) -> Option<(Preset, MatchKind)> {
        if let Some(p) = self.by_md5.get(&disc.md5) {
            return Some((p.clone(), MatchKind::BootSectorMd5));
        }
        let key = normalise_title(&disc.title);
        if key.is_empty() {
            return None;
        }
        self.by_title
            .get(&key)
            .map(|p| (p.clone(), MatchKind::Title))
    }

    /// How many distinct `memory` values presets under this title carry. 1 (or
    /// 0, for an unknown title) means a title match is not actually ambiguous.
    pub fn title_ambiguity(&self, title: &str) -> usize {
        self.title_addresses(title).len()
    }

    /// The addresses presets under this title disagree over, lowest first, or
    /// empty when they do not disagree at all.
    ///
    /// WHAT THE DISAGREEMENT IS ABOUT IS THE INFORMATION, and the count throws
    /// it away. Two presets titled "SONIC ADVENTURE" ask for 0x8c004000 and
    /// 0x8c000100: one vote for the stock base and one for below the BIOS
    /// syscall area, which is DreamShell saying that for at least one dump of
    /// this title even the stock base was not low enough. The tie-break above
    /// keeps the loader still, and for isoldr's 13 KB that is the safe answer;
    /// for an image four times the size it is the one address the other vote
    /// argues against. `main::low_family_contested` is what reads this.
    pub fn title_addresses(&self, title: &str) -> Vec<u32> {
        self.ambiguous_titles
            .get(&normalise_title(title))
            .cloned()
            .unwrap_or_default()
    }
}

/// IP.BIN titles are a fixed-width, space-padded field, and the same game can
/// be spelled with different runs of internal whitespace across regions. Fold
/// runs of whitespace and case so the two tiers agree on what "same title"
/// means.
fn normalise_title(title: &str) -> String {
    title.split_whitespace().collect::<Vec<_>>().join(" ").to_uppercase()
}

/// What the disc says about itself: the fields of IP.BIN sector 0, plus the
/// hash DreamShell keys its presets on.
#[derive(Debug, Clone)]
pub struct DiscIdentity {
    pub md5: String,
    pub title: String,
    pub product: String,
    pub version: String,
    pub region: String,
}

impl DiscIdentity {
    /// Parse a 2048-byte boot sector.
    ///
    /// Offsets are the standard IP.BIN meta header: 0x00 hardware ID, 0x30
    /// area symbols, 0x40 product number, 0x4a version, 0x80 software name.
    /// The hardware ID check is what keeps a garbage read from being reported
    /// as a game with an empty name.
    pub fn from_boot_sector(sector: &[u8]) -> Option<Self> {
        if sector.len() < 0x100 || !sector.starts_with(b"SEGA SEGAKATANA") {
            return None;
        }
        // Trim NULs as well as spaces. The fields are space-padded on a
        // properly mastered disc, but not every dump is: a short field left
        // zero-filled would otherwise carry its padding into the title, and
        // since the title is the fallback lookup key that means never matching
        // anything.
        let field = |start: usize, len: usize| {
            String::from_utf8_lossy(&sector[start..start + len])
                .trim_matches(|c: char| c.is_whitespace() || c == '\0')
                .to_string()
        };
        Some(DiscIdentity {
            md5: format!("{:x}", md5::compute(&sector[..2048])),
            title: field(0x80, 0x80),
            product: field(0x40, 10),
            version: field(0x4a, 6),
            region: field(0x30, 8),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: &str = "\
# comment
0e46ce45373a0c5c037e7e7d0d86f1db\tSONIC ADVENTURE\t0x8c004000\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t00000000\t00000000\t00000000\t00000000
82f2abcaa63a6477e796d25b29a1cecd\tSONIC ADVENTURE 2\t0x8cfe8000\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t00000000\t00000000\t00000000\t00000000
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tSONIC ADVENTURE 2\t0x8cfe8000\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t00000000\t00000000\t00000000\t00000000
";

    fn identity(md5: &str, title: &str) -> DiscIdentity {
        DiscIdentity {
            md5: md5.to_string(),
            title: title.to_string(),
            product: String::new(),
            version: String::new(),
            region: String::new(),
        }
    }

    #[test]
    fn md5_match_is_exact() {
        let db = PresetDb::parse(ROW);
        let (p, kind) = db
            .lookup(&identity("0e46ce45373a0c5c037e7e7d0d86f1db", "ANYTHING"))
            .unwrap();
        assert_eq!(kind, MatchKind::BootSectorMd5);
        assert_eq!(p.memory, 0x8c00_4000);
    }

    #[test]
    fn unknown_hash_falls_back_to_the_title() {
        let db = PresetDb::parse(ROW);
        // The PAL dump this was developed against is not in DreamShell's
        // database; only the title match can find it.
        let (p, kind) = db
            .lookup(&identity("ffffffffffffffffffffffffffffffff", "SONIC ADVENTURE 2"))
            .unwrap();
        assert_eq!(kind, MatchKind::Title);
        assert_eq!(p.memory, 0x8cfe_8000);
    }

    #[test]
    fn title_matching_ignores_padding_and_case() {
        let db = PresetDb::parse(ROW);
        assert!(
            db.lookup(&identity("ff", "  sonic   adventure 2   "))
                .is_some()
        );
    }

    #[test]
    fn a_tie_between_addresses_keeps_the_stock_base() {
        // The real split in DreamShell's database: two presets titled
        // "SONIC ADVENTURE", one at each address. A dump matched by title has
        // to pick one, and picking the stock base means a title that already
        // ran keeps running.
        let tied = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1\tSONIC ADVENTURE\t0x8c000100\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t0\t0\t0\t0
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2\tSONIC ADVENTURE\t0x8c004000\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t0\t0\t0\t0
";
        let db = PresetDb::parse(tied);
        let (p, kind) = db.lookup(&identity("ff", "SONIC ADVENTURE")).unwrap();
        assert_eq!(kind, MatchKind::Title);
        assert_eq!(p.memory, DEFAULT_BASE);
        assert_eq!(db.title_ambiguity("SONIC ADVENTURE"), 2);
    }

    #[test]
    fn a_clear_majority_still_wins_over_the_stock_base() {
        let split = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1\tGAME\t0x8cfe8000\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t0\t0\t0\t0
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2\tGAME\t0x8cfe8000\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t0\t0\t0\t0
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3\tGAME\t0x8c004000\t0\t1\t0\t00000000\t00000000\t0\t0\t0\t0\t0\t0\t0\t0\t0
";
        let db = PresetDb::parse(split);
        let (p, _) = db.lookup(&identity("ff", "GAME")).unwrap();
        assert_eq!(p.memory, 0x8cfe_8000);
    }

    #[test]
    fn no_match_is_not_an_error() {
        let db = PresetDb::parse(ROW);
        assert!(db.lookup(&identity("ff", "SOME OTHER GAME")).is_none());
    }

    #[test]
    fn boot_sector_needs_the_hardware_id() {
        assert!(DiscIdentity::from_boot_sector(&[0u8; 2048]).is_none());
        let mut sector = vec![0u8; 2048];
        sector[..16].copy_from_slice(b"SEGA SEGAKATANA ");
        sector[0x80..0x80 + 17].copy_from_slice(b"SONIC ADVENTURE 2");
        let id = DiscIdentity::from_boot_sector(&sector).unwrap();
        assert_eq!(id.title, "SONIC ADVENTURE 2");
    }
}
