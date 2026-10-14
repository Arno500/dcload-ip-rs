//! The resident loader, and what VERS says about the running build.
//!
//! `make loaders` (target-src/dcload, loader AGENTS.md 4.18) builds two images:
//! the universal `dcload-relocatable.elf`, with its screen and DHCP, used for
//! every hop, and `dcload-resident.elf`, the same loader without them, which is
//! what the title runs on. A resident image has no DHCP, so the host writes the
//! console's address and port into it (`patch_resident`); its symbols are not
//! at the universal image's addresses, so the host reads them from its own file
//! (`running_image`).

use std::sync::Mutex;

use crate::loaders;

/// What VERS's variant word says about the running build (cmd_version).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VariantWord {
    /// 0 LOW, 1 HIGH (2 was the withdrawn core).
    pub layout: u8,
    /// 0 all, 1 Katana, 2 KOS, 3 Windows CE.
    pub os: u8,
    pub cdda: bool,
    pub bba: bool,
    pub lan: bool,
    pub mark: bool,
    pub disc: bool,
    pub resident: bool,
    /// The title's own network served by the loader (`dcload-resident-net.elf`,
    /// `dispatch::vnic`).
    pub vnic: bool,
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
            vnic: bit(15),
        })
    }

}

/// The image of the loader VERS last said is running, when it is the resident
/// one: the ELF every symbol the host reads by name must come from (counters,
/// the GD entry, the staging buffers). `None`: the universal image.
static RUNNING_IMAGE: Mutex<Option<(u32, Vec<u8>, String)>> = Mutex::new(None);

pub fn set_running_image(image: Option<(u32, Vec<u8>, String)>) {
    *RUNNING_IMAGE.lock().unwrap() = image;
}

/// The running resident image, if it runs at `base`.
pub fn running_image(base: u32) -> Option<(Vec<u8>, String)> {
    RUNNING_IMAGE
        .lock()
        .unwrap()
        .as_ref()
        .filter(|(b, _, _)| *b == base)
        .map(|(_, bytes, label)| (bytes.clone(), label.clone()))
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

/// Does a stack seen as low as `sp` clear a loader image ending at `end` by the
/// margin the LOW base uses? Addresses in physical form: a title's stack may be
/// seen in P0 (0x0cb06ca4: Shenmue II keeps it in high RAM) or P1.
pub fn stack_clears(end: u32, sp: u32) -> bool {
    let phys = |a: u32| a & 0x1fff_ffff;
    let (sp, end) = (phys(sp), phys(end));
    sp >= 0x0c01_0000 || sp.saturating_sub(end) >= loaders::LOW_BASE_MIN_MARGIN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variant_word_reads_what_the_loader_builds() {
        // HIGH, every kind of title, CD-DA, both drivers, MARK, DISC, resident.
        let w = 0xA500_0000u32 | 1 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 13;
        let v = VariantWord::from_word(w).unwrap();
        assert_eq!((v.layout, v.os), (1, 0));
        assert!(v.cdda && v.bba && v.lan && v.mark && v.disc && v.resident && !v.vnic);
        // The network image: Katana only, RetroAchievements, bit 15.
        let v = VariantWord::from_word(w | 1 << 4 | 1 << 14 | 1 << 15).unwrap();
        assert!(v.os == 1 && v.resident && v.vnic);
        assert_eq!(VariantWord::from_word(0x0000_0102), None);
    }

    #[test]
    fn a_stack_in_high_ram_clears_a_low_image_and_sonic_adventures_does_not() {
        // Shenmue II: seen in P0 high RAM. Crazy Taxi 2 likewise.
        assert!(stack_clears(0x8c00_b960, 0x0cb0_6ca4));
        assert!(stack_clears(0x8c00_b960, 0x0c17_50ec));
        // Snow Surfers: 0x8c00e460 over an image ending 0x8c00b960.
        assert!(stack_clears(0x8c00_b960, 0x8c00_e460));
        // Sonic Adventure: 0x8c00b91c, under the image's own end.
        assert!(!stack_clears(0x8c00_b960, 0x8c00_b91c));
        assert!(!stack_clears(0x8c00_b960, 0x8c00_acac));
    }

    /// With `DCLOAD_LOADER_DIR` naming a freshly built set: the resident image
    /// relocates to high bases, and the console's address lands where it reads it.
    #[test]
    fn the_built_resident_image_takes_the_consoles_address() {
        let Ok(dir) = std::env::var("DCLOAD_LOADER_DIR") else {
            return;
        };
        for name in [loaders::RESIDENT_NAME, loaders::RESIDENT_NET_NAME] {
        let Ok(bytes) = std::fs::read(std::path::Path::new(&dir).join(name)) else {
            continue;
        };
        for base in [0x8c36_0000u32, 0x8ce0_0000, 0x8cee_0000, 0x8cfe_0000] {
            let mut moved = loaders::relocate(&bytes, base).unwrap();
            patch_resident(&mut moved, [192, 168, 1, 64], 53535).unwrap();
            let syms = loaders::symbols(&moved).unwrap();
            assert!(syms["end"].0 > base && syms["end"].0 < loaders::layout(base).stack);
            let at = file_offset(&moved, syms["our_ip"].0).unwrap();
            assert_eq!(&moved[at..at + 4], &0xc0a8_0140u32.to_le_bytes());
            let at = file_offset(&moved, syms["dcload_syscall_port"].0).unwrap();
            assert_eq!(&moved[at..at + 2], &53535u16.to_le_bytes());
            // The network image carries its way in, and the words it is told.
            if name == loaders::RESIDENT_NET_NAME {
                assert!(["vnic_etd", "vnic_pso", "g_vnic_slot"].iter().all(|s| syms.contains_key(*s)));
            }
        }
        }
    }
}
