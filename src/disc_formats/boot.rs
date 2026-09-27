//! Getting a title's boot binary out of a disc image.
//!
//! Before this existed, running a game meant extracting `1ST_READ.BIN` by hand
//! with some other tool and then pointing at BOTH files -- the extracted binary
//! to upload, and the image to serve disc reads from. The image already knows
//! where its binary is: IP.BIN names it and the ISO9660 root holds it. So the
//! image alone is enough, and `uexec <image>` does the extraction itself.
//!
//! Two things this has to get right, both of which fail silently otherwise:
//!
//! 1. **The high-density area.** A GD-ROM has at least two data tracks and the
//!    low-density one is a stub carrying a valid filesystem for a different,
//!    empty disc. `boot_sector()` is the one to read files from, and it is
//!    neither the first nor reliably the last -- see `types::DiscFormat` and
//!    `gdi::Gdi::high_density_start`.
//! 2. **Scrambling.** A binary from a CD-R self-boot image is stored permuted
//!    and the bootstrap unpermutes it while loading. We never run that
//!    bootstrap, so it has to be undone here or the upload is noise. See
//!    `super::scramble` for what can and cannot be detected.
//!
//! And one framing rule, for Windows CE titles only: DreamShell's isoldr drops
//! the first 2048-byte sector of a boot file named `0WINCEOS.BIN` and loads the
//! rest at 0x8c010000 (`modules/isoldr/module.c`, `get_executable_info`). This
//! host did not, and entered the file at its first byte. See [`WinCe`].

use crate::disc_formats::iso9660;
use crate::disc_formats::scramble::{self, Scrambling};
use crate::disc_formats::types::DiscFormat;

/// What to do about scrambling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Descramble {
    /// Undo it only when it can be PROVEN to be there. The default, because the
    /// failure modes are not symmetric: descrambling a plain binary destroys a
    /// working upload, while leaving a scrambled one alone produces a title
    /// that visibly does nothing and a log line saying to try
    /// `--descramble always`.
    #[default]
    Auto,
    Always,
    Never,
}

/// What to do about a Windows CE boot file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WinCe {
    /// Recognise it and frame it as isoldr does: a file NAMED `0WINCEOS.BIN`
    /// loses its first sector. The default, because it is the one documented
    /// difference from a loader that runs these titles.
    #[default]
    Auto,
    /// Recognise it (for the log and `identify`) but upload the file whole, as
    /// this host did before. `--no-wince`.
    Off,
}

/// How much isoldr drops from the front of `0WINCEOS.BIN`: one sector.
///
/// Carried over, not derived. On the one disc measured (Sega Rally 2 PAL) the
/// dropped sector and the payload both disassemble as mid-function SH4 code,
/// the `"ECEC"` signature is absent, and the word isoldr takes for a VBR at
/// payload+0x0c is not one -- so the skip is parity with the reference, not a
/// proven entry point. `--no-wince` keeps the old framing.
pub const WINCE_WRAPPER_BYTES: usize = 2048;

/// Windows CE, by either of isoldr's two tests.
///
/// By name first. Otherwise `"ECEC"` at file offset 64, the Windows CE ROM-image
/// signature (`is_wince_rom`). Only the name test implies the sector skip:
/// isoldr applies it to `0WINCEOS.BIN` and to nothing else.
fn wince_kind(name: &str, bytes: &[u8]) -> Option<bool> {
    if name.eq_ignore_ascii_case("0WINCEOS.BIN") {
        Some(true)
    } else if bytes.get(64..68) == Some(b"ECEC") {
        Some(false)
    } else {
        None
    }
}

pub struct BootBinary {
    pub name: String,
    pub bytes: Vec<u8>,
    /// Where `bytes` start on the disc: the file's own LBA, plus the sectors
    /// `skipped` dropped.
    pub lba: u32,
    /// What the disc was found to be, before `mode` was applied.
    pub scrambling: Scrambling,
    pub descrambled: bool,
    /// A Windows CE title, whatever `WinCe` said to do about it.
    pub wince: bool,
    /// Bytes dropped from the front of the file ([`WINCE_WRAPPER_BYTES`] or 0).
    pub skipped: usize,
}

/// Read the boot binary the disc's own IP.BIN names.
pub fn extract(
    disc: &dyn DiscFormat,
    mode: Descramble,
    wince_mode: WinCe,
) -> Result<BootBinary, String> {
    let base = disc.boot_sector();
    // Not just the boot sector: `ip_bin_at` also looks for IP.BIN as an
    // ordinary file in the root, which is where the Sonic Adventure Limited
    // Edition .cdi keeps it (see `types::find_ip_bin`). Without that fallback
    // here, such a disc identifies fine and then refuses to boot or extract --
    // with its header sitting in the very directory the next call walks.
    let header = crate::disc_formats::types::ip_bin_at(disc, base).ok_or_else(|| {
        format!(
            "neither LBA {base} nor an IP.BIN file in the root directory there \
             carries a Dreamcast header, so the disc does not say which file it boots"
        )
    })?;
    let name = iso9660::boot_file_name(&header).unwrap_or_else(|| {
        warn!("IP.BIN names no boot file; assuming 1ST_READ.BIN");
        "1ST_READ.BIN".to_string()
    });

    // Listed once. `find_in_root` would read and parse the whole extent, and
    // the error branch below would read and parse it a second time just to say
    // what is in it.
    let root = iso9660::list_root(disc, base);
    let entry = root
        .iter()
        .find(|e| !e.is_dir && e.name.eq_ignore_ascii_case(&name))
        .ok_or_else(|| {
            let listing = root
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "IP.BIN names '{name}' as the boot file, but the root directory of the \
                 boot area (LBA {base}) does not hold it. It holds: {listing}"
            )
        })?;

    let bytes = iso9660::read_file(disc, entry)
        .map_err(|e| format!("cannot read {name} (LBA {}, {} bytes): {e}", entry.lba, entry.size))?;

    let scrambling = scramble::assess(&bytes);
    let descramble = match (mode, scrambling) {
        (Descramble::Never, _) => false,
        (Descramble::Always, _) => true,
        (Descramble::Auto, Scrambling::Scrambled) => true,
        (Descramble::Auto, _) => false,
    };

    match (scrambling, descramble) {
        (Scrambling::Plain, false) => {
            debug!("{name}: plain binary (recognised header)");
        }
        // `Plain` is the one answer this module makes with certainty, so
        // overriding it is the one case that can only destroy a working upload.
        // A `warn!`, not the `info!` the general "as asked" arm used to swallow
        // this in.
        (Scrambling::Plain, true) => {
            warn!(
                "{name} was RECOGNISED as a plain, unscrambled binary, and \
                 `--descramble always` says to permute it anyway: what gets \
                 uploaded will not be executable code. Drop the flag."
            );
        }
        (Scrambling::Scrambled, true) => {
            info!("{name}: scrambled boot binary, unscrambling it before upload");
        }
        (Scrambling::Scrambled, false) => {
            warn!(
                "{name} IS scrambled and `--descramble never` was given: what gets \
                 uploaded will not be executable code."
            );
        }
        (Scrambling::Unknown, false) => {
            debug!(
                "{name}: cannot tell whether it is scrambled -- normal for a retail \
                 title. If it uploads and then does nothing at all, try \
                 `--descramble always`."
            );
        }
        (Scrambling::Unknown, true) => {
            info!("{name}: unscrambling as asked (`--descramble always`)");
        }
    }

    // Scrambling permutes the whole file, so it is undone on the whole file,
    // and only then is anything cut off the front.
    let mut bytes = if descramble {
        scramble::descramble(&bytes)
    } else {
        bytes
    };

    let kind = wince_kind(&name, &bytes);
    let skipped = match (kind, wince_mode) {
        (Some(true), WinCe::Auto) if bytes.len() > WINCE_WRAPPER_BYTES => {
            bytes.drain(..WINCE_WRAPPER_BYTES);
            info!(
                "{name}: Windows CE title -- dropping its first {WINCE_WRAPPER_BYTES}-byte \
                 sector and loading the rest, as DreamShell's isoldr does \
                 (`--no-wince` uploads the file whole)"
            );
            WINCE_WRAPPER_BYTES
        }
        (Some(_), WinCe::Off) => {
            warn!(
                "{name}: Windows CE title, uploaded whole and entered at its first byte \
                 (`--no-wince`) -- isoldr drops the first sector of 0WINCEOS.BIN"
            );
            0
        }
        (Some(false), _) => {
            info!(
                "{name}: Windows CE ROM image (\"ECEC\" at +64) -- uploaded whole, \
                 as isoldr does for a CE image that is not named 0WINCEOS.BIN"
            );
            0
        }
        _ => 0,
    };

    Ok(BootBinary {
        name,
        bytes,
        lba: entry.lba + (skipped / 2048) as u32,
        scrambling,
        descrambled: descramble,
        wince: kind.is_some(),
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wince_is_recognised_by_name_or_by_signature_and_only_the_name_skips() {
        let mut ecec = vec![0u8; 128];
        ecec[64..68].copy_from_slice(b"ECEC");
        assert_eq!(wince_kind("0WINCEOS.BIN", &[0; 128]), Some(true));
        assert_eq!(wince_kind("0winceos.bin", &[0; 128]), Some(true));
        assert_eq!(wince_kind("1ST_READ.BIN", &ecec), Some(false));
        assert_eq!(wince_kind("1ST_READ.BIN", &[0; 128]), None);
        // Too short to carry a signature is not a CE image.
        assert_eq!(wince_kind("1ST_READ.BIN", b"ECEC"), None);
    }
}
