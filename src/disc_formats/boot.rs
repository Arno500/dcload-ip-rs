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
//! 1. **The high-density area.** A GD-ROM has two data tracks and both carry a
//!    valid filesystem; the low-density one is a stub. `boot_sector()` is the
//!    one to read files from -- see `types::DiscFormat`.
//! 2. **Scrambling.** A binary from a CD-R self-boot image is stored permuted
//!    and the bootstrap unpermutes it while loading. We never run that
//!    bootstrap, so it has to be undone here or the upload is noise. See
//!    `super::scramble` for what can and cannot be detected.

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

pub struct BootBinary {
    pub name: String,
    pub bytes: Vec<u8>,
    pub lba: u32,
    /// What the disc was found to be, before `mode` was applied.
    pub scrambling: Scrambling,
    pub descrambled: bool,
}

/// Read the boot binary the disc's own IP.BIN names.
pub fn extract(disc: &dyn DiscFormat, mode: Descramble) -> Result<BootBinary, String> {
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

    if name.eq_ignore_ascii_case("0WINCEOS.BIN") {
        warn!(
            "'{name}' is a Windows CE title. It boots through its own loader and \
             not by being entered directly, which is what this host does -- expect \
             it not to run."
        );
    }

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

    let bytes = if descramble {
        scramble::descramble(&bytes)
    } else {
        bytes
    };

    Ok(BootBinary {
        name,
        bytes,
        lba: entry.lba,
        scrambling,
        descrambled: descramble,
    })
}
