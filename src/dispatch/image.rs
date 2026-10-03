//! Opening disc images (including members of a `.zip`) and identifying them.

use super::*;

/// What game a disc is, from its IP.BIN (the sector DreamShell hashes).
/// The error says why, since "not found" and "not a Dreamcast disc" call for
/// different fixes.
pub fn identify(
    disc: &dyn DiscFormat,
    path: &str,
) -> Result<crate::presets::DiscIdentity, String> {
    let sector = crate::disc_formats::types::find_ip_bin(disc).ok_or_else(|| {
        format!(
            "{path} opened, but neither its boot sector nor an IP.BIN file in its \
             root directory carries a Dreamcast header"
        )
    })?;
    crate::presets::DiscIdentity::from_boot_sector(&sector)
        .ok_or_else(|| format!("{path}: IP.BIN found but could not be parsed"))
}

/// Open a disc image by path: `.gdi`, `.cdi`, anything else as ISO, or a
/// `.zip` read in place (`archive.zip#member` to pick one). Every failure is
/// returned with its reason.
pub fn open_disc(spec: &str) -> Result<Box<dyn DiscFormat>, String> {
    let (path_str, member) = split_member(spec);
    let path = Path::new(path_str);
    if !path.is_file() {
        return Err(format!("no such disc image: {path_str}"));
    }

    if crate::disc_formats::zip::looks_like_zip(path) {
        let archive =
            std::rc::Rc::new(ZipArchive::open(path).map_err(|e| e.to_string())?);
        let member = match member {
            Some(want) => archive
                .find(want)
                .map(|e| e.name.clone())
                .ok_or_else(|| {
                    format!(
                        "{path_str} holds no member '{want}'. It holds: {}",
                        image_candidates(&archive).join(", ")
                    )
                })?,
            None => pick_zip_image(&archive, path_str)?,
        };
        info!("{path_str}: reading '{member}' from inside the archive");
        return open_zip_member(archive, &member);
    }

    if member.is_some() {
        warn!("{path_str} is not a zip archive; the '#member' part is ignored");
    }

    let lower = path_str.to_ascii_lowercase();
    if lower.ends_with(".gdi") {
        Gdi::open_path(path_str)
            .map(get_disc_format)
            .map_err(|e| format!("cannot read the GDI {path_str}: {e}"))
    } else {
        let src = FileSource::open(path).map_err(|e| format!("cannot open {path_str}: {e}"))?;
        open_cd(Box::new(src), &lower, path_str)
    }
}

/// A `.cdi` (by `lower`, the lowercased name), or else a plain ISO.
fn open_cd(
    src: Box<dyn ImageSource>,
    lower: &str,
    name: &str,
) -> Result<Box<dyn DiscFormat>, String> {
    if lower.ends_with(".cdi") {
        Cdi::new(src).map(get_disc_format)
    } else {
        Iso::new(src)
            .map(get_disc_format)
            .map_err(|e| format!("cannot read {name} as a plain ISO: {e}"))
    }
}

/// `archive.zip#member`, split only when the left half is a file (`#` is legal
/// in a path).
fn split_member(spec: &str) -> (&str, Option<&str>) {
    match spec.rsplit_once('#') {
        Some((left, right)) if !right.is_empty() && Path::new(left).is_file() => {
            (left, Some(right))
        }
        _ => (spec, None),
    }
}

const IMAGE_EXTENSIONS: [&str; 3] = [".gdi", ".cdi", ".iso"];

fn image_candidates(archive: &ZipArchive) -> Vec<String> {
    archive
        .entries()
        .iter()
        .filter(|e| !e.is_dir())
        // macOS metadata shadows, not images.
        .filter(|e| !e.name.starts_with("__MACOSX/"))
        .filter(|e| {
            let lower = e.name.to_ascii_lowercase();
            IMAGE_EXTENSIONS.iter().any(|x| lower.ends_with(x))
        })
        .map(|e| e.name.clone())
        .collect()
}

/// The image to read from an archive: `.gdi`, then `.cdi`, then `.iso`. Two of
/// the same kind is an error, not a guess.
fn pick_zip_image(archive: &ZipArchive, label: &str) -> Result<String, String> {
    let candidates = image_candidates(archive);
    for ext in IMAGE_EXTENSIONS {
        let of_kind: Vec<&str> = candidates
            .iter()
            .filter(|n| n.to_ascii_lowercase().ends_with(ext))
            .map(|n| n.as_str())
            .collect();
        match of_kind.len() {
            0 => continue,
            1 => return Ok(of_kind[0].to_string()),
            _ => {
                return Err(format!(
                    "{label} holds {} {ext} images and nothing says which one to run: \
                     {}. Name one with {label}#<member>.",
                    of_kind.len(),
                    of_kind.join(", ")
                ));
            }
        }
    }
    Err(format!(
        "{label} holds no .gdi, .cdi or .iso ({} members)",
        archive.entries().len()
    ))
}

fn open_zip_member(
    archive: std::rc::Rc<ZipArchive>,
    member: &str,
) -> Result<Box<dyn DiscFormat>, String> {
    let lower = member.to_ascii_lowercase();
    let base = member.rsplit('/').next().unwrap_or(member).to_string();
    if lower.ends_with(".gdi") {
        // Track files resolve next to the .gdi inside the archive.
        let prefix = match member.rfind('/') {
            Some(i) => member[..=i].to_string(),
            None => String::new(),
        };
        let container: Box<dyn Container> = Box::new(ZipContainer::new(archive.clone(), member));
        let gdi = Gdi::new(container, &base)
            .map_err(|e| format!("cannot read the GDI '{member}' in the archive: {e}"))?;
        // Index the audio tracks now, off the syscall path.
        crate::disc_formats::zip::warm_track_indexes(
            &archive,
            &prefix,
            &gdi.audio_track_files(),
        );
        return Ok(get_disc_format(gdi));
    }
    let src = archive.open_named(member).map_err(|e| e.to_string())?;
    open_cd(src, &lower, &format!("'{member}'"))
}

/// The title's boot binary, read out of the disc image.
pub fn boot_binary(
    spec: &str,
    mode: boot::Descramble,
    wince: boot::WinCe,
) -> Result<boot::BootBinary, String> {
    let disc = open_disc(spec)?;
    boot::extract(disc.as_ref(), mode, wince).map_err(|e| format!("{spec}: {e}"))
}

/// A disc image rather than something to upload: by extension, or a zip by
/// its magic.
pub fn is_disc_image(spec: &str) -> bool {
    let (path_str, _) = split_member(spec);
    let lower = path_str.to_ascii_lowercase();
    if IMAGE_EXTENSIONS.iter().any(|x| lower.ends_with(x)) {
        return true;
    }
    crate::disc_formats::zip::looks_like_zip(Path::new(path_str))
}
