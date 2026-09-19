//! The shipped patch library: which PPF belongs to which dump, and what this
//! host does with it.
//!
//! Some titles need a patch that no amount of looking at their code will
//! produce. `--vga` can force a Katana cable check and set a flag in IP.BIN,
//! because both of those are one known instruction and one known field; it
//! cannot give Snow Surfers the 60 Hz + VGA video path its PAL release was
//! built without. Somebody did that work in 2015, by hand, and shipped the
//! result as four bytes in a PPF. **That is what this module is for: patches
//! nobody can derive, only carry.**
//!
//! So, unlike `gaps_probe_patches` and `vga_cable_patches`, this one IS a
//! mapping list -- there is no content signature to find, because the thing
//! being fixed is different in every title. The list is `patches/patches.tsv`,
//! the patches sit beside it, and both travel with the loaders and
//! `game-presets.tsv` by the same search (`loaders::patch_dir_candidates`), so
//! a deployment has all of it or none of it.
//!
//! **A mapping list is a claim, and the patch itself can usually check it.** A
//! PPF3.0 carries 1024 bytes of the original file (`crate::ppf`), so the row
//! saying "this patch is for this dump" is verified against the image before
//! anything is written. A row that names the right file for the wrong dump is
//! then a refusal with a reason, not four bytes into the middle of live code.
//! The two keys are complementary and both are checked when present:
//!
//! - `disc_md5` -- the boot sector's MD5, the identity the rest of this host
//!   uses (DreamShell keys its presets on it, `presets::DiscIdentity`).
//! - `bin_md5` -- the MD5 of the UNPATCHED boot binary. Narrower, and the one
//!   that matters for a patch with no blockcheck, since it is then the only
//!   thing standing between the patch and the wrong image.
//!
//! **Patched on the host, before the upload, and guarded afterwards.** The
//! bytes go into the payload buffer, so what is uploaded is what runs, the
//! read-back verification checks the patched bytes like any other, and no round
//! trip is spent. The one thing that does not cover is a title reloading its
//! own image off the disc -- so the changed words are handed to the same reload
//! guard `--vga` and the GAPS guard already use (`dispatch::receive_syscalls`),
//! which puts them back before the title can run what was just delivered.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use log::warn;

use crate::ppf::{self, Fit, Ppf};

/// The manifest inside the patch directory.
pub const MANIFEST: &str = "patches.tsv";

/// Whether a row is applied by itself or has to be asked for.
///
/// `manual` is not a formality. A patch can be perfectly correct and still not
/// something to apply to somebody's session unasked -- the Snow Surfers patch
/// forces 60 Hz, which is a change to what the title does, not only to what it
/// supports. Shipping such a patch and letting `--ppf` reach it is better than
/// either applying it silently or not carrying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    Auto,
    Manual,
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Boot-sector MD5, or `None` when the row keys on the binary alone.
    pub disc_md5: Option<String>,
    /// MD5 of the unpatched boot binary, or `None`.
    pub bin_md5: Option<String>,
    pub file: String,
    pub when: When,
    pub title: String,
    pub note: String,
}

impl Entry {
    fn matches(&self, disc_md5: Option<&str>, bin_md5: &str) -> bool {
        let by_disc = matches!((self.disc_md5.as_deref(), disc_md5), (Some(a), Some(b)) if a == b);
        let by_bin = self.bin_md5.as_deref() == Some(bin_md5);
        by_disc || by_bin
    }
}

#[derive(Debug, Default)]
pub struct PatchDb {
    dir: Option<PathBuf>,
    entries: Vec<Entry>,
    /// Where it looked, for the message when it found nothing.
    searched: Vec<PathBuf>,
    /// Rows that could not be read. Kept rather than dropped: a manifest typo
    /// is otherwise indistinguishable from a title with no patch.
    pub problems: Vec<String>,
}

impl PatchDb {
    pub fn discover(explicit: Option<String>, loader_dir: &Path) -> Self {
        let exe = std::env::current_exe().ok();
        let cwd = std::env::current_dir().ok();
        let candidates = crate::loaders::patch_dir_candidates(
            explicit,
            std::env::var("DCLOAD_PATCH_DIR").ok(),
            loader_dir,
            exe.as_deref(),
            cwd.as_deref(),
            env!("CARGO_MANIFEST_DIR"),
        );
        let dir = candidates.iter().find(|p| p.is_dir()).cloned();
        let mut db = PatchDb {
            searched: candidates,
            dir,
            ..Default::default()
        };
        if let Some(dir) = db.dir.clone() {
            let manifest = dir.join(MANIFEST);
            match std::fs::read_to_string(&manifest) {
                Ok(text) => {
                    let (entries, problems) = parse_manifest(&text);
                    db.entries = entries;
                    db.problems = problems;
                }
                // Not an error: a directory of loose .ppf files with no
                // manifest still answers `--ppf` and still gets scanned for a
                // blockcheck that fits.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => db
                    .problems
                    .push(format!("{}: {e}", manifest.display())),
            }
        }
        db
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// How many rows the manifest holds, so "no patch for this dump" can say
    /// whether it looked at a list or at nothing.
    pub fn rows(&self) -> usize {
        self.entries.len()
    }

    /// Every place a patch directory was looked for. Printed when there is
    /// none: "no patches" and "the patches are somewhere this build does not
    /// look" are the same silence otherwise, and the second is the common one
    /// on a fresh checkout.
    pub fn searched(&self) -> String {
        self.searched
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn read(&self, file: &str) -> Result<(PathBuf, Ppf), String> {
        let dir = self.dir.as_deref().ok_or("no patch directory")?;
        let path = dir.join(file);
        let ppf = read_ppf(&path)?;
        Ok((path, ppf))
    }
}

/// Read and parse one `.ppf`, naming the file in every failure -- "not a PPF"
/// on its own has sent people looking at the wrong file more than once.
pub fn read_ppf(path: &Path) -> Result<Ppf, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    ppf::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse_manifest(text: &str) -> (Vec<Entry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut problems = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').map(str::trim).collect();
        if f.len() < 4 {
            problems.push(format!(
                "{MANIFEST} line {}: {} field(s), needs at least 4 \
                 (disc_md5, bin_md5, file, apply)",
                n + 1,
                f.len()
            ));
            continue;
        }
        // `-` is "no key of this kind". A row with neither is unreachable, and
        // silently keeping it is how a patch that never applies looks like a
        // patch that does not exist.
        let key = |s: &str| (s != "-" && !s.is_empty()).then(|| s.to_ascii_lowercase());
        let disc_md5 = key(f[0]);
        let bin_md5 = key(f[1]);
        if disc_md5.is_none() && bin_md5.is_none() {
            problems.push(format!(
                "{MANIFEST} line {}: neither disc_md5 nor bin_md5, so nothing can \
                 ever match this row",
                n + 1
            ));
            continue;
        }
        let when = match f[3].to_ascii_lowercase().as_str() {
            "auto" => When::Auto,
            "manual" => When::Manual,
            other => {
                problems.push(format!(
                    "{MANIFEST} line {}: apply is {other:?}, expected auto or manual \
                     -- treating it as manual",
                    n + 1
                ));
                When::Manual
            }
        };
        entries.push(Entry {
            disc_md5,
            bin_md5,
            file: f[2].to_string(),
            when,
            title: f.get(4).unwrap_or(&"").to_string(),
            note: f.get(5).unwrap_or(&"").to_string(),
        });
    }
    (entries, problems)
}

/// Why a patch is in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Named on the command line with `--ppf`.
    Explicit,
    /// A manifest row for this dump.
    Listed,
    /// Not in the manifest, but its own blockcheck says it is for this exact
    /// image. Reported, never applied -- see `Plan::offer`.
    Fits,
    /// A manifest row for this dump, held back by `--no-ppf`.
    ///
    /// Still reported, and that is the point of the variant: an off-switch
    /// that also silences "there is a patch for this game" turns an A/B test
    /// into a fact nobody is told twice.
    Disabled,
}

#[derive(Debug)]
pub struct Chosen {
    /// The path as given or as resolved -- never a bare filename. Which file
    /// on disk was applied is exactly the question a surprising result raises,
    /// and a deployment can have more than one directory of these.
    pub name: String,
    pub source: Source,
    pub fit: Fit,
    pub note: String,
    pub ppf: Ppf,
}

impl Chosen {
    /// One line for a log or for `identify`.
    pub fn describe(&self) -> String {
        format!(
            "{}{} ({}, {} record(s), {} byte(s); {})",
            self.name,
            match self.source {
                // Said, because "the manifest names it" and "the image itself
                // vouches for it" are different claims and only one of them
                // was a decision somebody made about this game.
                Source::Fits => " [not listed; its blockcheck matches this image]",
                Source::Disabled => " [listed for this dump; held back by --no-ppf]",
                _ => "",
            },
            self.ppf.version.name(),
            self.ppf.records.len(),
            self.ppf.patch_bytes(),
            self.fit
        )
    }
}

#[derive(Debug, Default)]
pub struct Plan {
    /// Where the library was found and how big it is. Printed when the plan is
    /// otherwise empty, because "this game has no patch" and "this build never
    /// found the patches" look identical without it -- and on a fresh checkout
    /// the second is the likely one.
    pub summary: String,
    /// Applied, in order.
    pub apply: Vec<Chosen>,
    /// Available and not applied: a `manual` row, or a loose file that fits.
    pub offer: Vec<Chosen>,
    /// Everything that went wrong, phrased for a human.
    pub problems: Vec<String>,
}

/// Work out what to do with the patch library for this image.
///
/// `enabled` is `--no-ppf` inverted, and it turns off the manifest, NOT
/// `--ppf`: a patch the user named by hand is not something the library's
/// off-switch should silently discard.
pub fn plan(
    db: &PatchDb,
    disc_md5: Option<&str>,
    image: &[u8],
    explicit: &[String],
    enabled: bool,
) -> Plan {
    let mut out = Plan {
        problems: db.problems.clone(),
        summary: match db.dir() {
            Some(d) => format!("{} row(s) in {}", db.rows(), d.join(MANIFEST).display()),
            None => format!("no patch directory found (looked in {})", db.searched()),
        },
        ..Default::default()
    };
    let bin_md5 = format!("{:x}", md5::compute(image));
    // Which files the manifest already speaks for, so the loose-file scan does
    // not offer a patch that is being applied two lines above.
    let mut spoken_for: Vec<String> = Vec::new();

    for path in explicit {
        match read_ppf(Path::new(path)) {
            Ok(p) => {
                let fit = p.fit(image);
                spoken_for.push(
                    Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.clone()),
                );
                let note = describe_self(&p);
                let chosen = Chosen {
                    name: path.clone(),
                    source: Source::Explicit,
                    note,
                    fit: fit.clone(),
                    ppf: p,
                };
                // A named patch that does not fit is REFUSED, not forced. Its
                // offsets mean something else in this image, so applying it
                // writes correct bytes into the wrong instructions -- a title
                // that boots and then misbehaves, which is the single most
                // expensive thing this file can produce.
                if fit.permits_apply() {
                    out.apply.push(chosen);
                } else {
                    out.problems.push(format!(
                        "--ppf {path}: {fit} -- REFUSED. This patch is for another dump."
                    ));
                }
            }
            Err(e) => out.problems.push(format!("--ppf: {e}")),
        }
    }

    {
        for e in db.entries.iter().filter(|e| e.matches(disc_md5, &bin_md5)) {
            // Claimed by a row whether or not the row is acted on, so the
            // loose-file scan below does not re-offer it as "not listed".
            spoken_for.push(e.file.clone());
            let (path, p) = match db.read(&e.file) {
                Ok(p) => p,
                Err(err) => {
                    out.problems.push(format!(
                        "{MANIFEST} names {} for this game, and it could not be read: {err}",
                        e.file
                    ));
                    continue;
                }
            };
            let fit = p.fit(image);
            let chosen = Chosen {
                name: path.display().to_string(),
                source: if enabled {
                    Source::Listed
                } else {
                    Source::Disabled
                },
                note: if e.note.is_empty() {
                    describe_self(&p)
                } else {
                    e.note.clone()
                },
                fit: fit.clone(),
                ppf: p,
            };
            match (fit.permits_apply(), enabled, e.when) {
                // Reported even under --no-ppf: a row that names the wrong
                // dump is a fact about the manifest, not an action to take.
                (false, _, _) => out.problems.push(format!(
                    "{MANIFEST} says {} is for {}, and this image matched the row, but the \
                     patch {fit} -- NOT applied. Either the row names the wrong dump or \
                     this image is not the one the patch was made for.",
                    e.file,
                    if e.title.is_empty() { "this game" } else { &e.title }
                )),
                (true, false, _) => out.offer.push(chosen),
                (true, true, When::Auto) => out.apply.push(chosen),
                (true, true, When::Manual) => out.offer.push(chosen),
            }
        }
    }

    // Loose files whose own blockcheck says they are for this exact image.
    // Costs one read and one memcmp per file and needs no row, so a patch
    // dropped into the directory says so instead of sitting there unmentioned.
    // Offered and never applied: fitting is not the same as being wanted, and
    // the manifest is where "wanted" is recorded.
    if let Some(dir) = db.dir()
        && let Ok(rd) = std::fs::read_dir(dir)
    {
        // Sorted, so two runs over the same directory report in the same order.
        let mut loose: BTreeMap<String, PathBuf> = BTreeMap::new();
        for entry in rd.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("ppf"))
                && !spoken_for.contains(&name)
            {
                loose.insert(name, path);
            }
        }
        for (_name, path) in loose {
            match read_ppf(&path) {
                // Only `Verified`. An unverifiable patch fits every image
                // equally, so offering those would offer the whole directory.
                Ok(p) if p.fit(image) == Fit::Verified => out.offer.push(Chosen {
                    name: path.display().to_string(),
                    source: Source::Fits,
                    note: describe_self(&p),
                    fit: Fit::Verified,
                    ppf: p,
                }),
                Ok(_) => {}
                Err(e) => warn!("{e}"),
            }
        }
    }
    out
}

/// What a patch says about itself, best first: its FILE_ID.DIZ note, then the
/// 50-byte description field. Only used when the manifest row has nothing to
/// say -- a row's note is somebody writing about THIS game, and the patch's own
/// text is the author writing about the patch.
fn describe_self(p: &Ppf) -> String {
    match p.file_id.as_deref().map(str::trim) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => p.description.clone(),
    }
}

/// The words the reload guard has to put back.
///
/// A PPF changes bytes; the guard writes 32-bit words (`dispatch::apply_patches`
/// -- a word is what `send_data` and its read-back check deal in). So each
/// changed byte is widened to the aligned word containing it, taken from the
/// image AFTER patching, and duplicates are folded: four bytes in one word are
/// one write, not four.
///
/// Alignment is done in the CONSOLE's address space, not in the file's, because
/// those differ whenever the load address is not a multiple of four -- and an
/// unaligned word write is one of the few things on SH4 that fails quietly.
pub fn guard_words(changed: &[ppf::Change], image: &[u8], load_at: u32) -> Vec<(u32, u32)> {
    let mut out: BTreeMap<u32, u32> = BTreeMap::new();
    for c in changed {
        let at = load_at.wrapping_add(c.offset as u32);
        let word_at = at & !3;
        let off = (word_at.wrapping_sub(load_at)) as usize;
        if off + 4 > image.len() {
            continue;
        }
        let word = u32::from_le_bytes([image[off], image[off + 1], image[off + 2], image[off + 3]]);
        out.insert(word_at, word);
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ppf3(bc: Option<&[u8]>, recs: &[(u64, &[u8])]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(b"PPF30");
        f.push(2);
        f.extend_from_slice(&[b' '; 50]);
        f.extend_from_slice(&[0, bc.is_some() as u8, 0, 0]);
        if let Some(bc) = bc {
            f.extend_from_slice(bc);
        }
        for (off, data) in recs {
            f.extend_from_slice(&off.to_le_bytes());
            f.push(data.len() as u8);
            f.extend_from_slice(data);
        }
        f
    }

    fn db_in(dir: &Path, manifest: &str, files: &[(&str, Vec<u8>)]) -> PatchDb {
        std::fs::write(dir.join(MANIFEST), manifest).unwrap();
        for (name, bytes) in files {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let (entries, problems) = parse_manifest(manifest);
        PatchDb {
            dir: Some(dir.to_path_buf()),
            entries,
            searched: vec![],
            problems,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dcload-patchdb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_row_matches_on_either_key() {
        let e = Entry {
            disc_md5: Some("aa".into()),
            bin_md5: None,
            file: "x.ppf".into(),
            when: When::Auto,
            title: String::new(),
            note: String::new(),
        };
        assert!(e.matches(Some("aa"), "zz"));
        assert!(!e.matches(Some("bb"), "zz"));
        let e = Entry {
            disc_md5: None,
            bin_md5: Some("zz".into()),
            ..e
        };
        assert!(e.matches(None, "zz"));
        assert!(!e.matches(Some("aa"), "yy"));
    }

    #[test]
    fn a_row_with_no_key_at_all_is_a_problem_not_a_silent_drop() {
        let (entries, problems) = parse_manifest("-\t-\tx.ppf\tauto\n");
        assert!(entries.is_empty());
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn an_auto_row_is_applied_and_a_manual_row_is_only_offered() {
        let dir = tmp("when");
        let image = vec![0u8; 64];
        let bin = format!("{:x}", md5::compute(&image));
        let db = db_in(
            &dir,
            &format!(
                "# c\n\
                 -\t{bin}\ta.ppf\tauto\tGame\tnote a\n\
                 -\t{bin}\tb.ppf\tmanual\tGame\tnote b\n"
            ),
            &[
                ("a.ppf", ppf3(None, &[(0, &[1])])),
                ("b.ppf", ppf3(None, &[(1, &[2])])),
            ],
        );
        let p = plan(&db, None, &image, &[], true);
        assert_eq!(p.apply.len(), 1);
        assert!(p.apply[0].name.ends_with("a.ppf"), "{}", p.apply[0].name);
        assert_eq!(p.apply[0].note, "note a");
        assert_eq!(p.offer.len(), 1);
        assert!(p.offer[0].name.ends_with("b.ppf"), "{}", p.offer[0].name);
        assert!(p.problems.is_empty(), "{:?}", p.problems);

        // --no-ppf applies nothing -- and still says both patches exist,
        // labelled as held back rather than as strays nobody listed.
        let off = plan(&db, None, &image, &[], false);
        assert!(off.apply.is_empty());
        assert_eq!(off.offer.len(), 2);
        assert!(off.offer.iter().all(|c| c.source == Source::Disabled));
    }

    /// The row is right about the game and wrong about the dump. That has to
    /// be a refusal with a reason: applying it writes correct bytes into the
    /// wrong instructions.
    #[test]
    fn a_listed_patch_whose_blockcheck_fails_is_refused() {
        let dir = tmp("mismatch");
        let mut image = vec![0u8; 0x9320 + ppf::BLOCKCHECK_LEN];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut wrong = image[0x9320..0x9320 + ppf::BLOCKCHECK_LEN].to_vec();
        wrong[0] ^= 0xff;
        let bin = format!("{:x}", md5::compute(&image));
        let db = db_in(
            &dir,
            &format!("-\t{bin}\tx.ppf\tauto\tGame\t\n"),
            &[("x.ppf", ppf3(Some(&wrong), &[(0, &[9])]))],
        );
        let p = plan(&db, None, &image, &[], true);
        assert!(p.apply.is_empty());
        assert_eq!(p.problems.len(), 1);
        assert!(p.problems[0].contains("NOT applied"), "{:?}", p.problems);
        assert_eq!(image[0], 0, "nothing may have been written");
    }

    /// A loose file that the image itself vouches for is worth saying so about,
    /// and is still not applied: fitting is not the same as being wanted.
    #[test]
    fn an_unlisted_patch_that_fits_is_offered_never_applied() {
        let dir = tmp("loose");
        let mut image = vec![0u8; 0x9320 + ppf::BLOCKCHECK_LEN];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 241) as u8;
        }
        let bc = image[0x9320..0x9320 + ppf::BLOCKCHECK_LEN].to_vec();
        let db = db_in(
            &dir,
            "# nothing listed\n",
            &[
                ("fits.ppf", ppf3(Some(&bc), &[(0, &[7])])),
                ("blind.ppf", ppf3(None, &[(0, &[7])])),
            ],
        );
        let p = plan(&db, None, &image, &[], true);
        assert!(p.apply.is_empty());
        // Only the one that can prove it. An unverifiable patch fits every
        // image equally, so offering those would offer the directory.
        assert_eq!(p.offer.len(), 1);
        assert!(p.offer[0].name.ends_with("fits.ppf"), "{}", p.offer[0].name);
        assert_eq!(p.offer[0].source, Source::Fits);
    }

    #[test]
    fn guard_words_fold_bytes_into_the_words_that_hold_them() {
        // Two bytes in one word, one in the next.
        let image = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let changed = [
            ppf::Change {
                offset: 1,
                from: 0,
                to: 0x22,
            },
            ppf::Change {
                offset: 2,
                from: 0,
                to: 0x33,
            },
            ppf::Change {
                offset: 5,
                from: 0,
                to: 0x66,
            },
        ];
        let w = guard_words(&changed, &image, 0x0c01_0000);
        assert_eq!(
            w,
            vec![(0x0c01_0000, 0x4433_2211), (0x0c01_0004, 0x8877_6655)]
        );
    }

    /// A change in the last partial word is dropped rather than read past the
    /// end of the image.
    #[test]
    fn guard_words_stop_at_the_end_of_the_image() {
        let image = vec![0u8; 6];
        let changed = [ppf::Change {
            offset: 5,
            from: 0,
            to: 1,
        }];
        assert!(guard_words(&changed, &image, 0x0c01_0000).is_empty());
    }
}
