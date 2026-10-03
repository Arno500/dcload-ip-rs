//! PPF -- the file format the Dreamcast scene ships a binary patch in.
//!
//! A PPF is a list of "at file offset N, the bytes are these instead". That is
//! all it is: no relocation, no symbols, no conditions. What makes it worth a
//! module rather than a loop is the part that says WHICH file it is for, and
//! getting that wrong is not a visible failure -- a patch aimed at another dump
//! writes plausible bytes into the middle of live SH4 code, and what comes back
//! is a title that boots and then behaves strangely. So every check the format
//! offers is enforced, and a patch that cannot prove it belongs is refused
//! rather than applied hopefully.
//!
//! Three versions exist and all three are read here, because a patch is
//! typically fifteen years old and nobody is going to re-master it:
//!
//! | | header | offsets | integrity |
//! | --- | --- | --- | --- |
//! | PPF1.0 | 56 B | 32-bit | **none at all** |
//! | PPF2.0 | 56 B + 4 B original size + 1024 B | 32-bit | size + block |
//! | PPF3.0 | 56 B + 4 B flags + optional 1024 B | 64-bit | block, optional |
//!
//! **The blockcheck is the useful one, and it is content, not a name.** It is
//! 1024 bytes copied out of the ORIGINAL file at a fixed offset -- 0x9320 for a
//! plain binary, 0x80a0 for a GI image -- so it identifies the exact bytes the
//! patch was made against without needing a database, a filename or a title.
//! Where a patch carries one, this module treats a mismatch as fatal: that is
//! the whole difference between "the shipped mapping list said so" and "the
//! image itself agrees".
//!
//! A PPF1.0, and a PPF3.0 built with the blockcheck off, carry nothing of the
//! kind. Those are the ones the manifest's `bin_md5` column exists for
//! (`crate::patchdb`), and applying one is an act of faith by construction.
//!
//! Measured, 2026-08-31, on `jc-snows-60hz-vga.ppf` against the 1ST_READ.BIN of
//! `Snow Surfers v1.001 (1999)(Sega)(PAL)[!]`: PPF3.0, blockcheck present and
//! matching, four single-byte records, and the result is
//! `1ST_READ_PATCHED.BIN` from the same archive byte for byte. That round trip
//! is the parser's test (`reproduces_the_shipped_patched_binary` needs the
//! dump, so the unit tests below build the same shapes synthetically).

use std::fmt;

/// Bytes of the original file a blockcheck covers.
pub const BLOCKCHECK_LEN: usize = 1024;

/// Where those bytes are taken from, per image type.
///
/// Both are inside the header region of the media the format was designed for
/// (PlayStation CD images), which is why they look arbitrary here. They are
/// arbitrary here -- what matters is only that the patch author and this reader
/// pick the same 1024 bytes.
const BLOCKCHECK_AT_BIN: u64 = 0x9320;
const BLOCKCHECK_AT_GI: u64 = 0x80a0;

/// The marker that ends the record list. Everything after it is the author's
/// FILE_ID.DIZ note, not patch data.
///
/// It is looked for AT A RECORD BOUNDARY, never with a search over the whole
/// file. A blind search finds a note that quotes the marker, and -- measured on
/// the Snow Surfers patch -- the tool that wrote it appended the block THREE
/// times, so "the last one" and "the first one" disagree about where the data
/// stops. At a boundary there is no ambiguity: a record starts with an offset,
/// and the trailer starts with this.
const FILE_ID_MARKER: &[u8] = b"@BEGIN_FILE_ID.DIZ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl Version {
    pub fn name(self) -> &'static str {
        match self {
            Version::V1 => "PPF1.0",
            Version::V2 => "PPF2.0",
            Version::V3 => "PPF3.0",
        }
    }
}

/// One "at this offset, these bytes".
#[derive(Debug, Clone)]
pub struct Record {
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Ppf {
    pub version: Version,
    /// The 50-byte description field. Latin-1 by convention, trimmed.
    pub description: String,
    /// PPF3 only: 0 = plain binary, 1 = GI. Decides where a blockcheck is taken
    /// from; 0 for everything this host deals with.
    pub image_type: u8,
    pub blockcheck: Option<Vec<u8>>,
    /// PPF2 only: the length the original file must have.
    pub original_len: Option<u64>,
    pub records: Vec<Record>,
    /// The author's note, when there is one. Worth logging: it is usually the
    /// only place a patch says what it does.
    pub file_id: Option<String>,
}

/// What a patch has to say about the image it was handed.
///
/// Deliberately not a `bool`. "This patch does not fit" and "this patch cannot
/// tell whether it fits" call for completely different things from whoever
/// reads the log, and collapsing them is how a patch with no integrity data at
/// all gets reported as verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fit {
    /// A blockcheck was present and matched. The strongest answer available.
    Verified,
    /// Nothing in the patch can identify the image. PPF1.0, or PPF3.0 written
    /// with the blockcheck off.
    Unverifiable,
    /// A blockcheck was present and did NOT match: this patch is for another
    /// dump. `at` is where the two first differ, as a hint for the human.
    Mismatch { at: usize },
    /// The image is too short to hold the blockcheck region, or a record.
    TooShort { needed: u64, got: u64 },
    /// PPF2 only: the length is stated and disagrees.
    WrongLength { want: u64, got: u64 },
}

impl fmt::Display for Fit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fit::Verified => write!(f, "blockcheck matches this image"),
            Fit::Unverifiable => write!(
                f,
                "carries no blockcheck, so nothing in it can confirm the image"
            ),
            Fit::Mismatch { at } => write!(
                f,
                "blockcheck does NOT match this image (first difference at byte {at} of 1024)"
            ),
            Fit::TooShort { needed, got } => write!(
                f,
                "needs an image of at least {needed} bytes, this one is {got}"
            ),
            Fit::WrongLength { want, got } => {
                write!(f, "is for a {want}-byte image, this one is {got}")
            }
        }
    }
}

impl Fit {
    /// Whether applying is defensible. `Unverifiable` is included: refusing
    /// every PPF1.0 would refuse most of what exists, and the manifest's own
    /// keys are then what stands behind it.
    pub fn permits_apply(&self) -> bool {
        matches!(self, Fit::Verified | Fit::Unverifiable)
    }
}

/// One byte the patch changed, kept so the caller can say what it did and turn
/// the result into something else -- the reload guard, in this host's case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub offset: u64,
    pub from: u8,
    pub to: u8,
}

#[derive(Debug, Clone, Default)]
pub struct Applied {
    /// Bytes that were actually different. A patch already applied to the image
    /// reports zero of these and is not an error -- see `already_applied`.
    pub changed: Vec<Change>,
    /// Bytes written that already held the wanted value.
    pub already: usize,
}

impl Applied {
    /// Every record's bytes were already in place. The honest reading of a
    /// pre-patched dump, and worth saying out loud rather than reporting "0
    /// bytes patched" as if nothing had matched.
    pub fn already_applied(&self) -> bool {
        self.changed.is_empty() && self.already > 0
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn le64(b: &[u8]) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[..8]);
    u64::from_le_bytes(v)
}

/// The 50-byte text fields are Latin-1 and space-padded. Decoded byte for byte
/// rather than as UTF-8: an author's name with an accent in it is not a reason
/// to fail to read a patch.
fn latin1(b: &[u8]) -> String {
    b.iter()
        .map(|&c| c as char)
        .collect::<String>()
        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string()
}

pub fn parse(bytes: &[u8]) -> Result<Ppf, String> {
    if bytes.len() < 56 {
        return Err(format!(
            "too short to be a PPF at all ({} bytes; the header alone is 56)",
            bytes.len()
        ));
    }
    let version = match &bytes[..5] {
        b"PPF10" => Version::V1,
        b"PPF20" => Version::V2,
        b"PPF30" => Version::V3,
        other => {
            return Err(format!(
                "not a PPF: magic is {:?}, expected PPF10, PPF20 or PPF30",
                String::from_utf8_lossy(other)
            ));
        }
    };
    // The encoding byte repeats the version. A disagreement means the file was
    // edited or truncated into another one, so it is worth refusing rather than
    // guessing which of the two to believe.
    let encoding = bytes[5];
    let want_encoding = match version {
        Version::V1 => 0,
        Version::V2 => 1,
        Version::V3 => 2,
    };
    if encoding != want_encoding {
        return Err(format!(
            "{} with encoding byte {encoding}, expected {want_encoding} -- \
             the header contradicts itself",
            version.name()
        ));
    }
    let description = latin1(&bytes[6..56]);

    let mut p = 56usize;
    let mut image_type = 0u8;
    let mut blockcheck = None;
    let mut original_len = None;
    let mut undo = false;
    let offset_width;

    match version {
        Version::V1 => {
            offset_width = 4;
        }
        Version::V2 => {
            offset_width = 4;
            if bytes.len() < p + 4 + BLOCKCHECK_LEN {
                return Err("PPF2.0 truncated before its blockcheck".to_string());
            }
            original_len = Some(le32(&bytes[p..]) as u64);
            p += 4;
            blockcheck = Some(bytes[p..p + BLOCKCHECK_LEN].to_vec());
            p += BLOCKCHECK_LEN;
        }
        Version::V3 => {
            offset_width = 8;
            if bytes.len() < p + 4 {
                return Err("PPF3.0 truncated before its flags".to_string());
            }
            image_type = bytes[p];
            let has_blockcheck = bytes[p + 1] != 0;
            undo = bytes[p + 2] != 0;
            p += 4;
            if has_blockcheck {
                if bytes.len() < p + BLOCKCHECK_LEN {
                    return Err("PPF3.0 says it has a blockcheck, and is truncated before it"
                        .to_string());
                }
                blockcheck = Some(bytes[p..p + BLOCKCHECK_LEN].to_vec());
                p += BLOCKCHECK_LEN;
            }
        }
    }

    let mut records = Vec::new();
    let mut file_id = None;
    while p < bytes.len() {
        // The trailer, if this is where it starts. Checked here and only here
        // -- see FILE_ID_MARKER.
        if bytes[p..].starts_with(FILE_ID_MARKER) {
            file_id = Some(latin1(&bytes[p + FILE_ID_MARKER.len()..]));
            break;
        }
        if p + offset_width + 1 > bytes.len() {
            return Err(format!(
                "truncated inside record {} (offset field runs past the end of the file)",
                records.len()
            ));
        }
        let offset = if offset_width == 8 {
            le64(&bytes[p..])
        } else {
            le32(&bytes[p..]) as u64
        };
        p += offset_width;
        let len = bytes[p] as usize;
        p += 1;
        // A zero-length record carries no data and cannot terminate anything:
        // taking it would loop forever on a corrupt file.
        if len == 0 {
            return Err(format!(
                "record {} at offset 0x{offset:x} claims zero bytes",
                records.len()
            ));
        }
        // `undo` doubles every record: the patched bytes, then the originals.
        // We keep only the first half -- this host never un-patches, it simply
        // re-reads the image -- but the second half still has to be stepped
        // over or every subsequent offset is garbage.
        let stride = if undo { len * 2 } else { len };
        if p + stride > bytes.len() {
            return Err(format!(
                "truncated inside record {} at offset 0x{offset:x} \
                 ({len} bytes claimed, {} left in the file)",
                records.len(),
                bytes.len() - p
            ));
        }
        records.push(Record {
            offset,
            data: bytes[p..p + len].to_vec(),
        });
        p += stride;
    }

    if records.is_empty() {
        return Err("valid header, but no patch records at all".to_string());
    }

    Ok(Ppf {
        version,
        description,
        image_type,
        blockcheck,
        original_len,
        records,
        file_id,
    })
}

impl Ppf {
    /// Total bytes this patch writes, records summed. Not the number of bytes
    /// it will CHANGE -- see `Applied::changed` for that.
    pub fn patch_bytes(&self) -> usize {
        self.records.iter().map(|r| r.data.len()).sum()
    }

    /// The highest byte the patch touches, so a caller can size an image.
    pub fn end(&self) -> u64 {
        self.records
            .iter()
            .map(|r| r.offset.saturating_add(r.data.len() as u64))
            .max()
            .unwrap_or(0)
    }

    fn blockcheck_at(&self) -> u64 {
        match (self.version, self.image_type) {
            (Version::V3, 1) => BLOCKCHECK_AT_GI,
            _ => BLOCKCHECK_AT_BIN,
        }
    }

    /// Does this patch belong to this image? Everything the format can say,
    /// and nothing it cannot.
    pub fn fit(&self, image: &[u8]) -> Fit {
        let len = image.len() as u64;
        if let Some(want) = self.original_len
            && want != len
        {
            return Fit::WrongLength { want, got: len };
        }
        // Checked before the blockcheck, because a record past the end is the
        // more useful thing to report: it says the image is the wrong file,
        // even for a patch that carries no blockcheck to say so.
        let end = self.end();
        if end > len {
            return Fit::TooShort {
                needed: end,
                got: len,
            };
        }
        let Some(bc) = self.blockcheck.as_deref() else {
            return Fit::Unverifiable;
        };
        let at = self.blockcheck_at();
        let needed = at + BLOCKCHECK_LEN as u64;
        if needed > len {
            return Fit::TooShort { needed, got: len };
        }
        let have = &image[at as usize..(at as usize + BLOCKCHECK_LEN)];
        match have.iter().zip(bc).position(|(a, b)| a != b) {
            None => Fit::Verified,
            Some(at) => Fit::Mismatch { at },
        }
    }

    /// Write the records into `image`, in place.
    ///
    /// `fit` is NOT called from here: the caller decides what to do about an
    /// unverifiable patch, and a function that silently refused would make
    /// "nothing was applied" and "the patch does not fit" the same outcome.
    /// What is refused here is only what cannot be done at all -- a record
    /// outside the image -- because writing part of a patch is worse than
    /// writing none of it.
    pub fn apply(&self, image: &mut [u8]) -> Result<Applied, String> {
        let end = self.end();
        if end > image.len() as u64 {
            return Err(format!(
                "this patch writes up to byte 0x{end:x} and the image is 0x{:x} long -- \
                 refusing to apply any of it",
                image.len()
            ));
        }
        let mut out = Applied::default();
        for r in &self.records {
            for (i, &to) in r.data.iter().enumerate() {
                let off = r.offset + i as u64;
                let slot = &mut image[off as usize];
                if *slot == to {
                    out.already += 1;
                } else {
                    out.changed.push(Change {
                        offset: off,
                        from: *slot,
                        to,
                    });
                    *slot = to;
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v3(image_type: u8, blockcheck: Option<&[u8]>, undo: bool, recs: &[(u64, &[u8])]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(b"PPF30");
        f.push(2);
        f.extend_from_slice(&[b' '; 50]);
        f.push(image_type);
        f.push(blockcheck.is_some() as u8);
        f.push(undo as u8);
        f.push(0);
        if let Some(bc) = blockcheck {
            f.extend_from_slice(bc);
        }
        for (off, data) in recs {
            f.extend_from_slice(&off.to_le_bytes());
            f.push(data.len() as u8);
            f.extend_from_slice(data);
            if undo {
                f.extend(std::iter::repeat_n(0xaau8, data.len()));
            }
        }
        f
    }

    #[test]
    fn reads_a_v3_with_no_blockcheck() {
        let f = v3(0, None, false, &[(4, &[1, 2, 3])]);
        let p = parse(&f).unwrap();
        assert_eq!(p.version, Version::V3);
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.patch_bytes(), 3);
        assert_eq!(p.end(), 7);
        assert_eq!(p.fit(&vec![0u8; 64]), Fit::Unverifiable);
    }

    /// The undo half doubles each record and must be stepped over, or every
    /// offset after the first one is read out of the previous record's data.
    #[test]
    fn steps_over_undo_data() {
        let f = v3(0, None, true, &[(0, &[1, 2]), (16, &[3, 4])]);
        let p = parse(&f).unwrap();
        assert_eq!(p.records.len(), 2);
        assert_eq!(p.records[1].offset, 16);
        assert_eq!(p.records[1].data, vec![3, 4]);
    }

    #[test]
    fn a_blockcheck_that_matches_verifies_and_one_that_does_not_is_fatal() {
        let mut image = vec![0u8; 0x9320 + BLOCKCHECK_LEN + 16];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let bc = image[0x9320..0x9320 + BLOCKCHECK_LEN].to_vec();
        let f = v3(0, Some(&bc), false, &[(0, &[0xff])]);
        let p = parse(&f).unwrap();
        assert_eq!(p.fit(&image), Fit::Verified);

        let mut other = image.clone();
        other[0x9320 + 7] ^= 0xff;
        assert_eq!(p.fit(&other), Fit::Mismatch { at: 7 });
        assert!(!p.fit(&other).permits_apply());
    }

    /// A GI patch takes its blockcheck from a different offset. Reading it at
    /// the binary offset would report a mismatch for a patch that fits.
    #[test]
    fn gi_images_check_a_different_offset() {
        let mut image = vec![0u8; 0x9320 + BLOCKCHECK_LEN];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        let bc = image[0x80a0..0x80a0 + BLOCKCHECK_LEN].to_vec();
        let p = parse(&v3(1, Some(&bc), false, &[(0, &[1])])).unwrap();
        assert_eq!(p.fit(&image), Fit::Verified);
    }

    #[test]
    fn applying_reports_what_changed_and_what_was_already_there() {
        let p = parse(&v3(0, None, false, &[(2, &[0xaa, 0xbb])])).unwrap();
        let mut image = vec![0u8, 0, 0, 0xbb, 0, 0];
        let a = p.apply(&mut image).unwrap();
        assert_eq!(a.already, 1);
        assert_eq!(
            a.changed,
            vec![Change {
                offset: 2,
                from: 0,
                to: 0xaa
            }]
        );
        assert_eq!(image, vec![0, 0, 0xaa, 0xbb, 0, 0]);

        // Second time round: nothing left to do, and that is not "no records
        // matched".
        let again = p.apply(&mut image).unwrap();
        assert!(again.already_applied());
    }

    /// Applying part of a patch is worse than applying none: half a code change
    /// is a title that runs and misbehaves, which is exactly the failure this
    /// module exists to prevent.
    #[test]
    fn a_record_past_the_end_applies_nothing() {
        let p = parse(&v3(0, None, false, &[(0, &[1]), (99, &[2])])).unwrap();
        let mut image = vec![0u8; 8];
        assert!(p.apply(&mut image).is_err());
        assert_eq!(image, vec![0u8; 8]);
        assert_eq!(p.fit(&image), Fit::TooShort { needed: 100, got: 8 });
    }

    /// A note that quotes the marker must not truncate the record list, which
    /// is why the trailer is only looked for at a record boundary.
    #[test]
    fn a_record_containing_the_marker_is_still_data() {
        let mut f = v3(0, None, false, &[(0, FILE_ID_MARKER)]);
        f.extend_from_slice(FILE_ID_MARKER);
        f.extend_from_slice(b" hello");
        let p = parse(&f).unwrap();
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.records[0].data, FILE_ID_MARKER.to_vec());
        assert_eq!(p.file_id.as_deref(), Some("hello"));
    }

    #[test]
    fn rejects_things_that_are_not_ppfs() {
        assert!(parse(b"not a patch at all").is_err());
        let mut f = v3(0, None, false, &[(0, &[1])]);
        f[5] = 9;
        assert!(parse(&f).is_err());
        // Header only: valid as far as it goes, and useless.
        assert!(parse(&v3(0, None, false, &[])).is_err());
    }

    /// The shipped patch, read as it lies. A regression guard on the parser
    /// AND on the file: four single bytes is the whole of it, and if that ever
    /// reads differently the patch in `patches/` is not the one measured here.
    #[test]
    fn the_shipped_snow_surfers_patch_is_four_bytes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("patches")
            .join("jc-snows-60hz-vga.ppf");
        let p = parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(p.version, Version::V3);
        assert_eq!(p.image_type, 0);
        assert!(p.blockcheck.is_some());
        let recs: Vec<(u64, Vec<u8>)> = p
            .records
            .iter()
            .map(|r| (r.offset, r.data.clone()))
            .collect();
        assert_eq!(
            recs,
            vec![
                (0x4d1e6, vec![0x01]),
                (0x4d1fa, vec![0x31]),
                (0x4d30c, vec![0x38]),
                (0x4d30e, vec![0x00]),
            ]
        );
    }

    /// END TO END, against the dump the patch was made for.
    ///
    /// Ignored by default because it needs two files this repository does not
    /// carry and must not: a 1.3 MB retail binary and the author's pre-patched
    /// copy of it. Run it with both in hand -- it is the only test that proves
    /// the whole path rather than the shapes:
    ///
    /// ```text
    /// dcload-ip-rs extract "<image>.gdi" -o /tmp/orig.bin
    /// unzip jc-snows-60hz-vga.zip -d /tmp/jc
    /// DCLOAD_TEST_ORIG=/tmp/orig.bin \
    /// DCLOAD_TEST_PATCHED=/tmp/jc/1ST_READ_PATCHED.BIN \
    ///   cargo test -- --ignored reproduces_the_shipped_patched_binary
    /// ```
    ///
    /// Measured 2026-08-31 on `Snow Surfers v1.001 (1999)(Sega)(PAL)[!]`:
    /// blockcheck verified, four bytes changed, and the result equals
    /// `1ST_READ_PATCHED.BIN` byte for byte.
    #[test]
    #[ignore = "needs the retail dump and the author's patched copy"]
    fn reproduces_the_shipped_patched_binary() {
        let (Ok(orig), Ok(want)) = (
            std::env::var("DCLOAD_TEST_ORIG"),
            std::env::var("DCLOAD_TEST_PATCHED"),
        ) else {
            panic!("set DCLOAD_TEST_ORIG and DCLOAD_TEST_PATCHED");
        };
        let mut image = std::fs::read(orig).unwrap();
        let want = std::fs::read(want).unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("patches")
            .join("jc-snows-60hz-vga.ppf");
        let p = parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(p.fit(&image), Fit::Verified);
        let applied = p.apply(&mut image).unwrap();
        assert_eq!(applied.changed.len(), 4);
        assert!(image == want, "patched image differs from the author's");

        // And the words the reload guard would keep: four bytes, but two of
        // them share a word, so three writes rather than four.
        let guard = crate::patchdb::guard_words(&applied.changed, &image, 0x0c01_0000);
        assert_eq!(
            guard.iter().map(|&(a, _)| a).collect::<Vec<_>>(),
            vec![0x0c05_d1e4, 0x0c05_d1f8, 0x0c05_d30c]
        );
        for &(at, word) in &guard {
            let off = (at - 0x0c01_0000) as usize;
            assert_eq!(word.to_le_bytes()[..], image[off..off + 4]);
        }
    }

    #[test]
    fn reads_a_v1_and_a_v2() {
        let mut f1 = Vec::new();
        f1.extend_from_slice(b"PPF10");
        f1.push(0);
        f1.extend_from_slice(&[b' '; 50]);
        f1.extend_from_slice(&7u32.to_le_bytes());
        f1.push(2);
        f1.extend_from_slice(&[0x11, 0x22]);
        let p = parse(&f1).unwrap();
        assert_eq!(p.version, Version::V1);
        assert_eq!(p.records[0].offset, 7);
        assert_eq!(p.fit(&vec![0u8; 32]), Fit::Unverifiable);

        let mut f2 = Vec::new();
        f2.extend_from_slice(b"PPF20");
        f2.push(1);
        f2.extend_from_slice(&[b' '; 50]);
        f2.extend_from_slice(&1024u32.to_le_bytes());
        f2.extend_from_slice(&[0u8; BLOCKCHECK_LEN]);
        f2.extend_from_slice(&0u32.to_le_bytes());
        f2.push(1);
        f2.push(0x55);
        let p = parse(&f2).unwrap();
        assert_eq!(p.version, Version::V2);
        assert_eq!(p.original_len, Some(1024));
        // Stated length first: it is the cheapest disagreement to report.
        assert_eq!(
            p.fit(&vec![0u8; 16]),
            Fit::WrongLength {
                want: 1024,
                got: 16
            }
        );
    }
}
