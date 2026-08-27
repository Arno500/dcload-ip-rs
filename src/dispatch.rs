use std::{
    collections::{HashMap, HashSet},
    io::{Error, ErrorKind},
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use elf::{ElfBytes, endian::AnyEndian, section::SectionHeader};
use indicatif::{HumanBytes, ProgressBar};

use crate::{
    CHUNK_SIZE,
    cd::build_dc_toc,
    cmds::{DCLoadClientCmds, DCLoadCmd, DCLoadCmds, DCReturnCmd},
    disc_formats::{
        boot,
        cdi::Cdi,
        gdi::Gdi,
        iso::Iso,
        source::{Container, FileSource},
        types::{DiscFormat, StubDisc, get_disc_format},
        zip::{ZipArchive, ZipContainer},
    },
    fs::{self, FSSyscallState},
    io::ExternalDcIo,
    protocol_version, ui,
};

/// REFUSE AN UPLOAD THAT LANDS ON THE LOADER DOING THE UPLOADING.
///
/// A chainload is an ordinary transfer: the running loader receives the parts
/// and writes them where they are addressed. Address them at itself and it
/// overwrites its own `cmd_partbin` mid-transfer -- the console goes straight
/// back to the BIOS, and all the host sees is a DoneBinary that never comes.
/// Measured 2026-08-15 uploading dcload-0x8c004000.elf to a loader already at
/// 0x8c004000: LBIN accepted, then nothing, and the machine was gone.
///
/// `running` is what the loader reported. When it reports nothing -- every
/// build before the base was added to the VERS payload -- the stock base is
/// assumed, because that is where such a build necessarily is: relocation is
/// the feature those builds do not have.
fn refuse_self_overwrite(
    running: Option<u32>,
    at: u32,
    len: usize,
) -> std::result::Result<(), std::boxed::Box<dyn std::error::Error>> {
    let base = running.unwrap_or(crate::loaders::DEFAULT_BASE);
    let image = (at, at.saturating_add(len as u32));
    let Some(hit) = crate::loaders::overlapping_range(base, image) else {
        return Ok(());
    };
    // Said in full through the logger, where it is readable and lands in a
    // redirected log; the returned error stays short, because a `Box<dyn
    // Error>` reaching main is printed with its Debug formatting.
    error!(
        "refusing to upload {} bytes at 0x{:08x}: that runs through \
         0x{:08x}..0x{:08x}, which the loader running at 0x{:08x} is using{}. \
         It would overwrite itself while receiving, and the console would drop \
         to the BIOS with no error anywhere. To replace a loader in place, move \
         out of the way first: `uexec loaders/dcload-0x{:08x}.elf`, then upload \
         the one you want -- from up there the low bases are untouched ground.",
        len,
        at,
        hit.0,
        hit.1,
        base,
        if running.is_none() {
            " (it does not report its address, so the stock base is assumed)"
        } else {
            ""
        },
        crate::loaders::SCRATCH_BASE
    );
    Err(Box::new(Error::other(format!(
        "upload to 0x{at:08x} would overwrite the loader running at 0x{base:08x}"
    ))))
}

/// The most this will ever send. A Dreamcast has 16 MiB of RAM.
pub const MAX_PAYLOAD_BYTES: u64 = crate::types::DREAMCAST_RAM_BYTES;

/// Read a file that is about to be uploaded, refusing an impossible one BEFORE
/// reading it.
///
/// The size check used to be here and moved to `upload_bytes`, which is after
/// the whole file is in RAM -- so `uexec` on a mistyped path that happens to
/// name a 1.1 GB image allocated all of it and only then said it was too large.
/// `upload_bytes` still checks, for the callers that hand it bytes; this stops
/// the file case from paying for it.
pub fn read_payload_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_PAYLOAD_BYTES {
        return Err(Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!(
                "{} is {len} bytes, too large for a Dreamcast executable (>{} bytes)",
                path.display(),
                MAX_PAYLOAD_BYTES
            ),
        ));
    }
    std::fs::read(path)
}

/// A file on the command line, as the pair everything downstream wants: the
/// bytes, and what to call them in the log and on the progress bar.
pub fn payload_from_file(path: &Path) -> std::io::Result<(Vec<u8>, String)> {
    let bytes = read_payload_file(path)?;
    debug!("Read file {} ({} bytes)", path.display(), bytes.len());
    let label = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    Ok((bytes, label))
}

/// Upload a payload that is already in memory.
///
/// EVERYTHING reaches the Dreamcast through here -- a file named on the command
/// line, and a boot binary read straight out of a disc image. Keeping one body
/// is what stops the ELF handling, the self-overwrite refusal and the byte
/// accounting from drifting apart between the two paths.
pub fn upload_bytes(
    conn: &mut impl ExternalDcIo,
    file_buffer: &[u8],
    label: &str,
    mut address: u32,
    running_base: Option<u32>,
) -> std::result::Result<(u32, usize), std::boxed::Box<dyn std::error::Error>> {
    if file_buffer.len() as u64 > MAX_PAYLOAD_BYTES {
        error!(
            "File size seems too large for a Dreamcast executable (>{} bytes)",
            MAX_PAYLOAD_BYTES
        );
        return Err(Box::new(Error::new(
            std::io::ErrorKind::FileTooLarge,
            "File too large",
        )));
    }
    let label = label.to_string();

    let mut elf_parts: Vec<SectionHeader> = vec![];

    // Analyze the ELF file
    let elf = ElfBytes::<AnyEndian>::minimal_parse(file_buffer);
    let started = Instant::now();
    if let Ok(elf) = elf {
        // Let's keep the entrypoint somewhere, it may be handy 👀
        address = elf.ehdr.e_entry as u32;
        trace!("ELF entry point at 0x{:08x}", address);

        // ONLY SECTIONS THAT OCCUPY MEMORY AT RUN TIME.
        //
        // This used to test SHT_PROGBITS, log "skipping", and then push the
        // section anyway -- the `if` had no `continue` -- so every ELF was
        // uploaded in full, symbol table included. `.symtab`, `.strtab`,
        // `.shstrtab` and `.comment` are all PROGBITS-or-similar with contents
        // and all sit at sh_addr 0, so those bytes were sent to address
        // 0x00000000, at the bottom of the Dreamcast's address map. It went
        // unnoticed because the common case is a raw 1ST_READ.BIN, which never
        // reaches this branch at all.
        //
        // SHF_ALLOC is the flag that actually means "this occupies memory when
        // the program runs"; a zero sh_addr means the section was never given
        // one. See loaders::is_uploadable, which is also what the loader-set
        // code measures an image's extent with, so the two cannot disagree
        // about what gets sent.
        elf.section_headers().iter().for_each(|table| {
            table.iter().for_each(|sh| {
                if crate::loaders::is_uploadable(&sh) {
                    elf_parts.push(sh);
                } else {
                    trace!(
                        "Skipping non-allocated section at 0x{:08x} ({} bytes)",
                        sh.sh_addr, sh.sh_size
                    );
                }
            });
        });

        // ONE BAR FOR THE WHOLE FILE, SIZED IN BYTES.
        //
        // There used to be a bar per section AND a fresh bar inside every
        // 360 KiB LoadBinary window, so a 6.4 MB upload drew nineteen separate
        // bars, each of which filled up and vanished. Every one of them
        // restarted the rate estimate from nothing -- which is why the rate
        // swung between 470 KiB/s and 2.24 MiB/s on a link whose real
        // throughput never moved -- and every one of them reported "ETA 0s",
        // because the end of a window is not the end of the job.
        //
        // Counting the bytes of the whole file up front costs one pass over
        // the section table and makes the rate and the ETA mean what a human
        // reads them to mean.
        let strtab = elf.section_headers_with_strtab().ok().and_then(|(_, s)| s);
        let total: u64 = elf_parts
            .iter()
            .filter_map(|sh| elf.section_data(sh).ok())
            .map(|(data, _)| data.len() as u64)
            .sum();
        // CHECK EVERY SECTION BEFORE SENDING ANY OF THEM. Refusing halfway
        // through has already destroyed the loader with the sections that did
        // go out; the point is to send nothing at all.
        for sh in elf_parts.iter() {
            if let Ok((data, _)) = elf.section_data(sh) {
                refuse_self_overwrite(running_base, sh.sh_addr as u32, data.len())?;
            }
        }

        let bar = ui::bytes_bar(total, label);

        for sh in elf_parts.iter() {
            if let Ok(section_data) = elf.section_data(sh) {
                if section_data.0.is_empty() {
                    trace!(
                        "Skipping empty section at address 0x{:08x}, offset 0x{:08x}",
                        sh.sh_addr, sh.sh_offset
                    );
                    continue;
                }
                let name = strtab
                    .and_then(|st| st.get(sh.sh_name as usize).ok())
                    .filter(|n| !n.is_empty())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| format!("0x{:08x}", sh.sh_addr));
                bar.set_message(name);
                debug!(
                    "Uploading section at address 0x{:08x} ({} bytes)",
                    sh.sh_addr, // where it goes, not where it is in the file
                    section_data.0.len()
                );
                if let Err(e) = send_data(conn, section_data.0, sh.sh_addr as u32, Some(&bar)) {
                    error!("Error uploading section: {}", e);
                    return Err(e);
                }
            } else {
                return Err(Box::new(Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Failed to get section data",
                )));
            }
        }
        drop(bar);
        report_upload(total, started.elapsed());
    } else {
        refuse_self_overwrite(running_base, address, file_buffer.len())?;
        let bar = ui::bytes_bar(file_buffer.len() as u64, label);
        let result = send_data(conn, file_buffer, address, Some(&bar));
        drop(bar);
        if let Err(e) = result {
            error!("Error uploading binary: {}", e);
            return Err(e);
        }
        report_upload(file_buffer.len() as u64, started.elapsed());
    }
    Ok((address, 0))
}

/// The one line that survives the transfer, for the terminal and for the log.
///
/// The bar itself is erased when it is done -- a finished bar is a stale bar --
/// so the numbers a human actually wants to keep (how much, how long, how fast)
/// are stated once, as a log record, where they also end up in a redirected
/// log with no escape sequences around them.
fn report_upload(bytes: u64, elapsed: Duration) {
    let rate = if elapsed.as_secs_f64() > 0.0 {
        (bytes as f64 / elapsed.as_secs_f64()) as u64
    } else {
        0
    };
    info!(
        "Uploaded {} in {:.2} s ({}/s)",
        HumanBytes(bytes),
        elapsed.as_secs_f64(),
        HumanBytes(rate)
    );
}

pub fn execute(
    conn: &mut impl ExternalDcIo,
    address: u32,
    console: bool,
    cdfs_redirect: bool,
) -> std::result::Result<(), std::boxed::Box<dyn std::error::Error>> {
    conn.send_command(DCLoadCmd {
        cmd: DCLoadCmds::Execute(),
        address,
        size: ((cdfs_redirect as u32) << 1) | console as u32,
    })
    .map(|_| ())
}

/// Ask the running loader who and where it is.
///
/// Returns the version string and, from a loader new enough to append it, the
/// address it was linked at. `None` for the address is a normal answer from an
/// older build and must not be treated as a failure -- it only means the host
/// has no basis on which to move anything.
pub fn query_loader(
    conn: &mut impl ExternalDcIo,
) -> std::result::Result<(String, Option<u32>), std::boxed::Box<dyn std::error::Error>> {
    let replies = send_version(conn)?;
    for reply in replies {
        if let Some(cmd) = reply.cmd
            && let DCLoadCmds::Version(Some(data)) = cmd.cmd
        {
            return Ok(crate::loaders::parse_version_payload(
                data.as_ref(),
                cmd.size as usize,
            ));
        }
    }
    Err(Box::new(Error::new(
        ErrorKind::InvalidData,
        "no VERS reply from the Dreamcast",
    )))
}

/// Poll for a loader at `expect` after a chainload.
///
/// Deliberately not `call_command`'s five 500 ms tries: what is being waited
/// for here is not a lost packet but a whole loader coming up, which re-detects
/// the network adapter on the way. On real hardware a cold RTL8139 init drops
/// the link and restarts auto-negotiation, and that alone costs seconds.
fn wait_for_loader(
    conn: &mut impl ExternalDcIo,
    expect: u32,
    timeout: Duration,
) -> std::result::Result<(), std::boxed::Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        match query_loader(conn) {
            Ok((version, Some(base))) if base == expect => {
                debug!("loader at 0x{:08x} answered: {}", base, version);
                return Ok(());
            }
            Ok((version, Some(base))) => {
                last = format!("a loader at 0x{base:08x} answered instead ({version})");
            }
            Ok((version, None)) => {
                last = format!("loader did not report its base ({version})");
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(Box::new(Error::new(
        ErrorKind::TimedOut,
        format!("no loader at 0x{expect:08x} after {timeout:?}: {last}"),
    )))
}

/// Put a loader linked for `want` in control, chainloading through an
/// intermediate base if going there directly would write over the running one.
///
/// Returns the base actually in control afterwards. A missing ELF, or a move
/// that cannot be made safely, is reported and the CURRENT loader is kept: a
/// title that runs badly at the stock address is a better outcome than one
/// launched into a loader that was half overwritten.
pub fn ensure_loader_base(
    conn: &mut impl ExternalDcIo,
    loaders: &crate::loaders::LoaderSet,
    running: u32,
    want: u32,
) -> u32 {
    if running == want {
        info!("loader is already at 0x{:08x}, no chainload needed", want);
        return running;
    }
    // A base that is known not to work is refused BEFORE the missing-ELF path,
    // so the message says why instead of inviting someone to build it.
    if let Some(reason) = crate::loaders::known_unsupported(want) {
        warn!(
            "this title's preset asks for the loader at 0x{want:08x}, which is not \
             supported: {reason}. Staying at 0x{running:08x}; the title may still run."
        );
        return running;
    }
    if !loaders.can_provide(want) {
        let available: Vec<String> = loaders
            .available()
            .iter()
            .map(|b| format!("0x{b:08x}"))
            .collect();
        warn!(
            "this title wants the loader at 0x{:08x} but {} has neither dcload-0x{:08x}.elf \
             nor {} (available: {}); staying at 0x{:08x}. Build the set with \
             `make -C target-src/dcload loaders` and put it in a `loaders` \
             directory at this project's root. Looked in: {}.",
            want,
            loaders.dir().display(),
            want,
            crate::loaders::RELOCATABLE_NAME,
            if available.is_empty() {
                "none".to_string()
            } else {
                available.join(", ")
            },
            running,
            loaders.searched()
        );
        return running;
    }

    // Materialised ONCE, here, and carried to the upload. Relocating is cheap,
    // but doing it twice would leave two answers to "what is being uploaded",
    // and only one of them checked.
    let mut images: std::collections::HashMap<u32, (Vec<u8>, String)> = Default::default();
    let mut fetch = |base: u32| -> Option<(Vec<u8>, String)> {
        if let Some(v) = images.get(&base) {
            return Some(v.clone());
        }
        match loaders.image_for(base) {
            Ok(v) => {
                images.insert(base, v.clone());
                Some(v)
            }
            Err(e) => {
                warn!("cannot get a loader for 0x{base:08x}: {e}");
                None
            }
        }
    };

    let Some((want_bytes, _)) = fetch(want) else {
        warn!("staying at 0x{running:08x}");
        return running;
    };
    let want_image = match crate::loaders::image_extent_bytes(&want_bytes) {
        Ok(extent) => extent,
        Err(e) => {
            warn!("cannot read the loader for 0x{want:08x}: {e}; staying at 0x{running:08x}");
            return running;
        }
    };
    let scratch_image = fetch(crate::loaders::SCRATCH_BASE)
        .and_then(|(b, _)| crate::loaders::image_extent_bytes(&b).ok())
        .unwrap_or((u32::MAX, u32::MAX));

    let hops = crate::loaders::plan(running, want, want_image, scratch_image);
    if hops.is_empty() {
        warn!(
            "cannot move the loader from 0x{running:08x} to 0x{want:08x} without writing \
             over the running image, and no clear intermediate base is available; \
             staying at 0x{running:08x}"
        );
        return running;
    }
    if hops.len() > 1 {
        debug!(
            "0x{:08x} -> 0x{:08x} overlaps the running loader; going via 0x{:08x}",
            running, want, hops[0]
        );
    }

    let mut current = running;
    for hop in hops {
        let Some((bytes, label)) = fetch(hop) else {
            warn!("staying at 0x{current:08x}");
            return current;
        };
        info!("chainloading dcload to 0x{:08x} ({label})", hop);
        let entry = match upload_bytes(conn, &bytes, &label, hop, Some(current)) {
            Ok((entry, _)) => entry,
            Err(e) => {
                warn!(
                    "uploading the loader for 0x{hop:08x} failed: {e}; staying at 0x{current:08x}"
                );
                return current;
            }
        };
        // No console and no CDFS redirection: what is being started is another
        // loader, and it must come up in the same idle state the CD image
        // leaves it in, not with a file server attached to a title that does
        // not exist yet.
        if let Err(e) = execute(conn, entry, false, false) {
            warn!("EXEC of the loader at 0x{hop:08x} failed: {e}; staying at 0x{current:08x}");
            return current;
        }
        if let Err(e) = wait_for_loader(conn, hop, Duration::from_secs(20)) {
            warn!("{e}");
            return current;
        }
        current = hop;
    }
    info!("loader is now at 0x{:08x}", current);
    current
}

/// Copy the disc's IP.BIN header sector to 0x8c008000, the way isoldr does.
///
/// isoldr's `Load_IPBin()` reads exactly ONE sector in BOOT_MODE_DIRECT --
/// `if (header_only) { cnt = 1; }` in loader/utils.c -- from the boot track to
/// IP_BIN_ADDR, and direct boot is the only mode this host has. Nothing on our
/// path has ever populated that region: the real bootstrap never runs, so a
/// title that reads its own disc header back out of RAM gets whatever the
/// previous session left there. On a console that is three chainloaded loaders'
/// worth of debris; under an emulator it is zeroes, which is why this could
/// only ever fail on hardware.
///
/// SKIPPED WHEN THE LOADER IS IN LOW RAM. At the stock base the loader's image
/// starts at 0x8c004000 and runs straight through 0x8c008000, so there is
/// nowhere to put this and writing it would shoot the loader serving the
/// upload. That is one more reason DreamShell moves such titles to a high base
/// (AGENTS.md 4.11), and the caller is told rather than left guessing.
pub fn load_ip_bin(
    conn: &mut impl ExternalDcIo,
    disc: &dyn DiscFormat,
    disc_path: &str,
    running_base: Option<u32>,
    full: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    const IP_BIN_ADDR: u32 = 0x0c008000;

    match running_base {
        Some(base) if base < 0x8c010000 => {
            warn!(
                "loader at 0x{base:08x} occupies the IP.BIN region; \
                 not loading IP.BIN for this title"
            );
            return Ok(false);
        }
        None => {
            warn!("the loader does not report where it is; not loading IP.BIN");
            return Ok(false);
        }
        _ => {}
    }

    if !full {
        let sector = crate::disc_formats::types::find_ip_bin(disc).ok_or_else(|| {
            std::io::Error::other(format!("{disc_path}: no IP.BIN header to load"))
        })?;

        info!(
            "IP.BIN header -> 0x{IP_BIN_ADDR:08x} ({} bytes), as isoldr does on a direct boot",
            sector.len()
        );
        send_data(conn, &sector, IP_BIN_ADDR, None)?;
        return Ok(true);
    }

    // The full sixteen sectors, contiguous from the start of the boot track.
    // find_ip_bin()'s fallback (IP.BIN as an ISO9660 FILE) is deliberately NOT
    // used here: it can hand back a header that is nowhere near the bootstrap
    // code, and the whole point of this mode is to run that code in place.
    let base = disc.boot_sector();
    let mut image = disc.read_sector(base, IP_BIN_SECTORS)?;
    if !image.starts_with(b"SEGA SEGAKATANA") {
        return Err(std::io::Error::other(format!(
            "{disc_path}: sector {base} is not a Dreamcast boot sector, so there \
             is no IP.BIN bootstrap to enter; use the header-only mode"
        ))
        .into());
    }
    let want = IP_BIN_SECTORS as usize * 2048;
    if image.len() < want {
        return Err(std::io::Error::other(format!(
            "{disc_path}: only {} of {want} IP.BIN bytes readable",
            image.len()
        ))
        .into());
    }
    image.truncate(want);

    // PROVE THIS IS THE BOOTSTRAP, because the wrong track looks right.
    //
    // Both data tracks of a GDI open with the same valid `SEGA SEGAKATANA`
    // header for the same title; only the high-density one carries code.
    // Measured on Sonic Adventure, Sonic Adventure 2 and Crazy Taxi, all PAL:
    // the low-density copy has 0/256 non-zero bytes at bootstrap 1 (+0x300)
    // against 207/256 for the high-density one -- and 32768 bytes of it are
    // ZEROES where the code should be. Entering 0x8c00e000 after loading that
    // one jumps into nothing, with no error reported at either end.
    //
    // The check is the patch site itself. Sega's bootstrap is stock across
    // retail discs, so +0x0cb0 reads 0x40006303 on every high-density area
    // measured and 0x00000000 on every low-density one. Verifying the word we
    // are about to overwrite proves BOTH that we picked the right track and
    // that the layout isoldr's offsets assume is the layout in front of us --
    // one test, and it fails loudly instead of silently writing into padding.
    const PATCH_SITE: usize = 0x0cb0;
    const PATCH_SITE_STOCK: u32 = 0x4000_6303;
    let found = u32::from_le_bytes(image[PATCH_SITE..PATCH_SITE + 4].try_into()?);
    if found != PATCH_SITE_STOCK {
        return Err(std::io::Error::other(format!(
            "{disc_path}: the IP.BIN at sector {base} does not look like a stock \
             Sega bootstrap (+0x{PATCH_SITE:04x} reads 0x{found:08x}, expected \
             0x{PATCH_SITE_STOCK:08x}) -- refusing to patch and enter it"
        ))
        .into());
    }

    // isoldr's four patches, Load_IPBin() in loader/utils.c, transcribed with
    // its pointer arithmetic worked out. They are applied HERE, in the buffer,
    // rather than poked afterwards: a poke is a four-byte write that fits
    // inside one cache line and is exactly the case `apply_patches` had to grow
    // a read-back check for. Bytes that travel with the upload cannot go
    // missing that way.
    //
    //   +0x0cb0  (uint32*)ip + 0x032c = 0x8c00e000  -- bootstrap 1 jumps to 2
    //   +0x21b0  (uint16*)ip + 0x10d8 = 0x5113
    //   +0x2814  (uint16*)ip + 0x140a = 0x000b      -- rts
    //   +0x2818  (uint16*)ip + 0x140c = 0x0009      -- nop
    //
    // The last pair neuters a routine outright; that is what lets the bootstrap
    // run without a drive under it. What isoldr also does at this point and we
    // do NOT is setup_region(), which needs the console's own flashrom region
    // byte -- we are on the wrong side of the wire to read it.
    image[0x0cb0..0x0cb4].copy_from_slice(&IP_BIN_BOOTSTRAP_2.to_le_bytes());
    image[0x21b0..0x21b2].copy_from_slice(&0x5113u16.to_le_bytes());
    image[0x2814..0x2816].copy_from_slice(&0x000bu16.to_le_bytes());
    image[0x2818..0x281a].copy_from_slice(&0x0009u16.to_le_bytes());

    // DO NOT WRITE OVER THE GUEST VBR. IP.BIN's 32 KB run from 0x8c008000 to
    // 0x8c010000, and 0x8c00f400 -- DCLOAD_GUEST_VBR -- is inside that. The
    // loader ELF carries exception.bin as a `.guestvbr` section and the
    // chainload has just placed it there; sending the whole image afterwards
    // replaces the title's vector table with what IP.BIN holds at +0x7400.
    //
    // Which is 3072 bytes of ZEROES, measured on both the Sonic Adventure and
    // the Sonic Adventure 2 PAL dumps. So nothing is lost by stopping short --
    // and what was lost by not stopping short is the exception dump, i.e. the
    // one report a crashed title could still have made. Measured 2026-08-19:
    // a --boot-ipbin run was therefore testing two changes at once.
    //
    // The tail is checked rather than assumed. A disc that does put something
    // there is a disc this rule is wrong for, and it should say so.
    const VBR_OFF: usize = 0x8c00_f400usize - 0x8c00_8000usize;
    let tail_live = image[VBR_OFF..].iter().filter(|b| **b != 0).count();
    if tail_live != 0 {
        warn!(
            "IP.BIN carries {tail_live} non-zero bytes at +0x{VBR_OFF:04x}, where the \
             guest vector table lives; they are NOT being sent. If this title needs \
             them, the loader's .guestvbr section is what stands in their way."
        );
    }
    image.truncate(VBR_OFF);

    info!(
        "IP.BIN -> 0x{IP_BIN_ADDR:08x} ({} sectors, {} bytes -- stopping at the guest \
         VBR); entry will be the bootstrap at 0x{IP_BIN_BOOTSTRAP_2:08x}, isoldr's 4 \
         patches applied",
        IP_BIN_SECTORS,
        image.len()
    );
    send_data(conn, &image, IP_BIN_ADDR, None)?;
    Ok(true)
}

/// Sectors isoldr reads for a full IP.BIN load (`cnt = 16`, `Load_IPBin()`).
pub const IP_BIN_SECTORS: u32 = 16;

/// isoldr's `IP_BIN_BOOTSTRAP_2_ADDR`, the entry point for a non-direct boot.
/// Cached window, because that is the literal the bootstrap patch stores and
/// the one the code there expects to see.
pub const IP_BIN_BOOTSTRAP_2: u32 = 0x8c00e000;

/// The same address in the window `EXEC` wants: dcload ORs 0xa0000000 onto
/// whatever it is handed (`go(ntohl(command->address) | 0xa0000000)`), so the
/// host sends the physical form exactly as it does for a title at 0x0c010000.
pub const IP_BIN_BOOTSTRAP_2_EXEC: u32 = 0x0c00e000;

/// Prove -- or disprove -- that reading memory back off the console works,
/// before any conclusion is drawn from a read-back.
///
/// WHY THIS EXISTS. Two probe runs on 2026-08-19/20 reported "read-back
/// MISMATCH". In the first the probe then executed and reported normally, so
/// the check was wrong. In the second the bytes that came back were the TAIL OF
/// dcload's OWN VERSION STRING starting at its 8th character -- i.e. the reply
/// carried 8 bytes of real data and then whatever the previous VERS reply had
/// left in `pkt_buf`. That is a defect in the read path itself, and until its
/// shape is known every read-back is worthless and every probe result is
/// ambiguous: "the probe never ran" and "the probe could not be verified" look
/// identical.
///
/// So this writes known patterns into free RAM and reads them straight back,
/// across the sizes and misalignments the probe path actually uses. It needs no
/// title, no disc and no chainload -- just a loader answering. What it reports
/// is which combinations are trustworthy.
///
/// 0x0c200000 is chosen because a 1.5 MB title at 0x0c010000 ends well below
/// it and every loader base is far above it, so nothing here can shoot either.
pub fn selftest_readback(conn: &mut impl ExternalDcIo) -> Result<bool, Box<dyn std::error::Error>> {
    const SCRATCH: u32 = 0x0c20_0000;

    // THE WINDOW IS A VARIABLE, and it is the one thing the probe path does
    // that nothing else does: apply_probes() normalises to P2 (0xa0000000)
    // while every other transfer here uses the physical 0x0c window. dcload
    // reads a SendBinQ with SH4_aligned_memcpy(to_p1(response->data), cmd_addr,
    // n) -- so a P2 source is mixed with a P1 destination inside hand-written
    // fast paths that switch strategy on the low bits of `src | dest`. That is
    // exactly the kind of thing that works for a 1440-byte aligned read and not
    // for a 30-byte one, which is the pattern the two probe runs showed.
    let windows: [(&str, u32); 2] = [("phys 0x0c", SCRATCH), ("P2   0xac", SCRATCH | 0xa000_0000)];
    let (mut phys_ok, mut p2_ok, mut phys_cases) = (true, true, 0usize);

    info!("read-back self-test at 0x{SCRATCH:08x} -- no title is uploaded by this");
    for (wname, wbase) in windows {
        for &len in &[4usize, 28, 30, 64, 1439, 1440, 1441, 3000] {
            for &skew in &[0u32, 1, 2, 3] {
                let addr = wbase + skew;
                // A pattern where every byte says where it belongs, so a shifted or
                // truncated reply is readable at a glance instead of just "differs".
                let want: Vec<u8> = (0..len)
                    .map(|i| (i as u32).wrapping_mul(31).wrapping_add(skew) as u8)
                    .collect();

                let is_phys = wbase == SCRATCH;
                if is_phys {
                    phys_cases += 1;
                }
                if let Err(e) = send_data(conn, &want, addr, None) {
                    error!("  {wname} len {len:5} skew {skew}: WRITE failed: {e}");
                    if is_phys { phys_ok = false } else { p2_ok = false }
                    continue;
                }
                match receive_data(conn, Some(Duration::from_millis(1500)), addr, len, true) {
                    Err(e) => {
                        error!("  {wname} len {len:5} skew {skew}: READ failed: {e}");
                        if is_phys { phys_ok = false } else { p2_ok = false }
                    }
                    Ok(got) if got == want => info!("  {wname} len {len:5} skew {skew}: ok"),
                    Ok(got) => {
                        if is_phys { phys_ok = false } else { p2_ok = false }
                        let first = got
                            .iter()
                            .zip(&want)
                            .position(|(a, b)| a != b)
                            .unwrap_or(want.len().min(got.len()));
                        let hex = |v: &[u8], from: usize| {
                            v.iter()
                                .skip(from)
                                .take(12)
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        };
                        error!(
                            "  {wname} len {len:5} skew {skew}: MISMATCH, {} bytes back, \
                         first bad byte at {first}",
                            got.len()
                        );
                        error!("      want[{first}..]: {}", hex(&want, first));
                        error!("      got [{first}..]: {}", hex(&got, first));
                    }
                }
            }
        }
    }
    // WHICH SIDE DROPS THE BYTES. Everything above writes and reads through the
    // SAME window, so "the write only placed 8 bytes" and "the read returned a
    // stale buffer" give an identical symptom: the previous test's pattern from
    // byte 8 on (verified -- len 28 skew 1 came back as the skew 0 pattern, len
    // 30 skew 0 as the skew 3 one). Crossing the windows separates them, now
    // that the physical window is known good in all 32 cases.
    //
    //   write P2,   read phys -> a mismatch means the WRITE dropped them
    //   write phys, read P2   -> a mismatch means the READ dropped them
    //
    // Both misaligned and 64 bytes long, i.e. squarely inside the broken range.
    let phys = SCRATCH + 0x1000;
    let p2 = phys | 0xa000_0000;
    for (label, waddr, raddr) in [
        ("write P2   / read phys", p2, phys),
        ("write phys / read P2  ", phys, p2),
    ] {
        // Filler first, through the window each case trusts, so a byte that was
        // never written is recognisable instead of being mistaken for the
        // previous pattern.
        let filler = vec![0x55u8; 96];
        if let Err(e) = send_data(conn, &filler, phys, None) {
            error!("  {label}: could not lay down filler: {e}");
            phys_ok = false;
            continue;
        }
        let want: Vec<u8> = (0..64u32)
            .map(|i| i.wrapping_mul(31).wrapping_add(7) as u8)
            .collect();
        if let Err(e) = send_data(conn, &want, waddr + 1, None) {
            error!("  {label}: WRITE failed: {e}");
            phys_ok = false;
            continue;
        }
        match receive_data(conn, Some(Duration::from_millis(1500)), raddr + 1, 64, true) {
            Ok(got) if got == want => info!("  {label}: ok (64 bytes, misaligned)"),
            Ok(got) => {
                phys_ok = false;
                let n = got.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(64);
                let filler_here = got.get(n).copied() == Some(0x55);
                error!(
                    "  {label}: MISMATCH at byte {n}{}",
                    if filler_here {
                        " -- and it is the 0x55 filler, so those bytes were NEVER WRITTEN"
                    } else {
                        " -- and it is not the filler, so the bytes were written and misread"
                    }
                );
            }
            Err(e) => {
                phys_ok = false;
                error!("  {label}: READ failed: {e}");
            }
        }
    }

    // A GLOBAL "FAILED" WOULD OVERSTATE IT. Measured 2026-08-20: the physical
    // window passes all 32 cases while P2 fails most of them, and everything
    // this host does now goes through the physical window. Saying only "FAILED"
    // would read as "no read-back can be trusted", which is the opposite of
    // what was measured and would throw away good runs -- the exact mistake
    // the bare "DID NOT LAND" caused a day earlier. So report per window.
    if phys_ok {
        info!(
            "read-back through the PHYSICAL window (0x0c...) is sound: {} cases, \
             no mismatch. Probe verification can be believed.",
            phys_cases
        );
    } else {
        error!(
            "read-back through the PHYSICAL window FAILED -- this is the window \
             probes, patches and uploads all use. Believe nothing until it is fixed."
        );
    }
    if !p2_ok {
        warn!(
            "read-back through P2 (0xac...) is NOT sound. It is not used by this \
             host any more; the defect is in dcload's cmd_partbin/cmd_sendbinq \
             path and is still there. Do not aim anything at 0xac... by hand."
        );
    }
    Ok(phys_ok)
}

/// Poke 32-bit words into the title's image after it is uploaded and before it
/// runs -- DreamShell's `pa1`/`pv1` mechanism, driven from the command line.
///
/// WHY THIS EXISTS, because it is a loaded gun otherwise. A title that hangs
/// before its first disc read leaves nothing to measure: dcload only executes
/// from a GD syscall, so no counter can be read back, no packet is sent, and
/// the screen belongs to the title. The only instrument left is to change the
/// title and see what changes -- neutralise a routine, cut out a give-up path,
/// redirect a call. That is exactly what DreamShell's per-game patch fields
/// are for, and the preset table already carries them (`presets.rs`).
///
/// The word is written little-endian, so a pair of SH4 instructions reads in
/// the order it executes: `rts; nop` is 0x0009000b.
///
/// The address may be given in any window (0x8c…, 0x0c…, 0xac…); it is
/// normalised to **P2, the uncached window**, for both the write and the check.
/// That is not cosmetic. dcload writes an upload with CPU stores, and `go()`
/// leaves with `CCR = 0x0808` -- an *invalidate*, not a purge, so any line
/// still dirty at that moment is DISCARDED. A multi-megabyte title evicts
/// itself long before then and never notices; a single four-byte poke fits
/// entirely inside one line and is exactly the case that would vanish, with
/// the transfer reporting success at both ends.
///
/// EVERY PATCH IS READ BACK AND COMPARED, and the word that was there before
/// is printed. An instrument that cannot prove it landed reports fiction with
/// full confidence (AGENTS.md 11, 14.19), and here that fiction would be
/// "changing the title changed nothing" -- the single most misleading result
/// this mechanism can produce.
/// The four G2 slot windows a Katana title probes for an expansion device.
const GAPS_SLOT_WINDOWS: [u32; 4] = [0xa100_0400, 0xa100_0800, 0xa100_1400, 0xa100_1800];
/// `"GAPS"` read back as a little-endian word -- the signature the probe compares against.
const GAPS_SIGNATURE: u32 = 0x5350_4147;
/// How far from the signature a slot-window literal may sit and still count as
/// corroboration. In Sonic Adventure 2 the two pools are 0x248 apart.
const GAPS_CORROBORATION_SPAN: usize = 4096;

/// Stop a title from switching the Broadband Adapter off, rather than
/// recovering afterwards.
///
/// Sonic Adventure 2 probes all four G2 slot windows during `main`, and parks
/// every expansion device it finds by writing the two words dcload itself uses
/// to power the GAPS bridge down. The loader then goes deaf with nothing logged
/// at either end -- see AGENTS.md 4.12. dcload can recover, but recovery costs
/// a full cold bring-up including auto-negotiation, seconds during which the
/// title is blocked; not being switched off in the first place is strictly
/// better.
///
/// The probe reads four bytes from a slot window and compares them against
/// `"GAPS"`. That comparison constant is the single choke point for all four
/// slots, so ONE word makes every probe fail and nothing gets parked -- and the
/// path it takes then is the ordinary one for a console with an empty expansion
/// port, which every such title must already support.
///
/// Found by content, so it needs no per-title knowledge and no disassembly. The
/// bare four bytes are not enough on their own -- `"GAPS"` could be ASCII in
/// data -- so a slot-window literal must corroborate it nearby. In Sonic
/// Adventure's 6.7 MB there is neither; in Sonic Adventure 2's 1.5 MB there is
/// exactly one of each.
pub fn gaps_probe_patches(buf: &[u8], address: u32) -> Vec<(u32, u32)> {
    // Raw binaries land whole at `address`; an ELF's sections land at their own.
    let mut spans: Vec<(u32, &[u8])> = vec![];
    if let Ok(elf) = ElfBytes::<AnyEndian>::minimal_parse(buf) {
        if let Some(headers) = elf.section_headers() {
            for sh in headers.iter() {
                if crate::loaders::is_uploadable(&sh)
                    && let Ok((data, _)) = elf.section_data(&sh)
                {
                    spans.push((sh.sh_addr as u32, data));
                }
            }
        }
    } else {
        spans.push((address, buf));
    }

    let mut out = vec![];
    for (base, data) in spans {
        let word = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let slots: Vec<usize> = (0..data.len().saturating_sub(3))
            .step_by(4)
            .filter(|&i| GAPS_SLOT_WINDOWS.contains(&word(i)))
            .collect();
        if slots.is_empty() {
            continue;
        }
        for i in (0..data.len().saturating_sub(3)).step_by(4) {
            if word(i) != GAPS_SIGNATURE {
                continue;
            }
            if !slots
                .iter()
                .any(|&s| s.abs_diff(i) <= GAPS_CORROBORATION_SPAN)
            {
                continue;
            }
            let at = (base & 0x1fff_ffff) | 0x8c00_0000;
            let at = at + i as u32;
            info!(
                "this title probes the expansion port for the GAPS bridge \
                 (signature at 0x{at:08x}); neutralising it so it cannot switch \
                 the adapter off"
            );
            out.push((at, 0xffff_ffff));
        }
    }
    out
}

/// Addresses the title loads as constants that land inside the running
/// loader's memory -- reported BEFORE the title is started, because nothing
/// can report them afterwards.
///
/// A title writes where it likes. When it writes with the CPU through a disc
/// read, the host sees the destination and `receive_syscalls` says so; when it
/// programs a DMA engine, nothing on either side is in the path at all. The
/// Maple DMA is the case that matters: the controller writes guest RAM
/// directly, so a loader whose stack and packet buffers sit in the target
/// region is overwritten by hardware, mid-frame, with no syscall, no packet
/// and no exception. The loader simply stops answering -- black screen, no
/// further requests, nothing logged anywhere. That is indistinguishable from
/// the adapter having been switched off (AGENTS.md 4.12) and from every other
/// silent ending, which is exactly why it has to be caught up front.
///
/// Sonic Adventure 2 is the measured case: it loads 0x0cff0000 into its Maple
/// DMA list, and at the 0x8cfe8000 base DreamShell asks for, the loader's own
/// stack top is 0x8cff3000, its `.hiram` packet buffers 0x8cff4000 and its
/// Maple buffer 0x8cff5000 -- all above the address the console's own hardware
/// is about to fill. isoldr fits at that base because its image is 13 KB and
/// it keeps everything under 0x8cff0000; ours reserves 56 KB from the base and
/// does not.
///
/// FOUND BY CONTENT, AND CORROBORATED THE SAME WAY THE GAPS PROBE IS. A bare
/// four-byte match is not enough -- any pointer-sized datum can read as a high
/// RAM address -- so a literal only counts when an `mov.l @(disp,PC),Rn`
/// actually loads it. On Sonic Adventure 2 that is the whole difference between
/// eight occurrences of 0x0cff0000 and the two sites that use them.
pub fn literals_in_loader_footprint(buf: &[u8], address: u32, base: u32) -> Vec<(u32, u32)> {
    let mut spans: Vec<(u32, &[u8])> = vec![];
    if let Ok(elf) = ElfBytes::<AnyEndian>::minimal_parse(buf) {
        if let Some(headers) = elf.section_headers() {
            for sh in headers.iter() {
                if crate::loaders::is_uploadable(&sh)
                    && let Ok((data, _)) = elf.section_data(&sh)
                {
                    spans.push((sh.sh_addr as u32, data));
                }
            }
        }
    } else {
        spans.push((address, buf));
    }

    let ranges: Vec<(u32, u32)> = crate::loaders::live_footprint(base)
        .into_iter()
        .filter(|&(lo, _)| lo >= 0x8c01_0000)
        .collect();
    if ranges.is_empty() {
        return vec![];
    }

    let mut out: Vec<(u32, u32)> = vec![];
    for (span_base, data) in spans {
        // Pass one: every aligned word that names RAM inside the footprint.
        let mut pool: HashMap<usize, u32> = HashMap::new();
        for i in (0..data.len().saturating_sub(3)).step_by(4) {
            let raw = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            // Only the three windows onto RAM; anything else is a plain number.
            if !matches!(raw & 0xff00_0000, 0x0c00_0000 | 0x8c00_0000 | 0xac00_0000) {
                continue;
            }
            let at = (raw & 0x1fff_ffff) | 0x8c00_0000;
            // ONLY THE PART OF THE LOADER NO TITLE HAS BUSINESS ADDRESSING.
            //
            // A low loader shares its region with the BIOS work area by
            // construction (AGENTS.md 4.6): 0x8c008000 is where IP.BIN lives,
            // and a title reads its own disc header there as a matter of
            // course. Measured: Sonic Adventure -- which runs perfectly at the
            // stock base -- has eleven constants in 0x8c0080f0..0x8c008208,
            // every one of them legitimate. Reporting those would have this
            // check crying wolf on the one title known to work, and a guard
            // that always fires guards nothing (AGENTS.md 14.9). The high
            // ranges are different: a loader's stack, packet buffers and Maple
            // buffer up there are in RAM a title is supposed to own outright,
            // so a constant naming them is a real collision either way.
            if ranges.iter().any(|&(lo, hi)| at >= lo && at < hi) {
                pool.insert(i, at);
            }
        }
        if pool.is_empty() {
            continue;
        }
        // Pass two: the `mov.l @(disp,PC),Rn` that read them. SH4 is fixed
        // 16-bit, PC-relative long loads round the PC down to 4.
        for i in (0..data.len().saturating_sub(1)).step_by(2) {
            let op = u16::from_le_bytes([data[i], data[i + 1]]);
            if op & 0xf000 != 0xd000 {
                continue;
            }
            let target = ((i + 4) & !3) + (op & 0xff) as usize * 4;
            if let Some(&at) = pool.get(&target) {
                // Reported in the cached window, which is what a disassembly
                // of the title shows, whatever window the payload was uploaded
                // through.
                let site = span_base.wrapping_add(i as u32);
                out.push((at, (site & 0x1fff_ffff) | 0x8c00_0000));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn apply_patches(
    conn: &mut impl ExternalDcIo,
    patches: &[(u32, u32)],
) -> Result<(), Box<dyn std::error::Error>> {
    for &(addr, value) in patches {
        // Physical, never P2: the P2 window drops bytes past the 8th and hands
        // back the previous transfer's, so both the write and its read-back
        // would be suspect. See the read-back self-test.
        let addr = (addr & 0x1fff_ffff) | 0x0c00_0000;
        let before = read_word(conn, addr);
        send_data(conn, &value.to_le_bytes(), addr, None)?;
        let after = read_word(conn, addr);

        match (before, after) {
            (_, Some(got)) if got == value => info!(
                "patch: 0x{addr:08x} = 0x{value:08x}, verified (was {})",
                before.map_or("unreadable".to_string(), |b| format!("0x{b:08x}"))
            ),
            (_, Some(got)) => error!(
                "PATCH DID NOT LAND: 0x{addr:08x} reads 0x{got:08x}, wanted 0x{value:08x}. \
                 Anything you conclude from this run is about an unpatched title."
            ),
            (_, None) => error!(
                "PATCH UNVERIFIABLE: 0x{addr:08x} could not be read back. \
                 Do not conclude anything from this run."
            ),
        }
    }
    Ok(())
}

/// One 32-bit word out of the console's memory, or `None` if it could not be
/// read. Used only to check a patch, so a failure is reported by the caller
/// rather than aborting the run.
fn read_word(conn: &mut impl ExternalDcIo, addr: u32) -> Option<u32> {
    match receive_data(conn, Some(Duration::from_millis(500)), addr, 4, true) {
        Ok(b) if b.len() == 4 => Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        _ => None,
    }
}

/// Read a disc image's boot sector and work out what game it is.
///
/// The sector is the first one of the boot data track, i.e. IP.BIN sector 0 --
/// the same sector DreamShell hashes to name its presets.
///
/// Returns the reason on failure rather than a bare `None`. THAT MATTERS: the
/// ways this fails -- `open_disc` says the path does not exist or the file is
/// not a format we can read, and this one says the file reads fine but holds no
/// Dreamcast header -- call for completely different things from whoever is
/// looking at the log, and reporting all of them as "no readable IP.BIN in
/// <path>" sent one debugging session after a disc reader when the file simply
/// was not there.
///
/// A run that boots an image needs its identity, its boot binary, its IP.BIN
/// and then its sectors. The image is opened ONCE for all four (`main` holds
/// the reader): opening it again per use re-reads the zip central directory,
/// re-probes every CDI track for a PVD and re-opens every GDI track file, none
/// of which is cached. `path` is only what to call it in the message.
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

/// One place that turns a path into a reader, so the extension rules cannot
/// drift between the identification pass and the syscall loop.
///
/// Every failure is returned, none is swallowed. The previous version fell
/// through to `StubDisc` whenever a `.gdi` or `.cdi` failed to open and only
/// warned on the `.iso` branch, so a typo in a path, or an image in a format
/// the reader does not understand, produced a session with CDFS silently dead
/// and nothing in the log to say so.
///
/// A `.zip` is opened IN PLACE -- see `disc_formats::zip`. `archive.zip#member`
/// picks a member explicitly when the archive holds more than one image.
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
    } else if lower.ends_with(".cdi") {
        let src = FileSource::open(path).map_err(|e| format!("cannot open {path_str}: {e}"))?;
        Cdi::new(Box::new(src)).map(get_disc_format)
    } else {
        let src = FileSource::open(path).map_err(|e| format!("cannot open {path_str}: {e}"))?;
        Iso::new(Box::new(src))
            .map(get_disc_format)
            .map_err(|e| format!("cannot read {path_str} as a plain ISO: {e}"))
    }
}

/// `archive.zip#member`, but only when the left half is really a file.
///
/// A `#` in an ordinary path is legal and does happen, so the split is only
/// taken when it produces something that exists. Getting this backwards would
/// turn a perfectly good filename into "no such disc image".
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
        // Archives made on macOS carry a shadow copy of every file under
        // __MACOSX/; it is metadata, not an image, and picking one is an
        // instant "this .cdi has no tracks".
        .filter(|e| !e.name.starts_with("__MACOSX/"))
        .filter(|e| {
            let lower = e.name.to_ascii_lowercase();
            IMAGE_EXTENSIONS.iter().any(|x| lower.ends_with(x))
        })
        .map(|e| e.name.clone())
        .collect()
}

/// Which image inside the archive to read.
///
/// Preference is `.gdi`, then `.cdi`, then `.iso`, and a tie is REFUSED rather
/// than broken: an archive holding two games is a question only the user can
/// answer, and quietly picking the alphabetically-first one would boot the
/// wrong title with everything else looking normal.
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
    // Falling out of the loop and an empty `candidates` are the same answer:
    // `image_candidates` only ever returns names ending in one of these
    // extensions, so nothing matching means nothing usable.
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
        // A .gdi names its track files, and inside an archive "next to it"
        // means the same prefix -- that is what ZipContainer resolves.
        let container: Box<dyn Container> = Box::new(ZipContainer::new(archive, member));
        return Gdi::new(container, &base)
            .map(get_disc_format)
            .map_err(|e| format!("cannot read the GDI '{member}' in the archive: {e}"));
    }
    let src = archive.open_named(member).map_err(|e| e.to_string())?;
    if lower.ends_with(".cdi") {
        Cdi::new(src).map(get_disc_format)
    } else {
        Iso::new(src)
            .map(get_disc_format)
            .map_err(|e| format!("cannot read '{member}' as a plain ISO: {e}"))
    }
}

/// The title's own boot binary, read out of the disc image.
///
/// This is what makes `uexec <image>` work: the image already says which file
/// it boots and where that file is, so nobody has to extract `1ST_READ.BIN`
/// by hand and then pass two paths that have to agree.
pub fn boot_binary(
    spec: &str,
    mode: boot::Descramble,
) -> Result<boot::BootBinary, String> {
    let disc = open_disc(spec)?;
    boot::extract(disc.as_ref(), mode).map_err(|e| format!("{spec}: {e}"))
}

/// Does this path look like a disc image rather than something to upload?
///
/// By extension, plus the zip magic -- a zip is recognised by content because
/// the interesting case is exactly the one where the name is unhelpful.
pub fn is_disc_image(spec: &str) -> bool {
    let (path_str, _) = split_member(spec);
    let lower = path_str.to_ascii_lowercase();
    if IMAGE_EXTENSIONS.iter().any(|x| lower.ends_with(x)) {
        return true;
    }
    crate::disc_formats::zip::looks_like_zip(Path::new(path_str))
}

pub fn reboot(
    conn: &mut impl ExternalDcIo,
) -> std::result::Result<usize, std::boxed::Box<dyn std::error::Error>> {
    let command = DCLoadCmd {
        cmd: DCLoadCmds::Reboot(),
        address: 0,
        size: 0,
    };
    log_command(&command);
    conn.send_command(command)?;
    Ok(0)
}

pub fn receive_syscalls(
    conn: &mut impl ExternalDcIo,
    cd_disc: Option<Box<dyn DiscFormat>>,
    mount: Option<String>,
    running_base: Option<u32>,
    gaps_guard: &[(u32, u32)],
    memory: Option<std::sync::Arc<std::sync::Mutex<crate::memmap::MemoryRecorder>>>,
) -> std::result::Result<(), std::boxed::Box<dyn std::error::Error>> {
    // A disc that could not be opened is not a silent no-op: the title is
    // about to be started with CDFS redirection ON, so it will ask for sectors
    // and get errors for the rest of the session. Whoever failed to open it
    // said so, loudly and with the reason; here it is a stub that answers
    // every read with one.
    let disc = cd_disc.unwrap_or_else(|| get_disc_format(StubDisc {}));
    // Worked out HERE, not in the ReadToc arm. Both answers are fixed for the
    // session, and `num_sectors()` on a zipped GDI opens the last data track --
    // which can mean a full deflate index build, with the title frozen waiting
    // for its table of contents. (A `debug!` would not have warmed it: log
    // macros do not evaluate their arguments at the default verbosity.)
    let toc_start = disc.start_sector();
    let toc_sectors = disc.num_sectors();
    debug!("CDFS source: start_sector={toc_start} num_sectors={toc_sectors}");
    let base_path = mount.as_ref().map(Path::new);
    if let Some(base_path) = base_path
        && !base_path.exists()
    {
        panic!("Mount path does not exist");
    }
    let mut fs_syscall_state = FSSyscallState {
        base_path: base_path.map(|p| p.to_path_buf()),
        emulated_current_dir: Path::new(".").to_path_buf(),
        openfiles: vec![],
        opendirs: vec![],
    };
    fs_syscall_state.opendirs.resize_with(256, || None);
    fs_syscall_state.openfiles.resize_with(256, || None);
    let mut logged_lbas: HashSet<u32> = HashSet::new();
    // Destinations already reported as landing on the loader. The condition is
    // fatal but not immediate, so the same read can be re-requested several
    // times on the way down; saying it once per destination keeps the line that
    // matters at the top of the log rather than buried in its own repeats.
    let mut warned_overlap: HashSet<u32> = HashSet::new();
    let loader_base = running_base.unwrap_or(crate::loaders::DEFAULT_BASE);
    // Closest a disc read has come to the loader, and whether that has been
    // said. See the check itself for what the number is worth.
    let mut nearest_read: u32 = u32::MAX;
    let mut warned_near = false;
    let pvd_lba = toc_start.saturating_add(16);
    // Aggregates the title's disc reads into "loading" bursts (see `ui`). It
    // also decides how long we wait for the next packet: forever when nothing
    // is loading, which is exactly what this loop did before, and briefly while
    // a burst is open so the bar can be taken down when the loading stops.
    let mut load = ui::LoadMonitor::new();
    loop {
        match await_result(conn, load.poll_timeout()) {
            Err(e) => {
                // A timeout is not a fault here: it is the burst having gone
                // quiet, and the only reason we asked for one.
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|ioe| ioe.kind() == ErrorKind::TimedOut)
                {
                    load.settle();
                } else {
                    warn!("Error waiting for syscall: {}", e);
                }
            }
            Ok(cmds) => {
                for cmd in cmds {
                    if let Some(inner_cmd) = cmd.request {
                        match inner_cmd {
                            // Handle special cases
                            DCLoadClientCmds::ReadSector(start, dc_address, size) => {
                                debug!(
                                    "Received ReadSector syscall: start=0x{:08x}, dc_address=0x{:08x}, size={}",
                                    start, dc_address, size
                                );
                                if size % 2048 != 0 {
                                    return Err(Box::new(Error::new(
                                        ErrorKind::InvalidData,
                                        format!(
                                            "ReadSector size is not a multiple of 2048: {}",
                                            size
                                        ),
                                    )));
                                }
                                let num_sectors = size / 2048;
                                let mut buf = disc.read_sector(start, num_sectors)?;

                                // DIAGNOSTIC ONLY: blank the payload for one LBA.
                                // Destination and transfer size have both been
                                // exonerated for the read Sonic Adventure never
                                // completes; content is the only variable left.
                                // A UDP checksum is content-dependent, and a
                                // packet dropped for a checksum quirk would look
                                // exactly like this. If zeros get through, the
                                // data is what breaks the transfer.
                                //   DCLOAD_ZERO_LBA  hex LBA to blank
                                if let Some(z) =
                                    std::env::var("DCLOAD_ZERO_LBA").ok().and_then(|v| {
                                        u32::from_str_radix(v.trim_start_matches("0x"), 16).ok()
                                    })
                                    && start == z
                                {
                                    warn!("ZEROING (diagnostic): LBA 0x{start:08x}");
                                    buf.iter_mut().for_each(|b| *b = 0);
                                }
                                let buf = buf;

                                // DIAGNOSTIC ONLY: send high-destination reads
                                // somewhere else. Sonic Adventure always dies on
                                // the same read, and its LBA and its destination
                                // have never once occurred apart, so neither can
                                // be blamed. Redirecting the write separates them
                                // in a single run: if the transfer then completes,
                                // the destination is what kills it; if it still
                                // hangs, the destination is innocent. The title
                                // gets wrong data either way -- this is not a fix.
                                //   DCLOAD_REDIRECT_ABOVE  threshold, hex
                                //   DCLOAD_REDIRECT_TO     replacement, hex
                                let dc_address = {
                                    let parse = |k: &str| {
                                        std::env::var(k).ok().and_then(|v| {
                                            u32::from_str_radix(v.trim_start_matches("0x"), 16).ok()
                                        })
                                    };
                                    match (
                                        parse("DCLOAD_REDIRECT_ABOVE"),
                                        parse("DCLOAD_REDIRECT_TO"),
                                    ) {
                                        (Some(above), Some(to)) if dc_address >= above => {
                                            warn!(
                                                "REDIRECT (diagnostic): 0x{dc_address:08x} -> 0x{to:08x}"
                                            );
                                            to
                                        }
                                        _ => dc_address,
                                    }
                                };
                                if logged_lbas.insert(start) && buf.len() >= 8 {
                                    debug!(
                                        "ReadSector LBA=0x{start:08x} first8={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                                        buf[0],
                                        buf[1],
                                        buf[2],
                                        buf[3],
                                        buf[4],
                                        buf[5],
                                        buf[6],
                                        buf[7]
                                    );
                                }
                                if start == pvd_lba && buf.len() >= 6 {
                                    if &buf[1..6] == b"CD001" {
                                        info!("PVD signature is valid at LBA 0x{start:08x}");
                                    } else {
                                        warn!(
                                            "PVD signature mismatch at LBA 0x{start:08x}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                                            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
                                        );
                                    }
                                }
                                // A DISC READ THAT LANDS ON THE LOADER IS THE
                                // ONE FAILURE NOTHING REPORTS.
                                //
                                // dcload writes what it is handed, wherever it
                                // is handed it: cmd_partbin checks the address
                                // against the transfer window and never against
                                // the loader's own image. So a title whose
                                // allocator reaches the RAM the loader sits in
                                // has dcload overwrite itself with disc data
                                // while it is serving the read, and the session
                                // ends in silence -- black screen, no further
                                // requests, no error at either end (AGENTS.md
                                // 4.6, 14.17). The host is the only side that
                                // can see it coming, and seeing it costs one
                                // comparison per read.
                                if let Some(hit) = crate::loaders::overlapping_range(
                                    loader_base,
                                    (dc_address, dc_address.saturating_add(buf.len() as u32)),
                                ) && warned_overlap.insert(dc_address)
                                {
                                    error!(
                                        "DISC READ LANDS ON THE LOADER: LBA 0x{start:08x} -> \
                                         0x{dc_address:08x}..0x{:08x} ({} B) runs through \
                                         0x{:08x}..0x{:08x}, which the loader running at \
                                         0x{loader_base:08x} is using. Serving it anyway, but it \
                                         overwrites dcload while dcload is receiving it: expect \
                                         the console to go quiet from here with nothing else \
                                         logged. This title needs a loader base its own memory \
                                         map leaves alone.",
                                        dc_address.saturating_add(buf.len() as u32),
                                        buf.len(),
                                        hit.0,
                                        hit.1,
                                    );
                                }
                                // WHERE THIS TITLE'S MEMORY ACTUALLY IS, kept
                                // for the next session. This is the only place
                                // anyone ever learns it: the addresses that
                                // matter are computed by the title's allocator
                                // and appear nowhere in its binary.
                                // Locked only for the marking, which is two
                                // shifts; the Ctrl-C handler is the only other
                                // holder and it takes it once, at the end.
                                if let Some(rec) = memory.as_ref()
                                    && let Ok(mut rec) = rec.lock()
                                {
                                    rec.record(dc_address, buf.len() as u32);
                                }
                                // HOW CLOSE THE TITLE IS COMING, not just whether
                                // it has hit. A collision is detected before the
                                // run from constants the title loads
                                // (`literals_in_loader_footprint`), but an
                                // allocator that grows into the loader names no
                                // address at all, so nothing sees it coming.
                                // Where a title's disc reads land is the one
                                // direct evidence of where its memory actually
                                // is, and this host has it for free.
                                //
                                // Measured 2026-08-27 on Sonic Adventure 2's
                                // Kart mode, which streams KART.ADX into
                                // 0x8ce3a920: with the loader at 0x8ce00000 --
                                // 182 KB below those reads -- the mode is a
                                // black screen; at 0x8cef8000, some 810 KB
                                // clear of them, it runs. ONE pair of
                                // observations, so treat this as a lead and not
                                // a verdict: it says the loader is sitting in
                                // the region the title is using, which is worth
                                // knowing and is not proof of the mechanism.
                                //
                                // HIGH BASES ONLY, and for the same reason the
                                // constant check excludes the low ranges: at the
                                // stock base the title is loaded at 0x8c010000,
                                // immediately above the loader, so every read it
                                // ever makes is "near" and the warning would fire
                                // on every title forever (AGENTS.md 14.9).
                                if loader_base >= 0x8c01_0000 {
                                    const TOO_NEAR: u32 = 0x4_0000;
                                    let lo = dc_address & 0x1fff_ffff;
                                    let (blo, bhi) = (
                                        loader_base & 0x1fff_ffff,
                                        (loader_base & 0x1fff_ffff)
                                            .saturating_add(crate::loaders::LOADER_SPAN),
                                    );
                                    let gap = if lo >= bhi {
                                        lo - bhi
                                    } else {
                                        blo.saturating_sub(lo + buf.len() as u32)
                                    };
                                    if gap < nearest_read {
                                        nearest_read = gap;
                                    }
                                    if !warned_near && nearest_read < TOO_NEAR {
                                        warned_near = true;
                                        warn!(
                                            "this title's disc reads come within {} KB of the \
                                             loader at 0x{loader_base:08x} (LBA 0x{start:08x} -> \
                                             0x{dc_address:08x}). Its memory reaches this far, so \
                                             the loader is in ground it is using -- an allocation \
                                             that goes a little further overwrites it, and nothing \
                                             reports that. If this title misbehaves, move the \
                                             loader further away with --loader-base before \
                                             suspecting anything else.",
                                            nearest_read / 1024
                                        );
                                    }
                                }
                                // A FAILED TRANSFER MUST NOT KILL THE SERVER.
                                //
                                // This used to be `send_data(...)?`, so the first
                                // transfer that went unanswered propagated out of
                                // the dispatch loop and the whole tool exited --
                                // taking away the only thing that could have
                                // served the DC's retry. And no ReturnValue is
                                // sent here on purpose: dcload must see its read
                                // time out and ask again, rather than be told a
                                // half-filled buffer is complete. A title that
                                // executes short data is far worse off than one
                                // that waits.
                                match send_data(conn, &buf, dc_address, None) {
                                    Ok(_) => {
                                        // READ-BACK VERIFICATION (DCLOAD_VERIFY_READS=1).
                                        //
                                        // Every other instrument on this path is
                                        // ACCOUNTING: it counts packets accepted and
                                        // checks the map is full. Corruption by RX-ring
                                        // splice is invisible to all of it, because the
                                        // bytes are all delivered and all counted -- just
                                        // not all right. This is the only check that
                                        // compares what the DC HOLDS against what was
                                        // sent, and it has to happen here, after the last
                                        // PartBinary and before the ReturnValue, while the
                                        // title is still waiting and nothing else can have
                                        // touched the buffer.
                                        if std::env::var("DCLOAD_VERIFY_READS").is_ok() {
                                            match receive_data(
                                                conn,
                                                Some(Duration::from_millis(3000)),
                                                dc_address,
                                                buf.len(),
                                                true,
                                            ) {
                                                Ok(back) => {
                                                    let bad: Vec<usize> = back
                                                        .iter()
                                                        .zip(buf.iter())
                                                        .enumerate()
                                                        .filter(|(_, (a, b))| a != b)
                                                        .map(|(i, _)| i)
                                                        .collect();
                                                    if bad.is_empty() {
                                                        info!(
                                                            "VERIFY ok: LBA 0x{start:08x} -> 0x{dc_address:08x} {} B clean",
                                                            buf.len()
                                                        );
                                                    } else {
                                                        error!(
                                                            "VERIFY MISMATCH: LBA 0x{start:08x} -> 0x{dc_address:08x}: \
                                                             {} of {} bytes wrong, first at +0x{:x} (sent {:02x}, holds {:02x})",
                                                            bad.len(),
                                                            buf.len(),
                                                            bad[0],
                                                            buf[bad[0]],
                                                            back[bad[0]]
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("VERIFY read-back failed: {e}");
                                                }
                                            }
                                        }
                                        // THE GAPS GUARD HAS TO SURVIVE A RELOAD.
                                        //
                                        // What it neutralises is a word in the
                                        // title's own image, and a title is free
                                        // to read its image back off its disc.
                                        // That would restore the probe's
                                        // comparison constant and let it switch
                                        // the adapter off, after which the loader
                                        // is deaf with nothing logged at either
                                        // end (AGENTS.md 4.12) -- the same silent
                                        // ending the guard exists to prevent,
                                        // reached the long way round. Tested on
                                        // every read, paid for only by one that
                                        // actually covers a patched word, and
                                        // done HERE: after the read-back
                                        // comparison, so it has nothing to
                                        // disagree with, and before the
                                        // ReturnValue, which is the last moment
                                        // the title is still parked and cannot
                                        // yet run what was just delivered.
                                        let reloaded: Vec<(u32, u32)> = gaps_guard
                                            .iter()
                                            .copied()
                                            .filter(|&(at, _)| {
                                                let lo = dc_address & 0x1fff_ffff;
                                                let hi = lo.saturating_add(buf.len() as u32);
                                                (lo..hi).contains(&(at & 0x1fff_ffff))
                                            })
                                            .collect();
                                        if !reloaded.is_empty() {
                                            warn!(
                                                "this read reloads the code the GAPS guard \
                                                 patched (LBA 0x{start:08x} -> 0x{dc_address:08x}, \
                                                 {} B); re-applying it before the title can run \
                                                 the bytes just delivered",
                                                buf.len()
                                            );
                                            if let Err(e) = apply_patches(conn, &reloaded) {
                                                error!("could not re-apply the GAPS guard: {e}");
                                            }
                                        }
                                        conn.send_command(DCLoadCmd {
                                            cmd: DCLoadCmds::ReturnValue(),
                                            address: 0,
                                            size: 0,
                                        })?;
                                        // AFTER the ReturnValue, deliberately.
                                        // Until it is sent the title is still
                                        // parked in bb->loop() waiting for this
                                        // read, so anything done before it --
                                        // including redrawing a bar -- is time
                                        // the game spends frozen.
                                        load.record(buf.len(), start);
                                    }
                                    Err(e) => {
                                        warn!(
                                            "ReadSector transfer unanswered (LBA 0x{start:08x} -> 0x{dc_address:08x}): {e}. \
                                             Staying up; the DC will time out and re-request."
                                        );
                                    }
                                }
                            }
                            DCLoadClientCmds::ReadToc(_session, dc_address, _unused) => {
                                let toc = build_dc_toc(toc_start, toc_sectors);
                                if let Err(e) = send_data(conn, &toc, dc_address, None) {
                                    warn!("Failed to send CDFS TOC data: {}", e);
                                    let _ = conn.send_command(DCLoadCmd {
                                        cmd: DCLoadCmds::ReturnValue(),
                                        address: u32::MAX,
                                        size: u32::MAX,
                                    });
                                    continue;
                                }
                                let _ = conn.send_command(DCLoadCmd {
                                    cmd: DCLoadCmds::ReturnValue(),
                                    address: 0,
                                    size: 0,
                                })?;
                            }
                            DCLoadClientCmds::Exit => {
                                info!("Received Exit syscall, terminating syscall receiver");
                                return Ok(());
                            }
                            DCLoadClientCmds::FSCommand(cmd) => {
                                debug!("Received FSCommand syscall: {:?}", cmd);
                                match fs::handle_fs_syscall(conn, cmd, &mut fs_syscall_state) {
                                    Ok(result) => {
                                        call_command(conn, result)?;
                                    }
                                    Err(e) => {
                                        warn!("Failed to handle FS syscall: {}", e);
                                        call_command(
                                            conn,
                                            DCLoadCmd {
                                                cmd: DCLoadCmds::ReturnValue(),
                                                address: u32::MAX,
                                                size: u32::MAX,
                                            },
                                        )?;
                                    }
                                }
                            }
                        }
                    }
                }
                // A batch that carried no disc read still tells us time has
                // passed. Without this, a title that goes on chatting -- console
                // output, a file syscall -- after it stops loading would keep
                // the poll returning promptly and leave the bar up.
                load.settle();
            }
        }
    }
}

pub fn send_version(
    conn: &mut impl ExternalDcIo,
) -> std::result::Result<Vec<DCReturnCmd>, std::boxed::Box<dyn std::error::Error>> {
    let protocol_version = protocol_version();
    call_command(
        conn,
        DCLoadCmd {
            cmd: DCLoadCmds::Version(None),
            address: ((protocol_version[0] as u32) << 16)
                | ((protocol_version[1] as u32) << 8)
                | protocol_version[2] as u32,
            size: 0,
        },
    )
}

/*
 * Largest payload dcload can track in ONE LoadBinary.
 *
 * Its packet map is BIN_INFO_MAP_SIZE (256) entries of CHUNK_SIZE each. That
 * array used to be 11656 entries -- 11.6 KB of the loader sitting exactly
 * where Sonic Adventure puts a stack, which is what eventually corrupts
 * dcload's adapter pointer. Shrinking it on the DC means the host must not
 * hand it a transfer it cannot map. THESE TWO NUMBERS MUST STAY IN STEP.
 */
const MAX_XFER: usize = 256 * CHUNK_SIZE;

/// Busy-wait for `d`, the way dc-tool paces its bursts.
///
/// thread::sleep is the wrong tool for sub-millisecond pacing on Windows: it
/// rounds up to the system timer tick, so a 1800 us pause is billed as 2 ms and
/// a 1 ns "yield" is billed as a full tick. On the runtime CDFS path that error
/// is not an inefficiency -- the Dreamcast blocks the running title for the
/// whole transfer, so every microsecond overspent here is a microsecond the
/// game is not rendering. Spin instead, and the pacing means what it says.
///
/// The cost is real CPU on the host, which is exactly the trade dc-tool makes
/// (`while ((time_in_usec() - start) < rx_fifo_delay);`). At the default 1800 us
/// per 12-packet chunk it is a few percent of one core.
fn spin_for(d: Duration) {
    if d.is_zero() {
        return;
    }
    let start = Instant::now();
    while start.elapsed() < d {
        std::hint::spin_loop();
    }
}

/// Split anything larger than the DC's packet map into successive transfers.
///
/// `progress_bar` is TWO THINGS AT ONCE, and both matter. It is where the
/// caller wants the bytes counted, and it is the flag that says "this is the
/// initial upload, not a runtime CDFS transfer" -- the two paths pace
/// differently, probe differently, and have completely different tolerance for
/// host-side delay (a runtime transfer freezes the running title for its whole
/// duration). Passing `None` from the upload path, or `Some` from the syscall
/// path, would silently swap those behaviours.
pub fn send_data(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    progress_bar: Option<&ProgressBar>,
) -> std::result::Result<usize, std::boxed::Box<dyn std::error::Error>> {
    if data.len() > MAX_XFER {
        let mut sent = 0usize;
        for (i, part) in data.chunks(MAX_XFER).enumerate() {
            send_data_one(conn, part, address + (i * MAX_XFER) as u32, progress_bar)?;
            sent += part.len();
        }
        return Ok(sent);
    }
    send_data_one(conn, data, address, progress_bar)
}

fn send_data_one(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    progress_bar: Option<&ProgressBar>,
) -> std::result::Result<usize, std::boxed::Box<dyn std::error::Error>> {
    let mut incr_address = address;

    // Every binary upload starts with a LoadBinary call.
    //
    // THE ACKNOWLEDGEMENT MUST BE THE RIGHT ONE. This used to accept whatever
    // packet happened to arrive next: any leftover from the previous transfer
    // -- a late ReturnValue, a duplicated DoneBinary reply -- satisfied the
    // loop and we moved straight on to blasting PartBinary. If the LoadBinary
    // itself had actually been lost, the DC still had the PREVIOUS window
    // installed, so every one of those parts fell outside it and was dropped
    // on the floor. Measured on the DC side: window (0x0cef7000, 16384) set
    // only afterwards, and exactly 12 parts -- one full 16 KB chunk -- refused.
    //
    // dcload echoes the command back, so the echo can simply be checked.
    let mut acked = false;
    for i in 0..5 {
        if let Ok(cmds) = call_command(
            conn,
            DCLoadCmd {
                cmd: DCLoadCmds::LoadBinary(),
                address: incr_address,
                size: data.len() as u32,
            },
        ) {
            if let Some(e) = cmds.first().and_then(|c| c.error_code) {
                warn!("Seems the load binary command was not understood, retrying...");
                if i == 4 {
                    return Err(Box::new(std::io::Error::other(format!(
                        "LoadBinary command not understood after several tries: {}",
                        e
                    ))));
                }
                continue;
            }
            if cmds.iter().any(|c| {
                c.cmd.as_ref().is_some_and(|inner| {
                    matches!(inner.cmd, DCLoadCmds::LoadBinary()) && inner.address == incr_address
                })
            }) {
                acked = true;
                break;
            }
            debug!("LoadBinary echo for 0x{incr_address:08x} not seen yet, retrying");
        }
    }
    if !acked {
        return Err(Box::new(std::io::Error::new(
            ErrorKind::TimedOut,
            format!(
                "No LoadBinary echo for 0x{incr_address:08x}; refusing to send parts into an unset window"
            ),
        )));
    }

    // How much of THIS transfer the DC has confirmed. The bar it feeds spans
    // the whole file, so this is the local half of the bookkeeping.
    let mut confirmed = 0usize;

    // Send each chunk using PartBinary with pacing to avoid overrunning
    // Dreamcast RX FIFO during runtime CDFS transfers.
    // Keep upload pacing close to existing behavior, but use dc-tool-like
    // conservative pacing for runtime syscall transfers.
    let (burst_packets, burst_delay) = if progress_bar.is_none() {
        // RUNTIME CDFS TRANSFERS: PACE EVERY PACKET.
        //
        // This used to send 10 back to back before pausing, i.e. ~15 KB into
        // a 16 KB RX ring with nothing in between. When that outruns dcload's
        // poll loop the ring does not merely drop a frame: it overflows and
        // desyncs, leaving CAPR ahead of CBR with RxBufEmpty clear, and from
        // then on the DC receives NOTHING -- measured CAPR 6340 vs CBR 2212,
        // dcload's LBIN/PBIN/DBIN counters frozen for the whole 20 s syscall
        // timeout while flycast reported every frame delivered (dropped=0).
        // That wedge does not recover, so being slow here costs nothing next
        // to being fast.
        //
        // Tunable without a rebuild:
        //   DCLOAD_RT_BURST     packets per pause (default 1 = pace each one)
        //   DCLOAD_RT_DELAY_US  pause length, microseconds (default 500)
        // Defaults left at the original values: pacing every packet at 500 us
        // was measured and changed NOTHING about the failure, so slowing every
        // transfer down for it would be a cost with no benefit.
        let n = std::env::var("DCLOAD_RT_BURST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10)
            .max(1);
        let us = std::env::var("DCLOAD_RT_DELAY_US")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1800);
        (n, Duration::from_micros(us))
    } else {
        // UPLOAD PACING: THE BURST MUST FIT THE RING.
        //
        // This was 15 packets back to back. At 1494 bytes on the wire that is
        // roughly 22 KB pushed into a 16 KB RX ring before the DC is given any
        // chance to drain -- so the tail of every burst is lost by
        // construction, and a 6.4 MB upload arrived with ~150 holes that then
        // had to be found and repaired one DoneBinary round trip at a time.
        //
        // Eight packets is about 12 KB, comfortably inside the ring.
        //
        // Do not tune this further hoping to reach zero. Measured: bursts of 8
        // and of 4 both leave the SAME number of holes (63 vs 64) while 4 makes
        // the upload 38% slower. The residual loss is not congestion -- it is
        // strictly periodic, one packet in every 75-80, independent of pacing,
        // and therefore structural. The RX ring wrap is the place to look:
        // 16384 / 1504 bytes per slot is 10.89, so the wrap point drifts, and
        // one loss per ~7 wraps is what that drift would look like.
        (8_u32, Duration::from_millis(2))
    };
    // THE INITIAL UPLOAD PACES ITSELF AGAINST THE DC, NOT AGAINST A CLOCK.
    //
    // Timed pacing here was OPEN LOOP: 256 parts went out back to back with a
    // 2 ms pause every 8, roughly 4000 packets/s, and nothing on the way ever
    // asked whether the DC had drained any of them. DoneBinary only came at the
    // end of the whole 368 KB transfer. When the Dreamcast drains slower than
    // that -- which under an interpreted SH4 it always does -- the shortfall
    // accumulates until the 16 KB RX ring overflows and the CHIP starts
    // discarding frames.
    //
    // That is now measured rather than inferred. dcload reads RT_RXMISSED, the
    // RTL8139's own tally of frames it threw away for want of ring space:
    // g_rx_missed = 887 across one upload, while every CPU-side counter stayed
    // clean (g_rx_status_drop 0, g_rx_hdr_defer 0, g_udp_cksum_bad 0,
    // g_pbin_rejected 0) and flycast's bridge reported dropped=0. The loss was
    // congestion all along; it looked structural because dcload's overflow
    // counter was being cleared by its own per-frame interrupt acknowledge, so
    // the one instrument that could have shown it read zero.
    //
    // This also explains why bursts of 8 and of 4 left the same number of holes:
    // only the burst changed, the 2 ms delay did not, so the average rate --
    // the thing that actually overruns the ring -- was nearly identical.
    //
    // So close the loop with the mechanism the protocol already has. DoneBinary
    // is a BARRIER: dcload processes datagrams in arrival order, so a reply
    // proves every PartBinary sent before it has been handled, and its payload
    // is the first part still missing -- exactly where to resume. A window that
    // fits the ring can therefore never be exceeded, whatever the DC's speed.
    //
    // RUNTIME CDFS TRANSFERS ARE DELIBERATELY LEFT ALONE. A 16 KB sector read is
    // only 12 parts, so probing per window would add a round trip to a path
    // whose timing a running title is sensitive to, to fix a problem that only
    // shows up over hundreds of consecutive parts.
    let mut packet_count: u32 = 0;
    if progress_bar.is_some() {
        let window = burst_packets.max(1) as usize;
        let mut pos: usize = 0;
        let mut last_missing: Option<usize> = None;
        let mut stalled: u32 = 0;

        loop {
            let mut in_window = 0usize;
            while pos < data.len() && in_window < window {
                let end = (pos + CHUNK_SIZE).min(data.len());
                let chunk = &data[pos..end];
                let mut padded_chunk = [0u8; CHUNK_SIZE];
                padded_chunk[..chunk.len()].copy_from_slice(chunk);
                conn.send_command(DCLoadCmd {
                    cmd: DCLoadCmds::PartBinary(Box::new(padded_chunk)),
                    address: address + pos as u32,
                    size: chunk.len() as u32,
                })?;
                pos = end;
                in_window += 1;
                packet_count = packet_count.saturating_add(1);
                sleep(Duration::from_nanos(1));
            }

            let probe = request_donebin(conn)?;
            if probe.size == 0 {
                // Nothing missing anywhere in this LoadBinary window: done.
                credit(progress_bar, &mut confirmed, data.len());
                break;
            }

            let missing = probe.address.wrapping_sub(address) as usize;
            if missing >= data.len() {
                // Cannot happen for a non-zero size, and acting on it would
                // index out of bounds. Treat as complete and let the existing
                // recovery loop below have the final word.
                break;
            }
            // DoneBinary names the FIRST part still missing, so everything
            // below it is confirmed received -- that, and nothing else, is
            // what the bar advances on.
            credit(progress_bar, &mut confirmed, missing);

            if missing < pos {
                // A hole inside what we already sent. Rewind exactly to it --
                // the parts after it are re-sent too, which costs nothing since
                // the DC simply overwrites them with identical bytes.
                if last_missing == Some(missing) {
                    stalled += 1;
                    // Refusing the same part over and over means something other
                    // than loss is wrong (a window the DC never installed, say).
                    // Bail rather than spin forever.
                    if stalled > 16 {
                        return Err(Box::new(std::io::Error::new(
                            ErrorKind::TimedOut,
                            format!(
                                "The Dreamcast kept asking for 0x{:08x} after {} attempts",
                                probe.address, stalled
                            ),
                        )));
                    }
                } else {
                    stalled = 0;
                }
                last_missing = Some(missing);
                pos = missing;
            }
        }
    } else {
        // RUNTIME CDFS TRANSFERS: THE TITLE IS FROZEN FOR EVERY MICROSECOND
        // SPENT IN HERE.
        //
        // dcload answers a disc read synchronously -- it sits in bb->loop()
        // until the last PartBinary lands -- so this loop does not merely pace
        // a transfer, it decides how long the game stops rendering. Measured on
        // Sonic Adventure before this change: 45.6 ms per 16 KB chunk, 3.7
        // chunks per read, so ~168 ms of frozen game per disc read, and dcload
        // holding 35.6% of the machine. That is the stutter, and almost none of
        // it was the network: 16 KB at 100 Mbit is 1.3 ms of wire time.
        //
        // It was thread::sleep. On Windows that rounds up to the system timer
        // tick, so the three sleeps below cost, per chunk:
        //   12 x sleep(1 ns)  -> ~12 ms   (a yield that was never free)
        //    1 x sleep(1800us)-> ~2 ms    (asked for 1.8, billed 2)
        //    1 x sleep(25 ms) -> 25 ms
        // ~39 ms of the 45.6 measured, all of it deliberate waiting.
        //
        // dc-tool, the reference host, does not sleep for this. It spins:
        //   while ((time_in_usec() - start) < rx_fifo_delay);
        // which is why 1800 us there means 1800 us. Do the same, and drop the
        // two waits that buy nothing.
        for chunk in data.chunks(CHUNK_SIZE) {
            let mut padded_chunk = [0u8; CHUNK_SIZE];
            padded_chunk[..chunk.len()].copy_from_slice(chunk);
            conn.send_command(DCLoadCmd {
                cmd: DCLoadCmds::PartBinary(Box::new(padded_chunk)),
                address: incr_address,
                size: chunk.len() as u32,
            })?;
            incr_address += chunk.len() as u32;
            packet_count = packet_count.saturating_add(1);
            // The per-packet sleep(1 ns) that used to be here is gone. It read
            // as "yield briefly"; on Windows it is a full timer tick, and it
            // was the single largest cost in this loop.
            if packet_count.is_multiple_of(burst_packets) {
                // KEPT, BUT MADE PRECISE. The burst still has to fit the DC's
                // 16 KB RX ring -- 12 packets is ~18 KB, so pausing once
                // partway through is what stops the tail being dropped. Only
                // the mechanism changes, not the pacing the DC sees.
                spin_for(burst_delay);
            }
        }

        // NO BLIND WAIT BEFORE DoneBinary.
        //
        // This was sleep(25 ms), "give in-flight UDP packets a chance to
        // arrive". The protocol already guarantees that, by the same argument
        // this file makes for the upload path above: dcload processes
        // datagrams in arrival order, so DoneBinary is a BARRIER -- its reply
        // proves every PartBinary sent before it has been handled, and names
        // the first part still missing. Waiting first cannot make that answer
        // more true; it only adds 25 ms of frozen game to every 16 KB read.
        //
        // If this is ever wrong, the symptom is specific and measurable: the
        // DC starts reporting holes it would have filled in, so watch
        // g_cdfs_read_retries and the "resending missing parts" warning.
    }

    let first_donebin = request_donebin(conn)?;
    if first_donebin.size > 0 {
        let mut last_cmd = first_donebin;
        // What the bar was saying before the repair started -- the section
        // being uploaded, usually. Put it back afterwards instead of blanking
        // it, so a repair does not cost the caller its label.
        let previous_message = progress_bar.map(|bar| bar.message());
        warn!("There was an error while uploading the binary, resending missing parts...");

        // RESEND A RUN, NOT A SINGLE PACKET.
        //
        // DoneBinary only ever names the FIRST missing part, and this loop used
        // to resend exactly that one packet and then ask again. Losses on this
        // link are not isolated: the DC's RX ring is 16 KB, so when it is
        // outrun the packets go missing in long CONSECUTIVE runs. One run of
        // 840 lost packets therefore cost 840 resends and 840 DoneBinary round
        // trips, each of which can itself time out -- minutes of recovery for
        // an incident measured in milliseconds.
        //
        // Resending a run from the reported address collapses that. Overshooting
        // is free: a part the DC already holds is simply written again with the
        // same bytes.
        //
        // The run GROWS, and that matters. Losses are sometimes one contiguous
        // burst and sometimes scattered across the whole transfer; measured on a
        // 6.4 MB upload, 154 holes spaced further apart than any fixed run length
        // still cost one round trip each. Doubling means a clustered loss is
        // repaired in one pass and a scattered one converges in about ten,
        // instead of once per hole. Paced exactly like the initial send, so a
        // large run cannot overflow the ring and re-create the problem.
        const RESEND_RUN_MAX: usize = 64;
        let mut resend_run: usize = 8;

        let mut resent_total: usize = 0;
        loop {
            debug!(
                "Missing {:?} bytes at address 0x{:08x}",
                last_cmd.size, last_cmd.address,
            );
            if last_cmd.address < address {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "The Dreamcast asked us to resend 0x{:08x}, below the transfer base 0x{:08x}",
                        last_cmd.address, address
                    ),
                )));
            }
            if last_cmd.size as usize > CHUNK_SIZE {
                // Just for safety, should never happens
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "The Dreamcast asked us to resend a chunk that was larger than the maximum allowed size of {} bytes",
                        CHUNK_SIZE
                    ),
                )));
            }

            // Say so on the bar. A repair is the one time an upload legitimately
            // stops making forward progress, and without a word for it the
            // display just looks stuck.
            if let Some(bar) = progress_bar {
                bar.set_message(format!("repairing +{resent_total}"));
            }

            let mut start = (last_cmd.address - address) as usize;
            for i in 0..resend_run {
                if start >= data.len() {
                    break;
                }
                let end = (start + CHUNK_SIZE).min(data.len());
                let chunk_slice = &data[start..end];
                let mut padded_chunk = [0u8; CHUNK_SIZE];
                padded_chunk[..chunk_slice.len()].copy_from_slice(chunk_slice);
                conn.send_command(DCLoadCmd {
                    cmd: DCLoadCmds::PartBinary(Box::new(padded_chunk)),
                    address: address + start as u32,
                    size: chunk_slice.len() as u32,
                })?;
                resent_total += 1;
                start = end;
                if (i + 1) % burst_packets as usize == 0 {
                    sleep(burst_delay);
                }
            }
            sleep(Duration::from_millis(5));

            let donebin = request_donebin(conn)?;
            if donebin.size > 0 {
                last_cmd = donebin;
                // Capped. Unbounded doubling was measured worse, not better:
                // it cut the round trips from 154 to 18 but resent 31472 parts
                // (45 MB for a 6.4 MB upload) and the whole transfer went from
                // 5.2 s to 9.0 s. Past a point, redundant payload costs more
                // than the round trips it saves.
                resend_run = (resend_run * 2).min(RESEND_RUN_MAX);
            } else {
                // And seems we're finally good!
                break;
            }
        }
        warn!("Recovered after resending {resent_total} part(s)");
        if let (Some(bar), Some(message)) = (progress_bar, previous_message) {
            bar.set_message(message);
        }
    }
    if let Some(bar) = progress_bar {
        // The whole window is acknowledged by now; make the bar say so, since
        // the credit above only ever advanced to the first *missing* part.
        credit(Some(bar), &mut confirmed, data.len());
    }

    Ok(0)
}

/// Advance a bar to `reached` bytes of the current transfer, never backwards.
///
/// DoneBinary reports the first part still missing, which MOVES BACKWARDS every
/// time a hole is found and re-sent. Feeding that straight to `set_position`
/// makes the bar jump about and poisons the rate estimate with negative
/// progress; crediting the high-water mark instead means the bar shows what the
/// Dreamcast has actually acknowledged, which is the number worth an ETA.
fn credit(bar: Option<&ProgressBar>, confirmed: &mut usize, reached: usize) {
    if reached <= *confirmed {
        return;
    }
    if let Some(bar) = bar {
        bar.inc((reached - *confirmed) as u64);
    }
    *confirmed = reached;
}

fn call_command(
    conn: &mut impl ExternalDcIo,
    command: DCLoadCmd,
) -> std::result::Result<Vec<DCReturnCmd>, std::boxed::Box<dyn std::error::Error>> {
    let tries = 5;
    for _ in 0..tries {
        log_command(&command);
        conn.send_command(command.clone())?;
        match await_result(conn, Some(Duration::from_millis(500))) {
            Err(e) => warn!(
                "Error waiting for response after command {}: {}, retrying... That might indicate packet loss",
                command, e
            ),
            Ok(cmds) => return Ok(cmds),
        }
    }
    Err(Box::new(std::io::Error::new(
        ErrorKind::TimedOut,
        format!("No response after {} tries for command {}", tries, command),
    )))
}

/// Log an outgoing command at the level its FREQUENCY deserves.
///
/// DoneBinary is not one command per transfer, it is one per eight-packet
/// window: an upload probes with it continuously, so at debug level it alone
/// produced hundreds of identical lines per second -- the noise that made the
/// display unreadable in the first place. It is still there under `-vv`, where
/// somebody asking for trace has asked for exactly that.
fn log_command(command: &DCLoadCmd) {
    if matches!(command.cmd, DCLoadCmds::DoneBinary()) {
        trace!("Sending command: {}", command);
    } else {
        debug!("Sending command: {}", command);
    }
}

fn extract_donebin(cmds: &[DCReturnCmd]) -> Option<DCLoadCmd> {
    cmds.iter().find_map(|ret| {
        ret.cmd.as_ref().and_then(|cmd| {
            if cmd.cmd == DCLoadCmds::DoneBinary() {
                Some(cmd.clone())
            } else {
                None
            }
        })
    })
}

fn request_donebin(
    conn: &mut impl ExternalDcIo,
) -> std::result::Result<DCLoadCmd, std::boxed::Box<dyn std::error::Error>> {
    let cmd = DCLoadCmd {
        cmd: DCLoadCmds::DoneBinary(),
        address: 0,
        size: 0,
    };

    // For large runtime CDFS transfers, responses can be delayed by queued PBIN packets.
    // Send DBIN, then keep polling for a while before retrying.
    //
    // Bounded much tighter than it used to be (5 x 4 s = 20 s). When a transfer
    // is genuinely lost, every second spent here is a second the server is NOT
    // listening, so the DC's own timeout and retry cannot be served. Giving up
    // sooner is what makes the retry path on the DC side reachable at all.
    for _retry in 0..2 {
        log_command(&cmd);
        conn.send_command(cmd.clone())?;

        for _poll_try in 0..10 {
            match await_result(conn, Some(Duration::from_millis(200))) {
                Ok(cmds) => {
                    if let Some(donebin) = extract_donebin(&cmds) {
                        return Ok(donebin);
                    }
                    debug!("Received non-DBIN packets while waiting for DoneBinary response");
                }
                Err(e) => {
                    if let Some(ioe) = e.downcast_ref::<std::io::Error>()
                        && ioe.kind() == ErrorKind::TimedOut
                    {
                        continue;
                    }
                    warn!("Error waiting for DoneBinary response: {}", e);
                }
            }
        }
    }

    Err(Box::new(std::io::Error::new(
        ErrorKind::TimedOut,
        "No DoneBinary response received",
    )))
}

fn await_result(
    conn: &mut impl ExternalDcIo,
    timeout: Option<Duration>,
) -> std::result::Result<Vec<DCReturnCmd>, std::boxed::Box<dyn std::error::Error>> {
    match conn.poll(timeout) {
        Err(e) if e.kind() == ErrorKind::TimedOut => {
            error!("Timeout waiting for response after execute command");
            Err(Box::new(e))
        }
        Err(e) => {
            error!("Error polling for response: {}", e);
            Err(Box::new(e))
        }
        Ok(evt) => {
            if evt.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "No events received",
                )));
            }
            Ok(conn.handle_data(&evt)?)
        }
    }
}

pub fn receive_data(
    conn: &mut impl ExternalDcIo,
    timeout: Option<Duration>,
    address: u32,
    size: usize,
    quiet: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let expected_chunks = size.div_ceil(CHUNK_SIZE);
    let mut data = vec![0u8; size];
    let mut chunk_map: Vec<bool> = vec![false; expected_chunks];

    conn.send_command(DCLoadCmd {
        cmd: if quiet {
            DCLoadCmds::SendBinaryQuiet(None)
        } else {
            DCLoadCmds::SendBinary(None)
        },
        address,
        size: size as u32,
    })?;

    // Same display as an upload, and registered with the same MultiProgress so
    // the read-back verification path cannot draw over the log either.
    let bar = ui::bytes_bar(size as u64, "read-back");

    for _ in 0..expected_chunks {
        match await_result(conn, timeout) {
            Err(e) => {
                warn!("Error waiting for data chunk: {}", e);
            }
            Ok(cmds) => {
                for cmd in cmds {
                    if let Some(inner_cmd) = cmd.cmd {
                        match inner_cmd.cmd {
                            DCLoadCmds::SendBinary(Some(chunk)) => {
                                // The bound here compares a BYTE OFFSET, not a chunk
                                // count. It used to be measured against
                                // (size + CHUNK_SIZE) / CHUNK_SIZE, i.e. the number of
                                // chunks -- so for any transfer bigger than one packet
                                // every chunk after the first was rejected as "bad",
                                // its slot never filled, and the recovery loop below
                                // re-requested it forever. receive_data() therefore
                                // only ever worked for single-packet reads.
                                if inner_cmd.address < address
                                    || (inner_cmd.address - address) as usize >= size
                                {
                                    warn!(
                                        "Out-of-range chunk at 0x{:08x} for read-back of 0x{:08x}+{}, ignoring",
                                        inner_cmd.address, address, size
                                    );
                                    continue;
                                }
                                // Append data chunk to data vector
                                let offset = (inner_cmd.address - address) as usize;
                                let end = (offset + chunk.len()).min(size);
                                data[offset..end].copy_from_slice(&chunk[..end - offset]);
                                chunk_map[offset / CHUNK_SIZE] = true;
                                bar.inc(chunk.len() as u64);
                            }
                            DCLoadCmds::DoneBinary() => break,
                            _ => {
                                warn!(
                                    "Unexpected command received while waiting for data: {:?}",
                                    inner_cmd
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    loop {
        for (i, received) in chunk_map.clone().iter().enumerate() {
            if !received {
                debug!("Missing chunk {}", i);
                conn.send_command(DCLoadCmd {
                    cmd: DCLoadCmds::SendBinaryQuiet(None),
                    address: address + (i as u32 * CHUNK_SIZE as u32),
                    size: if size.is_multiple_of(CHUNK_SIZE) {
                        CHUNK_SIZE as u32
                    } else {
                        size as u32 - (i as u32 * CHUNK_SIZE as u32)
                    },
                })?;

                match await_result(conn, timeout) {
                    Err(e) => {
                        warn!("Error waiting for data chunk: {}", e);
                    }
                    Ok(cmds) => {
                        for cmd in cmds {
                            if let Some(inner_cmd) = cmd.cmd {
                                match inner_cmd.cmd {
                                    DCLoadCmds::SendBinary(Some(chunk)) => {
                                        // Same two defects as the first copy of
                                        // this loop, and they panicked the whole
                                        // tool here: the bound compared a BYTE
                                        // OFFSET against a CHUNK COUNT, and the
                                        // copy used the full padded chunk length
                                        // even for the short final piece --
                                        // "range end index 1440 out of range for
                                        // slice of length 30".
                                        if inner_cmd.address < address
                                            || (inner_cmd.address - address) as usize >= size
                                        {
                                            warn!("Bad packet received for DoneBinary, ignoring");
                                            continue;
                                        }
                                        // Append data chunk to data vector
                                        let offset = (inner_cmd.address - address) as usize;
                                        let end = (offset + chunk.len()).min(size);
                                        data[offset..end].copy_from_slice(&chunk[..end - offset]);
                                        chunk_map[offset / CHUNK_SIZE] = true;
                                        bar.inc((end - offset) as u64);

                                        match await_result(conn, timeout) {
                                            Err(e) => {
                                                warn!("Error waiting for data chunk: {}", e);
                                            }
                                            Ok(cmds) => {
                                                for cmd in cmds {
                                                    if let Some(inner_cmd) = cmd.cmd {
                                                        match inner_cmd.cmd {
                                                            DCLoadCmds::DoneBinary() => {}
                                                            _ => {
                                                                warn!(
                                                                    "Unexpected command received after receiving data: {:?}",
                                                                    inner_cmd
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    DCLoadCmds::DoneBinary() => break,
                                    _ => {
                                        warn!(
                                            "Unexpected command received while waiting for data: {:?}",
                                            inner_cmd
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if chunk_map.iter().all(|&x| x) {
            break;
        }
    }

    drop(bar);

    Ok(data)
}

/// Assemble a 28-byte "phone home" probe and place it at `addr`.
///
/// WHY NOT `trapa`. A `trapa` probe reports through the exception vectors, and
/// a title takes those over during its own start-up: from that moment "the
/// probe fired" and "the probe was never reached" both look like a dead
/// console, and the only difference is whatever the title's own handler
/// happens to do. That ambiguity cost several console cycles on Sonic
/// Adventure 2. This probe reports through dcload's syscall trampoline
/// instead, which belongs to us, needs no vector table, and lands in the host
/// log as a line nothing else produces.
///
/// The probe id travels in the **length** of the write, so one log line names
/// which probe fired:
///
/// ```text
/// Received FSCommand syscall: Write(1, 0x8c110c00, 37)   <- probe 37
/// ```
///
/// The stub parks in a two-instruction loop afterwards, so the machine stops
/// where it is instead of running on through the code the stub overwrote. It
/// clobbers r0 and r4-r7 and never returns: a probe site is destroyed by
/// definition, and the question it answers is only "is this reached".
///
///   mov.l @(4,PC),r0   ; r0 = &dcload syscall pointer  (loader base + 8)
///   mov.l @r0,r0       ; r0 = dcload syscall entry
///   mov   #1,r4        ; pcwritenr
///   mov   #1,r5        ; fd = 1
///   mov.l @(3,PC),r6   ; buf (points at the stub's own literal pool)
///   mov   #id,r7       ; len = probe id
///   jsr   @r0
///   nop
/// spin: bra spin
///   nop
///   .long loader_base + 8
///   .long buf
fn probe_stub(addr: u32, syscall_ptr: u32, id: u8, peek: Option<u32>) -> Vec<u8> {
    // The two literals must be 4-aligned, the code need only be 2-aligned, and
    // half the interesting probe sites in a real title are at 2 mod 4. So the
    // pool goes at the first aligned slot past the code and the displacements
    // are computed, not baked: a `mov.l @(disp,PC)` reads from
    // (PC & ~3) + 4 + disp*4, and PC is the instruction's own address.
    let pool = (addr + 0x14 + 3) & !3;
    // Where the reported bytes come from: the stub's own pool by default (the
    // report is then only "I got here"), or an address the caller named, which
    // makes the same stub a one-shot memory read at a chosen instruction.
    let buf = peek.unwrap_or(pool);
    let disp0 = (pool - ((addr & !3) + 4)) / 4;
    let disp1 = ((pool + 4) - (((addr + 8) & !3) + 4)) / 4;

    let mut s = vec![0u8; (pool + 8 - addr) as usize];
    {
        let mut put = |off: u32, op: u16| {
            let off = off as usize;
            s[off] = op as u8;
            s[off + 1] = (op >> 8) as u8;
        };
        put(0x00, 0xd000 | disp0 as u16); // mov.l @(disp0,PC),r0  -> &syscall ptr
        put(0x02, 0x6002); //               mov.l @r0,r0          -> syscall entry
        put(0x04, 0xe401); //               mov   #1,r4            pcwritenr
        put(0x06, 0xe501); //               mov   #1,r5            fd = 1
        put(0x08, 0xd600 | disp1 as u16); // mov.l @(disp1,PC),r6  -> buf
        put(0x0a, 0xe700 | id as u16); //   mov   #id,r7           len = probe id
        put(0x0c, 0x400b); //               jsr   @r0
        put(0x0e, 0x0009); //               nop
        put(0x10, 0xaffe); //             spin: bra spin
        put(0x12, 0x0009); //               nop
    }
    let o = (pool - addr) as usize;
    s[o..o + 4].copy_from_slice(&syscall_ptr.to_le_bytes());
    s[o + 4..o + 8].copy_from_slice(&buf.to_le_bytes());
    s
}

/// Place one or more probes (see [`probe_stub`]) and verify each landed.
///
/// The syscall pointer is `running_base + 8`, the fixed jump table dcload
/// keeps at its own base (`dcload-crt0.s`) -- so this follows the loader
/// wherever the per-game base put it, and refuses to guess when the loader
/// does not say where it is.
pub fn apply_probes(
    conn: &mut impl ExternalDcIo,
    probes: &[(u32, u8, Option<u32>)],
    running_base: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(base) = running_base else {
        error!("the loader does not report where it is; cannot place a probe");
        return Ok(());
    };
    let syscall_ptr = (base & 0x1fff_ffff) | 0x8c00_0000;
    let syscall_ptr = syscall_ptr + 8;

    for &(addr, id, peek) in probes {
        // THE PHYSICAL WINDOW, NOT P2. This used to normalise to 0xa0000000 as
        // cache-coherency belt-and-braces. Measured 2026-08-20 with
        // `selftest-readback` on the console: through 0x0c... all 32 size/skew
        // combinations round-trip intact; through 0xac... anything longer than
        // 8 bytes comes back carrying the PREVIOUS transfer's bytes from offset
        // 8 on, except a few 32-byte-aligned cases. A probe stub is 28 or 30
        // bytes, so every probe placed through P2 was suspect -- including the
        // one that did report, which was therefore believed for the wrong
        // reason.
        //
        // Nothing is given up: dcload has run with caches off since 1st_read,
        // go() ends with a CCR write that invalidates, and the whole title is
        // already uploaded through this same window.
        let addr = (addr & 0x1fff_ffff) | 0x0c00_0000;
        if addr % 2 != 0 {
            error!("probe address 0x{addr:08x} is odd -- not an instruction; skipped");
            continue;
        }
        // The peek address goes into the stub as the buffer the title hands to
        // write(), and it is the HOST that then reads it back with SendBinQ --
        // so it lands in the same window trap as the stub itself. Normalise it
        // the same way. Harmless for the 4-byte reads this is normally used
        // for (length 4 survived even P2), decisive for anything longer.
        let peek = peek.map(|a| (a & 0x1fff_ffff) | 0x0c00_0000);
        // What the report will actually name: the peek address when there is
        // one, the stub's own pool otherwise. Printing the pool unconditionally
        // made a working peek look like a failed one for a whole analysis pass.
        let reported = peek.unwrap_or((addr + 0x14 + 3) & !3);
        let stub = probe_stub(addr, syscall_ptr, id, peek);
        send_data(conn, &stub, addr, None)?;
        match receive_data(
            conn,
            Some(Duration::from_millis(500)),
            addr,
            stub.len(),
            true,
        ) {
            Ok(got) if got == stub => info!(
                "probe {id} at 0x{addr:08x}, verified -- it will report as \
                 `Write(1, 0x{reported:08x}, {id})` if it is reached"
            ),
            // SAY WHAT DIFFERED. Measured 2026-08-19: this branch fired on a
            // probe that then went on to execute and report normally, and the
            // bare "DID NOT LAND" was very nearly taken at face value -- which
            // would have thrown away the run that proved Sonic Adventure 2
            // reaches its entry point at all. A mismatch is worth reporting,
            // but only the bytes can say whether the write missed, the read
            // came back from somewhere else, or the two simply disagree about
            // the address window.
            Ok(got) => {
                let hex = |v: &[u8]| {
                    v.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                error!(
                    "PROBE {id} at 0x{addr:08x}: read-back MISMATCH ({} bytes back, \
                     {} expected).",
                    got.len(),
                    stub.len()
                );
                error!("  wrote: {}", hex(&stub));
                error!("  read : {}", hex(&got));
                error!(
                    "  Treat the run as suspect, but NOT as proof the probe is absent: \
                     watch for `Write(1, 0x{reported:08x}, {id})` anyway -- if it arrives, the \
                     probe landed and this check is what is wrong."
                );
            }
            Err(e) => error!(
                "PROBE {id} at 0x{addr:08x} could not be read back ({e}). \
                 Watch for `Write(1, 0x{reported:08x}, {id})` regardless."
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod probe_tests {
    use super::probe_stub;

    /// The two PC-relative displacements are computed, not baked, and half the
    /// interesting probe sites are at 2 mod 4. A wrong displacement produces a
    /// stub that assembles, lands, verifies -- and reports from the wrong
    /// address. So check the literals land where the loads point.
    fn pool_of(addr: u32) -> u32 {
        (addr + 0x14 + 3) & !3
    }

    fn literals(addr: u32, s: &[u8]) -> (u32, u32) {
        let o = (pool_of(addr) - addr) as usize;
        (
            u32::from_le_bytes(s[o..o + 4].try_into().unwrap()),
            u32::from_le_bytes(s[o + 4..o + 8].try_into().unwrap()),
        )
    }

    /// `mov.l @(disp,PC),Rn` reads from (PC & !3) + 4 + disp*4, PC being the
    /// instruction's own address. Recompute that from the encoded opcode.
    fn load_target(addr: u32, s: &[u8], off: u32) -> u32 {
        let op = u16::from_le_bytes([s[off as usize], s[off as usize + 1]]);
        let disp = (op & 0xff) as u32;
        (((addr + off) & !3) + 4) + disp * 4
    }

    #[test]
    fn without_peek_the_buffer_is_the_stubs_own_pool() {
        for addr in [0xac01_0000u32, 0xac01_0002] {
            let s = probe_stub(addr, 0x8cfe_8008, 7, None);
            let (sysc, buf) = literals(addr, &s);
            assert_eq!(sysc, 0x8cfe_8008);
            assert_eq!(buf, pool_of(addr), "addr 0x{addr:08x}");
            assert_eq!(load_target(addr, &s, 0x00), pool_of(addr));
            assert_eq!(load_target(addr, &s, 0x08), pool_of(addr) + 4);
        }
    }

    #[test]
    fn with_peek_the_buffer_is_the_named_address() {
        for addr in [0xac01_0000u32, 0xac01_0002] {
            let s = probe_stub(addr, 0x8cfe_8008, 4, Some(0x8c00_00bc));
            let (_, buf) = literals(addr, &s);
            assert_eq!(buf, 0x8c00_00bc, "addr 0x{addr:08x}");
            // r7 = the length, i.e. how many bytes come back.
            assert_eq!(u16::from_le_bytes([s[0x0a], s[0x0b]]), 0xe704);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw image with `image[at..at+4]` set to `word`, zero elsewhere.
    ///
    /// It used to be written to a temp file, because `gaps_probe_patches` took
    /// a path. It takes the bytes now -- the payload can come out of a disc
    /// image and never exists as a file -- so the tests do not touch the
    /// filesystem at all.
    fn raw(len: usize, words: &[(usize, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; len];
        for &(at, w) in words {
            b[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    #[test]
    fn signature_with_a_nearby_slot_window_is_neutralised() {
        // The shape Sonic Adventure 2 has: one "GAPS" comparison constant and
        // the slot literals in a pool a few hundred bytes away.
        let p = raw(0x1000, &[(0x100, 0xa100_1400), (0x348, GAPS_SIGNATURE)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c01_0000 + 0x348, 0xffff_ffff)]);
    }

    #[test]
    fn the_four_bytes_alone_are_not_enough() {
        // "GAPS" as ASCII in data, with no slot window anywhere: a title that
        // never touches the expansion port must come back untouched.
        let p = raw(0x1000, &[(0x348, GAPS_SIGNATURE)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched on the signature alone: {got:?}");
    }

    #[test]
    fn corroboration_must_be_near() {
        // Same two constants, but far enough apart that they cannot be one
        // routine's literal pools.
        let p = raw(
            0x8000,
            &[(0x100, 0xa100_1400), (0x100 + GAPS_CORROBORATION_SPAN + 4, GAPS_SIGNATURE)],
        );
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "corroborated across {GAPS_CORROBORATION_SPAN}+ bytes: {got:?}");
    }

    #[test]
    fn a_slot_window_without_the_signature_is_left_alone() {
        // Sonic Adventure's shape: nothing to neutralise, and nothing to warn
        // about either.
        let p = raw(0x1000, &[(0x100, 0xa100_1400)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty());
    }

    #[test]
    fn the_signature_must_be_aligned() {
        // A literal pool entry is always 4-aligned; ASCII in the middle of a
        // string is not, and is the likeliest false positive.
        let p = raw(0x1000, &[(0x100, 0xa100_1400), (0x34a, GAPS_SIGNATURE)]);
        let got = gaps_probe_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "matched an unaligned occurrence: {got:?}");
    }

    use super::literals_in_loader_footprint;

    /// Sonic Adventure 2's base: image at 0x8cfe8000, stack top 0x8cff3000,
    /// `.hiram` 0x8cff4000, Maple 0x8cff5000.
    const HIGH_BASE: u32 = 0x8cfe_8000;

    /// `mov.l @(disp,PC),Rn` at `at`, reading the long at `pool`.
    ///
    /// The displacement is computed from the same rounding the hardware does
    /// (PC+4, rounded down to 4), because that rounding is the whole reason
    /// this pass cannot just scan for constants.
    fn mov_l_pc(at: usize, pool: usize, rn: u16) -> (usize, u16) {
        let disp = (pool - ((at + 4) & !3)) / 4;
        assert!(disp <= 0xff, "displacement out of range for a real load");
        (at, 0xd000 | (rn << 8) | disp as u16)
    }

    fn raw_ops(len: usize, words: &[(usize, u32)], ops: &[(usize, u16)]) -> Vec<u8> {
        let mut b = raw(len, words);
        for &(at, op) in ops {
            b[at..at + 2].copy_from_slice(&op.to_le_bytes());
        }
        b
    }

    #[test]
    fn a_constant_the_title_loads_into_the_loader_is_reported() {
        // What Sonic Adventure 2 does: 0x0cff0000 into a Maple DMA list, which
        // at this base is the loader's own stack and packet buffers.
        let p = raw_ops(
            0x1000,
            &[(0x200, 0x0cff_0000)],
            &[mov_l_pc(0x100, 0x200, 1)],
        );
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
        assert_eq!(got, vec![(0x8cff_0000, 0x8c01_0000 + 0x100)]);
    }

    #[test]
    fn a_constant_nothing_loads_is_ignored() {
        // The corroboration that matters. Sonic Adventure 2 has eight aligned
        // occurrences of 0x0cff0000 and two instructions that read one; without
        // this test the check would report the six that are only ever data.
        let p = raw(0x1000, &[(0x200, 0x0cff_0000)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
        assert!(got.is_empty(), "reported a literal nothing loads: {got:?}");
    }

    #[test]
    fn a_constant_outside_the_footprint_is_ignored() {
        // Loaded, and RAM, and none of our business: the title owns everything
        // the loader is not sitting in.
        let p = raw_ops(
            0x1000,
            &[(0x200, 0x0c80_0000)],
            &[mov_l_pc(0x100, 0x200, 1)],
        );
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
        assert!(got.is_empty(), "reported an address outside the loader: {got:?}");
    }

    #[test]
    fn the_same_address_is_seen_through_every_window() {
        // 0x0c..., 0x8c... and 0xac... are one address. A title picks the
        // window by what it is doing -- physical for a DMA engine, cached for
        // the CPU -- and the loader is hit either way.
        for w in [0x0cff_0000u32, 0x8cff_0000, 0xacff_0000] {
            let p = raw_ops(0x1000, &[(0x200, w)], &[mov_l_pc(0x100, 0x200, 1)]);
            let got = literals_in_loader_footprint(&p, 0x0c01_0000, HIGH_BASE);
            assert_eq!(got, vec![(0x8cff_0000, 0x8c01_0000 + 0x100)], "window 0x{w:08x}");
        }
    }

    #[test]
    fn the_bios_work_area_a_low_loader_shares_is_not_reported() {
        // Sonic Adventure's shape, and the control that keeps this check
        // honest: it runs at the stock base and loads constants in the IP.BIN
        // region, which the loader's own range covers. Reporting them would
        // condemn the one title measured to work.
        let p = raw_ops(0x1000, &[(0x200, 0x8c00_8200)], &[mov_l_pc(0x100, 0x200, 1)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, 0x8c00_4000);
        assert!(got.is_empty(), "reported the shared BIOS work area: {got:?}");
    }

    #[test]
    fn a_low_loaders_high_buffers_are_still_reported() {
        // The other half of the same rule: a low loader keeps its packet and
        // Maple buffers at 0x8cfe8000, outside its image and outside anything
        // a title legitimately shares. A constant naming those is a collision.
        let p = raw_ops(0x1000, &[(0x200, 0x0cfe_8800)], &[mov_l_pc(0x100, 0x200, 1)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, 0x8c00_4000);
        assert_eq!(got, vec![(0x8cfe_8800, 0x8c01_0000 + 0x100)]);
    }

    #[test]
    fn the_stock_low_base_does_not_see_sonic_adventure_2s_maple_buffer() {
        // The same title at the stock base: 0x8cff0000 is nowhere near the
        // loader, and a check that fired here would cry wolf on every title.
        let p = raw_ops(0x1000, &[(0x200, 0x0cff_0000)], &[mov_l_pc(0x100, 0x200, 1)]);
        let got = literals_in_loader_footprint(&p, 0x0c01_0000, 0x8c00_4000);
        assert!(got.is_empty(), "the low base reported a high-RAM constant: {got:?}");
    }
}
