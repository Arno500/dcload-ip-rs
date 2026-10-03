//! Talking to the loader: the handshake, placing the loader, uploading
//! a payload and starting it, and the read-backs that check the console.

use super::*;

/// Refuse an upload that would overwrite the loader receiving it: the console
/// would drop to the BIOS with no error anywhere. A loader that does not report
/// its base is assumed to be at the stock one.
fn refuse_self_overwrite(
    running: Option<u32>,
    at: u32,
    len: usize,
) -> DcResult<()> {
    let base = running.unwrap_or(crate::loaders::DEFAULT_BASE);
    let image = (at, at.saturating_add(len as u32));
    let Some(hit) = crate::loaders::overlapping_range(base, image) else {
        return Ok(());
    };
    // The full story goes to the log; the error stays short because main
    // prints it with Debug formatting.
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

/// Read a file to upload, refusing an impossible size before reading it.
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

/// A file's bytes and the name to show for them.
pub fn payload_from_file(path: &Path) -> std::io::Result<(Vec<u8>, String)> {
    let bytes = read_payload_file(path)?;
    debug!("Read file {} ({} bytes)", path.display(), bytes.len());
    let label = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    Ok((bytes, label))
}

/// Upload a payload: an ELF section by section, anything else whole at
/// `address`. Returns the entry point.
pub fn upload_bytes(
    conn: &mut impl ExternalDcIo,
    file_buffer: &[u8],
    label: &str,
    mut address: u32,
    running_base: Option<u32>,
) -> DcResult<(u32, usize)> {
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

    let elf = ElfBytes::<AnyEndian>::minimal_parse(file_buffer);
    let started = Instant::now();
    if let Ok(elf) = elf {
        address = elf.ehdr.e_entry as u32;
        trace!("ELF entry point at 0x{:08x}", address);

        // Only sections that occupy memory at run time (`is_uploadable`, which
        // is also what measures a loader image's extent).
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

        // One bar for the whole file.
        let strtab = elf.section_headers_with_strtab().ok().and_then(|(_, s)| s);
        let total: u64 = elf_parts
            .iter()
            .filter_map(|sh| elf.section_data(sh).ok())
            .map(|(data, _)| data.len() as u64)
            .sum();
        // Check every section before sending any: refusing halfway would
        // already have damaged the loader.
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
                    sh.sh_addr,
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

/// The line that outlives the (erased) progress bar.
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
) -> DcResult<()> {
    let flags = ((cdfs_redirect as u32) << 1) | console as u32;
    conn.send_command(DCLoadCmd::new(DCLoadCmds::Execute(), address, flags)).map(|_| ())
}

/// Ask the running loader its version and, if it reports them, its base and
/// cable. An older loader reporting no base is a normal answer.
pub fn query_loader(
    conn: &mut impl ExternalDcIo,
) -> DcResult<crate::loaders::VersionReply> {
    version_in(send_version(conn)?)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "no VERS reply from the Dreamcast").into())
}

/// The loader's answer, if one of these replies is it.
fn version_in(replies: Vec<DCReturnCmd>) -> Option<crate::loaders::VersionReply> {
    replies.into_iter().find_map(|reply| {
        if let Some(cmd) = reply.cmd
            && let DCLoadCmds::Version(Some(data)) = cmd.cmd
        {
            Some(crate::loaders::parse_version_payload(
                data.as_ref(),
                cmd.size as usize,
            ))
        } else {
            None
        }
    })
}

/// Ask for a loader until one answers (`--infinite`), quietly: a console that
/// is still booting is normal here, so no per-packet warnings, just a spinner.
pub fn wait_for_any_loader(
    conn: &mut impl ExternalDcIo,
) -> DcResult<crate::loaders::VersionReply> {
    const ASK_EVERY: Duration = Duration::from_millis(500);
    /// For a redirected log, where the spinner does not show.
    const SAY_EVERY: Duration = Duration::from_secs(60);

    let started = Instant::now();
    let mut said = started;
    let spinner = ui::wait_spinner("no answer yet");

    let found = 'wait: loop {
        // A failed send (ICMP unreachable, no ARP entry) also means "not there yet".
        if let Err(e) = conn.send_command(version_command()) {
            trace!("VERS could not be sent while waiting: {e}");
        }

        let deadline = Instant::now() + ASK_EVERY;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match conn.poll(Some(left)) {
                Ok(events) if events.is_empty() => continue,
                Ok(events) => match conn.handle_data(&events) {
                    Ok(replies) => {
                        if let Some(found) = version_in(replies) {
                            break 'wait found;
                        }
                    }
                    Err(e) => trace!("unparsed packet while waiting: {e}"),
                },
                Err(e) => {
                    debug!("poll failed while waiting for the Dreamcast: {e}");
                    sleep(left);
                    break;
                }
            }
        }

        if said.elapsed() >= SAY_EVERY {
            said = Instant::now();
            info!(
                "still waiting for the Dreamcast ({} s)",
                started.elapsed().as_secs()
            );
        }
    };

    drop(spinner);
    info!(
        "the Dreamcast answered after {:.1} s",
        started.elapsed().as_secs_f64()
    );
    Ok(found)
}

/// Poll for a loader at `expect` after a chainload. Bounded, but long: a cold
/// network adapter init alone can take seconds.
fn wait_for_loader(
    conn: &mut impl ExternalDcIo,
    expect: u32,
    timeout: Duration,
) -> DcResult<()> {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        match query_loader(conn) {
            Ok(r) => match r.base {
                Some(base) if base == expect => {
                    debug!("loader at 0x{:08x} answered: {}", base, r.text);
                    return Ok(());
                }
                Some(base) => {
                    last = format!("a loader at 0x{base:08x} answered instead ({})", r.text);
                }
                None => last = format!("loader did not report its base ({})", r.text),
            },
            Err(e) => last = e.to_string(),
        }
    }
    Err(timed_out(format!("no loader at 0x{expect:08x} after {timeout:?}: {last}")))
}

/// Put a loader linked for `want` in control, hopping through an intermediate
/// base when a direct move would overwrite the running one. Returns the base in
/// control afterwards; when a chainload fails the current loader is kept.
///
/// A SET THAT CANNOT PROVIDE `want` IS AN ERROR, NOT A REASON TO STAY. It used
/// to warn and keep the running loader, and the session went on to start the
/// title with the loader wherever it happened to be. Measured 2026-10-03:
/// `--loader-dir loaders-sa2-pick` named a directory that no longer existed,
/// Sonic Adventure 2 was started with the loader at 0x8ce00000 instead of
/// 0x8cae0000, booted, wrote over the loader (memory marks unanswered from
/// then on) and the console rebooted. Staying is still allowed when nothing
/// was asked for: no set named and the title content with the running base.
pub fn ensure_loader_base(
    conn: &mut impl ExternalDcIo,
    loaders: &crate::loaders::LoaderSet,
    running: u32,
    want: u32,
) -> DcResult<u32> {
    // No early return for `running == want`: the same base is not the same
    // build, which is checked below against the image.
    if let Some(reason) = crate::loaders::known_unsupported(want) {
        warn!(
            "this title's preset asks for the loader at 0x{want:08x}, which is not \
             supported: {reason}. Staying at 0x{running:08x}; the title may still run."
        );
        return Ok(running);
    }
    if !loaders.can_provide(want) {
        let available: Vec<String> = loaders
            .available()
            .iter()
            .map(|b| format!("0x{b:08x}"))
            .collect();
        let missing = if loaders.relocatable().is_some() {
            format!(
                "has no dcload-0x{want:08x}.elf, and 0x{want:08x} is not an address {} \
                 can be moved to: a loader's image, stack and buffers have to fit \
                 there, and they do not",
                crate::loaders::RELOCATABLE_NAME
            )
        } else {
            format!(
                "has neither dcload-0x{want:08x}.elf nor {}",
                crate::loaders::RELOCATABLE_NAME
            )
        };
        let what = format!(
            "this title wants the loader at 0x{:08x} but {} {} (available: {}). Build the \
             set with `make -C target-src/dcload loaders` and put it in a `loaders` \
             directory at this project's root, or name it with --loader-dir. Looked in: {}.",
            want,
            loaders.dir().display(),
            missing,
            if available.is_empty() {
                match loaders.relocatable() {
                    Some(_) => "relocatable (any base)".to_string(),
                    None => "none".to_string(),
                }
            } else {
                available.join(", ")
            },
            loaders.searched()
        );
        if want != running || loaders.explicit() {
            return Err(std::io::Error::other(format!(
                "{what} Not starting the title with the loader at 0x{running:08x}."
            ))
            .into());
        }
        warn!("{what} Staying at 0x{running:08x}.");
        return Ok(running);
    }

    // Each image is materialised once and reused for the upload.
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
        return Err(std::io::Error::other(format!(
            "no loader for 0x{want:08x} could be read out of {}; not starting the title \
             with the loader at 0x{running:08x}",
            loaders.dir().display()
        ))
        .into());
    };
    let want_image = crate::loaders::image_extent_bytes(&want_bytes).map_err(|e| {
        std::io::Error::other(format!(
            "cannot read the loader for 0x{want:08x}: {e}; not starting the title with \
             the loader at 0x{running:08x}"
        ))
    })?;
    let scratch_image = fetch(crate::loaders::SCRATCH_BASE)
        .and_then(|(b, _)| crate::loaders::image_extent_bytes(&b).ok())
        .unwrap_or((u32::MAX, u32::MAX));

    let mut hops = crate::loaders::plan(running, want, want_image, scratch_image);
    if running == want {
        let Some((bytes, label)) = fetch(want) else {
            return Ok(running);
        };
        match crate::diag::verify_image(conn, &bytes, &label) {
            Ok(()) => {
                info!(
                    "loader is already at 0x{running:08x} and is {label}; nothing to \
                     chainload"
                );
                return Ok(running);
            }
            Err(e) => {
                // A loader cannot be uploaded over itself: replace it through
                // the relay base with the shortest round trip.
                warn!(
                    "the loader running at 0x{running:08x} is not {label}: {e}. \
                     Replacing it by way of an intermediate base."
                );
                let mut relay: Vec<u32> = Vec::new();
                for alt in [
                    crate::loaders::SCRATCH_BASE,
                    crate::loaders::DEFAULT_BASE,
                    crate::loaders::ISOLDR_HIGH_ADDR,
                ] {
                    if alt == want || !loaders.can_provide(alt) {
                        continue;
                    }
                    let Some((alt_bytes, _)) = fetch(alt) else {
                        continue;
                    };
                    let Ok(alt_image) = crate::loaders::image_extent_bytes(&alt_bytes) else {
                        continue;
                    };
                    let there = crate::loaders::plan(running, alt, alt_image, scratch_image);
                    let back = crate::loaders::plan(alt, want, want_image, scratch_image);
                    if !there.is_empty()
                        && !back.is_empty()
                        && (relay.is_empty() || there.len() + back.len() < relay.len())
                    {
                        relay = [there, back].concat();
                    }
                }
                if relay.is_empty() {
                    warn!(
                        "no intermediate base is clear in both directions, so the loader \
                         at 0x{running:08x} cannot be replaced in place. Power-cycle the \
                         Dreamcast: it will boot the CD at the stock base and the move \
                         becomes an ordinary one."
                    );
                    return Ok(running);
                }
                hops = relay;
            }
        }
    }
    if hops.is_empty() {
        warn!(
            "cannot move the loader from 0x{running:08x} to 0x{want:08x} without writing \
             over the running image, and no clear intermediate base is available; \
             staying at 0x{running:08x}"
        );
        return Ok(running);
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
            return Ok(current);
        };
        info!("chainloading dcload to 0x{:08x} ({label})", hop);
        let entry = match upload_bytes(conn, &bytes, &label, hop, Some(current)) {
            Ok((entry, _)) => entry,
            Err(e) => {
                warn!(
                    "uploading the loader for 0x{hop:08x} failed: {e}; staying at 0x{current:08x}"
                );
                return Ok(current);
            }
        };
        // No console, no CDFS: the new loader comes up idle, as from the CD.
        if let Err(e) = execute(conn, entry, false, false) {
            warn!("EXEC of the loader at 0x{hop:08x} failed: {e}; staying at 0x{current:08x}");
            return Ok(current);
        }
        if let Err(e) = wait_for_loader(conn, hop, Duration::from_secs(20)) {
            warn!("{e}");
            return Ok(current);
        }
        current = hop;
    }
    info!("loader is now at 0x{:08x}", current);
    Ok(current)
}

/// Copy the disc's IP.BIN to 0x8c008000, as isoldr does: the header sector,
/// or with `full` all 16 sectors, patched to enter bootstrap 2.
///
/// Skipped when the loader sits in low RAM, whose image covers 0x8c008000.
pub fn load_ip_bin(
    conn: &mut impl ExternalDcIo,
    disc: &dyn DiscFormat,
    disc_path: &str,
    running_base: Option<u32>,
    full: bool,
    vga: bool,
) -> DcResult<bool> {
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
        let mut sector = crate::disc_formats::types::find_ip_bin(disc).ok_or_else(|| {
            std::io::Error::other(format!("{disc_path}: no IP.BIN header to load"))
        })?;
        if vga {
            declare_vga_and_say_so(&mut sector);
        }

        info!(
            "IP.BIN header -> 0x{IP_BIN_ADDR:08x} ({} bytes), as isoldr does on a direct boot",
            sector.len()
        );
        send_data(conn, &sector, IP_BIN_ADDR, None)?;
        return Ok(true);
    }

    // The full 16 sectors from the start of the boot track (never the ISO9660
    // file fallback, which need not sit next to the bootstrap code).
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

    if vga {
        declare_vga_and_say_so(&mut image);
    }

    // The patch site must hold Sega's stock bootstrap word. This also rejects
    // a GDI's low-density copy, which has the same header but no code.
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

    // isoldr's four patches (`Load_IPBin()`, loader/utils.c), in the buffer:
    //   +0x0cb0  bootstrap 1 jumps to bootstrap 2 (0x8c00e000)
    //   +0x21b0  0x5113
    //   +0x2814  rts; +0x2818 nop -- the routine that needs a drive
    // isoldr's setup_region() is not reproduced: it needs the flashrom.
    image[0x0cb0..0x0cb4].copy_from_slice(&IP_BIN_BOOTSTRAP_2.to_le_bytes());
    image[0x21b0..0x21b2].copy_from_slice(&0x5113u16.to_le_bytes());
    image[0x2814..0x2816].copy_from_slice(&0x000bu16.to_le_bytes());
    image[0x2818..0x281a].copy_from_slice(&0x0009u16.to_le_bytes());

    // Stop at 0x8c00f400: the loader's guest VBR (`.guestvbr`) lives there.
    // IP.BIN holds zeroes in that tail; anything else is reported.
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

/// isoldr's `IP_BIN_BOOTSTRAP_2_ADDR`, cached: the literal the patch stores.
pub const IP_BIN_BOOTSTRAP_2: u32 = 0x8c00e000;

/// The same address for `EXEC`, which ORs in 0xa0000000 itself.
pub const IP_BIN_BOOTSTRAP_2_EXEC: u32 = 0x0c00e000;

/// Write known patterns to free RAM (0x0c200000) and read them back, across
/// the sizes and misalignments probes use, through the physical and the P2
/// window. Returns whether the physical window, the one this host uses, is sound.
pub fn selftest_readback(conn: &mut impl ExternalDcIo) -> DcResult<bool> {
    const SCRATCH: u32 = 0x0c20_0000;

    let windows: [(&str, u32); 2] = [("phys 0x0c", SCRATCH), ("P2   0xac", SCRATCH | 0xa000_0000)];
    // Whether each window, physical then P2, has passed so far.
    let mut ok = [true, true];
    let mut phys_cases = 0usize;

    info!("read-back self-test at 0x{SCRATCH:08x} -- no title is uploaded by this");
    for (w, (wname, wbase)) in windows.into_iter().enumerate() {
        for &len in &[4usize, 28, 30, 64, 1439, 1440, 1441, 3000] {
            for &skew in &[0u32, 1, 2, 3] {
                let addr = wbase + skew;
                // Every byte says where it belongs, so a shifted reply is legible.
                let want: Vec<u8> = (0..len)
                    .map(|i| (i as u32).wrapping_mul(31).wrapping_add(skew) as u8)
                    .collect();

                if w == 0 {
                    phys_cases += 1;
                }
                if let Err(e) = send_data(conn, &want, addr, None) {
                    error!("  {wname} len {len:5} skew {skew}: WRITE failed: {e}");
                    ok[w] = false;
                    continue;
                }
                match receive_data(conn, Some(Duration::from_millis(1500)), addr, len, true) {
                    Err(e) => {
                        error!("  {wname} len {len:5} skew {skew}: READ failed: {e}");
                        ok[w] = false;
                    }
                    Ok(got) if got == want => info!("  {wname} len {len:5} skew {skew}: ok"),
                    Ok(got) => {
                        ok[w] = false;
                        let first = got
                            .iter()
                            .zip(&want)
                            .position(|(a, b)| a != b)
                            .unwrap_or(want.len().min(got.len()));
                        error!(
                            "  {wname} len {len:5} skew {skew}: MISMATCH, {} bytes back, \
                         first bad byte at {first}",
                            got.len()
                        );
                        error!("      want[{first}..]: {}", hex(want.iter().skip(first).take(12)));
                        error!("      got [{first}..]: {}", hex(got.iter().skip(first).take(12)));
                    }
                }
            }
        }
    }
    // Crossing the windows tells a dropped write (filler shows through) from a
    // misread one.
    let phys = SCRATCH + 0x1000;
    let p2 = phys | 0xa000_0000;
    for (label, waddr, raddr) in [
        ("write P2   / read phys", p2, phys),
        ("write phys / read P2  ", phys, p2),
    ] {
        let filler = vec![0x55u8; 96];
        if let Err(e) = send_data(conn, &filler, phys, None) {
            error!("  {label}: could not lay down filler: {e}");
            ok[0] = false;
            continue;
        }
        let want: Vec<u8> = (0..64u32)
            .map(|i| i.wrapping_mul(31).wrapping_add(7) as u8)
            .collect();
        if let Err(e) = send_data(conn, &want, waddr + 1, None) {
            error!("  {label}: WRITE failed: {e}");
            ok[0] = false;
            continue;
        }
        match receive_data(conn, Some(Duration::from_millis(1500)), raddr + 1, 64, true) {
            Ok(got) if got == want => info!("  {label}: ok (64 bytes, misaligned)"),
            Ok(got) => {
                ok[0] = false;
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
                ok[0] = false;
                error!("  {label}: READ failed: {e}");
            }
        }
    }

    // Reported per window: P2 is known broken and unused.
    let [phys_ok, p2_ok] = ok;
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

/// The video cable of the loader answering now (a chainload may have replaced
/// the one that answered first). `None` means unknown, never "not VGA".
pub fn query_cable(conn: &mut impl ExternalDcIo) -> Option<crate::loaders::Cable> {
    match query_loader(conn) {
        Ok(r) => r.cable,
        Err(e) => {
            warn!("could not ask the loader which video cable is plugged in: {e}");
            None
        }
    }
}

pub fn reboot(
    conn: &mut impl ExternalDcIo,
) -> DcResult<usize> {
    let command = DCLoadCmd::new(DCLoadCmds::Reboot(), 0, 0);
    log_command(&command);
    conn.send_command(command)?;
    Ok(0)
}

/// VERS, with our protocol version in the address field.
fn version_command() -> DCLoadCmd {
    let [major, minor, patch] = protocol_version();
    let version = ((major as u32) << 16) | ((minor as u32) << 8) | patch as u32;
    DCLoadCmd::new(DCLoadCmds::Version(None), version, 0)
}

pub fn send_version(
    conn: &mut impl ExternalDcIo,
) -> DcResult<Vec<DCReturnCmd>> {
    call_command(conn, version_command())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A console that must not be spoken to: refusing to start happens before
    /// any packet.
    struct Silent;

    impl ExternalDcIo for Silent {
        fn poll(&self, _t: Option<Duration>) -> Result<polling::Events, std::io::Error> {
            panic!("polled the console")
        }
        fn handle_data(
            &mut self,
            _e: &polling::Events,
        ) -> Result<Vec<DCReturnCmd>, std::io::Error> {
            panic!("read from the console")
        }
        fn send_command(&self, _c: DCLoadCmd) -> DcResult<usize> {
            panic!("sent to the console")
        }
    }

    fn empty_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 2026-10-03: `--loader-dir` named a directory with nothing in it, the
    /// title was started on the loader already at 0x8ce00000 instead of
    /// 0x8cae0000, wrote over it and the console rebooted.
    #[test]
    fn a_missing_set_refuses_to_move_the_loader() {
        let set = crate::loaders::LoaderSet::new(empty_dir("dcload-no-set-move"));
        let e = ensure_loader_base(&mut Silent, &set, 0x8ce0_0000, 0x8cae_0000).unwrap_err();
        assert!(e.to_string().contains("Not starting the title"), "{e}");
    }

    /// Named explicitly, an empty set is refused even where nothing would move:
    /// the user asked for that set, and the loader on the console is not from it.
    #[test]
    fn a_named_empty_set_refuses_even_to_stay() {
        let set = crate::loaders::LoaderSet::new(empty_dir("dcload-no-set-stay"));
        assert!(set.explicit());
        assert!(ensure_loader_base(&mut Silent, &set, 0x8ce0_0000, 0x8ce0_0000).is_err());
    }
}
