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
    cmds::{AudioFormat, DCLoadClientCmds, DCLoadCmd, DCLoadCmds, DCReturnCmd},
    disc_formats::{
        boot,
        cdi::Cdi,
        gdi::Gdi,
        iso::Iso,
        source::{Container, FileSource},
        types::{DiscFormat, RAW_SECTOR_SIZE, StubDisc, get_disc_format},
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
) -> std::result::Result<crate::loaders::VersionReply, std::boxed::Box<dyn std::error::Error>> {
    version_in(send_version(conn)?).ok_or_else(|| {
        Box::new(Error::new(
            ErrorKind::InvalidData,
            "no VERS reply from the Dreamcast",
        )) as std::boxed::Box<dyn std::error::Error>
    })
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

/// Ask for a loader until one answers, however long that takes.
///
/// THIS IS A START-UP PATH AND NOTHING ELSE. What it waits out is a console
/// that is not up yet -- still booting the CD, still being switched on, still
/// bringing up a cold RTL8139 -- which is a state with no upper bound worth
/// guessing at, and the reason it is opt-in (`--infinite`). Every command
/// after this one keeps `call_command`'s five tries: once a loader has
/// answered, silence means something has gone wrong, and waiting forever for
/// it would turn a reportable failure into a hang.
///
/// It is deliberately NOT `query_loader` in a loop. `call_command` logs a
/// warning per lost packet and `await_result` an error per timeout -- correct
/// for a command that was expected to work, and ten lines every 2.5 s for a
/// wait whose normal state is silence. So the question is asked directly here,
/// quietly, and what a person watching gets instead is the spinner.
///
/// Distinct from `wait_for_loader`, which waits for a SPECIFIC base to come up
/// after a chainload we ourselves started, and is bounded because we know
/// something was there a moment ago.
pub fn wait_for_any_loader(
    conn: &mut impl ExternalDcIo,
) -> std::result::Result<crate::loaders::VersionReply, std::boxed::Box<dyn std::error::Error>> {
    /// How often the question is repeated. Also the poll window: nothing is
    /// running on the console, so there is no cost here but this process's.
    const ASK_EVERY: Duration = Duration::from_millis(500);
    /// How often the wait says so in the log. The spinner covers a terminal;
    /// this is what a redirected log gets, so it is rare on purpose.
    const SAY_EVERY: Duration = Duration::from_secs(60);

    let started = Instant::now();
    let mut said = started;
    let spinner = ui::wait_spinner("no answer yet");

    let found = 'wait: loop {
        // A SEND THAT FAILS IS PART OF WHAT IS BEING WAITED OUT, not a reason
        // to stop: a connected UDP socket reports the last datagram's ICMP
        // unreachable on the next call, and an address with no ARP entry can
        // fail outright. Both mean "not there yet", which is the whole premise.
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
                    // Not a timeout -- `poll` reports that as no events. Sleep
                    // out the window rather than spinning on whatever it is.
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
    // NOTE THERE IS NO `running == want -> return` HERE, AND THAT IS THE POINT.
    // It used to say "loader is already at 0x…, no chainload needed" and return
    // before the image was ever materialised -- so the same address was taken as
    // proof of the same build, and a rebuilt loader set was silently not picked
    // up. The `running == want` case is handled below, AFTER the image exists to
    // compare against; it costs one round trip and no upload when they match.
    // Measured 2026-09-04, twice in one evening: a session run with
    // `--loader-dir loaders-tone` kept the ADPCM loader already at 0x8ce00000
    // and played the music exactly as before, which is the one outcome that
    // experiment could not tell apart from a result.
    //
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
        // Say WHICH of the two is missing. With the relocatable image present
        // this is now nearly unreachable -- it answers for any base a loader
        // fits at, in either family -- so when it does fire, the address itself
        // is the problem and the message has to say so rather than ask for a
        // file that may already be sitting in the directory.
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
        warn!(
            "this title wants the loader at 0x{:08x} but {} {} (available: {}); \
             staying at 0x{:08x}. Build the set with \
             `make -C target-src/dcload loaders` and put it in a `loaders` \
             directory at this project's root. Looked in: {}.",
            want,
            loaders.dir().display(),
            missing,
            if available.is_empty() {
                // Same trap as the "loader candidates" line in main.rs: this
                // counted pre-linked ELFs only, so it read "none" for a
                // directory holding the relocatable image that answers for
                // every base.
                match loaders.relocatable() {
                    Some(_) => "relocatable (any base)".to_string(),
                    None => "none".to_string(),
                }
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

    // THE SAME BASE IS NOT THE SAME BUILD, AND plan() ANSWERS ON THE ADDRESS
    // ALONE. A loader set rebuilt with different options -- a different CD-DA
    // format, an experiment, a fix -- is simply NOT picked up when the console
    // already runs something at that address: nothing is uploaded, nothing is
    // said, and the old image goes on serving. That is AGENTS.md 14.19 on the
    // host side, and on 2026-09-04 it silently voided a whole test run: the
    // session was started with `--loader-dir loaders-tone`, the host kept the
    // ADPCM loader already at 0x8ce00000, and the music played exactly as
    // before -- the one outcome the experiment could not distinguish from a
    // result. One blocking round trip on an idle console answers it.
    let mut hops = crate::loaders::plan(running, want, want_image, scratch_image);
    if running == want {
        let Some((bytes, label)) = fetch(want) else {
            return running;
        };
        match crate::diag::verify_image(conn, &bytes, &label) {
            Ok(()) => {
                // SAY THAT IT WAS CHECKED, not merely that nothing happened.
                // "no chainload needed" was the old message and it was true of
                // the address and silent about the build.
                info!(
                    "loader is already at 0x{running:08x} and is {label}; nothing to \
                     chainload"
                );
                return running;
            }
            Err(e) => {
                // REPLACE IT, DO NOT MERELY COMPLAIN. A loader cannot be
                // uploaded over itself, and here the destination IS the scratch
                // base, so there is no one-hop answer -- but the relocatable
                // image goes anywhere, so any base that is clear in both
                // directions works as a stepping stone. Both legs are ordinary
                // moves planned by the same function, so nothing new is being
                // reasoned about: the pair is only rejected together.
                warn!(
                    "the loader running at 0x{running:08x} is not {label}: {e}. \
                     Replacing it by way of an intermediate base."
                );
                // THE SHORTEST RELAY, not the first one found. Each leg goes
                // through the scratch base anyway, so a stepping stone other
                // than the scratch base costs two extra uploads: replacing a
                // stock-base loader went 0x8ce00000, 0x8cfe8000, 0x8ce00000,
                // 0x8c004000 -- four chainloads, four redrawn screens, for a
                // move the scratch base makes in two (2026-09-17).
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
                    return running;
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
    vga: bool,
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
        let mut sector = crate::disc_formats::types::find_ip_bin(disc).ok_or_else(|| {
            std::io::Error::other(format!("{disc_path}: no IP.BIN header to load"))
        })?;
        // In the buffer, not poked afterwards, for the same reason as the
        // bootstrap patches below: bytes that travel with the upload cannot go
        // missing in a cache line that is invalidated rather than purged.
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

    if vga {
        declare_vga_and_say_so(&mut image);
    }

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

/// Which video cable the console that is answering right now is plugged into.
///
/// ASKED AT THE MOMENT IT IS NEEDED, not carried down from the first VERS of
/// the session, and one round trip on an idle console is what that costs. The
/// loader answering at the start is not necessarily the one that will run the
/// title: a chainload replaces it, and the one that came off the CD may well
/// predate this field while the one just uploaded reports it. Asking here
/// removes the question.
///
/// `None` means the loader did not say -- an older build -- and a caller must
/// read that as "unknown", never as "not VGA".
pub fn query_cable(conn: &mut impl ExternalDcIo) -> Option<crate::loaders::Cable> {
    match query_loader(conn) {
        Ok(r) => r.cable,
        Err(e) => {
            warn!("could not ask the loader which video cable is plugged in: {e}");
            None
        }
    }
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
/// The bytes that will be in RAM, and the address each run of them lands at.
///
/// A raw binary lands whole at `address`; an ELF's sections land at their own.
/// Every pass that looks for something in a title -- the GAPS probe, the
/// constants naming the loader, the cable check -- has to agree about that, so
/// they all ask here rather than each carrying its own copy.
fn payload_spans(buf: &[u8], address: u32) -> Vec<(u32, &[u8])> {
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
    spans
}

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
    let spans = payload_spans(buf, address);

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

/// The SH4's port data register. Bits 8 and 9 are the video cable the console
/// is plugged into: 0 = VGA, 2 = RGB (SCART), 3 = composite.
const PDTRA: u32 = 0xff80_0030;

/// How far past the load of that address the read of it may sit, in
/// instructions. Two, in every title measured; eight leaves room for a
/// compiler that scheduled something in between, and is short enough that the
/// scan cannot wander into the next routine.
const CABLE_READ_WINDOW: usize = 8;

/// One entry of a packed 102-word TOC, for the log.
fn toc_word(toc: &[u8], i: usize) -> String {
    toc.get(i * 4..i * 4 + 4)
        .map(|b| format!("0x{:08x}", u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
        .unwrap_or_default()
}

/// The BIOS GD driver's body, which the two syscall vectors at 0x8c0000bc and
/// 0x8c0000c0 point at -- cached and uncached.
const GD_DRIVER_BODY: [u32; 2] = [0x8c00_10f0, 0xac00_10f0];

/// Send a title's DIRECT calls to the BIOS GD driver to the loader instead.
///
/// dcload emulates the GD driver by taking over the syscall vectors, and a
/// title that calls through them is served from this host. A title that holds
/// the driver's own address and calls it is not: it reaches the real driver,
/// which reads whatever disc is in the drive. Windows CE does exactly that --
/// its GD driver in Sega Rally 2's 0WINCEOS.BIN loads `0x8c0010f0` from 23
/// literal pools and calls it with r6 = 0 and r7 = the function index, the same
/// ABI the vectors use. None of the four Katana test titles carries the
/// literal; they call through 0x8c0000bc, 13 times each.
///
/// isoldr answers it the same way (`gdc_syscall_patch`, `patch_memory(
/// 0x8c0010f0, gdc_redir)`): rewrite the literal. From here rather than by
/// overwriting the BIOS's copy of the driver on the console, because the loader
/// still needs the real driver at its next boot (gd_spin_down_drive). `entry`
/// is the running loader's `_gd_bios_entry`; a P2 literal stays P2.
///
/// Word-aligned only: a literal pool entry always is, and a match at any other
/// offset is two halfwords of code that happen to spell the address.
pub fn gd_body_patches(buf: &[u8], address: u32, entry: u32) -> Vec<(u32, u32)> {
    let mut out = vec![];
    for (base, data) in payload_spans(buf, address) {
        let at = |i: usize| ((base & 0x1fff_ffff) | 0x8c00_0000).wrapping_add(i as u32);
        for i in (0..data.len().saturating_sub(3)).step_by(4) {
            let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            if GD_DRIVER_BODY.contains(&w) {
                out.push((at(i), (entry & 0x1fff_ffff) | (w & 0xe000_0000)));
            }
        }
    }
    out
}

/// Make a title believe a VGA box is plugged in -- which is the whole of what
/// a "VGA patch" is.
///
/// A Katana title asks the hardware which cable it is on, once, through the
/// SDK's cable check, and everything downstream follows from the two bits it
/// reads: 480p or interlace, and whether the VGA path is offered at all.
/// Forcing that read to 0 therefore IS the patch, and it is one halfword.
///
/// FOUND BY CONTENT, like the GAPS probe above, because the alternative is a
/// per-title table nobody can maintain. The register address is a literal in a
/// pool, an `mov.l @(disp,PC),Rn` loads it, and the read follows a couple of
/// instructions later. Measured on four PAL dumps -- Sonic Adventure, Sonic
/// Adventure 2, Crazy Taxi and Snow Surfers -- each has EXACTLY ONE aligned
/// occurrence of 0xff800030, exactly one instruction that loads it, and the
/// same routine around it, byte for byte:
///
/// ```text
///   d3 03   mov.l  @(3,PC),r3   ; 0xff800030
///   92 03   mov.w  @(3,PC),r2   ; 0x0300
///   64 31   mov.w  @r3,r4       <- becomes `mov #0,r4` (e4 00)
///   60 4d   extu.w r4,r0
///   00 0b   rts
///   20 29   and    r2,r0
/// ```
///
/// THE READ IS WHAT IS PATCHED, NOT THE EXTRACTION AFTER IT. The caller shifts
/// and masks the result in its own way -- `shlr8` then `and #3` in all four,
/// but a title is just as free to test the raw 0x300 -- and forcing the value
/// that comes off the port to 0 answers every one of those with "VGA" while
/// having to recognise none of them.
///
/// WHAT IT DOES NOT DO. It cannot make a title render 480p that has no code
/// for it: a title declaring no VGA support may set an interlaced mode by
/// hand, and that is a per-title patch no scan finds. And it is off by default
/// for a reason no scan can settle -- nothing on this side of the wire can see
/// which cable is plugged into the console, and a title forced to VGA on a TV
/// is a black screen.
pub fn vga_cable_patches(buf: &[u8], address: u32) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = vec![];
    for (span_base, data) in payload_spans(buf, address) {
        let word = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let half = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
        let pool: Vec<usize> = (0..data.len().saturating_sub(3))
            .step_by(4)
            .filter(|&i| word(i) == PDTRA)
            .collect();
        if pool.is_empty() {
            continue;
        }
        // Reported in the cached window, which is what a disassembly of the
        // title shows, whatever window the payload was uploaded through.
        let at_of = |i: usize| ((span_base & 0x1fff_ffff) | 0x8c00_0000).wrapping_add(i as u32);
        for i in (0..data.len().saturating_sub(1)).step_by(2) {
            let op = half(i);
            if op & 0xf000 != 0xd000 {
                continue;
            }
            let target = ((i + 4) & !3) + (op & 0xff) as usize * 4;
            if !pool.contains(&target) {
                continue;
            }
            let reg = (op >> 8) & 0xf;
            let mut done = false;
            // `rts` ends the routine one delay slot later; the read is before
            // it in every title measured, and stopping there keeps a literal
            // pool or the next function from being read as code.
            let mut last = CABLE_READ_WINDOW;
            for k in 1..=CABLE_READ_WINDOW {
                let at = i + k * 2;
                if at + 1 >= data.len() || k > last {
                    break;
                }
                let op = half(at);
                // `mov.w @Rm,Rn` (0x6mn1) and `mov.l @Rm,Rn` (0x6mn2) -- the
                // two widths that can carry bits 8 and 9 in one instruction.
                if matches!(op & 0xf00f, 0x6001 | 0x6002) && (op >> 4) & 0xf == reg {
                    let dst = (op >> 8) & 0xf;
                    let mov_imm0 = 0xe000u16 | (dst << 8);
                    let aligned = at & !3;
                    let before = word(aligned);
                    let after = if at & 2 == 0 {
                        (before & 0xffff_0000) | mov_imm0 as u32
                    } else {
                        (before & 0x0000_ffff) | ((mov_imm0 as u32) << 16)
                    };
                    info!(
                        "this title reads the cable type at 0x{:08x} (0x{PDTRA:08x} loaded \
                         into r{reg} at 0x{:08x}); it will read 0 -- VGA",
                        at_of(at),
                        at_of(i)
                    );
                    out.push((at_of(aligned), after));
                    done = true;
                    break;
                }
                if op == 0x000b {
                    last = k + 1;
                }
            }
            if !done {
                warn!(
                    "this title loads the cable-type register 0x{PDTRA:08x} at 0x{:08x} and \
                     then reads it in a shape this host does not recognise -- NOTHING was \
                     patched there, so it will see the cable that is really plugged in",
                    at_of(i)
                );
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// IP.BIN's peripheral field: seven ASCII hex digits at +0x38 holding the
/// Katana peripheral word, of which bit 4 means "VGA box".
///
/// Measured on the four PAL dumps here: Sonic Adventure `0601A10`, Sonic
/// Adventure 2 `0799A10` and Crazy Taxi `0799A10` all carry the bit; Snow
/// Surfers is `0799A00` and does not -- which is the title that needs the
/// patch, and the reason this is not judged from the cable check alone.
const IP_BIN_PERIPHERALS: std::ops::Range<usize> = 0x38..0x40;

/// Bit 4 of that word: "supports the VGA box".
pub const PERIPHERAL_VGA: u32 = 0x10;

/// What the header says the title can be played with, or `None` when that
/// field is not the hex string it is supposed to be.
pub fn ip_bin_peripherals(header: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(header.get(IP_BIN_PERIPHERALS)?).ok()?;
    u32::from_str_radix(text.trim(), 16).ok()
}

/// Set the VGA bit in an IP.BIN header, in place, and say what it read before
/// and after.
///
/// WHY BOTHER, when the cable check is what the title actually asks. Because
/// neither of the two readers of this field is the title's own cable check:
/// IP.BIN's bootstrap consults it, and `--boot-ipbin` runs that bootstrap; and
/// the header stays in RAM at 0x8c008000, where a title can read it back --
/// this host puts it there itself, exactly as isoldr does, precisely because
/// nothing else on our path ever populates that region. A title that finds no
/// VGA bit there can refuse the mode its patched cable check just asked for.
///
/// The field's width is preserved rather than assumed: every disc measured
/// writes seven digits and a space, and a disc that writes eight is a disc
/// this must not shorten.
pub fn declare_vga_in_ip_bin(header: &mut [u8]) -> Option<(u32, u32)> {
    let before = ip_bin_peripherals(header)?;
    let after = before | PERIPHERAL_VGA;
    let width = std::str::from_utf8(&header[IP_BIN_PERIPHERALS])
        .ok()?
        .trim()
        .len();
    let text = format!("{after:0width$X}");
    if text.len() > IP_BIN_PERIPHERALS.len() {
        return None;
    }
    let mut field = [b' '; IP_BIN_PERIPHERALS.end - IP_BIN_PERIPHERALS.start];
    field[..text.len()].copy_from_slice(text.as_bytes());
    header[IP_BIN_PERIPHERALS].copy_from_slice(&field);
    Some((before, after))
}

/// The same thing, said out loud, so both IP.BIN paths report it identically.
fn declare_vga_and_say_so(header: &mut [u8]) {
    match declare_vga_in_ip_bin(header) {
        Some((before, after)) if before != after => info!(
            "--vga: IP.BIN peripherals 0x{before:07X} -> 0x{after:07X}, declaring VGA box support"
        ),
        Some((before, _)) => {
            info!("--vga: IP.BIN already declares VGA box support (peripherals 0x{before:07X})")
        }
        None => warn!(
            "--vga: IP.BIN's peripheral field is not the hex string it should be; \
             leaving it as it is"
        ),
    }
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
    let spans = payload_spans(buf, address);

    let ranges = crate::loaders::exclusive_footprint(base);
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
            // Only the part of the loader no title has business addressing --
            // see `exclusive_footprint`, which is also what keeps this and the
            // map check in main.rs looking at the same RAM.
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

/// RAM the title fills in a loop whose two bounds are constants in its code:
/// `(lo, hi, site)`, `hi` exclusive, both in the cached window, `site` the
/// loop's first instruction.
///
/// WHY THIS EXISTS: A KATANA TITLE PAINTS THE BIOS STACK BEFORE ANYTHING ELSE.
/// The crt0 that 0x8c010000 jumps to fills 0x8c00c000..0x8c00f400 with the
/// word "SEGA" as its very first loop -- found in the boot binaries of Snow
/// Surfers, Crazy Taxi, Jet Set Radio, ChuChu Rocket!, Power Stone and Sonic
/// Adventure (2026-09-17). A low loader whose `_end` is above 0x8c00c000 has
/// its `.data` and `.bss` turned into "SEGA" before the title's first GD
/// syscall. Measured under flycast the same day: Snow Surfers at 0x8c004000
/// (`_end` 0x8c00cb48) failed `gdFsInit` and called the BIOS's exit-to-menu
/// 180 ms after EXEC; on the error codes it does not exit for, it spins forever.
///
/// `literals_in_loader_footprint` cannot see it, on purpose: a low loader's
/// image is the BIOS work area, where titles name IP.BIN addresses as a matter
/// of course, so that scan skips it (see `exclusive_footprint`). A fill loop is
/// not a mention but a write, and its shape corroborates it the way a
/// `mov.l @(disp,PC)` corroborates a literal.
///
/// THE SHAPE, and nothing looser:
///
/// ```text
///     mov.l  @(disp,PC),Rx     up to four PC-relative loads, immediately
///     ...                      before the loop, giving Rp and Rend
/// L:  mov.{b,w,l} Rv,@Rp
///     add    #1|2|4,Rp         the store's size
///     cmp/hs Rend,Rp           (cmp/hi makes the bound inclusive)
///     bf     L
/// ```
///
/// The loads have to be contiguous with the loop. A bound loaded from a
/// literal and then dereferenced (`mov.l @Rn,Rn`) is a variable holding the
/// range, not the range, and every crt0 measured clears its `.bss` that way.
pub fn constant_range_fills(buf: &[u8], address: u32) -> Vec<(u32, u32, u32)> {
    let ram = |w: u32| matches!(w & 0xff00_0000, 0x0c00_0000 | 0x8c00_0000 | 0xac00_0000);
    let cached = |w: u32| (w & 0x1fff_ffff) | 0x8c00_0000;
    let mut out = vec![];
    for (span_base, data) in payload_spans(buf, address) {
        let op = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
        for at in (0..data.len().saturating_sub(7)).step_by(2) {
            let store = op(at);
            let size = match store & 0xf00f {
                0x2000 => 1,
                0x2001 => 2,
                0x2002 => 4,
                _ => continue,
            };
            let rp = (store >> 8) & 0xf;
            let cmp = op(at + 4);
            let inclusive = match cmp & 0xf00f {
                0x3002 => false,
                0x3006 => true,
                _ => continue,
            };
            // add #size,Rp; cmp against Rp; bf back to the store (PC+4-10).
            if op(at + 2) != 0x7000 | (rp << 8) | size
                || (cmp >> 8) & 0xf != rp
                || op(at + 6) != 0x8bfb
            {
                continue;
            }
            let rend = (cmp >> 4) & 0xf;
            let (mut lo, mut hi) = (None, None);
            for k in (1..=4).filter_map(|n| at.checked_sub(2 * n)) {
                let load = op(k);
                if load & 0xf000 != 0xd000 {
                    break;
                }
                let pool = ((k + 4) & !3) + (load & 0xff) as usize * 4;
                let Some(b) = data.get(pool..pool + 4) else {
                    break;
                };
                let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                // Walking backwards, the first load of a register is the one
                // the loop sees.
                match (load >> 8) & 0xf {
                    r if r == rp && lo.is_none() => lo = Some(v),
                    r if r == rend && hi.is_none() => hi = Some(v),
                    _ => {}
                }
            }
            let (Some(lo), Some(hi)) = (lo, hi) else {
                continue;
            };
            if !ram(lo) || !ram(hi) {
                continue;
            }
            let (lo, hi) = (cached(lo), cached(hi) + if inclusive { size as u32 } else { 0 });
            if lo < hi {
                out.push((lo, hi, cached(span_base.wrapping_add(at as u32))));
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
        let prefix = match member.rfind('/') {
            Some(i) => member[..=i].to_string(),
            None => String::new(),
        };
        let container: Box<dyn Container> = Box::new(ZipContainer::new(archive.clone(), member));
        let gdi = Gdi::new(container, &base)
            .map_err(|e| format!("cannot read the GDI '{member}' in the archive: {e}"))?;
        // Now, while the title is still being uploaded, rather than inside the
        // first CD-DA sub-fetch of a track with the loader's deadline running:
        // see zip::warm_track_indexes.
        crate::disc_formats::zip::warm_track_indexes(
            &archive,
            &prefix,
            &gdi.audio_track_files(),
        );
        return Ok(get_disc_format(gdi));
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
    wince: boot::WinCe,
) -> Result<boot::BootBinary, String> {
    let disc = open_disc(spec)?;
    boot::extract(disc.as_ref(), mode, wince).map_err(|e| format!("{spec}: {e}"))
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

/// Where the CD-DA samples come from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CddaSource {
    /// Refuse every audio read (`--no-cdda`), so the loader stops the stream.
    Off,
    /// The disc image.
    Disc,
    /// A synthetic two-tone triangle (`--cdda-tone`), sent through the normal
    /// audio path in place of the disc read. A clean tone clears the wire, the
    /// encoder and the loader, and leaves the disc read as the suspect.
    Tone,
}

/// The test tone as raw 2352-byte audio sectors: 344.5 Hz left, 689.1 Hz right.
///
/// The phase is computed from the absolute sample index (LBA x 588 + frame),
/// so consecutive requests join without a seam and a re-asked sector comes
/// back byte for byte.
fn tone_sectors(lba: u32, sectors: u32) -> Vec<u8> {
    const PERIOD_L: u64 = 128;
    const PERIOD_R: u64 = 64;

    fn tri(i: u64, period: u64) -> i16 {
        let half = period / 2;
        let scale = (32768 / half) as i64;
        let t = i % period;
        let a = if t < half { t } else { period - t } as i64;
        ((a - (half / 2) as i64) * scale) as i16
    }

    let mut out = Vec::with_capacity(sectors as usize * RAW_SECTOR_SIZE);
    for s in 0..sectors as u64 {
        let base = (lba as u64 + s) * FRAMES_PER_SECTOR as u64;
        for i in 0..FRAMES_PER_SECTOR as u64 {
            out.extend_from_slice(&tri(base + i, PERIOD_L).to_le_bytes());
            out.extend_from_slice(&tri(base + i, PERIOD_R).to_le_bytes());
        }
    }
    out
}

/// Sample-to-sample continuity scan of the PCM this host serves, taken before
/// any encoding.
///
/// It counts steps larger than `LIMIT` ("hits") and pairs of consecutive ones
/// ("runs"), but **those counts are not evidence of a defect**: a band-limited
/// signal of peak A may step by up to 2A between samples, so loud music produces
/// thousands. Splicing real ring seams into a track moved the count from 4934
/// to 4933. What separates a defect from music is where the hits land; see
/// `verdict()`.
///
/// Used live by `receive_syscalls` (a warning only for an aligned spike) and
/// offline by `audit_audio`.
pub struct SlewWatch {
    prev: Option<(i32, i32)>,
    hits: u64,
    runs: u64,
    max: i32,
    /// LBA and frame of the first run.
    first: Option<(u32, usize)>,
    /// 32 bytes of PCM around the first run, captured during the scan: only the
    /// PCM buffer can be indexed by a frame number (an ADPCM answer is a quarter
    /// of its size).
    first_bytes: Vec<u8>,
    /// Hit counts per frame offset inside a sector (588 frames).
    off: Vec<u64>,
}

impl SlewWatch {
    const LIMIT: i32 = 24000;

    pub fn new() -> Self {
        Self {
            prev: None,
            hits: 0,
            runs: 0,
            max: 0,
            first: None,
            first_bytes: Vec::new(),
            off: vec![0; FRAMES_PER_SECTOR as usize],
        }
    }

    /// Where the hits concentrate inside a sector: `(offset, hits there,
    /// sigma above a uniform spread)`, or `None` below 64 hits.
    ///
    /// Every defect this pipeline can have -- a dropped sector in the rip, a
    /// wrong deflate cursor, a lost sub-fetch, a ring seam -- is aligned to a
    /// structure whose period divides a sector; music is aligned to nothing.
    /// So a spike (callers use more than 8 sigma) is a defect at that offset,
    /// and a flat spread is loud music.
    pub fn verdict(&self) -> Option<(usize, u64, f64)> {
        if self.hits < 64 {
            return None;
        }
        let n = self.off.len() as f64;
        let mean = self.hits as f64 / n;
        // Poisson: a uniform spread over 588 bins puts the largest bin a few
        // sigma above the mean by chance alone, so only a real spike counts.
        let (i, top) = self
            .off
            .iter()
            .enumerate()
            .max_by_key(|&(_, c)| *c)
            .map(|(i, c)| (i, *c))
            .unwrap();
        let sigma = mean.sqrt().max(1e-9);
        let z = (top as f64 - mean) / sigma;
        Some((i, top, z))
    }

    pub fn describe(&self) -> String {
        match self.verdict() {
            None => "too few steps to say anything".into(),
            Some((i, top, z)) if z > 8.0 => format!(
                "CONCENTRATED at sector offset {i} ({top} of {} hits, {z:.1} sigma) \
                 -- that alignment is a reader or dump defect, not music",
                self.hits
            ),
            Some((_, _, z)) => format!(
                "spread evenly across all {} sector offsets ({z:.1} sigma at the \
                 busiest) -- the fingerprint of loud music, not of a defect",
                self.off.len()
            ),
        }
    }

    /// `pcm` is interleaved little-endian 16-bit stereo, which is what a raw
    /// audio sector is and what both `read_audio` and `tone_sectors` produce.
    pub fn scan(&mut self, lba: u32, pcm: &[u8]) {
        let mut prev_big = false;
        for (i, f) in pcm.chunks_exact(4).enumerate() {
            let l = i16::from_le_bytes([f[0], f[1]]) as i32;
            let r = i16::from_le_bytes([f[2], f[3]]) as i32;
            let Some((pl, pr)) = self.prev else {
                self.prev = Some((l, r));
                continue;
            };
            let (dl, dr) = ((l - pl).abs(), (r - pr).abs());
            self.prev = Some((l, r));
            self.max = self.max.max(dl).max(dr);
            let big = dl > Self::LIMIT || dr > Self::LIMIT;
            if big {
                self.hits += 1;
                let slot = i % self.off.len();
                self.off[slot] += 1;
                if prev_big {
                    self.runs += 1;
                    if self.first.is_none() {
                        self.first = Some((lba, i));
                        let at = i * 4;
                        let lo = at.saturating_sub(16).min(pcm.len());
                        let hi = (lo + 32).min(pcm.len());
                        self.first_bytes = pcm[lo..hi].to_vec();
                    }
                }
            }
            prev_big = big;
        }
    }
}

/// Scan every audio track of a disc image with `SlewWatch`, with no console.
///
/// Prints the track table, then one line per audio track: "clean" when the big
/// steps are spread evenly across sector offsets (loud music), or a warning
/// listing the bands of reads they occur in when they concentrate at one
/// offset. Returns the number of steps in tracks judged defective.
///
/// This is where a suspected audio defect gets judged. The live path must not
/// re-read the image while a title waits for its audio.
pub fn audit_audio(disc: &dyn DiscFormat, only: Option<u8>) -> Result<u64, String> {
    const RUN: u32 = 3;
    let toc = disc.toc_tracks();
    if toc.is_empty() {
        return Err("this image reports no tracks at all".into());
    }
    info!("{} tracks:", toc.len());
    for (i, t) in toc.iter().enumerate() {
        let end = toc.get(i + 1).map(|n| n.start_lba);
        info!(
            "  track {:2} {:5} at LBA {:8} (0x{:08x}){}",
            t.number,
            if t.audio { "audio" } else { "data" },
            t.start_lba,
            t.start_lba,
            match end {
                Some(e) => format!(
                    " .. {:8}, {} sectors, {:.1} s",
                    e - 1,
                    e - t.start_lba,
                    (e - t.start_lba) as f64 * 588.0 / 44100.0
                ),
                None => " .. end of disc".into(),
            }
        );
    }

    let mut total = 0u64;
    for (i, t) in toc.iter().enumerate() {
        if !t.audio || only.is_some_and(|n| n != t.number) {
            continue;
        }
        let Some(end) = toc.get(i + 1).map(|n| n.start_lba) else {
            continue;
        };
        let mut watch = SlewWatch::new();
        // Bands, not individual hits: consecutive bad reads are one event.
        let mut bands: Vec<(u32, u32)> = Vec::new();
        let mut lba = t.start_lba;
        let mut failed = 0u32;
        while lba + RUN <= end {
            match disc.read_audio(lba, RUN) {
                Ok(pcm) => {
                    let before = watch.runs;
                    watch.scan(lba, &pcm);
                    if watch.runs > before {
                        match bands.last_mut() {
                            Some(b) if lba <= b.1 + RUN * 2 => b.1 = lba + RUN,
                            _ => bands.push((lba, lba + RUN)),
                        }
                    }
                }
                Err(_) => failed += 1,
            }
            lba += RUN;
        }
        let secs = |n: u32| n as f64 * 588.0 / 44100.0;
        let aligned = matches!(watch.verdict(), Some((_, _, z)) if z > 8.0);
        if !aligned {
            info!(
                "  track {:2}: clean ({:.1} s, {} big step(s), largest {}) -- {}",
                t.number,
                secs(end - t.start_lba),
                watch.hits,
                watch.max,
                watch.describe()
            );
        } else {
            warn!(
                "  track {:2}: {} big step(s) in {} band(s), largest {}{} -- {}",
                t.number,
                watch.hits,
                bands.len(),
                watch.max,
                if failed > 0 {
                    format!(", {failed} read(s) failed")
                } else {
                    String::new()
                },
                watch.describe()
            );
            for (a, b) in bands.iter().take(16) {
                warn!(
                    "      LBA 0x{a:08x}..0x{b:08x}  ({:.1} s in, {:.1} s long)",
                    secs(a - t.start_lba),
                    secs(b - a)
                );
            }
            if bands.len() > 16 {
                warn!("      ... and {} more band(s)", bands.len() - 16);
            }
        }
        if aligned {
            total += watch.hits;
        }
        
    }
    Ok(total)
}

// Nine arguments, each something the session already decided: the disc, the
// mount, where the loader is, the guards to keep alive, whether to serve
// audio, where to record what is learned, what to sample, and the stack watch.
// A struct would only move the list out of sight of this signature.
#[allow(clippy::too_many_arguments)]
pub fn receive_syscalls(
    conn: &mut impl ExternalDcIo,
    cd_disc: Option<Box<dyn DiscFormat>>,
    mount: Option<String>,
    running_base: Option<u32>,
    guards: &[(u32, u32)],
    cdda: CddaSource,
    memory: Option<std::sync::Arc<std::sync::Mutex<crate::memmap::MemoryRecorder>>>,
    mut diag: Option<crate::diag::Probe>,
    mut stack: Option<crate::stackwatch::StackWatch>,
    stage: Vec<(u32, u32)>,
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
    // Enumerated ONCE, here, for the same reason as the two above: on a zipped
    // GDI, opening a track can mean a full deflate index build, and this would
    // otherwise happen inside the TOC syscall with the title frozen waiting.
    let toc_all_tracks = disc.toc_tracks();
    let mut cdda_reads: u64 = 0;
    /// An audio answer that took longer than this to produce is dropped, not
    /// sent -- ReturnValue included. The loader has stopped waiting for it, and
    /// a late burst naming the same staging buffer as its next request could be
    /// taken for that request's answer (or its ReturnValue release it early).
    ///
    /// **Must stay below the loader's `CDDA_FETCH_DEADLINE_TICKS` (20 ms)**, so
    /// that "dropped here" and "arrived in time" cannot overlap. A normal answer
    /// takes well under a millisecond; what this drops in practice is the first
    /// read of a session, when a deflate index is being built.
    const CDDA_GIVE_UP: Duration = Duration::from_millis(15);
    let mut cdda_too_late: u64 = 0;
    let mut slew = SlewWatch::new();
    let mut slew_audited = false;
    // The ADPCM encoder, one per session: its state must carry from one request
    // to the next, in step with the AICA's decoder (see `adpcm::Stream`).
    let mut adpcm = crate::adpcm::Stream::new();
    // Raw disc sectors in the last audio request. Not derivable from the
    // answer: an ADPCM answer is a quarter of the bytes it was encoded from.
    let mut cdda_sectors: u64 = 0;
    let mut cdda_started: Option<Instant> = None;
    // Per-window accounting, reported every 250 audio requests.
    //
    // The title is frozen from its audio request until our ReturnValue, and the
    // console cannot time that while it waits, so this host does: disc read
    // time, total time, the maximum, and how many were slow.
    //
    // Loss sampling: `send_audio` does not check delivery, so one request in
    // 256 is probed with a DoneBinary to catch a link that starts dropping
    // audio.
    let mut cdda_probes: u64 = 0;
    let mut cdda_probes_lossy: u64 = 0;
    let mut cdda_win_start: Option<Instant> = None;
    let mut cdda_win_disc_us: u64 = 0;
    let mut cdda_win_total_us: u64 = 0;
    let mut cdda_win_max_us: u64 = 0;
    // Requests in this window that took longer than `CDDA_SLOW_US` to serve.
    let mut cdda_win_slow: u64 = 0;
    // The loader's audio clock, measured against this host's. See `CddaClock`.
    let mut cdda_clock = CddaClock::new();
    let mut cdda_errors: u64 = 0;
    debug!("CDFS source: start_sector={toc_start} num_sectors={toc_sectors}");
    if toc_all_tracks.is_empty() {
        debug!(
            "this image does not enumerate its tracks: the table of contents will be \
             the single-data-track one, and a title reading it cannot discover any CDDA"
        );
    } else {
        let audio = toc_all_tracks.iter().filter(|t| t.audio).count();
        info!(
            "disc has {} tracks, {audio} of them audio",
            toc_all_tracks.len()
        );
    }
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
        // TOP OF THE ITERATION, AND ONLY HERE. The counter probe posts its own
        // SendBinQ; doing that anywhere else would put an outgoing command in
        // the middle of a transfer that owns the conversation. Nothing blocks:
        // the replies are picked out of the ordinary flow below.
        if let Some(d) = diag.as_mut() {
            d.tick(conn);
        }
        // Same rule, same place: the stack watch posts its own SendBinQ, and
        // the top of the loop is the one point where no transfer owns the
        // conversation.
        if let Some(s) = stack.as_mut() {
            s.tick(conn);
        }
        // Whoever wants waking up soonest decides. `LoadMonitor` asks for
        // nothing while no burst is open -- the normal state of a running
        // title -- so without the panel this is still the block-forever it
        // always was.
        let timeout = [
            load.poll_timeout(),
            diag.as_ref().and_then(|d| d.poll_timeout()),
            stack.as_ref().and_then(|s| s.poll_timeout()),
        ]
        .into_iter()
        .flatten()
        .min();
        match await_result(conn, timeout) {
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
                    // NOTHING TO FILTER HERE. The probe's replies are claimed
                    // in the IO layer instead (`io::PacketSink`), because they
                    // arrive inside whatever transfer happens to be polling --
                    // never here. See `diag::SampleSink`.
                    if let Some(inner_cmd) = cmd.request {
                        match inner_cmd {
                            // Handle special cases
                            DCLoadClientCmds::ReadSector(start, dc_address, size) => {
                                debug!(
                                    "Received ReadSector syscall: start=0x{:08x}, dc_address=0x{:08x}, size={}",
                                    start, dc_address, size
                                );
                                // A REQUEST THIS MALFORMED IS EVIDENCE, NOT A
                                // REASON TO DIE. dcload builds it out of its
                                // own state, so a size that is not a sector
                                // multiple means that state was overwritten --
                                // and at a low base the thing that overwrites
                                // it is the title's own stack descending past
                                // `_end` (AGENTS.md §4.6). Ending the session
                                // here loses the memory map and the counters,
                                // which are the only two things that say where
                                // to put the loader next time. Refuse the read
                                // and stay up, exactly as an unanswered
                                // transfer does.
                                if size % 2048 != 0 || size > MAX_XFER as u32 {
                                    warn!(
                                        "ReadSector request is malformed (LBA 0x{start:08x} ->                                          0x{dc_address:08x}, size {size}). The loader's own state                                          has been overwritten -- at a low base, check                                          g_gd_sp_in_image with --diag, and see AGENTS.md 4.6.                                          Refusing this read and staying up."
                                    );
                                    continue;
                                }
                                let num_sectors = size / 2048;
                                // A READ OFF THE END OF THE DISC IS THE TITLE'S
                                // ERROR TO RECEIVE, NOT THIS HOST'S TO DIE OF.
                                // A real drive answers it with a failed
                                // command; so does this, and the loader fails
                                // the read after its retries. Windows CE asked
                                // for LBA 0x9e80f on a disc ending at 549300,
                                // and the `?` that was here ended the session
                                // on the spot -- taking with it everything the
                                // title would have done next.
                                let mut buf = match disc.read_sector(start, num_sectors) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        warn!(
                                            "ReadSector for {num_sectors} sector(s) at LBA {start} \
                                             (0x{start:08x}) -> 0x{dc_address:08x} cannot be served: \
                                             {e}. The disc spans LBA {toc_start}..{}; answering \
                                             with a failure, as a drive would.",
                                            toc_start.saturating_add(toc_sectors)
                                        );
                                        let _ = conn.send_command(DCLoadCmd {
                                            cmd: DCLoadCmds::ReturnValue(),
                                            address: u32::MAX,
                                            size: u32::MAX,
                                        });
                                        continue;
                                    }
                                };

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
                                // EXCEPT THE LOADER'S OWN STAGING BUFFERS
                                // (`_gd_stage`, `_gd_stage_big`: `stage`). A read there is dcload
                                // asking for sectors it copies to the title
                                // itself, because the title's buffer is a
                                // virtual address its MMU translates, which
                                // cmd_partbin cannot write (Windows CE;
                                // dcload-ip: cdfs_syscalls.c). It is neither a
                                // collision nor evidence of where the title's
                                // memory is. Those symbols only: anything else in
                                // the loader is still a collision.
                                let staged = stage.iter().any(|&(lo, len)| {
                                    let (lo, a) = (lo & 0x1fff_ffff, dc_address & 0x1fff_ffff);
                                    a >= lo && a.saturating_add(buf.len() as u32) <= lo + len
                                });
                                if !staged
                                    && let Some(hit) = crate::loaders::overlapping_range(
                                        loader_base,
                                        (dc_address, dc_address.saturating_add(buf.len() as u32)),
                                    )
                                    && warned_overlap.insert(dc_address)
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
                                if !staged
                                    && let Some(rec) = memory.as_ref()
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
                                if !staged && loader_base >= 0x8c01_0000 {
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
                                //
                                // WHICH IS NOW THE LOADER'S JUDGEMENT, NOT OURS
                                // (2026-09-20). `send_sectors` sends the window
                                // and the parts and waits for neither the echo
                                // nor a DoneBinary probe -- ~1.9 ms of frozen
                                // title per 16 KB chunk out of 5. The loader
                                // checks its own window when the ReturnValue
                                // lands (`bin_window_complete`), fails a chunk
                                // with a hole in it and asks again, so a short
                                // buffer is still never reported complete; it
                                // just costs a round trip when it happens
                                // instead of two when it does not. It only
                                // returns Err if the socket itself failed, and
                                // the arm below then leaves the DC to time out
                                // exactly as before.
                                match send_sectors(conn, &buf, dc_address) {
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
                                        // A GUARD PATCH HAS TO SURVIVE A RELOAD.
                                        //
                                        // What the GAPS guard and the VGA patch
                                        // change is a word in the title's own
                                        // image, and a title is free to read its
                                        // image back off its disc. That would
                                        // restore the probe's comparison constant
                                        // and let it switch the adapter off,
                                        // after which the loader is deaf with
                                        // nothing logged at either end
                                        // (AGENTS.md 4.12) -- the same silent
                                        // ending the guard exists to prevent,
                                        // reached the long way round; and it
                                        // would put the cable check back, which
                                        // is a title that changes video mode
                                        // half way through its own start-up.
                                        // Tested on
                                        // every read, paid for only by one that
                                        // actually covers a patched word, and
                                        // done HERE: after the read-back
                                        // comparison, so it has nothing to
                                        // disagree with, and before the
                                        // ReturnValue, which is the last moment
                                        // the title is still parked and cannot
                                        // yet run what was just delivered.
                                        let reloaded: Vec<(u32, u32)> = guards
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
                                                "this read reloads {} patched word(s) \
                                                 (LBA 0x{start:08x} -> 0x{dc_address:08x}, \
                                                 {} B); re-applying them before the title can \
                                                 run the bytes just delivered",
                                                reloaded.len(),
                                                buf.len()
                                            );
                                            if let Err(e) = apply_patches(conn, &reloaded) {
                                                error!("could not re-apply the guard: {e}");
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
                            // CD-DA (DC23 PCM / DC24 ADPCM). Not recorded in the
                            // memory map: the destination is the loader's own
                            // staging buffer, and marking it would teach the map
                            // that the title writes where the loader lives.
                            DCLoadClientCmds::ReadAudio(start, dc_address, size, fmt) => {
                                // The title is frozen from here until the
                                // ReturnValue below: dcload sent this from
                                // cdda_fetch() and waits in bb->loop().
                                let t0 = Instant::now();
                                // Request size per raw sector: PCM asks for the
                                // disc's bytes (2352), ADPCM for one byte per
                                // stereo frame (588).
                                let per_sector = match fmt {
                                    AudioFormat::Pcm => RAW_SECTOR_SIZE as u32,
                                    AudioFormat::Adpcm { .. } => FRAMES_PER_SECTOR,
                                };
                                let answer = if cdda == CddaSource::Off {
                                    Err("CDDA is off (--no-cdda)".to_string())
                                } else if size == 0 || size % per_sector != 0 {
                                    Err(format!(
                                        "CDDA read size {size} is not a multiple of \
                                         {per_sector}"
                                    ))
                                } else {
                                    cdda_sectors = (size / per_sector) as u64;
                                    // A re-ask comes out of the encoder's history
                                    // BEFORE any disc read: see Stream::replay.
                                    if let AudioFormat::Adpcm { restart: false } = fmt
                                        && let Some(bytes) = adpcm.replay(start, size as usize)
                                    {
                                        Ok(bytes)
                                    } else {
                                        // The tone replaces the disc read and nothing
                                        // else: the ADPCM encoder below still runs.
                                        if cdda == CddaSource::Tone {
                                            Ok(tone_sectors(start, size / per_sector))
                                        } else {
                                            disc.read_audio(start, size / per_sector)
                                                .map_err(|e| e.to_string())
                                        }
                                        // Scanned before encoding, so it sees PCM
                                        // whatever format the loader asked for.
                                        .inspect(|pcm: &Vec<u8>| {
                                            let was = slew.runs;
                                            slew.scan(start, pcm);
                                            // Big steps alone are loud music: only an
                                            // aligned spike is a warning (see
                                            // SlewWatch::verdict).
                                            if slew.runs > was && (was == 0 || slew.runs % 250 == 0) {
                                                match slew.verdict() {
                                                    Some((_, _, z)) if z > 8.0 => debug!(
                                                        "the audio leaving this host has \
                                                         ALIGNED discontinuities: {}",
                                                        slew.describe()
                                                    ),
                                                    _ => debug!(
                                                        "audio slew: {} hit(s), largest step {} -- {}",
                                                        slew.hits,
                                                        slew.max,
                                                        slew.describe()
                                                    ),
                                                }
                                            }
                                        })
                                            .and_then(|pcm| match fmt {
                                                AudioFormat::Pcm => Ok(pcm),
                                                // Encoded inside the timed section,
                                                // so encoder time shows up in the
                                                // per-request figures.
                                                AudioFormat::Adpcm { restart } => {
                                                    let enc =
                                                        adpcm.encode_request(start, &pcm, restart);
                                                    // A short answer is refused, and the
                                                    // loader re-asks. Both `read_audio`
                                                    // implementations fill or fail, so
                                                    // this should never fire.
                                                    if enc.len() as u32 == size {
                                                        Ok(enc)
                                                    } else {
                                                        Err(format!(
                                                            "ADPCM encode produced {} bytes, not \
                                                             the {size} the loader asked for",
                                                            enc.len()
                                                        ))
                                                    }
                                                }
                                            })
                                    }
                                };
                                // Disc read (and encode) time, kept apart from
                                // the wire: they need different fixes and look
                                // the same from the console.
                                let disc_us = t0.elapsed().as_micros() as u64;
                                // Once per session, if the scan has found an
                                // ALIGNED spike (a real defect, see
                                // SlewWatch::verdict), print the bytes around
                                // its first run as hex and text: foreign data
                                // such as an ASCII header shows at a glance.
                                // Outside the timing above on purpose.
                                if slew.runs > 0
                                    && matches!(slew.verdict(), Some((_, _, z)) if z > 8.0)
                                    && !slew_audited
                                    && answer.is_ok()
                                    && !slew.first_bytes.is_empty()
                                    && let Some((bad_lba, bad_frame)) = slew.first
                                {
                                    slew_audited = true;
                                    let lo = (bad_frame * 4).saturating_sub(16);
                                    let mut hex = String::new();
                                    let mut txt = String::new();
                                    for b in &slew.first_bytes {
                                        hex.push_str(&format!("{b:02x}"));
                                        txt.push(if (0x20..0x7f).contains(b) {
                                            *b as char
                                        } else {
                                            '.'
                                        });
                                    }
                                    debug!(
                                        "the discontinuity, as bytes: LBA 0x{bad_lba:08x} \
                                         +{lo} ({} B) {hex} |{txt}|",
                                        slew.first_bytes.len()
                                    );
                                    // The LBA is not re-read here to check the
                                    // reader: that can build a deflate index while
                                    // the title waits (measured at 223 ms, which
                                    // then cost the answer in flight). The deflate
                                    // reader is tested against ground truth, and
                                    // `audit-audio` judges the image offline.
                                    debug!(
                                        "run `dcload-ip-rs audit-audio` on this image to \
                                         judge LBA 0x{bad_lba:08x}: it is NOT re-read here, \
                                         because doing that froze the title for 223 ms and \
                                         cost the audio answer that was in flight"
                                    );
                                }
                                match answer {
                                    Ok(buf) => {
                                        // Too late: see CDDA_GIVE_UP. Nothing is
                                        // sent, not even the ReturnValue, which
                                        // could release a later request early.
                                        let spent = t0.elapsed();
                                        if spent >= CDDA_GIVE_UP {
                                            cdda_too_late += 1;
                                            debug!(
                                                "CDDA read of LBA 0x{start:08x}{} took \
                                                 {:.0} ms ({:.1} ms of it reading and \
                                                 encoding), past the loader's deadline: \
                                                 dropping it rather than answering a \
                                                 request that has moved on ({cdda_too_late} \
                                                 so far)",
                                                if let AudioFormat::Adpcm { restart: true } = fmt {
                                                    " (stream restart)"
                                                } else {
                                                    ""
                                                },
                                                spent.as_secs_f64() * 1000.0,
                                                disc_us as f64 / 1000.0
                                            );
                                            continue;
                                        }
                                        let first = cdda_reads == 0;
                                        if first {
                                            cdda_started = Some(Instant::now());
                                            cdda_win_start = Some(Instant::now());
                                        }
                                        cdda_reads += 1;
                                        // No acknowledgement round trips (see
                                        // `send_audio`); one request in 256 is
                                        // probed for loss.
                                        let probe = cdda_reads.is_multiple_of(256);
                                        match send_audio(conn, &buf, dc_address, probe) {
                                            Ok(Some(missing)) => {
                                                cdda_probes += 1;
                                                if missing > 0 {
                                                    cdda_probes_lossy += 1;
                                                }
                                            }
                                            Ok(None) => {}
                                            Err(e) => {
                                                debug!("CDDA read transfer failed: {e}");
                                                let _ = conn.send_command(DCLoadCmd {
                                                    cmd: DCLoadCmds::ReturnValue(),
                                                    address: u32::MAX,
                                                    size: u32::MAX,
                                                });
                                                continue;
                                            }
                                        }
                                        // The ReturnValue releases the loader.
                                        // `address` echoes the LBA served: every
                                        // audio answer names the same buffer and
                                        // size, so this is how the loader tells
                                        // it from a late answer to an earlier
                                        // request. `size` carries the clock trim
                                        // in ppm (1000000 = no correction; see
                                        // `CddaClock`). Both fields were unused.
                                        conn.send_command(DCLoadCmd {
                                            cmd: DCLoadCmds::ReturnValue(),
                                            address: start,
                                            size: cdda_clock.scale_ppm,
                                        })?;
                                        // The title is running again. Everything
                                        // below is accounting, kept after the
                                        // ReturnValue so the title never waits
                                        // for it.
                                        let total_us = t0.elapsed().as_micros() as u64;
                                        cdda_win_disc_us += disc_us;
                                        cdda_win_total_us += total_us;
                                        cdda_win_max_us = cdda_win_max_us.max(total_us);
                                        if total_us > CDDA_SLOW_US {
                                            cdda_win_slow += 1;
                                        }
                                        // Clock trim: the LBA asked for and the
                                        // arrival time are all it needs.
                                        if cdda_trim()
                                            && let Some(step) = cdda_clock.note(t0, start)
                                        {
                                            match step {
                                                CddaTrim::Applied { from, to, win_ppm, secs } => {
                                                    debug!(
                                                        "CDDA clock: the loader's model ran {} \
                                                         ppm {} over {secs:.0} s of free-running \
                                                         stream -- trim {from} -> {to} ppm",
                                                        win_ppm.abs(),
                                                        if win_ppm < 0 { "slow" } else { "fast" }
                                                    );
                                                }
                                                CddaTrim::Held { ppm, win_ppm, secs } => {
                                                    debug!(
                                                        "CDDA clock: the loader's model is within \
                                                         {} ppm over {secs:.0} s -- the trim \
                                                         stays at {ppm} ppm",
                                                        win_ppm.abs()
                                                    );
                                                }
                                                CddaTrim::Refused { est_ppm, secs } => {
                                                    debug!(
                                                        "CDDA clock: {secs:.0} s of stream say \
                                                         the trim should be {est_ppm} ppm, which \
                                                         is further out than any clock can be -- \
                                                         not applied. Something other than the \
                                                         model's period is wrong."
                                                    );
                                                }
                                                CddaTrim::Discarded { secs, ratio } => {
                                                    debug!(
                                                        "CDDA clock: discarded {secs:.0} s -- \
                                                         audio against real time came out at \
                                                         {ratio:.3}, so the stream was not \
                                                         free-running"
                                                    );
                                                }
                                            }
                                        }
                                        // A single slow answer is reported as it
                                        // happens (a window average hides it),
                                        // split into the disc read -- the image
                                        // may be on a network or sync folder --
                                        // and the rest: the wire and this
                                        // process's scheduling.
                                        const CDDA_LOUD_US: u64 = 20_000;
                                        if total_us > CDDA_LOUD_US {
                                            debug!(
                                                "CDDA read took {:.1} ms to serve (disc {:.1},                                                  rest {:.1}) at LBA 0x{start:08x} -- the title                                                  was frozen for all of it",
                                                total_us as f64 / 1000.0,
                                                disc_us as f64 / 1000.0,
                                                (total_us - disc_us) as f64 / 1000.0,
                                            );
                                        }
                                        if first {
                                            debug!(
                                                "CDDA: first audio read served (LBA \
                                                 0x{start:08x}, {} bytes)",
                                                buf.len()
                                            );
                                        }
                                        // Every 250 requests: the periodic
                                        // report. The ratio is a runaway guard
                                        // (a loader fetching much faster than
                                        // real time starves the title). It
                                        // counts requests, so re-asks inflate it
                                        // slightly; the clock estimator measures
                                        // by disc position instead.
                                        if cdda_reads % 250 == 0 {
                                            let secs = cdda_started
                                                .get_or_insert_with(Instant::now)
                                                .elapsed()
                                                .as_secs_f64();
                                            let audio =
                                                (cdda_reads * cdda_sectors) as f64 / 75.0;
                                            let ratio = if secs > 0.0 { audio / secs } else { 0.0 };
                                            if ratio > 1.5 {
                                                debug!(
                                                    "CDDA is streaming {ratio:.1}x faster than \
                                                     real time ({cdda_reads} reads): the \
                                                     loader's flow control is not holding, and \
                                                     it will starve the title"
                                                );
                                            } else {
                                                // The LBA too: a stream stuck
                                                // replaying the same sectors at
                                                // the right rate looks healthy
                                                // from a count alone.
                                                debug!(
                                                    "CDDA: {cdda_reads} reads, {ratio:.2}x real \
                                                     time, at LBA 0x{start:08x}"
                                                );
                                                // The clock estimator's running
                                                // view, printed before it commits,
                                                // so "no trim yet" and "nothing
                                                // to trim" can be told apart.
                                                {
                                                    let (banked, rate, ppm, trims) =
                                                        cdda_clock.progress();
                                                    let want = if trims == 0 {
                                                        CDDA_TRIM_FIRST_S
                                                    } else {
                                                        CDDA_TRIM_S
                                                    };
                                                    debug!(
                                                        "CDDA clock: window has {banked:.1}s of \
                                                         {want:.0}s free-running stream banked, \
                                                         reading {:+.0} ppm; {trims} trim(s) \
                                                         applied, loader running on {ppm} ppm",
                                                        if rate > 0.0 {
                                                            (rate * f64::from(ppm) / 1e6 - 1.0)
                                                                * 1e6
                                                        } else {
                                                            0.0
                                                        }
                                                    );
                                                }
                                                // Continuity counts of the audio
                                                // leaving this host. Big steps
                                                // are normal in loud music; only
                                                // an aligned spike means a
                                                // defect (SlewWatch::verdict).
                                                debug!(
                                                    "CDDA continuity leaving this host: \
                                                     {} run(s), {} hit(s), largest step {}",
                                                    slew.runs, slew.hits, slew.max
                                                );
                                            }
                                            // Encoder history. A re-ask answered
                                            // from the kept bytes is free; one
                                            // older than RECENT (`lost_replay`)
                                            // decodes from the wrong coder state
                                            // on both ears with every loader
                                            // counter clean, so it must stay 0.
                                            if adpcm.lost_replay > 0 {
                                                debug!(
                                                    "CDDA ADPCM: {} re-ask(s) older than the \
                                                     {}-deep history -- those blocks decoded \
                                                     from the wrong coder state and ARE the \
                                                     audible glitches ({} replayed, {} \
                                                     out of order)",
                                                    adpcm.lost_replay,
                                                    crate::adpcm::RECENT,
                                                    adpcm.replays,
                                                    adpcm.out_of_order
                                                );
                                            } else {
                                                debug!(
                                                    "CDDA ADPCM: {} re-ask(s) answered from \
                                                     the kept bytes, {} out of order, none lost",
                                                    adpcm.replays, adpcm.out_of_order
                                                );
                                            }
                                            // What the music costs the title:
                                            // time frozen per request (disc read
                                            // + the rest) and the share of wall
                                            // time. This host's half only: the
                                            // flight times and the loader's G2
                                            // copies into sound RAM, after the
                                            // ReturnValue, are not in it.
                                            let win = cdda_win_start
                                                .get_or_insert_with(Instant::now)
                                                .elapsed()
                                                .as_secs_f64();
                                            let n = 250.0_f64;
                                            let frozen = cdda_win_total_us as f64 / 1000.0;
                                            debug!(
                                                "CDDA: 250 fetches in {win:.2} s ({:.1}/s) -- \
                                                 title frozen {:.2} ms each (disc {:.2} + wire \
                                                 {:.2}), max {:.2} ms, {cdda_win_slow} over \
                                                 5 ms = {:.1}% of wall time",
                                                n / win.max(1e-9),
                                                frozen / n,
                                                cdda_win_disc_us as f64 / 1000.0 / n,
                                                (cdda_win_total_us - cdda_win_disc_us) as f64
                                                    / 1000.0
                                                    / n,
                                                cdda_win_max_us as f64 / 1000.0,
                                                frozen / (win.max(1e-9) * 1000.0) * 100.0,
                                            );
                                            // Only when it has something to
                                            // say. A clean link should print
                                            // this line never.
                                            if cdda_probes_lossy > 0 {
                                                debug!(
                                                    "CDDA: {cdda_probes_lossy} of \
                                                     {cdda_probes} sampled fetches arrived \
                                                     incomplete -- the fast path does not \
                                                     repair them, so this is audible as \
                                                     crackle"
                                                );
                                            }
                                            cdda_win_start = Some(Instant::now());
                                            cdda_win_disc_us = 0;
                                            cdda_win_total_us = 0;
                                            cdda_win_max_us = 0;
                                            cdda_win_slow = 0;
                                        }
                                    }
                                    // NOT fatal to the session. A title that
                                    // asks for audio this image cannot serve
                                    // should lose its music, not its disc: the
                                    // loader turns a refusal into silence and
                                    // the game goes on reading data.
                                    Err(e) => {
                                        if cdda_errors == 0 {
                                            debug!(
                                                "CDDA read refused (LBA 0x{start:08x}): {e}. \
                                                 The title will get silence; further \
                                                 refusals are not logged."
                                            );
                                        }
                                        cdda_errors += 1;
                                        conn.send_command(DCLoadCmd {
                                            cmd: DCLoadCmds::ReturnValue(),
                                            address: u32::MAX,
                                            size: u32::MAX,
                                        })?;
                                    }
                                }
                            }
                            DCLoadClientCmds::ReadToc(area, dc_address, _unused) => {
                                let toc =
                                    build_dc_toc(toc_start, toc_sectors, &toc_all_tracks, area);
                                if let Err(e) = send_data(conn, &toc, dc_address, None) {
                                    warn!("Failed to send CDFS TOC data: {}", e);
                                    let _ = conn.send_command(DCLoadCmd {
                                        cmd: DCLoadCmds::ReturnValue(),
                                        address: u32::MAX,
                                        size: u32::MAX,
                                    });
                                    continue;
                                }
                                // NOT READ BACK. It was, for one session:
                                // Windows CE asked for this TOC at 0x080df654,
                                // a virtual address in a CE process slot, and
                                // the SendBinQ that read it back froze the
                                // console for good -- while the write that
                                // delivered it had gone through. An instrument
                                // that reads a title's virtual memory from
                                // inside its GD call is inside the blast
                                // radius (AGENTS.md 14.13). What was sent is
                                // logged instead, to compare with what the
                                // title does next.
                                debug!(
                                    "TOC area {area} -> 0x{dc_address:08x}: first {:?}, last {:?}, \
                                     leadout {:?}",
                                    toc_word(&toc, 99),
                                    toc_word(&toc, 100),
                                    toc_word(&toc, 101)
                                );
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
                // Picks up a repaint the display throttled away between two of
                // its own frames -- a keypress, most often. Cheap: indicatif
                // decides whether it is due, and drops it if it is not.
                if let Some(d) = diag.as_ref() {
                    d.repaint();
                }
            }
        }
    }
}

/// The version handshake, as it goes on the wire: our protocol version stuffed
/// into the address field, which is where dcload reads it from.
fn version_command() -> DCLoadCmd {
    let protocol_version = protocol_version();
    DCLoadCmd {
        cmd: DCLoadCmds::Version(None),
        address: ((protocol_version[0] as u32) << 16)
            | ((protocol_version[1] as u32) << 8)
            | protocol_version[2] as u32,
        size: 0,
    }
}

pub fn send_version(
    conn: &mut impl ExternalDcIo,
) -> std::result::Result<Vec<DCReturnCmd>, std::boxed::Box<dyn std::error::Error>> {
    call_command(conn, version_command())
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

/// Stereo frames in one raw CD sector (2352 / 4, i.e. 1/75 s). An ADPCM request
/// is one byte per frame, so this is also the ADPCM bytes a sector is worth.
const FRAMES_PER_SECTOR: u32 = RAW_SECTOR_SIZE as u32 / 4;

/// An audio answer this process took longer than this to serve is counted as
/// slow in the periodic report (5 ms, a third of a PAL frame).
const CDDA_SLOW_US: u64 = 5_000;

// ---- The CD-DA clock estimator's thresholds (see `CddaClock`) ----
//
// They describe the loader's geometry. Since 2026-09-20 it keeps a fixed lead
// of audio ahead of the AICA and fetches one sub-fetch of 4 sectors (53 ms)
// whenever the lead is short, so the stream is PACED: one request every ~53 ms,
// not a burst of 13 and then a 477 ms idle tail. The alignment machinery that
// tail needed is gone with it. If the sub-fetch length or the pacing changes on
// the loader, re-check these values and the `feed_stream` tests: the estimator
// once accepted nothing for days because they still described an 80 ms half.

/// Seconds of accepted stream before the first estimate, and between later
/// ones. Later estimates refine the same constant over a longer total.
///
/// The error being resolved is a few hundred ppm (184 ppm measured), which
/// moves the loader's write head through its lead in about an hour, so
/// resolution matters more than speed: a 20 s window carries ~500 ppm of
/// service jitter. A window's endpoints are two fetch instants, and the lead
/// at each is the same to within one service call, so the phase the window
/// cannot account for is ~17 ms: 190 ppm over 90 s, 55 over 300, and less again
/// as the accumulated span grows.
const CDDA_TRIM_FIRST_S: f64 = 90.0;
const CDDA_TRIM_S: f64 = 300.0;
/// The longest gap between two audio requests that still counts as a
/// free-running stream. A paced stream asks every ~53 ms and a title that stops
/// calling the GD driver stretches that to a few hundred ms; a longer gap means
/// the loader was kept off the ring (a disc read, a pause), and the interval is
/// dropped from both sums.
const CDDA_TRIM_GAP_MAX: f64 = 1.0;
/// The most sectors one request may advance the disc position and still be the
/// next piece of the same stream (a sub-fetch is 3 or 4 sectors; a seek, a
/// repeat or a new track jumps further).
const CDDA_TRIM_STEP_MAX: u32 = 12;
/// Seconds banked before a segment is judged and added to the window.
///
/// It is the whole defence against the bias a dropped interval leaves behind:
/// the loader owes that audio and delivers it as fast as it can afterwards, so
/// the catch-up must land in a segment short enough for the test below to see
/// it. The lead is 893 ms, so a catch-up is at most that; two seconds puts it
/// at +45 %, well past the gate, while the ordinary service jitter of a 2 s
/// segment is under 1 %.
const CDDA_TRIM_SEG_S: f64 = 2.0;
/// A banked segment must itself have taken about as long as the audio in it. A
/// loading stall is many times slower than real time; a segment with a couple
/// of failed sub-fetches is at most ~10 % slower. Outside +/-20 % it is
/// dropped.
const CDDA_TRIM_SEG_SANE: f64 = 0.20;
/// A window whose own estimate (corrected for the scale in force) is more than
/// 3 % out was not measuring a clock, and is discarded.
const CDDA_TRIM_WINDOW_SANE: f64 = 0.03;
/// Estimates outside +/-1.5 % are refused: two crystals are a few hundred ppm
/// apart at most, so such a number is a broken measurement (a loading stall once
/// read as 25 %). The loader applies the same gate.
const CDDA_TRIM_SANE: std::ops::RangeInclusive<u32> = 985_000..=1_015_000;

/// What one clock measurement decided.
#[derive(Debug, PartialEq)]
enum CddaTrim {
    Applied { from: u32, to: u32, win_ppm: i64, secs: f64 },
    Held { ppm: u32, win_ppm: i64, secs: f64 },
    Refused { est_ppm: u32, secs: f64 },
    Discarded { secs: f64, ratio: f64 },
}

/// Measures the loader's CD-DA clock against this host's.
///
/// The loader decides which half of its ring the AICA is playing from an SH4
/// timer with a compiled-in period; nothing on the console is locked to the
/// AICA. If that period is off, the loader's idea of the play position drifts.
/// This host serves every audio request and has its own clock, so it measures
/// audio staged per second of real time and returns a scale in parts per
/// million in the ReturnValue of every audio request.
///
/// What keeps the estimate honest:
///  - it counts disc position, not requests (a re-asked sub-fetch repeats an
///    LBA);
///  - it uses only free-running intervals, in segments that must themselves
///    have taken about as long as the audio in them (the `CDDA_TRIM_*`
///    thresholds above);
///  - it estimates one constant: total accepted audio over the sum of each
///    epoch's accepted time divided by the scale then in force, so each
///    correction is a fresh estimate over a longer span, not an increment.
struct CddaClock {
    /// What the loader is running on, in parts per million of its constant.
    scale_ppm: u32,
    prev: Option<(Instant, u32)>,
    /// This segment, not yet judged. See `CDDA_TRIM_SEG_S`.
    pend_audio_s: f64,
    pend_time_s: f64,
    win_audio_s: f64,
    win_time_s: f64,
    audio_s: f64,
    denom_s: f64,
    trims: u32,
}

impl CddaClock {
    fn new() -> Self {
        Self {
            scale_ppm: 1_000_000,
            prev: None,
            pend_audio_s: 0.0,
            pend_time_s: 0.0,
            win_audio_s: 0.0,
            win_time_s: 0.0,
            audio_s: 0.0,
            denom_s: 0.0,
            trims: 0,
        }
    }

    /// The estimator's current view, committed or not: seconds banked toward
    /// the next window, that window's audio/time rate, the scale in force, and
    /// how many estimates have been made.
    fn progress(&self) -> (f64, f64, u32, u32) {
        let rate = if self.win_time_s > 0.0 {
            self.win_audio_s / self.win_time_s
        } else {
            0.0
        };
        (self.win_time_s, rate, self.scale_ppm, self.trims)
    }

    /// One audio fetch, at the instant it arrived and the LBA it asked for.
    fn note(&mut self, now: Instant, lba: u32) -> Option<CddaTrim> {
        if let Some((pt, plba)) = self.prev {
            let gap = now.saturating_duration_since(pt).as_secs_f64();
            let step = lba.wrapping_sub(plba);
            if gap <= CDDA_TRIM_GAP_MAX && step <= CDDA_TRIM_STEP_MAX {
                self.pend_audio_s += f64::from(step) / 75.0;
                self.pend_time_s += gap;
            } else {
                // The stream was not free-running across this interval: the
                // elapsed time is real and the audio it should answer for was
                // never asked. Drop what is pending and start a fresh segment;
                // the lead the loader owes comes back as a burst, which the
                // test below is what refuses.
                self.pend_audio_s = 0.0;
                self.pend_time_s = 0.0;
            }
        }
        self.prev = Some((now, lba));
        if self.pend_time_s < CDDA_TRIM_SEG_S {
            return None;
        }
        let (pa, pt) = (self.pend_audio_s, self.pend_time_s);
        self.pend_audio_s = 0.0;
        self.pend_time_s = 0.0;
        // THE SEGMENT THAT JUST CLOSED MUST ITSELF LOOK LIKE REAL TIME. A
        // stalled stream is many-fold behind and a catch-up many-fold ahead;
        // dropping both keeps the sums honest.
        if ((pa / pt) - 1.0).abs() > CDDA_TRIM_SEG_SANE {
            return None;
        }
        self.win_audio_s += pa;
        self.win_time_s += pt;

        let want = if self.trims == 0 { CDDA_TRIM_FIRST_S } else { CDDA_TRIM_S };
        if self.win_time_s < want {
            return None;
        }
        let scale = f64::from(self.scale_ppm) / 1e6;
        let rate = self.win_audio_s / self.win_time_s;
        let secs = self.win_time_s;
        // The window's own answer, which is the rate CORRECTED FOR THE SCALE
        // ALREADY IN FORCE -- not the raw rate. Testing the raw rate would
        // deadlock a loader that has already been trimmed: it would look 1 %
        // out forever and never be measured again.
        let est_win = rate * scale;
        if (est_win - 1.0).abs() > CDDA_TRIM_WINDOW_SANE {
            self.win_audio_s = 0.0;
            self.win_time_s = 0.0;
            return Some(CddaTrim::Discarded { secs, ratio: rate });
        }
        self.audio_s += self.win_audio_s;
        self.denom_s += self.win_time_s / scale;
        self.win_audio_s = 0.0;
        self.win_time_s = 0.0;
        self.trims += 1;
        let win_ppm = ((est_win - 1.0) * 1e6).round() as i64;
        let est_ppm = ((self.audio_s / self.denom_s) * 1e6).round() as u32;
        if !CDDA_TRIM_SANE.contains(&est_ppm) {
            return Some(CddaTrim::Refused { est_ppm, secs });
        }
        if est_ppm == self.scale_ppm {
            return Some(CddaTrim::Held { ppm: est_ppm, win_ppm, secs });
        }
        let from = self.scale_ppm;
        self.scale_ppm = est_ppm;
        Some(CddaTrim::Applied { from, to: est_ppm, win_ppm, secs })
    }
}

/// Is the clock trim on? `DCLOAD_CDDA_TRIM=0` turns it off, which leaves the
/// loader on its compiled-in constant -- the A/B for "is the trim helping".
fn cdda_trim() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("DCLOAD_CDDA_TRIM").as_deref(),
            Ok("0") | Ok("false") | Ok("no")
        )
    })
}

/// Packets of one audio answer sent before a short spin that lets the loader's
/// 16 KB RX ring drain, and the length of the spin. An ADPCM answer is two
/// packets and a PCM one five, so at the default geometry this never fires; it
/// guards a larger sub-fetch, because an overrun ring does not degrade
/// gracefully (loader AGENTS.md 4.8).
const AUDIO_BURST_PACKETS: u32 = 8;
const AUDIO_BURST_DELAY: Duration = Duration::from_micros(250);

/// `DCLOAD_CDDA_SAFE=1` sends audio through the fully acknowledged `send_data`
/// path instead of `send_audio`. Read once.
///
/// NOTE: current loaders do not echo the LoadBinary of an audio request, and
/// `send_data` waits for that echo, so against them every audio request times
/// out. It is only useful with a loader built without the echo suppression.
fn cdda_safe() -> bool {
    static SAFE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SAFE.get_or_init(|| {
        matches!(
            std::env::var("DCLOAD_CDDA_SAFE").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    })
}

/// Ring pacing for the runtime path, in ONE place so the sector path and the
/// audio fast path below cannot drift apart. Both feed the same 16 KB RX ring.
///
/// A SHORTER PAUSE TAKEN MORE OFTEN, since 2026-09-20. The defaults were 10
/// packets and 1800 us, which for a 16 KB chunk means exactly one pause fires
/// -- 1.8 ms of the ~5 ms the title spent frozen per chunk, and after the two
/// acknowledgement round trips were removed from `send_sectors` it became the
/// single largest cost left on the path. Six packets is ~9 KB in front of the
/// loader against a 16 KB ring, so it is also the safer of the two, and two
/// 600 us pauses cost a third of one 1800 us pause.
///
/// WHAT IT DEFENDS AGAINST, and why it is not zero: outrunning the ring does
/// not drop a frame, it desyncs CAPR from CBR and the loader receives NOTHING
/// from then on -- a wedge that does not recover.
///
/// THE ACCEPTANCE TEST, before shortening it further (300, then 0): serve a
/// busy session and check `g_cdfs_read_retries`, `g_cdfs_read_holes`,
/// `g_rx_overflow` and `g_rx_missed`.
///
/// MEASURED AT 6/600, 2026-09-20, Crazy Taxi, 2302 chunks: `g_rx_missed` 0 --
/// the chip never dropped a frame for want of ring space, so the pacing is
/// adequate -- but `g_rx_overflow` 3 and `g_rx_resync` 2. **So do not shorten
/// it further.** The ring is being pushed to its back-pressure limit already,
/// and what is left is not congestion the delay can buy off: a resync is the
/// status-word race of AGENTS.md 4.8 rule 4, and it DISCARDS THE QUEUE, which
/// is where both of that session's two lost answers went
/// (`g_cdfs_read_fails` 2 = `g_fine_timeouts` 2, `g_cdfs_read_holes` 0).
fn runtime_pacing() -> (u32, Duration) {
    let n = std::env::var("DCLOAD_RT_BURST")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(6)
        .max(1);
    let us = std::env::var("DCLOAD_RT_DELAY_US")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600);
    (n, Duration::from_micros(us))
}

/// Send an audio answer with no acknowledgement round trips: the LoadBinary and
/// the parts. The caller sends the ReturnValue.
///
/// `send_data_one` waits for the LoadBinary echo and probes with DoneBinary.
/// A disc read needs both (a lost LoadBinary voids the whole window). For audio
/// they cost more than they protect: measured 2026-08-31, they were 2.4 ms of
/// the 3.0 ms each audio request froze the title. A lost packet here makes the
/// loader's window incomplete, which it detects and re-asks for.
///
/// The ReturnValue stays mandatory: it is what releases the loader from
/// `bb->loop()`.
///
/// With `probe` set, a DoneBinary follows the parts and the number of bytes
/// the loader still reports missing is returned (`None` if no answer came in
/// time).
fn send_audio(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    probe: bool,
) -> std::result::Result<Option<u32>, std::boxed::Box<dyn std::error::Error>> {
    // The acknowledged path, switchable without a rebuild (see `cdda_safe` for
    // its limit with current loaders).
    if cdda_safe() {
        send_data(conn, data, address, None)?;
        return Ok(None);
    }
    let (burst_packets, burst_delay) = runtime_pacing();
    // Audio has its own, smaller burst threshold (see AUDIO_BURST_PACKETS).
    let audio_burst = burst_packets.min(AUDIO_BURST_PACKETS);
    let audio_delay = burst_delay.min(AUDIO_BURST_DELAY);
    conn.send_command(DCLoadCmd {
        cmd: DCLoadCmds::LoadBinary(),
        address,
        size: data.len() as u32,
    })?;
    let mut incr_address = address;
    let mut packet_count: u32 = 0;
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
        if packet_count.is_multiple_of(audio_burst) {
            spin_for(audio_delay);
        }
    }
    if !probe {
        return Ok(None);
    }
    // Before the caller's ReturnValue: after it the loader stops listening.
    // One short wait, never `request_donebin`, which can wait seconds with the
    // title frozen. A sample that gets no answer is simply ignored.
    let deadline = Duration::from_millis(20);
    conn.send_command(DCLoadCmd {
        cmd: DCLoadCmds::DoneBinary(),
        address: 0,
        size: 0,
    })?;
    Ok(await_result(conn, Some(deadline))
        .ok()
        .as_deref()
        .and_then(extract_donebin)
        .map(|d| d.size))
}

/// Serve one chunk of a disc read: the LoadBinary, the parts, and nothing else.
/// The caller sends the ReturnValue, which is what releases the loader from
/// `bb->loop()`.
///
/// THE TITLE IS FROZEN FOR EVERY MICROSECOND SPENT IN HERE, so this path buys
/// nothing it does not need. `send_data_one` waits for the LoadBinary echo
/// before sending the parts and probes with DoneBinary after them. Measured on
/// Crazy Taxi, 2026-09-20: a 16 KB chunk took ~5 ms end to end, of which the
/// wire is 1.3 ms, the deliberate pause 1.8 ms, and those two round trips
/// ~1.9 ms. A 73-sector read is ten chunks, so the title stopped rendering for
/// 58 ms at a time, several times a second -- which is what the stutter was.
///
/// What the two round trips bought was the host's only way of noticing a lost
/// packet. The loader notices instead, for free: `cmd_partbin` already keeps a
/// map of the window, so `bin_window_complete()` answers at no network cost,
/// and a chunk with a hole is failed and asked for again (`g_cdfs_read_holes`,
/// then `g_cdfs_read_retries`). That is one extra round trip on a loss instead
/// of two on every chunk -- and across that session there were no losses to
/// catch: `g_rx_missed`, `g_rx_overflow`, `g_pbin_rejected` and
/// `g_cdfs_read_retries` were all 0 over 4000 chunks.
///
/// THIS NEEDS A LOADER THAT CHECKS ITS OWN WINDOW. An older one accepts the
/// ReturnValue as proof of completion and would hand the title short data
/// silently. There is no feature bit for it; what keeps the two in step is that
/// the host chainloads its own loader from `loaders/` for every disc image, so
/// that directory must be redeployed with this change (AGENTS.md 14.19).
fn send_sectors(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
) -> std::result::Result<(), std::boxed::Box<dyn std::error::Error>> {
    // ONE WINDOW, OR THE LOADER'S CHECK CANNOT SPEAK FOR THE WHOLE TRANSFER.
    //
    // `bin_window_complete()` judges the window that is installed, so a payload
    // split across several LoadBinary windows would be judged on its last one
    // and the earlier ones would go unchecked. A chunk is GD_EMU_ASYNC sectors
    // (16 KB today), far inside MAX_XFER, so this cannot fire as the loader is
    // built -- but GD_BULK_SECTORS would send a whole 100-sector read in one
    // call, and then the acknowledged path is the correct one.
    if data.len() > MAX_XFER {
        send_data(conn, data, address, None)?;
        return Ok(());
    }
    let (burst_packets, burst_delay) = runtime_pacing();
    conn.send_command(DCLoadCmd {
        cmd: DCLoadCmds::LoadBinary(),
        address,
        size: data.len() as u32,
    })?;
    // LET THE WINDOW BE INSTALLED BEFORE THE FIRST PART.
    //
    // `cmd_loadbin` is not a cheap handler: it zeroes the part map and purges
    // the cache over the WHOLE destination range -- 512 cache blocks for a
    // 16 KB chunk. Waiting for the echo used to cover that work by accident,
    // which is the one thing it did for the loader rather than for us, and
    // dropping the wait without replacing it put the first parts on the wire
    // while the loader was still purging. That is a ring overflow, and an
    // overflow does not cost one part: the ring is drained or re-initialised
    // and the whole answer is gone, after which the loader has nothing to do
    // but wait out its deadline (measured on Crazy Taxi, 2026-09-20: 7.0 s,
    // the coarse backstop, because TMU2 was not running either).
    //
    // One pause, not a round trip: it costs what it costs whatever the loader
    // is doing, and it cannot deadlock.
    //
    // SCALED TO THE WINDOW (2026-09-27). The purge it covers is one cache
    // block per 32 bytes of the window, and the full pause was sized for the
    // 16 KB chunk of a Katana title. A Windows CE title reads through the
    // loader's staging buffer, 6-10 KB a round trip, hundreds of trips for
    // one file, and the title waits for all of them (dcload-ip:
    // docs/wince-investigation.md 7u): a fixed 600 us was a third of each
    // trip. Never below 100 us.
    let scaled = burst_delay.mul_f64((data.len() as f64 / 16384.0).min(1.0));
    spin_for(scaled.max(Duration::from_micros(100)));
    let mut incr_address = address;
    let mut packet_count: u32 = 0;
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
        // The burst still has to fit the loader's 16 KB RX ring. With the two
        // round trips gone this pause is the largest remaining cost on the
        // path; the acceptance test for shortening it is in `runtime_pacing`.
        if packet_count.is_multiple_of(burst_packets) {
            spin_for(burst_delay);
        }
    }
    Ok(())
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
        //   DCLOAD_RT_BURST     packets per pause (default 10)
        //   DCLOAD_RT_DELAY_US  pause length, microseconds (default 1800)
        //
        // THE DEFAULTS ARE THE DOMINANT COST ON THIS PATH, so know what they
        // buy before raising them and what they cost before leaving them. A
        // 16 KB read is 12 packets, so exactly ONE pause fires, at packet 10 --
        // 1800 us of deliberate idling per chunk with the title frozen for all
        // of it. Measured 2026-08-31 on Snow Surfers at 153 chunks/s: 276 ms
        // per second, 27.6 % of wall time, spent waiting on purpose.
        //
        // What it buys is ring headroom: 10 packets back to back is ~15 KB into
        // a 16 KB ring, which is the edge. A SHORTER pause taken MORE OFTEN is
        // both safer and cheaper -- DCLOAD_RT_BURST=6 never puts more than
        // ~9 KB in front of the DC and two 600 us pauses still cost a third of
        // one 1800 us pause. Tune with g_cdfs_read_retries, g_rx_overflow and
        // the "resending missing parts" warning as the acceptance test; if
        // those stay at zero the pacing is not doing anything.
        //
        // A CD-DA fetch is 5 packets, so it never reaches the burst and pays
        // none of this -- which is why the audio path's cost is round trips and
        // G2 stores, not pacing.
        runtime_pacing()
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

pub(crate) fn await_result(
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

/// Is this SendBinary chunk an answer to THIS read?
///
/// A STALE ANSWER FROM AN EARLIER READ IS INDISTINGUISHABLE BY ADDRESS ALONE,
/// and that is not a theoretical worry. `measure_rtt()` reads four bytes at the
/// loader's base five times over, and `diag::verify_image()` then reads the
/// whole first segment from the SAME address: a straggler from the first
/// arrives as a perfectly in-range chunk at offset 0, writes four bytes, marks
/// the entire 1440-byte slot present -- and the other 1436 bytes stay zero.
///
/// Measured 2026-09-04 on Snow Surfers: `--diag` refused to start because the
/// console "differed" from the ELF at base+4, reading 0x00 where the image
/// carries the 0xdeadbeef magic. The loader was correct and the counters were
/// there; the READ was wrong, and it reported that as a wrong build -- the one
/// failure mode this check exists to catch, produced by the check itself.
///
/// The length is what tells them apart, because this read expects exactly
/// `min(CHUNK_SIZE, size - offset)` bytes at each chunk boundary and anything
/// else was cut to somebody else's request. The offset must land on a boundary
/// too: `chunk_map` is indexed by `offset / CHUNK_SIZE`, so an unaligned chunk
/// would mark a slot it does not fill.
///
/// `chunk_len` IS THE COMMAND'S `size` FIELD, NOT `chunk.len()`. The payload is
/// carried as a fixed `Box<[u8; CHUNK_SIZE]>`, so `chunk.len()` is 1440 for
/// every packet ever received and tells you nothing -- which is also why the
/// copy below has to clamp with `.min(size)`. dcload sends
/// `bytes_thistime = min(1440, bytes_left)` and puts it in `size`
/// (`commands.c`, `cmd_sendbinq`), so that field is exact.
fn chunk_is_ours(address: u32, size: usize, chunk_addr: u32, chunk_len: usize) -> bool {
    if chunk_addr < address {
        return false;
    }
    let offset = (chunk_addr - address) as usize;
    offset < size
        && offset.is_multiple_of(CHUNK_SIZE)
        && chunk_len == CHUNK_SIZE.min(size - offset)
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

    // PATIENCE, NOT A PACKET COUNT. This used to be `for _ in 0..expected_chunks`,
    // so a batch carrying nothing but somebody else's leftovers burned one of
    // this read's expected chunks -- and one straggler therefore shifted every
    // subsequent read one answer out of phase, each one re-requesting in
    // recovery and leaving a fresh duplicate behind it for the next. Measured
    // 2026-09-04: a single stray packet from the PPF patch verification
    // propagated through all five of measure_rtt()'s reads and ended up
    // corrupting verify_image()'s, which is what disabled --diag. The budget is
    // what keeps a silent console bounded; STRAGGLER_BUDGET is the slack.
    const STRAGGLER_BUDGET: usize = 8;
    let mut budget = expected_chunks + STRAGGLER_BUDGET;
    let mut saw_done = false;
    while budget > 0 && !saw_done && chunk_map.iter().any(|received| !received) {
        budget -= 1;
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
                                //
                                // The length half is chunk_is_ours(); read it there.
                                if !chunk_is_ours(
                                    address,
                                    size,
                                    inner_cmd.address,
                                    inner_cmd.size as usize,
                                ) {
                                    warn!(
                                        "chunk at 0x{:08x}+{} is not an answer to the \
                                         read-back of 0x{:08x}+{}, ignoring",
                                        inner_cmd.address, inner_cmd.size, address, size
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
                            DCLoadCmds::DoneBinary() => {
                                saw_done = true;
                                break;
                            }
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

    // AND THIS LOOP NEEDS THE SAME BUDGET THE ONE ABOVE HAS.
    //
    // It had none: it re-requested every missing chunk and repeated until the
    // map was full, so a console that answers NOTHING turned it into an
    // unbounded SendBinQ flood -- thousands a second, logging "Missing chunk 0"
    // for each. Two consequences, and the second is the serious one: the
    // Dreamcast is buried in requests it must answer from inside bb->loop(),
    // and this host is single-threaded, so while it spins here **it never
    // serves another disc read** and the title freezes for good.
    //
    // Measured 2026-09-20 on Crazy Taxi. The trigger was a 30-byte read: the
    // loader's failed-chunk trace calls write(), and a write is fetched back
    // off the console with SendBinQ (fs.rs, download_data) -- so a failing
    // disc read produced an instrument read that could not be answered either,
    // and that is what wedged the tool. The loader no longer emits that trace
    // (cdfs_syscalls.c), but an instrument must not be able to do this
    // whatever asks for it.
    //
    // A read that cannot be completed is a FAILED READ. Every caller here
    // treats the Err (--diag skips the sample, the read-back verification
    // warns), and all of them are better off than frozen. AGENTS.md 14.9: the
    // first loop's budget was proof this could happen, and it guarded one loop
    // out of two.
    const REPAIR_PASSES: usize = 4;
    let mut passes = REPAIR_PASSES;
    loop {
        if passes == 0 {
            let missing = chunk_map.iter().filter(|&&r| !r).count();
            return Err(Box::new(std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "read-back of 0x{address:08x}+{size} never completed: {missing} of \
                     {expected_chunks} chunks still missing after {REPAIR_PASSES} repair \
                     passes. The console is not answering; giving up rather than \
                     re-requesting forever."
                ),
            )));
        }
        passes -= 1;
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
                                        if !chunk_is_ours(
                                            address,
                                            size,
                                            inner_cmd.address,
                                            inner_cmd.size as usize,
                                        ) {
                                            warn!(
                                                "chunk at 0x{:08x}+{} is not an answer to \
                                                 the re-request of 0x{:08x}+{}, ignoring",
                                                inner_cmd.address, inner_cmd.size, address, size
                                            );
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
                                                            // The first answer to this chunk,
                                                            // late: it is what made the chunk
                                                            // look missing, and the re-request
                                                            // has just answered it again.
                                                            DCLoadCmds::SendBinary(Some(_))
                                                                if chunk_is_ours(
                                                                    address,
                                                                    size,
                                                                    inner_cmd.address,
                                                                    inner_cmd.size as usize,
                                                                ) =>
                                                            {
                                                                debug!(
                                                                    "duplicate answer for 0x{:08x}+{} ignored",
                                                                    inner_cmd.address, inner_cmd.size
                                                                );
                                                            }
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

    /// The scan reports nothing on the clean test tone (whose steps are exactly
    /// 512 and 1024) and does register foreign full-scale bytes as a run.
    #[test]
    fn the_continuity_check_is_silent_on_a_clean_signal_and_not_on_a_splice() {
        let mut clean = SlewWatch::new();
        for lba in 1000..1010 {
            clean.scan(lba, &tone_sectors(lba, 1));
        }
        assert_eq!(clean.runs, 0, "the triangle is continuous by construction");
        assert_eq!(clean.hits, 0);
        assert_eq!(clean.max, 1024, "the right ear's step, and the larger one");

        // Not a phase jump inside the tone: it only reaches +/-16384, so such a
        // jump stays under LIMIT. Insert full-scale foreign bytes instead.
        let mut spliced = SlewWatch::new();
        let mut bad = tone_sectors(1000, 1);
        for (k, f) in bad.chunks_exact_mut(4).skip(300).take(6).enumerate() {
            let v: i16 = if k % 2 == 0 { i16::MAX } else { i16::MIN };
            f[0..2].copy_from_slice(&v.to_le_bytes());
            f[2..4].copy_from_slice(&v.to_le_bytes());
        }
        spliced.scan(1000, &bad);
        assert!(spliced.runs > 0, "foreign bytes have to register as a run");
        assert_eq!(spliced.first.map(|(l, _)| l), Some(1000));
    }

    /// A tone sector depends on its LBA alone: requests join without a seam
    /// and a re-asked sector is byte-identical.
    #[test]
    fn the_served_tone_is_continuous_and_repeatable() {
        let two = tone_sectors(1000, 2);
        assert_eq!(two.len(), 2 * RAW_SECTOR_SIZE);
        assert_eq!(tone_sectors(1000, 1), two[..RAW_SECTOR_SIZE]);
        assert_eq!(tone_sectors(1001, 1), two[RAW_SECTOR_SIZE..]);
        // ...and it is actually a signal, not a constant.
        assert!(two.chunks_exact(2).any(|w| w != &two[0..2]));
    }

    /// The exact shape that disabled `--diag` on 2026-09-04.
    ///
    /// `measure_rtt()` reads four bytes at the loader base; `verify_image()`
    /// then reads the whole first segment from that same address. A straggler
    /// from the first is in range for the second, lands on chunk boundary 0,
    /// and used to fill four bytes while marking all 1440 present -- so the
    /// comparison read 0x00 where the image carries the 0xdeadbeef magic and
    /// reported a perfectly good loader as the wrong build.
    #[test]
    fn a_four_byte_answer_is_not_a_chunk_of_a_long_read() {
        let base = 0x8ce0_0000;
        assert!(!chunk_is_ours(base, 27212, base, 4));
        // ...while the real chunks of that read all are.
        assert!(chunk_is_ours(base, 27212, base, CHUNK_SIZE));
        assert!(chunk_is_ours(base, 27212, base + CHUNK_SIZE as u32, CHUNK_SIZE));
        // 27212 = 18 * 1440 + 1292: the short tail is served short, not padded
        // (`bytes_thistime = min(1440, bytes_left)` in cmd_sendbinq).
        assert!(chunk_is_ours(base, 27212, base + 18 * CHUNK_SIZE as u32, 1292));
        assert!(!chunk_is_ours(base, 27212, base + 18 * CHUNK_SIZE as u32, CHUNK_SIZE));
        // And the four-byte read is still able to accept its own answer.
        assert!(chunk_is_ours(base, 4, base, 4));
    }

    #[test]
    fn a_chunk_off_the_boundary_or_out_of_range_is_refused() {
        let base = 0x8ce0_0000;
        // chunk_map is indexed by offset / CHUNK_SIZE, so an unaligned offset
        // would mark a slot it does not fill.
        assert!(!chunk_is_ours(base, 27212, base + 8, CHUNK_SIZE));
        assert!(!chunk_is_ours(base, 27212, base - 4, CHUNK_SIZE));
        assert!(!chunk_is_ours(base, 27212, base + 27212, CHUNK_SIZE));
    }

    /// Every packet `send_audio` puts on the wire, in order.
    struct Wire(std::cell::RefCell<Vec<(String, u32, u32)>>);

    impl ExternalDcIo for Wire {
        fn poll(&self, _t: Option<Duration>) -> Result<polling::Events, std::io::Error> {
            Ok(polling::Events::new())
        }
        fn handle_data(
            &mut self,
            _e: &polling::Events,
        ) -> Result<Vec<DCReturnCmd>, std::io::Error> {
            Ok(Vec::new())
        }
        fn send_command(
            &self,
            c: DCLoadCmd,
        ) -> Result<usize, Box<dyn std::error::Error>> {
            let name = match c.cmd {
                DCLoadCmds::LoadBinary() => "LBIN",
                DCLoadCmds::PartBinary(_) => "PBIN",
                DCLoadCmds::DoneBinary() => "DBIN",
                DCLoadCmds::ReturnValue() => "RETV",
                _ => "other",
            };
            self.0.borrow_mut().push((name.to_string(), c.address, c.size));
            Ok(0)
        }
    }

    /// What `send_audio` puts on the wire for an ADPCM answer (2352 bytes): one
    /// LoadBinary covering the whole answer, then two parts, and nothing else.
    #[test]
    fn an_audio_fetch_is_one_loadbin_two_parts_and_a_returnvalue() {
        let w = Wire(std::cell::RefCell::new(Vec::new()));
        // The ADPCM fetch: 4 sectors, one byte per stereo frame.
        let buf = vec![0x80u8; 2352];
        send_audio(&mut { w }, &buf, 0x8ce0_cc00, false).unwrap();
        // `send_audio` took the value; rebuild to inspect. (Kept simple: the
        // assertions below run on a second, identical call.)
        let w2 = Wire(std::cell::RefCell::new(Vec::new()));
        let mut w2 = w2;
        send_audio(&mut w2, &buf, 0x8ce0_cc00, false).unwrap();
        let sent = w2.0.borrow().clone();

        let names: Vec<&str> = sent.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(
            names,
            vec!["LBIN", "PBIN", "PBIN"],
            "send_audio put this on the wire: {sent:?}"
        );
        assert_eq!(sent[0].2, 2352, "the LoadBinary must open the whole window");
        assert_eq!(sent[1].1, 0x8ce0_cc00);
        assert_eq!(sent[1].2, CHUNK_SIZE as u32);
        assert_eq!(sent[2].1, 0x8ce0_cc00 + CHUNK_SIZE as u32);
        assert_eq!(sent[2].2, 2352 - CHUNK_SIZE as u32);
    }

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

    use super::constant_range_fills;

    /// The Katana crt0's first loop: r5 = hi, r6 = "SEGA", r4 = lo, then
    /// `mov.l r6,@r4; add #4,r4; cmp/hs r5,r4; bf`. `between` goes after the
    /// loads, to break the contiguity the scan relies on.
    fn stack_paint(lo: u32, hi: u32, cmp: u16, between: Option<u16>) -> Vec<u8> {
        let loop_at = if between.is_some() { 0x108 } else { 0x106 };
        let mut ops = vec![
            mov_l_pc(0x100, 0x208, 5),
            mov_l_pc(0x102, 0x204, 6),
            mov_l_pc(0x104, 0x200, 4),
            (loop_at, 0x2462),
            (loop_at + 2, 0x7404),
            (loop_at + 4, cmp),
            (loop_at + 6, 0x8bfb),
        ];
        if let Some(op) = between {
            ops.push((0x106, op));
        }
        raw_ops(0x1000, &[(0x200, lo), (0x204, 0x4147_4553), (0x208, hi)], &ops)
    }

    #[test]
    fn the_katana_stack_paint_is_found() {
        let p = stack_paint(0x8c00_c000, 0x8c00_f400, 0x3452, None);
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c00_c000, 0x8c00_f400, 0x8c01_0106)]);
    }

    #[test]
    fn an_inclusive_bound_covers_the_last_store() {
        // cmp/hi keeps looping while Rp <= Rend, so the store AT hi happens.
        let p = stack_paint(0x8c00_c000, 0x8c00_f3fc, 0x3456, None);
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c00_c000, 0x8c00_f400, 0x8c01_0106)]);
    }

    #[test]
    fn a_bound_read_through_a_pointer_is_not_a_range() {
        // `mov.l @r4,r4`: the literal is where the bound is kept, which is how
        // every crt0 measured clears its .bss. Reporting it would name the
        // variable's address as a range the title writes.
        let p = stack_paint(0x8c00_c000, 0x8c00_f400, 0x3452, Some(0x6442));
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert!(got.is_empty(), "reported a range held in a variable: {got:?}");
    }

    #[test]
    fn a_fill_outside_ram_is_ignored() {
        // Hardware registers are filled the same way, and are nobody's loader.
        let p = stack_paint(0xa05f_8000, 0xa05f_8100, 0x3452, None);
        let got = constant_range_fills(&p, 0x0c01_0000);
        assert!(got.is_empty(), "reported a fill of hardware registers: {got:?}");
    }
    use super::{PDTRA, declare_vga_in_ip_bin, ip_bin_peripherals, vga_cable_patches};

    /// The cable check every Katana title measured carries, byte for byte --
    /// the literal, the load that reads it, and the `mov.w @r3,r4` that reads
    /// the port. `at` only has to be 2-aligned, which is all an instruction is.
    fn cable_check(len: usize, at: usize) -> Vec<u8> {
        let pool = ((at + 4) & !3) + 12;
        let (_, load) = mov_l_pc(at, pool, 3);
        raw_ops(
            len,
            &[(pool, PDTRA)],
            &[
                (at, load),        // mov.l  @(3,PC),r3
                (at + 2, 0x9203),  // mov.w  @(3,PC),r2   ; 0x0300
                (at + 4, 0x6431),  // mov.w  @r3,r4
                (at + 6, 0x604d),  // extu.w r4,r0
                (at + 8, 0x000b),  // rts
                (at + 10, 0x2029), // and    r2,r0
            ],
        )
    }

    #[test]
    fn the_cable_read_becomes_mov_zero() {
        // The read is at 0x104, the low half of its word: `mov.w @r3,r4`
        // (0x6431) becomes `mov #0,r4` (0xe400) and `extu.w r4,r0` above it is
        // left exactly as it was.
        let p = cable_check(0x1000, 0x100);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c01_0104, 0x604d_e400)]);
    }

    #[test]
    fn a_read_in_the_high_half_of_a_word_keeps_the_low_one() {
        // The same routine two bytes along, so the instruction to replace is
        // the second one in its word. Getting this backwards would rewrite the
        // wrong instruction and still report a verified patch.
        let p = cable_check(0x1000, 0x102);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert_eq!(got, vec![(0x8c01_0104, 0xe400_9203)]);
    }

    #[test]
    fn a_port_address_nothing_loads_is_left_alone() {
        // 0xff800030 as a plain number in data. Without this the scan would
        // patch whatever instruction happened to follow it.
        let p = raw(0x1000, &[(0x200, PDTRA)]);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched on the literal alone: {got:?}");
    }

    #[test]
    fn a_load_with_no_read_after_it_patches_nothing() {
        // A shape this host does not recognise must come back empty -- and
        // say so, which is the whole point: a title that was never patched and
        // a title that ignored the patch look identical afterwards.
        let pool = 0x110;
        let p = raw_ops(0x1000, &[(pool, PDTRA)], &[mov_l_pc(0x100, pool, 3)]);
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched without finding the read: {got:?}");
    }

    #[test]
    fn the_read_must_use_the_register_the_address_went_into() {
        // Same routine, but the read is of r5 -- another pointer entirely.
        let mut p = cable_check(0x1000, 0x100);
        p[0x104..0x106].copy_from_slice(&0x6451u16.to_le_bytes()); // mov.w @r5,r4
        let got = vga_cable_patches(&p, 0x0c01_0000);
        assert!(got.is_empty(), "patched a read of another register: {got:?}");
    }

    /// An IP.BIN header whose peripheral field reads `text`.
    fn header_with(text: &[u8]) -> Vec<u8> {
        let mut h = vec![b' '; 0x100];
        h[..16].copy_from_slice(b"SEGA SEGAKATANA ");
        h[0x38..0x38 + text.len()].copy_from_slice(text);
        h
    }

    #[test]
    fn the_vga_bit_is_set_and_the_field_keeps_its_width() {
        // Snow Surfers' field, the one title of the four measured that does
        // not declare VGA support.
        let mut h = header_with(b"0799A00");
        assert_eq!(declare_vga_in_ip_bin(&mut h), Some((0x0079_9A00, 0x0079_9A10)));
        assert_eq!(&h[0x38..0x40], b"0799A10 ");
    }

    #[test]
    fn a_title_that_already_declares_vga_is_unchanged() {
        // Sonic Adventure's field. Setting a bit that is set must not rewrite
        // the field into a different spelling of the same number.
        let mut h = header_with(b"0601A10");
        let before = h[0x38..0x40].to_vec();
        assert_eq!(declare_vga_in_ip_bin(&mut h), Some((0x0060_1A10, 0x0060_1A10)));
        assert_eq!(h[0x38..0x40], before[..]);
    }

    #[test]
    fn a_field_that_is_not_hex_is_refused() {
        let mut h = header_with(b"NOT HEX");
        assert_eq!(ip_bin_peripherals(&h), None);
        assert_eq!(declare_vga_in_ip_bin(&mut h), None);
        assert_eq!(&h[0x38..0x40], b"NOT HEX ");
    }

    /// Four sectors to a sub-fetch in ADPCM.
    const TEST_SECTORS: u32 = 4;
    /// The audio in one sub-fetch: what a correct model takes to play it, and
    /// so the period a paced loader asks for the next one at.
    fn fetch_audio_s() -> f64 {
        f64::from(TEST_SECTORS) / 75.0
    }

    /// Feed a free-running stream shaped like the loader's: one sub-fetch every
    /// `period_s` of real time, which is `fetch_audio_s()` when the loader's
    /// clock is right and longer when it runs slow.
    ///
    /// Keep this in step with the loader's geometry: when it modelled an old
    /// 80 ms half, every test passed on an estimator that accepted nothing on
    /// the console.
    fn feed_stream(clock: &mut CddaClock, fetches: u32, period_s: f64) -> Vec<CddaTrim> {
        feed_from(clock, Instant::now(), 1000, fetches, period_s).0
    }

    /// The same, from a given instant and LBA, returning where it got to.
    fn feed_from(
        clock: &mut CddaClock,
        base: Instant,
        first_lba: u32,
        fetches: u32,
        period_s: f64,
    ) -> (Vec<CddaTrim>, Instant, u32) {
        let mut out = Vec::new();
        let mut lba = first_lba;
        let mut at = base;
        for _ in 0..fetches {
            if let Some(step) = clock.note(at, lba) {
                out.push(step);
            }
            lba += TEST_SECTORS;
            at += Duration::from_secs_f64(period_s);
        }
        (out, at, lba)
    }

    /// The estimator accepts time at all on the stream shape the console
    /// produces (it once banked 0 s after minutes of play).
    #[test]
    fn a_free_running_stream_banks_time_at_all() {
        let mut clock = CddaClock::new();
        feed_stream(&mut clock, 280, fetch_audio_s());
        let (banked, rate, _, _) = clock.progress();
        assert!(banked > 10.0, "banked only {banked}s of a 14.9 s stream");
        assert!((rate - 1.0).abs() < 0.001, "and it must read ~1.0, got {rate}");
    }

    /// And the guard that replaces what GAP_MAX used to do for stalls: a stream
    /// whose every gap is short enough to be accepted, but which takes half
    /// again as long as the audio it carries, is not a clock measurement.
    #[test]
    fn a_segment_that_took_too_long_is_not_banked() {
        let mut clock = CddaClock::new();
        // 80 ms of wall for 53 ms of audio: every gap is well inside
        // CDDA_TRIM_GAP_MAX, so only CDDA_TRIM_SEG_SANE can refuse it.
        feed_stream(&mut clock, 280, fetch_audio_s() * 1.5);
        let (banked, _, _, trims) = clock.progress();
        assert_eq!(banked, 0.0, "a stretched segment was banked");
        assert_eq!(trims, 0);
        assert_eq!(clock.scale_ppm, 1_000_000);
    }

    /// THE BIAS THE SEGMENT TEST EXISTS FOR. A gap past `CDDA_TRIM_GAP_MAX` is
    /// dropped, but the audio it owes is not lost: the loader is behind by up
    /// to its lead and asks for it as fast as the title lets it. Counted, that
    /// burst is free audio against no elapsed time -- 890 ms of it, which is
    /// 3000 ppm over a 300 s window, ten times the error being resolved.
    #[test]
    fn the_catch_up_after_a_long_gap_is_not_free_audio() {
        let mut clock = CddaClock::new();
        let base = Instant::now();
        let (_, at, lba) = feed_from(&mut clock, base, 1000, 200, fetch_audio_s());
        // The loader is kept off the ring for 3 s, then wins its lead back:
        // 17 sub-fetches at the rate a service call can place them.
        let at = at + Duration::from_secs_f64(3.0);
        let (_, at, lba) = feed_from(&mut clock, at, lba, 17, 0.008);
        let (_, _, _) = feed_from(&mut clock, at, lba, 200, fetch_audio_s());
        let (banked, rate, _, _) = clock.progress();
        assert!(banked > 15.0, "the whole stream was thrown away ({banked}s)");
        assert!(
            (rate - 1.0).abs() < 0.005,
            "the catch-up dragged the rate to {rate}"
        );
    }

    /// But an ordinary service stall -- the title not calling the GD driver for
    /// a few hundred ms -- is inside GAP_MAX, so its deficit AND the catch-up
    /// that answers it are both counted, and they cancel. Dropping those would
    /// throw away most of a real session.
    #[test]
    fn a_short_service_stall_still_banks_its_time() {
        let mut clock = CddaClock::new();
        let base = Instant::now();
        let (_, at, lba) = feed_from(&mut clock, base, 1000, 100, fetch_audio_s());
        let at = at + Duration::from_secs_f64(0.30);
        let (_, at, lba) = feed_from(&mut clock, at, lba, 6, 0.008);
        feed_from(&mut clock, at, lba, 200, fetch_audio_s());
        let (banked, rate, _, _) = clock.progress();
        assert!(
            banked > 15.0,
            "a 300 ms stall cost more than one segment of a 16.3 s stream ({banked}s)"
        );
        assert!((rate - 1.0).abs() < 0.005, "rate {rate}");
    }

    #[test]
    fn the_clock_measures_a_model_that_runs_slow() {
        // 0.3 % slow: one half of audio staged every half/0.997 of real time.
        let mut clock = CddaClock::new();
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s() / 0.997);
        let first = steps.first().expect("a long stream must produce a decision");
        match *first {
            CddaTrim::Applied { from, to, .. } => {
                assert_eq!(from, 1_000_000);
                assert!(
                    (996_800..=997_200).contains(&to),
                    "measured {to} ppm, wanted 997000"
                );
            }
            ref other => panic!("expected a trim, got {other:?}"),
        }
        assert_eq!(clock.scale_ppm, 997_000, "and it is what goes back to the loader");
    }

    #[test]
    fn a_model_that_is_already_right_is_left_alone() {
        let mut clock = CddaClock::new();
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s());
        assert!(
            matches!(steps.first(), Some(CddaTrim::Held { ppm: 1_000_000, .. })),
            "got {steps:?}"
        );
    }

    /// THE DEFECT THIS EXISTS FOR. While a title loads, the loader stops
    /// servicing the ring on time and the stream falls behind real time -- 250
    /// fetches in 37 s instead of 9 was measured on a real boot. Read as a clock
    /// that says 25 % slow, and it drove the trim to its clamp.
    #[test]
    fn a_loading_stall_is_not_a_clock_measurement() {
        let mut clock = CddaClock::new();
        // Four times behind real time, without a single gap past GAP_MAX.
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s() * 4.0);
        assert!(steps.is_empty(), "a stalled stream decided something: {steps:?}");
        assert_eq!(clock.scale_ppm, 1_000_000);
    }

    /// A sub-fetch that missed its deadline is re-asked at the same LBA. Counted
    /// as audio it is 1.5 % of error against the 0.03 % being resolved.
    #[test]
    fn a_re_asked_sub_fetch_is_not_audio() {
        let mut clock = CddaClock::new();
        let base = Instant::now();
        clock.note(base, 1000);
        clock.note(base + Duration::from_millis(2), 1000);
        assert_eq!(clock.pend_audio_s, 0.0);
        assert!(clock.pend_time_s > 0.0, "but the time it took still counts");
    }

    /// POSITIVE CONTROL FOR THE DISCONTINUITY DUMP, which printed nothing at all
    /// for five sessions. The hit is placed deliberately past frame 588 --
    /// a quarter of a 2352-frame request -- because that is where the old code,
    /// indexing a PCM frame number into the ADPCM payload, clamped its slice to
    /// empty. An instrument that prints an empty field looks like an instrument
    /// that found nothing.
    #[test]
    fn the_discontinuity_dump_is_not_empty_past_the_adpcm_length() {
        let mut pcm = vec![0u8; 2352 * 4];
        // A full-scale flip at frame 1200: two samples no acoustic signal joins.
        let at = 1200 * 4;
        pcm[at..at + 4].copy_from_slice(&[0x00, 0x80, 0x00, 0x80]);
        pcm[at + 4..at + 8].copy_from_slice(&[0xff, 0x7f, 0xff, 0x7f]);
        pcm[at + 8..at + 12].copy_from_slice(&[0x00, 0x80, 0x00, 0x80]);
        let mut slew = SlewWatch::new();
        slew.scan(0x0004_e6ce, &pcm);
        assert!(slew.runs > 0, "the control did not trip the scan at all");
        let (lba, frame) = slew.first.expect("a run must record where it was");
        assert_eq!(lba, 0x0004_e6ce);
        assert!(frame > 588, "place the hit past the ADPCM length, got {frame}");
        assert_eq!(
            slew.first_bytes.len(),
            32,
            "the dump came back empty or short -- the exact defect this is for"
        );
    }

    /// An answer further out than any pair of crystals can be is a broken
    /// measurement, and applying one is worse than applying nothing.
    #[test]
    fn an_impossible_answer_is_refused() {
        let mut clock = CddaClock::new();
        // 2.5 % slow: inside the window's own sanity test, outside the range a
        // clock can occupy.
        let steps = feed_stream(&mut clock, 1800, fetch_audio_s() / 0.975);
        assert!(
            matches!(steps.first(), Some(CddaTrim::Refused { .. })),
            "got {steps:?}"
        );
        assert_eq!(clock.scale_ppm, 1_000_000, "and nothing moved");
    }
}

#[cfg(test)]
mod gd_body_tests {
    use super::gd_body_patches;

    #[test]
    fn direct_driver_calls_are_redirected_and_keep_their_segment() {
        let mut p = vec![0u8; 64];
        p[8..12].copy_from_slice(&0x8c00_10f0u32.to_le_bytes());
        p[20..24].copy_from_slice(&0xac00_10f0u32.to_le_bytes());
        // Not word-aligned: two halfwords of code, not a literal pool entry.
        p[34..38].copy_from_slice(&0x8c00_10f0u32.to_le_bytes());
        let got = gd_body_patches(&p, 0x0c01_0000, 0x8c8a_4400);
        assert_eq!(got, vec![(0x8c01_0008, 0x8c8a_4400), (0x8c01_0014, 0xac8a_4400)]);
    }

    #[test]
    fn a_title_without_the_literal_is_left_alone() {
        let mut p = vec![0u8; 64];
        p[8..12].copy_from_slice(&0x8c00_00bcu32.to_le_bytes());
        assert!(gd_body_patches(&p, 0x0c01_0000, 0x8c8a_4400).is_empty());
    }
}
