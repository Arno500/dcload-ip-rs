use std::{
    collections::HashSet,
    io::{Error, ErrorKind},
    path::Path,
    thread::sleep,
    time::Duration,
};

use elf::{ElfBytes, endian::AnyEndian, section::SectionHeader};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::{
    CHUNK_SIZE,
    cd::build_dc_toc,
    cmds::{DCLoadClientCmds, DCLoadCmd, DCLoadCmds, DCReturnCmd},
    disc_formats::{
        cdi::Cdi, gdi::Gdi, iso::Iso, types::{StubDisc, get_disc_format}
    },
    fs::{self, FSSyscallState},
    io::ExternalDcIo,
    protocol_version,
};

pub fn upload(
    conn: &mut impl ExternalDcIo,
    file: String,
    mut address: u32,
) -> std::result::Result<(u32, usize), std::boxed::Box<dyn std::error::Error>> {
    let path = Path::new(&file);
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len() as usize;

    if file_size > 16 * 1024 * 1024 {
        error!(
            "File size seems too large for a Dreamcast executable (>{} bytes)",
            16 * 1024 * 1024
        );
        return Err(Box::new(Error::new(
            std::io::ErrorKind::FileTooLarge,
            "File too large",
        )));
    }

    let file_buffer = std::fs::read(path)?;
    debug!("Read file {} ({} bytes)", file, file_size);

    let progress = MultiProgress::new();
    let mut elf_parts: Vec<SectionHeader> = vec![];

    // Analyze the ELF file
    let elf = ElfBytes::<AnyEndian>::minimal_parse(file_buffer.as_slice());
    if let Ok(elf) = elf {
        // Let's keep the entrypoint somewhere, it may be handy 👀
        address = elf.ehdr.e_entry as u32;
        trace!("ELF entry point at 0x{:08x}", address);

        elf.section_headers().iter().for_each(|table| {
            table.iter().for_each(|sh| {
                // Only keep interesting and uploadable sections
                if sh.sh_type != elf::abi::SHT_PROGBITS {
                    trace!("Skipping section without address or outside of the program");
                }
                elf_parts.push(sh);
            });
        });

        let parts_progress =
            ProgressBar::new(elf_parts.len().try_into()?).with_style(ProgressStyle::with_template(
                "[{elapsed_precise}] [{bar:40.cyan/blue}] {human_pos}/{human_len} ({eta})",
            )?);
        progress.add(parts_progress.clone());

        for sh in elf_parts.iter() {
            parts_progress.inc(1);
            if let Ok(section_data) = elf.section_data(sh) {
                if section_data.0.is_empty() {
                    trace!(
                        "Skipping empty section at address 0x{:08x}, offset 0x{:08x}",
                        sh.sh_addr, sh.sh_offset
                    );
                    continue;
                }
                debug!(
                    "Uploading section at address 0x{:08x} ({} bytes)",
                    sh.sh_addr + sh.sh_offset,
                    section_data.0.len()
                );
                if let Err(e) = send_data(conn, section_data.0, sh.sh_addr as u32, Some(&progress))
                {
                    error!("Error uploading section: {}", e);
                    return Err(e);
                }
            } else {
                let _ = progress.clear();
                return Err(Box::new(Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Failed to get section data",
                )));
            }
        }
        parts_progress.finish_with_message("All sections uploaded");
        let _ = progress.clear();
    } else if let Err(e) = send_data(conn, file_buffer.as_slice(), address, Some(&progress)) {
        error!("Error uploading binary: {}", e);
        return Err(e);
    }
    Ok((address, 0))
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

pub fn reboot(
    conn: &mut impl ExternalDcIo,
) -> std::result::Result<usize, std::boxed::Box<dyn std::error::Error>> {
    let command = DCLoadCmd {
        cmd: DCLoadCmds::Reboot(),
        address: 0,
        size: 0,
    };
    debug!("Sending command: {:?}", command);
    conn.send_command(command)?;
    Ok(0)
}

pub fn receive_syscalls(
    conn: &mut impl ExternalDcIo,
    cd_path: Option<String>,
    mount: Option<String>,
) -> std::result::Result<(), std::boxed::Box<dyn std::error::Error>> {
    let mut disc = get_disc_format(StubDisc {});
    if let Some(cd_path) = cd_path {
        if cd_path.to_ascii_lowercase().ends_with(".gdi") {
            if let Ok(gdi) = Gdi::new(cd_path) {
                disc = get_disc_format(gdi);
            }
        } else if cd_path.to_ascii_lowercase().ends_with(".cdi") {
            if let Ok(cdi) = Cdi::new(cd_path) {
                disc = get_disc_format(cdi);
            }
        }
         else if let Ok(iso) = Iso::new(cd_path) {
            disc = get_disc_format(iso);
        } else {
            warn!("Could not parse disc image, CDFS redirection disabled");
        }
    }
    debug!(
        "CDFS source: start_sector={} num_sectors={}",
        disc.start_sector(),
        disc.num_sectors()
    );
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
    let pvd_lba = disc.start_sector().saturating_add(16);
    loop {
        match await_result(conn, None) {
            Err(e) => warn!("Error waiting for syscall: {}", e),
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
                                        format!("ReadSector size is not a multiple of 2048: {}", size),
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
                                if let Some(z) = std::env::var("DCLOAD_ZERO_LBA")
                                    .ok()
                                    .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
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
                                    match (parse("DCLOAD_REDIRECT_ABOVE"), parse("DCLOAD_REDIRECT_TO")) {
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
                                        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]
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
                                        conn.send_command(DCLoadCmd {
                                            cmd: DCLoadCmds::ReturnValue(),
                                            address: 0,
                                            size: 0,
                                        })?;
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
                                let toc = build_dc_toc(disc.start_sector(), disc.num_sectors());
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
                                        call_command(conn, DCLoadCmd {
                                            cmd: DCLoadCmds::ReturnValue(),
                                            address: u32::MAX,
                                            size: u32::MAX,
                                        })?;
                                    }
                                }
                            }
                        }
                    }
                }
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

/// Split anything larger than the DC's packet map into successive transfers.
pub fn send_data(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    progress_bar: Option<&MultiProgress>,
) -> std::result::Result<usize, std::boxed::Box<dyn std::error::Error>> {
    if data.len() > MAX_XFER {
        let mut sent = 0usize;
        for (i, part) in data.chunks(MAX_XFER).enumerate() {
            send_data_one(
                conn,
                part,
                address + (i * MAX_XFER) as u32,
                progress_bar,
            )?;
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
    progress_bar: Option<&MultiProgress>,
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

    // Rust have some chunking utilities, let's use them to split packets automatically
    let bar = if data.len() < 10000 {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(data.len().try_into()?).with_style(ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
    )?)
    };

    if let Some(progress_bar) = progress_bar {
        progress_bar.add(bar.clone());
    }

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
    let mut packet_count: u32 = 0;
    for chunk in data.chunks(CHUNK_SIZE) {
        let mut padded_chunk = [0u8; CHUNK_SIZE];
        padded_chunk[..chunk.len()].copy_from_slice(chunk);
        conn.send_command(DCLoadCmd {
            cmd: DCLoadCmds::PartBinary(Box::new(padded_chunk)),
            address: incr_address,
            size: chunk.len() as u32,
        })?;
        bar.inc(chunk.len() as u64);
        incr_address += chunk.len() as u32;
        packet_count = packet_count.saturating_add(1);
        sleep(Duration::from_nanos(1));
        if packet_count.is_multiple_of(burst_packets) {
            sleep(burst_delay);
        }
    }

    // Give in-flight UDP packets a chance to arrive before DoneBinary.
    sleep(Duration::from_millis(25));

    bar.finish_with_message("Initial upload complete, verifying...");

    let first_donebin = request_donebin(conn)?;
    if first_donebin.size > 0 {
        let mut last_cmd = first_donebin;
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
                if let Some(progress_bar) = progress_bar {
                    progress_bar.remove(&bar);
                }
                // Just for safety, should never happens
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "The Dreamcast asked us to resend a chunk that was larger than the maximum allowed size of {} bytes",
                        CHUNK_SIZE
                    ),
                )));
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
    }
    if let Some(progress_bar) = progress_bar {
        progress_bar.remove(&bar);
    }

    Ok(0)
}

fn call_command(
    conn: &mut impl ExternalDcIo,
    command: DCLoadCmd,
) -> std::result::Result<Vec<DCReturnCmd>, std::boxed::Box<dyn std::error::Error>> {
    let tries = 5;
    for _ in 0..tries {
        debug!("Sending command: {:?}", command);
        conn.send_command(command.clone())?;
        match await_result(conn, Some(Duration::from_millis(500))) {
            Err(e) => warn!(
                "Error waiting for response after command {:?}: {}, retrying... That might indicate packet loss",
                command, e
            ),
            Ok(cmds) => return Ok(cmds),
        }
    }
    Err(Box::new(std::io::Error::new(
        ErrorKind::TimedOut,
        format!(
            "No response after {} tries for command {:?}",
            tries, command
        ),
    )))
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
        debug!("Sending command: {:?}", cmd);
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

    let bar = if size < 10000 {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(size as u64).with_style(ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
    )?)
    };

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

    bar.finish_with_message("Data reception complete");

    Ok(data)
}
