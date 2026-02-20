use std::{
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
        gdi::Gdi,
        iso::Iso,
        types::{StubDisc, get_disc_format},
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
        } else if let Ok(iso) = Iso::new(cd_path) {
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
                                let buf = disc.read_sector(start, num_sectors)?;
                                send_data(conn, &buf, dc_address, None)?;
                                conn.send_command(DCLoadCmd {
                                    cmd: DCLoadCmds::ReturnValue(),
                                    address: 0,
                                    size: 0,
                                })?;
                            }
                            DCLoadClientCmds::ReadToc(_session, dc_address, _unused) => {
                                let toc = build_dc_toc(disc.start_sector(), disc.num_sectors());
                                send_data(conn, &toc, dc_address, None)?;
                                conn.send_command(DCLoadCmd {
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

pub fn send_data(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    progress_bar: Option<&MultiProgress>,
) -> std::result::Result<usize, std::boxed::Box<dyn std::error::Error>> {
    let mut incr_address = address;

    // Every binary upload starts with a LoadBinary call
    for i in 0..5 {
        if let Ok(cmds) = call_command(
            conn,
            DCLoadCmd {
                cmd: DCLoadCmds::LoadBinary(),
                address: incr_address,
                size: data.len() as u32,
            },
        ) && let Some(cmd) = cmds.first()
        {
            match cmd.error_code {
                Some(e) => {
                    warn!("Seems the load binary command was not understood, retrying...");
                    if i == 4 {
                        return Err(Box::new(std::io::Error::other(format!(
                            "LoadBinary command not understood after several tries: {}",
                            e
                        ))));
                    }
                }
                _ => break,
            }
        };
    }

    // Rust have some chunking utilities, let's use them to split in 1440 bytes packets automatically
    let mut chunked = data.chunks(CHUNK_SIZE);
    let bar = if data.len() < 1000 {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(data.len().try_into()?).with_style(ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
    )?)
    };

    if let Some(progress_bar) = progress_bar {
        progress_bar.add(bar.clone());
    }

    // Send each of the chunk using the PartBinary command
    chunked.try_for_each(|chunk| -> Result<(), Box<dyn std::error::Error>> {
        let mut padded_chunk = [0u8; CHUNK_SIZE];
        padded_chunk[..chunk.len()].copy_from_slice(chunk);
        conn.send_command(DCLoadCmd {
            cmd: DCLoadCmds::PartBinary(Box::new(padded_chunk)),
            address: incr_address,
            size: chunk.len() as u32,
        })?;
        bar.inc(chunk.len() as u64);
        incr_address += chunk.len() as u32;
        sleep(Duration::from_nanos(1));
        Ok(())
    })?;

    bar.finish_with_message("Initial upload complete, verifying...");

    let first_donebin = request_donebin(conn)?;
    if first_donebin.size > 0 {
        let mut last_cmd = first_donebin;
        warn!("There was an error while uploading the binary, resending missing parts...");

        // Basically loop on the parts send and check, as long as we do not validate a DoneBinary
        loop {
            debug!(
                "Missing {:?} bytes at address 0x{:08x}",
                last_cmd.size, last_cmd.address,
            );
            // Select only the section that we need to resend
            let start = (last_cmd.address - address) as usize;
            let end = start + last_cmd.size as usize;
            let mut padded_chunk = [0u8; CHUNK_SIZE];
            let chunk_slice = &data[start..end];
            padded_chunk[..chunk_slice.len()].copy_from_slice(chunk_slice);
            if chunk_slice.len() <= CHUNK_SIZE {
                conn.send_command(DCLoadCmd {
                    cmd: DCLoadCmds::PartBinary(Box::new(padded_chunk)),
                    address: last_cmd.address,
                    size: chunk_slice.len() as u32,
                })?;
            } else {
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
            let donebin = request_donebin(conn)?;
            if donebin.size > 0 {
                last_cmd = donebin;
                warn!("There are still some errors, continuing to send failed parts");
            } else {
                // And seems we're finally good!
                break;
            }
        }
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

    for _ in 0..10 {
        let cmds = call_command(conn, cmd.clone())?;
        if let Some(donebin) = extract_donebin(&cmds) {
            return Ok(donebin);
        }
        debug!("Received non-DBIN packets while waiting for DoneBinary response");
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

    let bar = if size < 1000 {
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
                                if inner_cmd.address - address >= (size as u32 + CHUNK_SIZE as u32) / CHUNK_SIZE as u32 {
                                    warn!("Bad packet received for DoneBinary, ignoring");
                                    continue;
                                }
                                // Append data chunk to data vector
                                let offset = (inner_cmd.address - address) as usize;
                                data[offset..(offset + chunk.len()).min(size)]
                                    .copy_from_slice(&chunk[..chunk.len().min(size)]);
                                chunk_map[(inner_cmd.address - address) as usize / CHUNK_SIZE] = true;
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
                                        if inner_cmd.address - address
                                            >= (size as u32 + CHUNK_SIZE as u32) / CHUNK_SIZE as u32
                                        {
                                            warn!("Bad packet received for DoneBinary, ignoring");
                                            continue;
                                        }
                                        // Append data chunk to data vector
                                        let offset = (inner_cmd.address - address) as usize;
                                        data[offset..offset + chunk.len()]
                                            .copy_from_slice(&chunk[..]);
                                        chunk_map[(inner_cmd.address - address) as usize / CHUNK_SIZE] =
                                            true;
                                        bar.inc(chunk.len() as u64);

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
