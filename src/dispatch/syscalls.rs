//! The syscall loop: what the running title asks the host for, until it exits.

use super::*;

/// One entry of a packed 102-word TOC, for the log.
fn toc_word(toc: &[u8], i: usize) -> String {
    toc.get(i * 4..i * 4 + 4)
        .map(|b| format!("0x{:08x}", u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
        .unwrap_or_default()
}

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
    mut marks: Option<crate::marks::MarkWatch>,
    stage: Vec<(u32, u32)>,
) -> DcResult<()> {
    // A disc that failed to open (already reported) answers every read with
    // an error.
    let disc = cd_disc.unwrap_or_else(|| get_disc_format(StubDisc {}));
    // Worked out once, here: on a zipped GDI each of these can build a deflate
    // index, which must not happen inside a syscall.
    let toc_start = disc.start_sector();
    let toc_sectors = disc.num_sectors();
    let toc_all_tracks = disc.toc_tracks();
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
    let mut sectors =
        SectorServer::new(toc_start, toc_sectors, running_base, guards, memory, stage);
    let mut audio = AudioServer::new(cdda);
    loop {
        // Instruments post their own requests here, at the top, where no
        // transfer owns the conversation; their replies are claimed in the IO
        // layer (`io::PacketSink`).
        if let Some(d) = diag.as_mut() {
            d.tick(conn);
        }
        if let Some(s) = stack.as_mut() {
            s.tick(conn);
        }
        if let Some(m) = marks.as_mut() {
            m.tick(conn);
        }
        // The soonest wake-up anyone wants; none at all blocks.
        let timeout = [
            sectors.load.poll_timeout(),
            diag.as_ref().and_then(|d| d.poll_timeout()),
            stack.as_ref().and_then(|s| s.poll_timeout()),
            marks.as_ref().and_then(|m| m.poll_timeout()),
        ]
        .into_iter()
        .flatten()
        .min();
        match await_result(conn, timeout) {
            // A timeout is the loading burst going quiet, not a fault.
            Err(e) if is_timeout(&*e) => sectors.load.settle(),
            Err(e) => warn!("Error waiting for syscall: {}", e),
            Ok(cmds) => {
                for cmd in cmds {
                    if let Some(inner_cmd) = cmd.request {
                        match inner_cmd {
                            DCLoadClientCmds::ReadSector(start, dc_address, size) => {
                                sectors.serve(conn, disc.as_ref(), start, dc_address, size)?;
                            }
                            // Not recorded in the memory map: it lands in the
                            // loader's own staging buffer.
                            DCLoadClientCmds::ReadAudio(start, dc_address, size, fmt) => {
                                audio.serve(conn, disc.as_ref(), start, dc_address, size, fmt)?;
                            }
                            DCLoadClientCmds::ReadToc(area, dc_address, _unused) => {
                                let toc =
                                    build_dc_toc(toc_start, toc_sectors, &toc_all_tracks, area);
                                if let Err(e) = send_data(conn, &toc, dc_address, None) {
                                    warn!("Failed to send CDFS TOC data: {}", e);
                                    let _ = conn.send_command(refused());
                                    continue;
                                }
                                // Logged, not read back: under Windows CE the
                                // destination is a virtual address, and reading
                                // it froze the console.
                                debug!(
                                    "TOC area {area} -> 0x{dc_address:08x}: first {:?}, last {:?}, \
                                     leadout {:?}",
                                    toc_word(&toc, 99),
                                    toc_word(&toc, 100),
                                    toc_word(&toc, 101)
                                );
                                conn.send_command(DCLoadCmd::new(DCLoadCmds::ReturnValue(), 0, 0))?;
                            }
                            // No answer: the title does not wait for one.
                            DCLoadClientCmds::Console(fd, bytes) => {
                                let rendered = fs::render_console_bytes(&bytes);
                                if fd == 2 {
                                    error!("{}", rendered);
                                } else {
                                    info!("{}", rendered);
                                }
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
                                        call_command(conn, refused())?;
                                    }
                                }
                            }
                        }
                    }
                }
                // Any batch means time has passed: lets the loading bar close
                // while the title keeps chatting.
                sectors.load.settle();
                if let Some(d) = diag.as_ref() {
                    d.repaint();
                }
            }
        }
    }
}
