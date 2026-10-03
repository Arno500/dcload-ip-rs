//! Moving bytes over the wire: `send_data` and the disc-read answer, the
//! read-back (`receive_data`), and the command/acknowledgement plumbing under them.

use super::*;

/// Largest payload one LoadBinary can carry: the loader's packet map is 256
/// entries of `CHUNK_SIZE` (`BIN_INFO_MAP_SIZE`). Must match the loader.
pub(super) const MAX_XFER: usize = 256 * CHUNK_SIZE;

/// Busy-wait for `d`. `thread::sleep` rounds up to the timer tick on Windows,
/// and on the runtime path the title is frozen for every microsecond spent here.
pub(super) fn spin_for(d: Duration) {
    if d.is_zero() {
        return;
    }
    let start = Instant::now();
    while start.elapsed() < d {
        std::hint::spin_loop();
    }
}

/// Send `data`, split into transfers the loader can map.
///
/// `progress_bar` also selects the path: `Some` is the initial upload (paced
/// against DoneBinary), `None` a runtime transfer (spin-paced, the title frozen).
pub fn send_data(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    progress_bar: Option<&ProgressBar>,
) -> DcResult<usize> {
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

/// Runtime pacing, shared by the sector and audio paths (one 16 KB RX ring):
/// a pause of `DCLOAD_RT_DELAY_US` (600) every `DCLOAD_RT_BURST` (6) packets.
///
/// Outrunning the ring desyncs it and the loader then receives nothing. At 6/600
/// the chip drops no frames but the ring already resyncs occasionally, so do
/// not shorten it; check `g_rx_overflow`/`g_rx_missed` before changing it.
pub(super) fn runtime_pacing() -> (u32, Duration) {
    static PACING: std::sync::OnceLock<(u32, Duration)> = std::sync::OnceLock::new();
    *PACING.get_or_init(|| {
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
    })
}

/// One PartBinary: `chunk` (at most `CHUNK_SIZE` bytes) for `address`.
fn part(address: u32, chunk: &[u8]) -> DCLoadCmd {
    let mut padded = [0u8; CHUNK_SIZE];
    padded[..chunk.len()].copy_from_slice(chunk);
    DCLoadCmd::new(DCLoadCmds::PartBinary(Box::new(padded)), address, chunk.len() as u32)
}

/// Send `data` as parts, spinning for `pause` after every `burst` of them.
pub(super) fn send_parts(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    burst: u32,
    pause: Duration,
) -> DcResult<()> {
    for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
        conn.send_command(part(address + (i * CHUNK_SIZE) as u32, chunk))?;
        if (i as u32 + 1).is_multiple_of(burst) {
            spin_for(pause);
        }
    }
    Ok(())
}

/// Serve one chunk of a disc read: the LoadBinary and the parts, with no
/// acknowledgement round trips. The caller sends the ReturnValue.
///
/// The loader checks its own window when the ReturnValue lands
/// (`bin_window_complete`) and re-asks for a chunk with a hole, so this needs
/// a loader that does; `loaders/` must be redeployed with the host.
pub(super) fn send_sectors(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
) -> DcResult<()> {
    // The loader can only vouch for one window: anything larger goes through
    // the acknowledged path.
    if data.len() > MAX_XFER {
        send_data(conn, data, address, None)?;
        return Ok(());
    }
    let (burst_packets, burst_delay) = runtime_pacing();
    conn.send_command(DCLoadCmd::new(DCLoadCmds::LoadBinary(), address, data.len() as u32))?;
    // Give `cmd_loadbin` time to clear its map and purge the cache over the
    // window before the first part, or the ring overflows. Scaled to the window
    // (one cache block per 32 bytes), never below 100 us.
    let scaled = burst_delay.mul_f64((data.len() as f64 / 16384.0).min(1.0));
    spin_for(scaled.max(Duration::from_micros(100)));
    send_parts(conn, data, address, burst_packets, burst_delay)
}

fn send_data_one(
    conn: &mut impl ExternalDcIo,
    data: &[u8],
    address: u32,
    progress_bar: Option<&ProgressBar>,
) -> DcResult<usize> {
    // Wait for the loader's echo of THIS LoadBinary: parts sent into a window
    // that was never installed are silently dropped.
    let mut acked = false;
    for i in 0..5 {
        let load = DCLoadCmd::new(DCLoadCmds::LoadBinary(), address, data.len() as u32);
        if let Ok(cmds) = call_command(conn, load) {
            if let Some(e) = cmds.first().and_then(|c| c.error_code) {
                warn!("Seems the load binary command was not understood, retrying...");
                if i == 4 {
                    return Err(Box::new(Error::other(format!(
                        "LoadBinary command not understood after several tries: {}",
                        e
                    ))));
                }
                continue;
            }
            if cmds.iter().any(|c| {
                c.cmd.as_ref().is_some_and(|inner| {
                    matches!(inner.cmd, DCLoadCmds::LoadBinary()) && inner.address == address
                })
            }) {
                acked = true;
                break;
            }
            debug!("LoadBinary echo for 0x{address:08x} not seen yet, retrying");
        }
    }
    if !acked {
        return Err(timed_out(format!(
            "No LoadBinary echo for 0x{address:08x}; refusing to send parts into an unset window"
        )));
    }

    // Bytes of this transfer the loader has confirmed (the bar spans the file).
    let mut confirmed = 0usize;

    // Upload: windows of 8 packets (~12 KB, inside the 16 KB ring), each closed
    // by a DoneBinary.
    let (burst_packets, burst_delay) = if progress_bar.is_none() {
        runtime_pacing()
    } else {
        (8_u32, Duration::from_millis(2))
    };
    if progress_bar.is_some() {
        // DoneBinary is a barrier: the loader handles datagrams in order, so its
        // reply covers every part sent before it and names the first one still
        // missing. One window in flight can never overrun the ring.
        let window = burst_packets.max(1) as usize;
        let mut pos: usize = 0;
        let mut last_missing: Option<usize> = None;
        let mut stalled: u32 = 0;

        loop {
            let mut in_window = 0usize;
            while pos < data.len() && in_window < window {
                let end = (pos + CHUNK_SIZE).min(data.len());
                conn.send_command(part(address + pos as u32, &data[pos..end]))?;
                pos = end;
                in_window += 1;
                sleep(Duration::from_nanos(1));
            }

            let probe = request_donebin(conn)?;
            if probe.size == 0 {
                credit(progress_bar, &mut confirmed, data.len());
                break;
            }

            let missing = probe.address.wrapping_sub(address) as usize;
            if missing >= data.len() {
                // Out of range; the repair loop below has the final word.
                break;
            }
            credit(progress_bar, &mut confirmed, missing);

            if missing < pos {
                // Rewind to the hole; resending the parts after it is harmless.
                if last_missing == Some(missing) {
                    stalled += 1;
                    if stalled > 16 {
                        return Err(timed_out(format!(
                            "The Dreamcast kept asking for 0x{:08x} after {} attempts",
                            probe.address, stalled
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
        // Runtime: the title is frozen until the last part lands, so pace with
        // a spin and no blind waits; the DoneBinary below is the barrier.
        send_parts(conn, data, address, burst_packets, burst_delay)?;
    }

    let first_donebin = request_donebin(conn)?;
    if first_donebin.size > 0 {
        let mut last_cmd = first_donebin;
        // Restored after the repair so the bar keeps its label.
        let previous_message = progress_bar.map(|bar| bar.message());
        warn!("There was an error while uploading the binary, resending missing parts...");

        // Losses come in runs, and DoneBinary only names the first hole: resend
        // a run from there, doubling up to 64 parts per round trip.
        const RESEND_RUN_MAX: usize = 64;
        let mut resend_run: usize = 8;

        let mut resent_total: usize = 0;
        loop {
            debug!(
                "Missing {:?} bytes at address 0x{:08x}",
                last_cmd.size, last_cmd.address,
            );
            if last_cmd.address < address {
                return Err(Box::new(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "The Dreamcast asked us to resend 0x{:08x}, below the transfer base 0x{:08x}",
                        last_cmd.address, address
                    ),
                )));
            }
            if last_cmd.size as usize > CHUNK_SIZE {
                return Err(Box::new(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "The Dreamcast asked us to resend a chunk that was larger than the maximum allowed size of {} bytes",
                        CHUNK_SIZE
                    ),
                )));
            }

            if let Some(bar) = progress_bar {
                bar.set_message(format!("repairing +{resent_total}"));
            }

            let mut start = (last_cmd.address - address) as usize;
            for i in 0..resend_run {
                if start >= data.len() {
                    break;
                }
                let end = (start + CHUNK_SIZE).min(data.len());
                conn.send_command(part(address + start as u32, &data[start..end]))?;
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
                resend_run = (resend_run * 2).min(RESEND_RUN_MAX);
            } else {
                break;
            }
        }
        warn!("Recovered after resending {resent_total} part(s)");
        if let (Some(bar), Some(message)) = (progress_bar, previous_message) {
            bar.set_message(message);
        }
    }
    if let Some(bar) = progress_bar {
        credit(Some(bar), &mut confirmed, data.len());
    }

    Ok(0)
}

/// Advance a bar to `reached` bytes, never backwards: DoneBinary's "first
/// missing part" moves back whenever a hole is found.
fn credit(bar: Option<&ProgressBar>, confirmed: &mut usize, reached: usize) {
    if reached <= *confirmed {
        return;
    }
    if let Some(bar) = bar {
        bar.inc((reached - *confirmed) as u64);
    }
    *confirmed = reached;
}

pub(super) fn call_command(
    conn: &mut impl ExternalDcIo,
    command: DCLoadCmd,
) -> DcResult<Vec<DCReturnCmd>> {
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
    Err(timed_out(format!("No response after {} tries for command {}", tries, command)))
}

/// DoneBinary goes out once per upload window, so it is logged at trace.
pub(super) fn log_command(command: &DCLoadCmd) {
    if matches!(command.cmd, DCLoadCmds::DoneBinary()) {
        trace!("Sending command: {}", command);
    } else {
        debug!("Sending command: {}", command);
    }
}

pub(super) fn extract_donebin(cmds: &[DCReturnCmd]) -> Option<DCLoadCmd> {
    cmds.iter()
        .filter_map(|ret| ret.cmd.as_ref())
        .find(|cmd| cmd.cmd == DCLoadCmds::DoneBinary())
        .cloned()
}

fn request_donebin(conn: &mut impl ExternalDcIo) -> DcResult<DCLoadCmd> {
    let cmd = DCLoadCmd::new(DCLoadCmds::DoneBinary(), 0, 0);

    // Two tries of 2 s: queued parts can delay the answer, but while this waits
    // nothing serves the loader's own retry.
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
                Err(e) if is_timeout(&*e) => {}
                Err(e) => warn!("Error waiting for DoneBinary response: {}", e),
            }
        }
    }

    Err(timed_out("No DoneBinary response received"))
}

pub(crate) fn await_result(
    conn: &mut impl ExternalDcIo,
    timeout: Option<Duration>,
) -> DcResult<Vec<DCReturnCmd>> {
    match conn.poll(timeout) {
        Err(e) if e.kind() == ErrorKind::TimedOut => {
            error!("Timeout waiting for response after execute command");
            Err(Box::new(e))
        }
        Err(e) => {
            error!("Error polling for response: {}", e);
            Err(Box::new(e))
        }
        Ok(evt) if evt.is_empty() => Err(timed_out("No events received")),
        Ok(evt) => Ok(conn.handle_data(&evt)?),
    }
}

/// Is this SendBinary chunk an answer to THIS read of `size` bytes at `address`?
///
/// A straggler from an earlier read at the same address is in range, so the
/// length decides: each chunk is exactly `min(CHUNK_SIZE, size - offset)` bytes,
/// at a chunk boundary. `chunk_len` is the command's `size` field; the payload
/// itself is always padded to `CHUNK_SIZE`.
fn chunk_is_ours(address: u32, size: usize, chunk_addr: u32, chunk_len: usize) -> bool {
    if chunk_addr < address {
        return false;
    }
    let offset = (chunk_addr - address) as usize;
    offset < size
        && offset.is_multiple_of(CHUNK_SIZE)
        && chunk_len == CHUNK_SIZE.min(size - offset)
}

/// The commands in the next batch from the console. An error is logged and
/// reads as an empty batch.
fn next_cmds(conn: &mut impl ExternalDcIo, timeout: Option<Duration>) -> Vec<DCLoadCmd> {
    match await_result(conn, timeout) {
        Ok(cmds) => cmds.into_iter().filter_map(|c| c.cmd).collect(),
        Err(e) => {
            warn!("Error waiting for data chunk: {}", e);
            vec![]
        }
    }
}

/// A read back of `data.len()` bytes at `address`, filled in as chunks arrive.
struct ReadBack<'a> {
    address: u32,
    data: &'a mut [u8],
    got: Vec<bool>,
}

impl ReadBack<'_> {
    /// Store `chunk` if `cmd` answers this read; the bytes stored.
    fn store(&mut self, cmd: &DCLoadCmd, chunk: &[u8]) -> Option<usize> {
        let size = self.data.len();
        if !chunk_is_ours(self.address, size, cmd.address, cmd.size as usize) {
            return None;
        }
        let offset = (cmd.address - self.address) as usize;
        let end = (offset + chunk.len()).min(size);
        self.data[offset..end].copy_from_slice(&chunk[..end - offset]);
        self.got[offset / CHUNK_SIZE] = true;
        Some(end - offset)
    }

    fn missing(&self) -> Vec<usize> {
        (0..self.got.len()).filter(|&i| !self.got[i]).collect()
    }
}

pub fn receive_data(
    conn: &mut impl ExternalDcIo,
    timeout: Option<Duration>,
    address: u32,
    size: usize,
    quiet: bool,
) -> DcResult<Vec<u8>> {
    let expected_chunks = size.div_ceil(CHUNK_SIZE);
    let mut data = vec![0u8; size];
    let mut read = ReadBack { address, data: &mut data, got: vec![false; expected_chunks] };

    let ask = if quiet {
        DCLoadCmds::SendBinaryQuiet(None)
    } else {
        DCLoadCmds::SendBinary(None)
    };
    conn.send_command(DCLoadCmd::new(ask, address, size as u32))?;

    let bar = ui::bytes_bar(size as u64, "read-back");

    // Bounded by batches, not chunks received: a batch of stragglers must not
    // use up this read's answers.
    const STRAGGLER_BUDGET: usize = 8;
    let mut budget = expected_chunks + STRAGGLER_BUDGET;
    let mut saw_done = false;
    while budget > 0 && !saw_done && read.got.contains(&false) {
        budget -= 1;
        for cmd in next_cmds(conn, timeout) {
            match &cmd.cmd {
                DCLoadCmds::SendBinary(Some(chunk)) => match read.store(&cmd, &chunk[..]) {
                    Some(n) => bar.inc(n as u64),
                    None => warn!(
                        "chunk at 0x{:08x}+{} is not an answer to the \
                         read-back of 0x{:08x}+{}, ignoring",
                        cmd.address, cmd.size, address, size
                    ),
                },
                DCLoadCmds::DoneBinary() => {
                    saw_done = true;
                    break;
                }
                _ => warn!("Unexpected command received while waiting for data: {:?}", cmd),
            }
        }
    }

    // Re-request what is missing, a bounded number of times: a console that
    // answers nothing must fail the read, not keep this (single-threaded) host
    // from serving the title.
    const REPAIR_PASSES: usize = 4;
    let mut passes = 0;
    while read.got.contains(&false) {
        if passes == REPAIR_PASSES {
            let missing = read.missing().len();
            return Err(timed_out(format!(
                "read-back of 0x{address:08x}+{size} never completed: {missing} of \
                 {expected_chunks} chunks still missing after {REPAIR_PASSES} repair \
                 passes. The console is not answering; giving up rather than \
                 re-requesting forever."
            )));
        }
        passes += 1;
        for i in read.missing() {
            debug!("Missing chunk {}", i);
            let len = if size.is_multiple_of(CHUNK_SIZE) {
                CHUNK_SIZE as u32
            } else {
                size as u32 - (i as u32 * CHUNK_SIZE as u32)
            };
            let at = address + (i as u32 * CHUNK_SIZE as u32);
            conn.send_command(DCLoadCmd::new(DCLoadCmds::SendBinaryQuiet(None), at, len))?;

            for cmd in next_cmds(conn, timeout) {
                match &cmd.cmd {
                    DCLoadCmds::SendBinary(Some(chunk)) => {
                        let Some(n) = read.store(&cmd, &chunk[..]) else {
                            warn!(
                                "chunk at 0x{:08x}+{} is not an answer to \
                                 the re-request of 0x{:08x}+{}, ignoring",
                                cmd.address, cmd.size, address, size
                            );
                            continue;
                        };
                        bar.inc(n as u64);
                        // Then its DoneBinary, or the late first answer to this chunk.
                        for late in next_cmds(conn, timeout) {
                            match late.cmd {
                                DCLoadCmds::DoneBinary() => {}
                                DCLoadCmds::SendBinary(Some(_))
                                    if chunk_is_ours(
                                        address,
                                        size,
                                        late.address,
                                        late.size as usize,
                                    ) =>
                                {
                                    debug!(
                                        "duplicate answer for 0x{:08x}+{} ignored",
                                        late.address, late.size
                                    );
                                }
                                _ => warn!(
                                    "Unexpected command received after receiving data: {:?}",
                                    late
                                ),
                            }
                        }
                    }
                    DCLoadCmds::DoneBinary() => break,
                    _ => warn!("Unexpected command received while waiting for data: {:?}", cmd),
                }
            }
        }
    }

    drop(bar);
    Ok(data)
}

/// The ReturnValue that refuses a syscall: the loader reads `u32::MAX` as a
/// failure and, for a disc or audio read, asks again.
pub(super) fn refused() -> DCLoadCmd {
    DCLoadCmd::new(DCLoadCmds::ReturnValue(), u32::MAX, u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A four-byte straggler at the same address must not pass for the first
    /// chunk of a longer read.
    #[test]
    fn a_four_byte_answer_is_not_a_chunk_of_a_long_read() {
        let base = 0x8ce0_0000;
        assert!(!chunk_is_ours(base, 27212, base, 4));
        assert!(chunk_is_ours(base, 27212, base, CHUNK_SIZE));
        assert!(chunk_is_ours(base, 27212, base + CHUNK_SIZE as u32, CHUNK_SIZE));
        // 27212 = 18 * 1440 + 1292: the tail is served short, not padded.
        assert!(chunk_is_ours(base, 27212, base + 18 * CHUNK_SIZE as u32, 1292));
        assert!(!chunk_is_ours(base, 27212, base + 18 * CHUNK_SIZE as u32, CHUNK_SIZE));
        assert!(chunk_is_ours(base, 4, base, 4));
    }

    #[test]
    fn a_chunk_off_the_boundary_or_out_of_range_is_refused() {
        let base = 0x8ce0_0000;
        assert!(!chunk_is_ours(base, 27212, base + 8, CHUNK_SIZE));
        assert!(!chunk_is_ours(base, 27212, base - 4, CHUNK_SIZE));
        assert!(!chunk_is_ours(base, 27212, base + 27212, CHUNK_SIZE));
    }
}
