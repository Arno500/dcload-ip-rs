//! `--probe`: stubs that log when an address executes.

use super::*;

/// A probe stub for `addr`: it calls the loader's console write with the probe
/// id as the length, so reaching it logs `Write(1, <buf>, <id>)`, then spins
/// forever. It reports through dcload's syscall pointer, not `trapa`, because a
/// title owns the exception vectors. `peek` makes the write report that
/// address's bytes instead of the stub's own pool.
///
/// ```text
///   mov.l @(disp,PC),r0   ; &dcload syscall pointer (loader base + 8)
///   mov.l @r0,r0
///   mov   #1,r4           ; pcwritenr
///   mov   #1,r5           ; fd 1
///   mov.l @(disp,PC),r6   ; buf
///   mov   #id,r7          ; len = probe id
///   jsr   @r0
///   nop
/// spin: bra spin
///   nop
///   .long loader_base + 8
///   .long buf
/// ```
fn probe_stub(addr: u32, syscall_ptr: u32, id: u8, peek: Option<u32>) -> Vec<u8> {
    // The pool is the first 4-aligned slot after the code; the code itself may
    // sit at 2 mod 4, so the displacements are computed.
    let pool = (addr + 0x14 + 3) & !3;
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

/// Place probes and read each back. The syscall pointer is at
/// `running_base + 8`, so a loader that does not report its base gets none.
pub fn apply_probes(
    conn: &mut impl ExternalDcIo,
    probes: &[(u32, u8, Option<u32>)],
    running_base: Option<u32>,
) -> DcResult<()> {
    let Some(base) = running_base else {
        error!("the loader does not report where it is; cannot place a probe");
        return Ok(());
    };
    let syscall_ptr = p1(base) + 8;

    for &(addr, id, peek) in probes {
        // Physical window, never P2: P2 transfers past 8 bytes are unreliable
        // (`selftest_readback`). The peek address is read back the same way.
        let addr = phys(addr);
        if addr % 2 != 0 {
            error!("probe address 0x{addr:08x} is odd -- not an instruction; skipped");
            continue;
        }
        let peek = peek.map(phys);
        // What the report will name: the peek address, or the stub's pool.
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
            // Show the bytes: a mismatch may be the read-back that is wrong.
            Ok(got) => {
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
mod tests {
    use super::probe_stub;

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

    /// Where the `mov.l @(disp,PC)` at `off` actually reads.
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
            assert_eq!(u16::from_le_bytes([s[0x0a], s[0x0b]]), 0xe704);
        }
    }
}
