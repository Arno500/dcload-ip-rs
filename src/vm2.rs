//! Tell a VM2 / VMUPro which game is about to boot.
//!
//! A VM2, a VMUPro and the USB/Bluetooth Maple adapters that answer the same
//! way are memory cards that hold many games' saves at once. They pick the
//! right one when the software that launches a title hands them its product
//! number, and until it does they show whatever was selected last. openMenu
//! does this from the console (`openmenu/src/vm2/vm2_api.c`); dcload-ip is the
//! thing launching the title here, so the job falls to this host.
//!
//! # Why none of this is on the Dreamcast
//!
//! The loader already forwards an arbitrary Maple frame for us: `MAPL` takes a
//! port, a unit, a Maple command and a payload, runs one DMA cycle and sends
//! the response frame back (`cmd_maple` in dcload's `commands.c`). So the whole
//! protocol below is host code and costs the loader nothing -- which is the
//! only reason it exists at all. The loader's `_end` is 0x8c00bea0 and a retail
//! title's crt0 paints `0x8c00c000` upwards before it calls anything, so there
//! are 288 bytes of room down there and no more (loader AGENTS.md 4.6).
//!
//! # It needs a loader from 2026-09-20 or later
//!
//! `MAPL` had never carried a payload longer than one longword before this, and
//! two defects had been waiting there for it: the payload copy counted
//! longwords into a byte-counted memcpy, so a 12-character ID arrived as 3
//! characters, and the response was read back through the cache, so every probe
//! after the first returned the first one's answer. Both are fixed in the
//! loader; an older one will report the same device on all four ports and send
//! it a truncated ID. There is no feature bit to test for it -- the host
//! chainloads its own loader for every disc image, so redeploying `loaders/` is
//! what keeps the two in step.
//!
//! # The protocol
//!
//! Detection is Maple `ALLINFO` (command 2). A plain VMU answers it; so do
//! these, but with 40 bytes of `extended` text after the 112-byte device info
//! naming who they are. Selection is Maple command 33, whose payload is the
//! memory-card function code, 12 bytes of product number and, optionally, 128
//! bytes of title.

use std::time::{Duration, Instant};

use crate::cmds::{DCLoadCmd, DCLoadCmds, DCReturnCmd};
use crate::io::ExternalDcIo;

/// The ordinary enumeration command every Maple host sends first.
const MAPLE_COMMAND_DEVINFO: u8 = 1;
/// What KOS sends to every device on shutdown, "to leave them as we found
/// them" (`maple_dev_reset`). It is the software equivalent of unplugging one.
const MAPLE_COMMAND_RESET: u8 = 3;
/// Ask a device everything it knows about itself.
const MAPLE_COMMAND_ALLINFO: u8 = 2;
/// The VM2's own command: "this is the game that is about to run".
const VM2_COMMAND_SET_ID: u8 = 33;

const MAPLE_RESPONSE_DEVINFO: i8 = 5;
const MAPLE_RESPONSE_ALLINFO: i8 = 6;
const MAPLE_RESPONSE_OK: i8 = 7;
/// "Busy, ask me again" -- a VM2 answers this while it swaps card images.
const MAPLE_RESPONSE_AGAIN: i8 = -4;
/// Nothing answered at that Maple address: an empty slot. The Maple controller
/// itself writes this into the response buffer when its timeout expires.
const MAPLE_RESPONSE_NONE: i8 = -1;
/// The loader's own sentinel (`MAPLE_NO_REPLY`, 0xee), stamped into the
/// response header before every DMA cycle. Seeing it back means the controller
/// wrote NOTHING -- a different fault from -1, which is the controller saying
/// the device did not answer in time. Loaders before 2026-09-20 never cleared
/// the buffer at all, so a cycle that wrote nothing read back as stale RAM and
/// was served to the host as a Maple response.
const MAPLE_NO_REPLY: i8 = -18;

/// `MAPLE_FUNC_MEMCARD` as the bus carries it: function codes go big-endian.
///
/// KOS spells the same four bytes `0x02000000`, because it stores the word
/// little-endian and lets the memory order be the wire order. Written out here
/// so neither end has to be reasoned about.
const FUNC_MEMCARD: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

/// Where `extended` starts in an `ALLINFO` response frame.
///
/// 4 bytes of Maple frame header, then the 112-byte device info every Maple
/// device returns (function codes 16, area code and connector direction 2,
/// product name 30, licence 60, standby and maximum power 4), then the 40 bytes
/// only these devices fill in.
const EXTENDED_AT: usize = 4 + 112;

/// The names these devices introduce themselves with, exactly 16 bytes each.
const KNOWN: [(&[u8; 16], &str); 4] = [
    (b"VM2 by Dreamware", "VM2"),
    (b"8BITMODS VMUPro ", "VMUPro"),
    (b"USB RP2040 EMU  ", "USB4MAPLE"),
    (b"Pico2Maple USBBT", "Pico2Maple"),
];

// There used to be a SLOTS table here -- units 1 and 2 of all four ports,
// probed blind. KOS does not work that way and neither does this any more:
// `reported_units()` reads the occupied slots out of the port's own answer.

/// How many times to take `AGAIN` for an answer before giving up on a device.
///
/// The loader retries 64 times inside its own `MAPL` handler; this is the
/// second line, for a card that is still busy after all of those.
const AGAIN_TRIES: usize = 4;

/// Consecutive unanswered probes before the scan is abandoned.
const GIVE_UP_AFTER_SILENT: usize = 2;

/// How many times to re-ask a slot whose answer is not a Maple response at all.
const PROBE_TRIES: usize = 3;

/// Rounds of `DEVINFO` to every port's controller before the scan is believed.
///
/// KOS polls the Maple bus at 60 Hz and never stops, so under openMenu a device
/// has been addressed hundreds of times before anyone asks it anything. dcload
/// touches the bus only when a `MAPL` command arrives, so without this the scan
/// is the first traffic the bus has seen since the console booted. The answers
/// are thrown away; driving the bus is the point.
const WARM_UP_ROUNDS: usize = 3;

/// `DCLOAD_VM2_WARMUP` overrides it, so how much warming the bus needs can be
/// found on the console without a rebuild.
fn warm_up_rounds() -> usize {
    std::env::var("DCLOAD_VM2_WARMUP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(WARM_UP_ROUNDS)
}

/// How long to leave the Maple bus alone between transactions.
///
/// **KOS never starts two DMA bursts closer together than one vblank.** It
/// queues frames and flushes them from `maple_vbl_irq_hnd`, at most once per
/// frame, and the next burst waits for the previous one's completion
/// interrupt. Every frame a device sees under KOS therefore arrives at 60 Hz
/// or slower. This host drives the bus one `MAPL` command at a time, which is
/// one DMA burst per UDP round trip -- about a millisecond, ten to thirty
/// times faster than anything the hardware is ever asked to do in practice.
///
/// This is before `EXEC`, so a real sleep is fine here (the rule against
/// sleeping is for the runtime path, where it would freeze the title).
/// `DCLOAD_VM2_PACE_MS` tunes it; 0 removes it.
const PACE_MS: u64 = 17;

fn pace() -> Duration {
    Duration::from_millis(
        std::env::var("DCLOAD_VM2_PACE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(PACE_MS),
    )
}

/// One card that answered, and what it said it was.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    pub port: u8,
    pub unit: u8,
    pub kind: &'static str,
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The port letter and slot number a Dreamcast owner reads off the
        // console, not the numbers the bus uses.
        write!(
            f,
            "{} in {}{}",
            self.kind,
            (b'A' + self.port) as char,
            self.unit
        )
    }
}

/// Who a reply belongs to.
///
/// `cmd_maple` copies the request's header into its answer and only overwrites
/// `size`, so whatever goes in `address` comes back. That is the only way to
/// tell one `MAPL` answer from another, and it matters: this runs in the
/// seconds after an upload, when the socket still has stragglers in it.
fn tag(port: u8, unit: u8, command: u8) -> u32 {
    (port as u32) << 16 | (unit as u32) << 8 | command as u32
}

/// Build the argument block `cmd_maple` expects: port, unit, command, payload
/// length in LONGWORDS, then the payload.
fn request(port: u8, unit: u8, command: u8, payload: &[u8]) -> DCLoadCmd {
    debug_assert!(payload.len() % 4 == 0, "a Maple payload is whole longwords");
    let mut data = Vec::with_capacity(4 + payload.len());
    data.extend_from_slice(&[port, unit, command, (payload.len() / 4) as u8]);
    data.extend_from_slice(payload);
    let size = data.len() as u32;
    DCLoadCmd {
        cmd: DCLoadCmds::Mapl(Some(data)),
        address: tag(port, unit, command),
        size,
    }
}

/// THIS request's Maple response frame, out of a batch that may hold anything.
///
/// A wakeup drains the whole socket, so the batch can carry an upload's last
/// `DBIN`, a probe's `SBIQ`, or nothing at all -- none of which means the
/// Dreamcast went quiet. Only an answer carrying our own tag counts.
///
/// Byte 0 of the frame is the response code (signed: everything negative is a
/// failure, and -1 is "nothing at that address"), byte 3 the payload length in
/// longwords. `size` is how many bytes the loader actually copied out of its
/// receive buffer, which is the only length worth trusting.
fn response(replies: &[DCReturnCmd], tag: u32) -> Option<Vec<u8>> {
    replies.iter().find_map(|reply| {
        let cmd = reply.cmd.as_ref()?;
        let DCLoadCmds::Mapl(Some(frame)) = &cmd.cmd else {
            return None;
        };
        if cmd.address != tag {
            return None;
        }
        let len = (cmd.size as usize).min(frame.len());
        (len >= 4).then(|| frame[..len].to_vec())
    })
}

/// Copy `text` into a fixed field the way `strncpy` does: truncated to fit,
/// NUL-padded, and with no terminator at all when it fills the field exactly.
/// That is the shape the devices are written against, so it is the shape sent.
fn fixed_field(text: &str, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let bytes = text.as_bytes();
    let n = bytes.len().min(len);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// The payload of command 33: function code, product number, and the title if
/// there is one to send.
fn set_id_payload(product: &str, name: Option<&str>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + 12 + 128);
    payload.extend_from_slice(&FUNC_MEMCARD);
    payload.extend_from_slice(&fixed_field(product, 12));
    if let Some(name) = name {
        payload.extend_from_slice(&fixed_field(name, 128));
    }
    payload
}

/// The `extended` bytes of an `ALLINFO` frame -- however many came back.
///
/// NOT a fixed 40-byte slice. A frame shorter than 116 bytes has no `extended`
/// at all, and that is one of the ways detection fails; returning what is there
/// lets `explain()` say so instead of the whole thing collapsing to `None`.
fn extended(frame: &[u8]) -> &[u8] {
    let tail = frame.get(EXTENDED_AT..).unwrap_or(&[]);
    &tail[..tail.len().min(40)]
}

// There used to be an `extended_is_blank()` here, on the assumption that a
// plain VMU leaves the field empty and so is not worth reporting. It does not:
// a Sega VMU answers with its own version string -- measured 2026-09-20,
// "Version 1.005,1999/04/28,315-6124-07,SEG". Nothing in the field's content
// separates a card worth naming from one that is not, so the scan reports by
// OUTCOME instead: every rejected slot is collected, and printed only when the
// whole scan found nothing.

/// Which of the known devices this `ALLINFO` frame describes, if any.
///
/// MATCHED AS A SUBSTRING, case-insensitively, against whatever `extended`
/// holds -- not as an exact 16-byte field. The names in `KNOWN` are how
/// openMenu spells them, padded to 16 with spaces, and an exact compare makes
/// the match hostage to a firmware that pads with NUL instead, or adds a
/// version after its name. The distinctive part is the name.
fn identify(frame: &[u8]) -> Option<&'static str> {
    if frame.first().copied().map(|b| b as i8) != Some(MAPLE_RESPONSE_ALLINFO) {
        return None;
    }
    let extended = extended(frame);
    KNOWN.iter().find_map(|(signature, kind)| {
        let name = trim_trailing_blanks(signature.as_slice());
        contains_ignore_ascii_case(extended, name).then_some(*kind)
    })
}

fn trim_trailing_blanks(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map_or(0, |i| i + 1);
    &field[..end]
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// What a slot actually answered, in one line.
///
/// `identify` returns `None` for four different reasons -- the slot is empty,
/// the device refused `ALLINFO`, the frame came back too short to hold
/// `extended`, or the name is one this does not know -- and a scan that prints
/// nothing cannot be told apart from a scan that found nothing. This is the
/// line that tells them apart.
fn explain(frame: &[u8]) -> String {
    let code = frame[0] as i8;
    let longs = frame.get(3).copied().unwrap_or(0);
    let reason = match code {
        MAPLE_RESPONSE_NONE => "nothing plugged in there".to_string(),
        MAPLE_NO_REPLY => "the loader's Maple DMA cycle wrote nothing at all \
             (its sentinel came back intact)"
            .to_string(),
        MAPLE_RESPONSE_DEVINFO => format!(
            "functions {:08x}, product {:?}{}",
            u32::from_be_bytes(frame.get(4..8).and_then(|s| s.try_into().ok()).unwrap_or([0; 4])),
            printable(frame.get(4 + 18..4 + 18 + 30).unwrap_or(&[])),
            slots_reported(frame).map_or(String::new(), |s| format!(", {s}")),
        ),
        MAPLE_RESPONSE_ALLINFO if frame.len() <= EXTENDED_AT => format!(
            "answered ALLINFO but the frame stops at {} bytes, before the \
             extended field at {EXTENDED_AT}",
            frame.len()
        ),
        MAPLE_RESPONSE_ALLINFO => format!(
            "product {:?}, extended {:?}",
            printable(frame.get(4 + 18..4 + 18 + 30).unwrap_or(&[])),
            printable(extended(frame)),
        ),
        _ => format!("not a Maple response code; first bytes {}", hex(frame, 64)),
    };
    format!(
        "response {code} from {:#04x}, {longs} longwords, {} bytes: {reason}",
        frame.get(2).copied().unwrap_or(0),
        frame.len()
    )
}

/// What a port's main device says is plugged into its expansion slots.
///
/// The response frame's SENDER byte carries it: bit 5 marks the port's own
/// peripheral, and bits 0..4 are one per expansion slot. This is the one thing
/// no amount of addressing a slot can tell you -- a slot the controller does
/// not report never answers, and "nothing plugged in there" is what that looks
/// like from the slot's side, identically to an empty slot.
fn slots_reported(frame: &[u8]) -> Option<String> {
    let sender = *frame.get(2)?;
    if sender & 0x20 == 0 {
        return None; // not a port's main device
    }
    let occupied = sender & 0x1f;
    if occupied == 0 {
        return Some("it reports NO expansion slot occupied".to_string());
    }
    let list: Vec<String> = (0..5)
        .filter(|i| occupied & (1 << i) != 0)
        .map(|i| (i + 1).to_string())
        .collect();
    Some(format!("it reports slots {} occupied", list.join(" and ")))
}

/// Response codes the Maple protocol actually defines: -5..-1 for failures,
/// 1..14 for commands and answers. Anything else is not an answer at all --
/// the loader's "the DMA wrote nothing" sentinel, or a bus that was not
/// driving its lines properly when the cycle ran.
fn is_maple_code(code: i8) -> bool {
    (-5..=-1).contains(&code) || (1..=14).contains(&code)
}

/// One probe, re-asked while what comes back is not a Maple response at all.
///
/// Measured 2026-09-20: port A answered `00 ff ff ff` repeating -- response
/// code 0, which no Maple device can send -- to both of its commands, while
/// port B answered perfectly. A code outside the protocol is not information
/// about the device, so it is worth asking again rather than filing.
fn probe(
    bus: &mut impl MapleBus,
    port: u8,
    unit: u8,
    command: u8,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut last = None;
    for _ in 0..PROBE_TRIES {
        let frame = bus.transact(port, unit, command, &[])?;
        if is_maple_code(frame[0] as i8) {
            return Ok(frame);
        }
        last = Some(frame);
    }
    Ok(last.expect("PROBE_TRIES is never zero"))
}

/// Drive the bus before believing what it says. See `WARM_UP_ROUNDS`.
fn warm_up(bus: &mut impl MapleBus) {
    for _ in 0..warm_up_rounds() {
        for port in 0..4u8 {
            let _ = bus.transact(port, 0, MAPLE_COMMAND_DEVINFO, &[]);
        }
    }
}

/// The first `n` bytes, for a frame nothing else can make sense of.
fn hex(frame: &[u8], n: usize) -> String {
    frame
        .iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Printable ASCII as itself, everything else as a dot, trailing blanks gone.
fn printable(field: &[u8]) -> String {
    let field = trim_trailing_blanks(field);
    field
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}

/// One Maple transaction: send a frame, get the response frame back.
///
/// The scan below is the part with judgement in it -- which slots to try, which
/// answers mean a card is there, when to stop -- and this seam is what lets it
/// be tested without a console. `polling::Events` cannot be fabricated, so a
/// fake `ExternalDcIo` can record what was sent but can never answer.
trait MapleBus {
    fn transact(
        &mut self,
        port: u8,
        unit: u8,
        command: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

/// The real one: a `MAPL` command to the running loader.
struct Loader<'a, C: ExternalDcIo>(&'a mut C);

/// How long to wait for one `MAPL` answer, and how many times to re-ask.
///
/// The loader answers a Maple probe in about a millisecond even when the slot
/// is empty -- the DMA has its own 50000-tick timeout -- so this is slack for
/// a lost datagram, not for a slow device.
const REPLY_TIMEOUT: Duration = Duration::from_millis(500);
const SEND_TRIES: usize = 3;

impl<C: ExternalDcIo> MapleBus for Loader<'_, C> {
    fn transact(
        &mut self,
        port: u8,
        unit: u8,
        command: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let tag = tag(port, unit, command);
        let request = request(port, unit, command, payload);
        // Leave the bus alone first, not after: a caller that gives up early
        // must not be able to skip it. See PACE_MS.
        let pace = pace();
        if !pace.is_zero() {
            std::thread::sleep(pace);
        }
        for _ in 0..SEND_TRIES {
            self.0.send_command(request.clone())?;
            let deadline = Instant::now() + REPLY_TIMEOUT;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                // KEEP WAITING WHEN THE BATCH IS NOT OURS. This is the first
                // thing the host does after an upload, and one wakeup drains
                // the whole socket: the first batch is routinely the upload's
                // own tail. Reading "no MAPL in this batch" as "the loader is
                // not answering" is what made the very first probe give up and
                // take the whole scan with it (measured on hardware with a
                // VMUPro in A1, 2026-09-20).
                let Ok(replies) = crate::dispatch::await_result(self.0, Some(left)) else {
                    break;
                };
                if let Some(frame) = response(&replies, tag) {
                    return Ok(frame);
                }
            }
        }
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("no MAPL answer for port {port} unit {unit} command {command}"),
        )) as Box<dyn std::error::Error>)
    }
}

/// Probe every slot and tell each VM2-like card found that `product` is about
/// to run. Returns the cards that took it.
///
/// **Never fatal.** A memory card is optional hardware and this runs in the
/// seconds before `EXEC`; anything that goes wrong here is logged and the title
/// starts anyway.
pub fn announce(
    conn: &mut impl ExternalDcIo,
    product: &str,
    name: Option<&str>,
) -> Vec<Device> {
    announce_on(&mut Loader(conn), product, name)
}

/// The expansion slots a port's main device says are occupied.
///
/// KOS reads exactly this, from exactly this byte: `vbl_chk_subdevs(state, p,
/// resp->src_addr)`, and then probes only the units in it
/// (`vbl_chk_next_subdev`). Bit 5 of the sender marks the port's own
/// peripheral; bits 0..4 are one per slot.
fn reported_units(frame: &[u8]) -> Vec<u8> {
    let sender = frame.get(2).copied().unwrap_or(0);
    if sender & 0x20 == 0 {
        return Vec::new();
    }
    (1..=5u8).filter(|u| sender & (1 << (u - 1)) != 0).collect()
}

fn announce_on(bus: &mut impl MapleBus, product: &str, name: Option<&str>) -> Vec<Device> {
    let mut told = Vec::new();
    if product.is_empty() {
        debug!("VM2: the disc names no product number, nothing to send");
        return told;
    }

    warm_up(bus);

    let payload = set_id_payload(product, name);
    let mut silent = 0;
    // What every slot that was NOT a known card answered. Printed in full only
    // when the scan ends empty: silence then is the one outcome that needs
    // explaining, and a working session does not want eight lines of it.
    let mut rejected: Vec<String> = Vec::new();

    // ENUMERATE THE WAY KOS DOES, which is the sequence openMenu really runs
    // on: ask the port's main device (unit 0), read the expansion slots it
    // reports out of the answer's sender byte, and probe ONLY those. KOS never
    // addresses a slot it has not been told about, and never touches a port
    // whose unit 0 is silent.
    //
    // The old loop asked all eight slots blind. On a console with two
    // controllers that is twelve transactions aimed at ports where no device
    // exists -- traffic KOS never generates, on a bus that turned out to be
    // damaged by being driven wrongly (loader AGENTS.md §8).
    for port in 0..4u8 {
        let letter = (b'A' + port) as char;
        let controller = match probe(bus, port, 0, MAPLE_COMMAND_DEVINFO) {
            Ok(frame) => {
                silent = 0;
                frame
            }
            // Silence here is the LOADER, not the port: an empty port still
            // produces a prompt "nothing at that address" frame. Two in a row
            // means WITH_MAPLE=0 or a dead link -- but ONE is not enough to
            // conclude that, and reading it that way once cost the whole scan.
            Err(e) => {
                silent += 1;
                debug!("VM2: no answer probing port {letter} unit 0 ({e})");
                if silent >= GIVE_UP_AFTER_SILENT {
                    warn!("VM2: the loader is not answering Maple probes; not looking further");
                    return told;
                }
                continue;
            }
        };

        if controller[0] as i8 == MAPLE_RESPONSE_NONE {
            debug!("VM2: {letter}0 -- nothing on this port");
            continue;
        }

        let units = reported_units(&controller);
        rejected.push(format!("{letter}0 (controller) DEVINFO {}", explain(&controller)));
        if units.is_empty() {
            continue;
        }

        for unit in units {
            let slot = format!("{letter}{unit}");
            // DEVINFO before ALLINFO on the card too: openMenu only ever calls
            // check_vm2_present() on a device KOS has already enumerated this
            // way, so ALLINFO is never the first thing a device hears.
            let mut devinfo = probe(bus, port, unit, MAPLE_COMMAND_DEVINFO).ok();

            // THE CONTROLLER SAYS THIS SLOT IS OCCUPIED AND THE CARD DOES NOT
            // ANSWER. That contradiction is the whole hardware failure of
            // 2026-09-20: A0 reported slots 1 and 2, and both answered as if
            // empty. On that console the owner clears it by unplugging the
            // controller; KOS has the software equivalent, and sends it to
            // every device on shutdown "to leave them as we found them"
            // (`maple_dev_reset`). So: reset the slot and ask once more.
            let answered = devinfo
                .as_ref()
                .is_some_and(|d| d[0] as i8 == MAPLE_RESPONSE_DEVINFO);
            if !answered {
                rejected.push(format!(
                    "{slot} did not answer although {letter}0 reports it occupied -- \
                     sent a Maple RESET and asked again"
                ));
                let _ = bus.transact(port, unit, MAPLE_COMMAND_RESET, &[]);
                devinfo = probe(bus, port, unit, MAPLE_COMMAND_DEVINFO).ok();
            }
            let Ok(frame) = probe(bus, port, unit, MAPLE_COMMAND_ALLINFO) else {
                rejected.push(format!("{slot} ALLINFO no answer from the loader"));
                continue;
            };
            let Some(kind) = identify(&frame) else {
                if let Some(d) = &devinfo {
                    rejected.push(format!("{slot} DEVINFO {}", explain(d)));
                }
                rejected.push(format!("{slot} ALLINFO {}", explain(&frame)));
                continue;
            };
            let device = Device { port, unit, kind };

            let mut answer = None;
            for _ in 0..AGAIN_TRIES {
                match bus.transact(port, unit, VM2_COMMAND_SET_ID, &payload) {
                    Ok(frame) => {
                        let code = frame[0] as i8;
                        if code == MAPLE_RESPONSE_AGAIN {
                            continue;
                        }
                        answer = Some(code);
                        break;
                    }
                    Err(e) => {
                        warn!("VM2: {device} did not answer the game ID ({e})");
                        break;
                    }
                }
            }
            match answer {
                Some(MAPLE_RESPONSE_OK) => {
                    info!("VM2: {device} switched to {product}");
                    told.push(device);
                }
                Some(code) => warn!("VM2: {device} refused the game ID (Maple response {code})"),
                None => warn!("VM2: {device} stayed busy; it keeps whatever game was selected"),
            }
        }
    }
    if told.is_empty() {
        // Distinct, in the log, from the give-up above: this one means every
        // port answered and none of them held a card that selects games. With
        // what each one said, because "found nothing" on its own is what made
        // the first hardware failure undiagnosable.
        info!("VM2: no VM2/VMUPro found. What each port answered:");
        for line in &rejected {
            info!("VM2:   {line}");
        }
    } else {
        for line in &rejected {
            debug!("VM2: {line}");
        }
    }
    told
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_bytes(command: &DCLoadCmd) -> &[u8] {
        match &command.cmd {
            DCLoadCmds::Mapl(Some(data)) => data,
            _ => panic!("not a MAPL command"),
        }
    }

    /// The length byte is LONGWORDS. This is the number the loader shifts into
    /// the Maple frame header and the number it copies by, and getting it wrong
    /// is invisible on the wire -- the command goes out, it is just short.
    #[test]
    fn the_length_is_in_longwords() {
        let with_name = request(1, 2, VM2_COMMAND_SET_ID, &set_id_payload("T-8101N", Some("X")));
        assert_eq!(frame_bytes(&with_name)[..4], [1, 2, 33, 36]);
        assert_eq!(frame_bytes(&with_name).len(), 4 + 144);

        let without = request(0, 1, VM2_COMMAND_SET_ID, &set_id_payload("T-8101N", None));
        assert_eq!(frame_bytes(&without)[..4], [0, 1, 33, 4]);
        assert_eq!(frame_bytes(&without).len(), 4 + 16);

        let probe = request(3, 1, MAPLE_COMMAND_ALLINFO, &[]);
        assert_eq!(frame_bytes(&probe), &[3, 1, 2, 0]);
    }

    /// Function codes go on the bus big-endian, and the ID field is NUL-padded
    /// with no terminator when it is exactly full.
    #[test]
    fn the_payload_matches_what_a_vm2_is_written_against() {
        let payload = set_id_payload("MK-51035", Some("SONIC ADVENTURE"));
        assert_eq!(&payload[..4], &[0, 0, 0, 2]);
        assert_eq!(&payload[4..16], b"MK-51035\0\0\0\0");
        assert_eq!(&payload[16..31], b"SONIC ADVENTURE");
        assert!(payload[31..].iter().all(|&b| b == 0));

        // Twelve characters fill the field exactly: strncpy leaves no NUL, and
        // neither do we.
        let full = set_id_payload("123456789012", None);
        assert_eq!(&full[4..16], b"123456789012");
        // Thirteen are cut, not wrapped into the next field.
        let over = set_id_payload("1234567890123", Some("n"));
        assert_eq!(&over[4..16], b"123456789012");
        assert_eq!(over[16], b'n');
    }

    fn allinfo(extended: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 4 + 192];
        frame[0] = MAPLE_RESPONSE_ALLINFO as u8;
        frame[3] = 48;
        frame[EXTENDED_AT..EXTENDED_AT + extended.len()].copy_from_slice(extended);
        frame
    }

    #[test]
    fn a_plain_vmu_is_not_a_vm2() {
        // A VMU answers ALLINFO perfectly well; it just leaves `extended` blank.
        assert_eq!(identify(&allinfo(b"")), None);
        assert_eq!(identify(&allinfo(b"8BITMODS VMUPro ")), Some("VMUPro"));
        assert_eq!(identify(&allinfo(b"vm2 by dreamware")), Some("VM2"));
        assert_eq!(identify(&allinfo(b"Pico2Maple USBBT")), Some("Pico2Maple"));
        // "nothing at that address": a four-byte frame, all failure.
        assert_eq!(identify(&[0xff, 0, 0, 0]), None);
        // A response that is not ALLINFO is not read for a signature, whatever
        // happens to be in the buffer behind it.
        let mut wrong = allinfo(b"VM2 by Dreamware");
        wrong[0] = MAPLE_RESPONSE_OK as u8;
        assert_eq!(identify(&wrong), None);
    }

    /// The loader's `size` is the length, not the datagram's.
    #[test]
    fn the_reply_is_cut_to_what_the_loader_copied() {
        let mut padded = allinfo(b"VM2 by Dreamware");
        padded.extend_from_slice(&[0xaa; 64]);
        let replies = vec![reply(tag(0, 1, MAPLE_COMMAND_ALLINFO), padded, 196)];
        let frame = response(&replies, tag(0, 1, MAPLE_COMMAND_ALLINFO)).expect("a frame");
        assert_eq!(frame.len(), 196);
        assert_eq!(identify(&frame), Some("VM2"));
    }

    /// What actually leaves the host: the four-character code, big-endian
    /// address and size, then the argument block. The loader reads the block
    /// straight out of the datagram, so this encoding IS the interface.
    #[test]
    fn the_datagram_carries_the_argument_block() {
        let wire: Vec<u8> = request(2, 1, MAPLE_COMMAND_ALLINFO, &[]).into();
        assert_eq!(&wire[..4], b"MAPL");
        // `address` is the tag the loader echoes back, not an address.
        assert_eq!(u32::from_be_bytes(wire[4..8].try_into().unwrap()), 0x00020102);
        assert_eq!(u32::from_be_bytes(wire[8..12].try_into().unwrap()), 4);
        assert_eq!(&wire[12..], &[2, 1, 2, 0]);

        // And it survives the parse back, which is how a reply is read.
        let back = DCReturnCmd::try_from(wire).expect("parses");
        let cmd = back.cmd.expect("a command");
        assert_eq!(cmd.cmd, DCLoadCmds::Mapl(Some(vec![2, 1, 2, 0])));
    }

    /// A scripted console: some slots hold a card, the rest answer "nothing
    /// there", and every transaction is written down.
    struct Console {
        cards: Vec<((u8, u8), &'static [u8])>,
        /// Slots whose probe goes unanswered.
        silent: Vec<(u8, u8)>,
        /// How many times each set-id should answer AGAIN before OK.
        busy: usize,
        /// Never clears: always AGAIN.
        forever_busy: bool,
        /// The loader itself does not answer.
        dead: bool,
        /// How many probes answer with the port-A pattern before a real one.
        garbage_first: usize,
        /// Ports with a controller but no card in any slot.
        bare_ports: Vec<u8>,
        /// Slots that answer as empty until they are sent a Maple RESET.
        needs_reset: Vec<(u8, u8)>,
        log: Vec<(u8, u8, u8, usize)>,
    }

    impl Console {
        fn with(cards: Vec<((u8, u8), &'static [u8])>) -> Self {
            Console {
                cards,
                silent: Vec::new(),
                busy: 0,
                forever_busy: false,
                dead: false,
                garbage_first: 0,
                bare_ports: Vec::new(),
                needs_reset: Vec::new(),
                log: Vec::new(),
            }
        }
        fn probes(&self) -> Vec<(u8, u8)> {
            self.log.iter().filter(|e| e.2 == MAPLE_COMMAND_ALLINFO).map(|e| (e.0, e.1)).collect()
        }
        /// Port probes outside the warm-up.
        fn ports_asked(&self) -> Vec<u8> {
            self.log
                .iter()
                .skip(WARM_UP_ROUNDS * 4)
                .filter(|e| e.1 == 0 && e.2 == MAPLE_COMMAND_DEVINFO)
                .map(|e| e.0)
                .collect()
        }
        fn set_ids(&self) -> Vec<(u8, u8, usize)> {
            self.log.iter().filter(|e| e.2 == VM2_COMMAND_SET_ID).map(|e| (e.0, e.1, e.3)).collect()
        }
    }

    impl MapleBus for Console {
        fn transact(
            &mut self,
            port: u8,
            unit: u8,
            command: u8,
            payload: &[u8],
        ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            self.log.push((port, unit, command, payload.len()));
            if self.dead || self.silent.contains(&(port, unit)) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no reply",
                )));
            }
            if self.garbage_first > 0 && unit != 0 {
                self.garbage_first -= 1;
                // What port A actually answered on 2026-09-20.
                return Ok([0x00, 0xff, 0xff, 0xff].repeat(256));
            }
            if command == MAPLE_COMMAND_RESET {
                self.needs_reset.retain(|s| *s != (port, unit));
                return Ok(vec![MAPLE_RESPONSE_OK as u8, 0, 0, 0]);
            }
            if self.needs_reset.contains(&(port, unit)) {
                return Ok(vec![0xff, 0, 0, 0]);
            }
            let card = self.cards.iter().find(|(slot, _)| *slot == (port, unit)).map(|(_, e)| *e);
            if unit == 0 {
                // A port's main device, answering with the slot bitmap in its
                // sender byte -- which is the whole basis of the enumeration.
                let bits: u8 = self
                    .cards
                    .iter()
                    .filter(|((p, _), _)| *p == port)
                    .map(|((_, u), _)| 1u8 << (u - 1))
                    .fold(0, |a, b| a | b);
                if bits == 0 && !self.bare_ports.contains(&port) {
                    return Ok(vec![0xff, 0, 0, 0]);
                }
                let mut frame = vec![0u8; 4 + 112];
                frame[0] = MAPLE_RESPONSE_DEVINFO as u8;
                frame[2] = (port << 6) | 0x20 | bits;
                frame[3] = 28;
                frame[4..8].copy_from_slice(&[0, 0, 0, 1]); // controller
                return Ok(frame);
            }
            match (command, card) {
                (MAPLE_COMMAND_DEVINFO, Some(_)) => {
                    let mut frame = vec![0u8; 4 + 112];
                    frame[0] = MAPLE_RESPONSE_DEVINFO as u8;
                    frame[3] = 28;
                    frame[4..8].copy_from_slice(&[0, 0, 0, 2]); // memcard
                    Ok(frame)
                }
                (MAPLE_COMMAND_ALLINFO, Some(extended)) => Ok(allinfo(extended)),
                (VM2_COMMAND_SET_ID, Some(_)) => {
                    if self.forever_busy {
                        return Ok(vec![MAPLE_RESPONSE_AGAIN as u8, 0, 0, 0]);
                    }
                    if self.busy > 0 {
                        self.busy -= 1;
                        return Ok(vec![MAPLE_RESPONSE_AGAIN as u8, 0, 0, 0]);
                    }
                    Ok(vec![MAPLE_RESPONSE_OK as u8, 0, 0, 0])
                }
                // Nothing at that address.
                _ => Ok(vec![0xff, 0, 0, 0]),
            }
        }
    }

    /// Every slot is tried, and only the card that says it is a VM2 is told.
    /// The plain VMU in B2 answers ALLINFO perfectly and must be left alone --
    /// command 33 means nothing to it.
    #[test]
    fn only_a_vm2_is_told_which_game_is_starting() {
        let mut console = Console::with(vec![
            ((0, 1), b"8BITMODS VMUPro ".as_slice()),
            ((1, 2), b"".as_slice()),
        ]);
        let told = announce_on(&mut console, "MK-51035", Some("SONIC ADVENTURE"));

        assert_eq!(told, vec![Device { port: 0, unit: 1, kind: "VMUPro" }]);
        // ONLY the slots the controllers reported: A1 and B2. Not A2, not B1,
        // and nothing at all on the two empty ports.
        assert_eq!(console.probes(), vec![(0, 1), (1, 2)]);
        assert_eq!(
            console.set_ids(),
            vec![(0, 1, 144)],
            "one set-id, to the VMUPro, carrying func + 12 + 128"
        );
    }

    /// Without a title there is no 128-byte field, and the frame is the short
    /// form the devices also accept.
    #[test]
    fn the_title_is_optional() {
        let mut console = Console::with(vec![((3, 2), b"VM2 by Dreamware".as_slice())]);
        let told = announce_on(&mut console, "T-8101N", None);
        assert_eq!(told, vec![Device { port: 3, unit: 2, kind: "VM2" }]);
        assert_eq!(console.set_ids(), vec![(3, 2, 16)]);
    }

    /// AGAIN is "busy, ask me again", not a refusal.
    #[test]
    fn a_busy_card_is_asked_again() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        console.busy = 2;
        let told = announce_on(&mut console, "MK-51035", None);
        assert_eq!(told.len(), 1);
        assert_eq!(console.set_ids().len(), 3, "two AGAINs, then the one that took");
    }

    /// ...but it is bounded. A card that never clears keeps the game it had,
    /// and the title still starts.
    #[test]
    fn a_card_that_never_clears_is_given_up_on() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        console.forever_busy = true;
        let told = announce_on(&mut console, "MK-51035", None);
        assert!(told.is_empty());
        assert_eq!(console.set_ids().len(), AGAIN_TRIES);
    }

    /// A loader with WITH_MAPLE=0 answers nothing at all. Eight probes at three
    /// tries and a 500 ms timeout each is twelve seconds in front of EXEC, so
    /// the scan stops as soon as silence is established -- which takes two.
    #[test]
    fn a_loader_that_does_not_answer_is_not_asked_eight_times() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        console.dead = true;
        assert!(announce_on(&mut console, "MK-51035", None).is_empty());
        assert_eq!(console.ports_asked().len(), GIVE_UP_AFTER_SILENT);
    }

    /// One unanswered probe is a hiccup, not a verdict: the scan goes on and
    /// still finds the card in the next slot.
    #[test]
    fn one_silent_slot_does_not_end_the_scan() {
        let mut console = Console::with(vec![((1, 2), b"8BITMODS VMUPro ".as_slice())]);
        console.silent = vec![(0, 0)];
        let told = announce_on(&mut console, "MK-51035", None);
        assert_eq!(told, vec![Device { port: 1, unit: 2, kind: "VMUPro" }]);
        assert_eq!(console.ports_asked(), vec![0, 1, 2, 3], "all four still asked");
    }

    /// Two in a row is a verdict.
    #[test]
    fn two_silent_slots_in_a_row_end_it() {
        let mut console = Console::with(vec![((2, 1), b"8BITMODS VMUPro ".as_slice())]);
        console.silent = vec![(0, 0), (1, 0)];
        assert!(announce_on(&mut console, "MK-51035", None).is_empty());
        assert_eq!(console.ports_asked(), vec![0, 1], "stopped after two silences");
    }

    /// A disc with no product number has nothing to select: no Maple traffic
    /// at all, rather than a card switched to the empty string.
    #[test]
    fn no_product_number_means_no_traffic() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        assert!(announce_on(&mut console, "", Some("SOMETHING")).is_empty());
        assert!(console.log.is_empty());
    }

    fn reply(address: u32, frame: Vec<u8>, size: u32) -> DCReturnCmd {
        DCReturnCmd {
            cmd: Some(DCLoadCmd {
                cmd: DCLoadCmds::Mapl(Some(frame)),
                address,
                size,
            }),
            request: None,
            error_code: None,
        }
    }

    #[test]
    fn a_reply_that_is_not_a_maple_frame_is_not_one() {
        let t = tag(0, 1, MAPLE_COMMAND_ALLINFO);
        assert_eq!(response(&[], t), None);
        // Four bytes is the shortest real frame; three is a malformed one.
        assert_eq!(response(&[reply(t, vec![7, 0, 0], 3)], t), None);
    }

    /// Every slot is enumerated the ordinary way before it is asked the
    /// unusual question -- which is the sequence openMenu really performs,
    /// through KOS, and which dcload does not do on its own.
    #[test]
    fn devinfo_comes_before_allinfo_on_every_slot() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        announce_on(&mut console, "MK-51035", None);
        // Unit 0 is the warm-up and the controller probe; the cards are 1 and 2.
        let order: Vec<(u8, u8, u8)> = console
            .log
            .iter()
            .filter(|e| e.1 != 0)
            .map(|e| (e.0, e.1, e.2))
            .collect();
        assert_eq!(
            &order[..3],
            &[
                (0, 1, MAPLE_COMMAND_DEVINFO),
                (0, 1, MAPLE_COMMAND_ALLINFO),
                (0, 1, VM2_COMMAND_SET_ID)
            ]
        );
        // And the port itself was asked before its slot.
        let first_port_probe = console
            .log
            .iter()
            .skip(WARM_UP_ROUNDS * 4)
            .position(|e| e.0 == 0 && e.1 == 0)
            .expect("port A was asked");
        let first_card_probe = console
            .log
            .iter()
            .skip(WARM_UP_ROUNDS * 4)
            .position(|e| e.0 == 0 && e.1 == 1)
            .expect("A1 was asked");
        assert!(first_port_probe < first_card_probe);
        // The bus is driven before any of it is believed.
        let warm: Vec<(u8, u8, u8)> = console
            .log
            .iter()
            .take(WARM_UP_ROUNDS * 4)
            .map(|e| (e.0, e.1, e.2))
            .collect();
        assert!(
            warm.iter().all(|e| e.1 == 0 && e.2 == MAPLE_COMMAND_DEVINFO),
            "the warm-up is DEVINFO to every port's controller: {warm:?}"
        );
        // DEVINFO on the card is not a gate either: the ALLINFO goes out
        // whatever it answered, because a device that answers one and not the
        // other is exactly what this is looking for.
        assert!(order.contains(&(0, 1, MAPLE_COMMAND_ALLINFO)));
    }

    /// `00 ff ff ff` repeating is not an answer: 0 is not a defined Maple
    /// response code, and neither is the loader's own "the DMA wrote nothing"
    /// sentinel. Filing either as "no card here" is what a whole session of
    /// port-A logs looked like.
    #[test]
    fn a_code_outside_the_protocol_is_not_an_answer() {
        assert!(!is_maple_code(0));
        assert!(!is_maple_code(MAPLE_NO_REPLY));
        assert!(!is_maple_code(-6));
        assert!(!is_maple_code(15));
        // The ones that are.
        assert!(is_maple_code(MAPLE_RESPONSE_NONE));
        assert!(is_maple_code(MAPLE_RESPONSE_DEVINFO));
        assert!(is_maple_code(MAPLE_RESPONSE_ALLINFO));
        assert!(is_maple_code(MAPLE_RESPONSE_OK));
        assert!(is_maple_code(MAPLE_RESPONSE_AGAIN));
    }

    /// ...so it is asked again, and a card that answers properly on the second
    /// go is still found.
    #[test]
    fn a_slot_that_answers_nonsense_is_asked_again() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        console.garbage_first = 2;
        let told = announce_on(&mut console, "MK-51035", None);
        assert_eq!(told, vec![Device { port: 0, unit: 1, kind: "VMUPro" }]);
    }

    /// But it is bounded: nonsense forever is reported, not retried forever.
    #[test]
    fn nonsense_forever_is_bounded() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        console.garbage_first = usize::MAX;
        assert!(announce_on(&mut console, "MK-51035", None).is_empty());
        // DEVINFO re-asked, a RESET, DEVINFO re-asked again, ALLINFO re-asked:
        // bounded, and every one of them accounted for.
        let asked = console.log.iter().filter(|e| e.1 == 1 && e.0 == 0).count();
        assert_eq!(asked, 3 * PROBE_TRIES + 1, "{:?}", console.log);
    }

    /// The sender byte of a port's main device is the only place that says
    /// whether the controller can see anything in its slots. A slot the
    /// controller does not report answers exactly like an empty one, so
    /// without this the two are indistinguishable -- which is where the
    /// hardware investigation of 2026-09-20 stalled.
    #[test]
    fn the_controller_says_which_slots_it_sees() {
        let devinfo = |sender: u8| {
            let mut f = vec![0u8; 4 + 112];
            f[0] = MAPLE_RESPONSE_DEVINFO as u8;
            f[2] = sender;
            f[3] = 28;
            f
        };
        // Port A's main peripheral, nothing in either slot.
        assert_eq!(
            slots_reported(&devinfo(0x20)).as_deref(),
            Some("it reports NO expansion slot occupied")
        );
        // Both slots full.
        assert_eq!(
            slots_reported(&devinfo(0x23)).as_deref(),
            Some("it reports slots 1 and 2 occupied")
        );
        // Slot 2 only, on port B (the port bits do not disturb it).
        assert_eq!(
            slots_reported(&devinfo(0x62)).as_deref(),
            Some("it reports slots 2 occupied")
        );
        // A sub-unit's own answer is not a main device and says nothing here.
        assert_eq!(slots_reported(&devinfo(0x01)), None);
        // And it reaches the line the log prints.
        assert!(
            explain(&devinfo(0x23)).contains("slots 1 and 2 occupied"),
            "{}",
            explain(&devinfo(0x23))
        );
    }

    /// KOS asks a port's main device which slots are occupied and probes only
    /// those (`vbl_chk_subdevs` / `vbl_chk_next_subdev`). A slot the controller
    /// does not report is never addressed, and a port whose unit 0 is silent is
    /// left alone entirely -- twelve transactions a scan, on a console with two
    /// controllers, aimed at nothing.
    #[test]
    fn a_slot_the_controller_does_not_report_is_never_addressed() {
        let mut console = Console::with(vec![((0, 2), b"8BITMODS VMUPro ".as_slice())]);
        console.bare_ports = vec![1]; // a controller with empty slots
        let told = announce_on(&mut console, "MK-51035", None);
        assert_eq!(told, vec![Device { port: 0, unit: 2, kind: "VMUPro" }]);

        let after_warmup: Vec<(u8, u8)> = console
            .log
            .iter()
            .skip(WARM_UP_ROUNDS * 4)
            .map(|e| (e.0, e.1))
            .collect();
        // A1 was never reported, so it was never asked.
        assert!(!after_warmup.contains(&(0, 1)), "{after_warmup:?}");
        // Port B has a controller but no card: its unit 0 is asked, its slots
        // are not.
        assert!(after_warmup.contains(&(1, 0)));
        assert!(!after_warmup.contains(&(1, 1)) && !after_warmup.contains(&(1, 2)));
        // Ports C and D answer nothing at unit 0, so nothing below it is tried.
        assert!(!after_warmup.iter().any(|(p, u)| (*p == 2 || *p == 3) && *u != 0));
    }

    /// A controller that reports a slot occupied while the slot answers as
    /// empty is a contradiction, not a verdict. KOS's answer to a device in a
    /// state like that is a Maple RESET, which is what the owner was doing by
    /// hand with a screwdriver's patience.
    #[test]
    fn a_slot_that_answers_as_empty_is_reset_and_asked_again() {
        let mut console = Console::with(vec![((0, 1), b"8BITMODS VMUPro ".as_slice())]);
        console.needs_reset = vec![(0, 1)];
        let told = announce_on(&mut console, "MK-51035", None);
        assert_eq!(told, vec![Device { port: 0, unit: 1, kind: "VMUPro" }]);
        assert!(
            console.log.iter().any(|e| (e.0, e.1, e.2) == (0, 1, MAPLE_COMMAND_RESET)),
            "no RESET was sent"
        );
    }

    /// ...but a card that answers normally is never reset. A plain VMU is not
    /// a VM2 and that is not a fault to recover from.
    #[test]
    fn a_healthy_card_is_never_reset() {
        let mut console = Console::with(vec![((0, 1), b"".as_slice())]);
        assert!(announce_on(&mut console, "MK-51035", None).is_empty());
        assert!(!console.log.iter().any(|e| e.2 == MAPLE_COMMAND_RESET));
    }

    /// A firmware is free to pad its name with NUL instead of a space, or to
    /// put a version after it. openMenu's exact 16-byte compare says no to
    /// both; the substring match says yes, and the name is the distinctive
    /// part anyway.
    #[test]
    fn the_name_is_matched_not_the_padding() {
        assert_eq!(identify(&allinfo(b"8BITMODS VMUPro ")), Some("VMUPro"));
        // NUL-padded instead of space-padded.
        assert_eq!(identify(&allinfo(b"8BITMODS VMUPro")), Some("VMUPro"));
        // A version after the name.
        assert_eq!(identify(&allinfo(b"8BITMODS VMUPro v2.1")), Some("VMUPro"));
        // A real Sega VMU's own extended string, measured on hardware: it is
        // not blank, and it must not match anything.
        assert_eq!(
            identify(&allinfo(b"Version 1.005,1999/04/28,315-6124-07,SEG")),
            None
        );
        assert_eq!(identify(&allinfo(b"")), None);
    }

    /// `identify` says `None` four different ways, and a scan that prints
    /// nothing cannot be told from a scan that found nothing. Each way has to
    /// come out of `explain` as its own sentence -- this is the instrument the
    /// hardware failure of 2026-09-20 had no version of.
    #[test]
    fn every_way_of_finding_nothing_says_which_one_it_was() {
        // Empty slot.
        let empty = vec![0xff, 0, 0, 0];
        assert_eq!(identify(&empty), None);
        assert!(explain(&empty).contains("nothing plugged in"), "{}", explain(&empty));

        // A device that refuses ALLINFO (BADCMD). Nothing can be read out of
        // such a frame, so the bytes themselves are the report.
        let refused = vec![0xfdu8, 0, 0, 0];
        assert_eq!(identify(&refused), None);
        let said = explain(&refused);
        assert!(said.contains("response -3"), "{said}");
        assert!(said.contains("fd 00 00 00"), "{said}");

        // The loader's sentinel: the DMA cycle wrote nothing at all. This is
        // the reading that was indistinguishable from stale RAM before the
        // loader started stamping the buffer.
        let nothing = vec![0xeeu8, 0xee, 0xee, 0xee];
        assert_eq!(identify(&nothing), None);
        assert!(explain(&nothing).contains("wrote nothing at all"), "{}", explain(&nothing));

        // An ALLINFO answer too short to carry `extended` at all. This is the
        // one that used to vanish: `frame.get(116..132)` was None and the
        // whole thing read as "no card here".
        let mut short = allinfo(b"");
        short.truncate(4 + 112);
        short[3] = 28;
        assert_eq!(identify(&short), None);
        assert!(extended(&short).is_empty());
        let said = explain(&short);
        assert!(said.contains("stops at 116 bytes"), "{said}");
        assert!(said.contains("extended field at 116"), "{said}");

        // A full answer from a card nobody has heard of: the bytes come out.
        let unknown = allinfo(b"ACME MapleThing!");
        assert_eq!(identify(&unknown), None);
        let said = explain(&unknown);
        assert!(said.contains("ACME MapleThing!"), "{said}");
        assert!(said.contains("196 bytes"), "{said}");
    }

    /// The product name is read out too -- it is the field a plain VMU fills
    /// in, and it says which device answered when `extended` is empty.
    #[test]
    fn the_product_name_is_reported() {
        let mut frame = allinfo(b"");
        frame[4 + 18..4 + 18 + 12].copy_from_slice(b"Visual Memo\0");
        assert!(explain(&frame).contains("Visual Memo"), "{}", explain(&frame));
    }

    /// THE DEFECT THAT SHIPPED. The first thing this module does happens right
    /// after an upload, and one wakeup drains the whole socket -- so the batch
    /// a probe sees first is routinely somebody else's. An answer is only ours
    /// if it carries our tag, and a batch without it is not a silent console.
    #[test]
    fn another_commands_answer_is_not_this_ones() {
        let mine = tag(0, 1, MAPLE_COMMAND_ALLINFO);
        let batch = vec![
            // An upload's last DoneBinary, still in the socket.
            DCReturnCmd {
                cmd: Some(DCLoadCmd { cmd: DCLoadCmds::DoneBinary(), address: 0x8c01_0000, size: 0 }),
                request: None,
                error_code: None,
            },
            // A late answer to the PREVIOUS slot's probe.
            reply(tag(0, 2, MAPLE_COMMAND_ALLINFO), allinfo(b"8BITMODS VMUPro "), 196),
        ];
        assert_eq!(response(&batch, mine), None, "neither of those is ours");

        // ...and the real one, in a later batch, is.
        let ours = vec![reply(mine, allinfo(b"8BITMODS VMUPro "), 196)];
        assert!(response(&ours, mine).is_some());
    }
}
