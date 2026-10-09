//! The whole bridge, with a fake RetroAchievements server and a fake console:
//! login, the Dreamcast hash of a synthetic ISO, the set, the table sent over
//! UDP, frames fed back, a pointer that grows the table, and both achievements
//! awarded to the server.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::frames::build;
use super::table::Assembler;
use super::session::{self, Config};
use super::tests::SET;
use crate::cmds::DCReturnCmd;

/// One session at a time: a disc swap is announced to the running session through a
/// global mailbox (`session::disc_changed`), which two sessions would share.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// What the fake server answers, in order, when a request comes more than once.
#[derive(Default)]
struct Plan {
    sets: std::collections::VecDeque<String>,
    game_ids: std::collections::VecDeque<u32>,
}

fn fake_server(requests: Arc<Mutex<Vec<String>>>, plan: Arc<Mutex<Plan>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let body_at = loop {
                let n = s.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(p + 4);
                }
            };
            let Some(at) = body_at else { continue };
            let head = String::from_utf8_lossy(&buf[..at]).to_lowercase();
            let want: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < at + want {
                let n = s.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let form = String::from_utf8_lossy(&buf[at..]).to_string();
            let param = |k: &str| {
                form.split('&')
                    .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                    .unwrap_or("")
                    .to_string()
            };
            let r = param("r");
            requests.lock().unwrap().push(format!("{r} a={}", param("a")));
            let out = match r.as_str() {
                "login2" => r#"{"Success":true,"User":"tester","DisplayName":"Tester","Token":"tok","Score":0,"SoftcoreScore":0,"Messages":0,"Permissions":1,"AccountType":"Registered"}"#.to_string(),
                "achievementsets" => plan.lock().unwrap().sets.pop_front().unwrap_or_else(|| SET.to_string()),
                "gameid" => format!(
                    r#"{{"Success":true,"GameID":{}}}"#,
                    plan.lock().unwrap().game_ids.pop_front().unwrap_or(42)
                ),
                "startsession" => r#"{"Success":true,"Unlocks":[],"HardcoreUnlocks":[],"ServerNow":1700000000}"#.to_string(),
                "awardachievement" => r#"{"Success":true,"Score":5,"SoftcoreScore":5,"AchievementID":1,"AchievementsRemaining":1}"#.to_string(),
                _ => r#"{"Success":true}"#.to_string(),
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                out.len()
            );
        }
    });
    port
}

/// RAFR bytes: one keyframe of `words`, as the loader frames it.
fn rafr(seq: u32, generation: u32, frame: u16, words: &[u32]) -> Vec<u8> {
    let payload = build::datagram(generation, &build::keyframe(frame, words));
    let mut out = b"RAFR".to_vec();
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// The console's memory. A trigger that is TRUE on its first look waits for
/// a false one before it may fire (rcheevos' "waiting" state, so that loading
/// a save does not unlock things): the values come up after a few frames.
fn console_value(addr: u32, frames_in_generation: u32) -> u32 {
    let up = frames_in_generation >= 6;
    match addr {
        0x1000 => if up { 5 } else { 0 },
        0x2000 => 0x3000, // a pointer
        0x3010 => if up { 1 } else { 0 }, // what it points at
        _ => 0,
    }
}

/// One session against the fake server and the fake console. `ce`: the title is
/// Windows CE, and the loader answers that its room there is `ce_room` words.
/// Returns whether each achievement was awarded and how many tables were sent.
fn session_run(ce: bool, ce_room: u32, seconds: u64) -> ((bool, bool), u32) {
    session_run_with(None, console_value, ce, ce_room, seconds)
}

/// The same, with another set (`None`: `SET`) and another console memory.
fn session_run_with(
    set: Option<&str>,
    value: fn(u32, u32) -> u32,
    ce: bool,
    ce_room: u32,
    seconds: u64,
) -> ((bool, bool), u32) {
    let (awards, tables, _) = session_run_slow(set, value, ce, ce_room, seconds, None);
    (awards, tables)
}

/// The same, also returning the slow path's reads (`SBIQ`: wire address, size),
/// which the fake console answers from `value` like the loader does. `lose`: the
/// first `RACT` of that generation never arrives (the console goes on sending
/// the frames of the table it has).
fn session_run_slow(
    set: Option<&str>,
    value: fn(u32, u32) -> u32,
    ce: bool,
    ce_room: u32,
    seconds: u64,
    lose: Option<u32>,
) -> ((bool, bool), u32, Vec<(u32, u32)>) {
    // A Dreamcast ISO to hash: IP.BIN in the system area, the boot file in the
    // filesystem. Skipped where there is no tool to build one.
    let dir = std::env::temp_dir().join(format!("dcload-ra-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("iso")).unwrap();
    let mut ip = vec![0u8; 32768];
    ip[..16].copy_from_slice(b"SEGA SEGAKATANA ");
    ip[96..112].copy_from_slice(b"1ST_READ.BIN    ");
    std::fs::write(dir.join("IP.BIN"), &ip).unwrap();
    std::fs::write(dir.join("iso/1ST_READ.BIN"), vec![9u8; 8192]).unwrap();
    let iso = dir.join("t.iso");
    let made = std::process::Command::new("genisoimage")
        .args(["-quiet", "-V", "RATEST", "-G"])
        .arg(dir.join("IP.BIN"))
        .arg("-l")
        .arg("-o")
        .arg(&iso)
        .arg(dir.join("iso"))
        .status();
    if !made.is_ok_and(|s| s.success()) {
        eprintln!("skipped: genisoimage is not available");
        return ((true, true), 2, vec![]);
    }

    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut plan = Plan::default();
    // The same set each time it is asked for: a set that does not fit is loaded
    // again (trimmed on this side, `session::trim_sets`).
    plan.sets.extend(set.map(str::to_string).into_iter().cycle().take(3));
    let port = fake_server(requests.clone(), Arc::new(Mutex::new(plan)));
    let login = Some(("tester".to_string(), "tok".to_string()));

    // The fake console: a UDP socket the host sends the table to.
    let console = UdpSocket::bind("127.0.0.1:0").unwrap();
    console.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    host.connect(console.local_addr().unwrap()).unwrap();

    let handle = session::start(
        Config {
            hardcore: false,
            ce,
            host: Some(format!("http://127.0.0.1:{port}")),
            login,
            discord: None,
        },
        Some(iso.to_string_lossy().into()),
        host,
    )
        .expect("the session starts");
    let sink = handle.sink();

    let (mut seq, mut frame) = (0u32, 0u16);
    let mut tables = 0;
    let mut parts = Assembler::default();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let awarded = |r: &Arc<Mutex<Vec<String>>>| {
        let r = r.lock().unwrap();
        (
            r.iter().any(|l| l == "awardachievement a=1"),
            r.iter().any(|l| l == "awardachievement a=2"),
        )
    };
    let mut current: Option<(u32, Vec<u32>, Vec<(usize, u32, i32)>)> = None;
    let mut in_generation = 0u32;
    let mut slow_reads = Vec::new();
    let mut lost = false;
    while Instant::now() < deadline && awarded(&requests) != (true, true) {
        let mut buf = [0u8; 2048];
        if let Ok((n, _)) = console.recv_from(&mut buf) {
            if &buf[..4] == b"SBIQ" {
                // A memory read, answered as cmd_sendbinq does: SBIN pieces of
                // at most 1440 bytes, then a DBIN naming the range served.
                let addr = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                let size = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                slow_reads.push((addr, size));
                let bytes: Vec<u8> = (0..size)
                    .map(|i| {
                        let a = (addr + i) & 0x00ff_ffff;
                        (value(a & !3, in_generation) >> (8 * (a & 3))) as u8
                    })
                    .collect();
                for (k, piece) in bytes.chunks(1440).enumerate() {
                    let mut p = b"SBIN".to_vec();
                    p.extend_from_slice(&(addr + 1440 * k as u32).to_be_bytes());
                    p.extend_from_slice(&(piece.len() as u32).to_be_bytes());
                    p.extend_from_slice(piece);
                    let cmd = DCReturnCmd::try_from(p).unwrap();
                    assert!(sink.lock().unwrap().claim(&cmd), "our own read's answer is claimed");
                }
                let mut d = b"DBIN".to_vec();
                d.extend_from_slice(&addr.to_be_bytes());
                d.extend_from_slice(&size.to_be_bytes());
                assert!(sink.lock().unwrap().claim(&DCReturnCmd::try_from(d).unwrap()));
                continue;
            }
            // RACT: id, generation, size, then the ranges
            assert_eq!(&buf[..4], b"RACT");
            assert!(n >= 16);
            let generation = u32::from_be_bytes(buf[4..8].try_into().unwrap());
            tables += 1;
            if lose == Some(generation) && !lost {
                lost = true;
                continue;
            }
            // a part; only the one that completes the table is answered
            let size = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
            let Some((ranges, specs)) = parts.push(generation, &buf[12..12 + size]) else {
                continue;
            };
            let addrs: Vec<u32> =
                ranges.iter().flat_map(|&(off, w)| (0..w).map(move |k| off + 4 * k)).collect();
            // then the chains the loader follows itself: parent index << 22 | shift flag
            // << 21 | offset in words (signed, 21 bits)
            let chains: Vec<(usize, u32, i32)> = specs
                .iter()
                .map(|&v| ((v >> 22) as usize, if v >> 21 & 1 != 0 { 8 } else { 0 }, ((v << 11) as i32) >> 11))
                .collect();
            // the loader's answer
            let mut reply = b"RACT".to_vec();
            reply.extend_from_slice(&generation.to_be_bytes());
            reply.extend_from_slice(&0u32.to_be_bytes());
            // the room: Katana, Windows CE
            reply.extend_from_slice(&512u32.to_be_bytes());
            reply.extend_from_slice(&ce_room.to_be_bytes());
            let cmd = DCReturnCmd::try_from(reply).unwrap();
            sink.lock().unwrap().claim(&cmd);
            current = Some((generation, addrs, chains));
            in_generation = 0;
        }
        if let Some((generation, addrs, chains)) = current.as_ref() {
            let mut words: Vec<u32> = addrs.iter().map(|a| value(*a, in_generation)).collect();
            // what the loader does: (parent & 0xffffff) + offset, one word
            for (parent, shift, off) in chains {
                let at = ((words[*parent] >> shift) & 0xff_ffff).wrapping_add((*off as u32) << 2) & !3;
                words.push(value(at, in_generation));
            }
            in_generation += 1;
            frame += 1;
            let cmd = DCReturnCmd::try_from(rafr(seq, *generation, frame, &words)).unwrap();
            seq += 1;
            sink.lock().unwrap().claim(&cmd);
        }
    }
    drop(handle);
    let _ = std::fs::remove_dir_all(&dir);
    (awarded(&requests), tables, slow_reads)
}

#[test]
fn two_achievements_are_awarded_through_a_pointer() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let (awards, tables) = session_run(false, 248, 20);
    assert_eq!(awards, (true, true), "tables {tables}");
    assert_eq!(tables, 1, "the loader follows the pointer itself: no second table");

    // Windows CE with room for the table: the same.
    let (awards, _) = session_run(true, 248, 20);
    assert_eq!(awards, (true, true), "Windows CE with room");

    // Windows CE with room for less than the table (it reads 3 words, then 4 once
    // the pointer's target is known): refused, nothing is judged.
    let (awards, tables) = session_run(true, 2, 4);
    assert_eq!(awards, (false, false), "a table that does not fit must not be sampled");
    assert_eq!(tables, 1, "and no second table is asked for");
}

/// A pointer two levels deep: `0x2000` -> `+4` -> `+0x10`.
const SET_DEEP: &str = r#"{"Success":true,"GameId":42,"Title":"Test Game","ConsoleId":40,
"ImageIconUrl":"/Images/000001.png","RichPresencePatch":"",
"Sets":[{"AchievementSetId":7,"GameId":42,"Title":"Test Game","Type":"core",
"ImageIconUrl":"/Images/000001.png",
"Achievements":[
{"ID":1,"Title":"Direct","Description":"d","Flags":3,"Points":5,
 "MemAddr":"0xH001000=5","Author":"a","BadgeName":"00001","Created":1,"Modified":1,"Type":""},
{"ID":2,"Title":"Pointer","Description":"p","Flags":3,"Points":10,
 "MemAddr":"I:0xW002000_I:0xW000004_0xH000010=1","Author":"a","BadgeName":"00002","Created":1,"Modified":1,"Type":""}
],"Leaderboards":[]}]}"#;

/// For 40 frames the root pointer holds something that is not an address and not
/// a multiple of 4, different every frame (a pointer field between levels); then
/// 0x3000, whose +4 holds 0x4000, whose +0x10 is the flag. Everything else holds
/// a value that, read as a pointer, leads elsewhere again.
fn console_skewed(addr: u32, f: u32) -> u32 {
    let up = f >= 46;
    match addr {
        0x1000 => if up { 5 } else { 0 },
        0x2000 if f < 40 => 0x5001 + 0x40 * f,
        0x2000 => 0x3000,
        0x3004 => 0x4000,
        0x4010 => if up { 1 } else { 0 },
        a => a.wrapping_mul(0x9e37_79b1) & 0x00ff_fffc | 0x8c00_0000,
    }
}

#[test]
fn a_pointer_that_holds_no_address_neither_grows_the_table_nor_stops_judging() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let (awards, tables) = session_run_with(Some(SET_DEEP), console_skewed, false, 248, 20);
    assert_eq!(awards, (true, true), "tables {tables}");
    assert_eq!(tables, 1, "reads through a misaligned pointer are no reason to grow");
}

/// `SET` with a rich presence that reads 600 words: more than the loader
/// samples (512), while the achievements read 3.
fn set_with_big_rich_presence() -> String {
    let mut v: serde_json::Value = serde_json::from_str(SET).unwrap();
    let conds: Vec<String> = (0..600).map(|i| format!("0xX{:06x}=1", 0x10_0000 + 4 * i)).collect();
    v["RichPresencePatch"] = format!("Display:\n?{}?Racing\nIn the menus", conds.join("_")).into();
    v.to_string()
}

/// The table is built without the rich presence, the achievements count, and
/// the rich presence's 600 words are read slowly through P1 (a Katana title).
#[test]
fn a_set_too_big_for_the_loader_reads_its_rich_presence_slowly() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let set = set_with_big_rich_presence();
    let (awards, tables, reads) = session_run_slow(Some(&set), console_value, false, 248, 20, None);
    assert_eq!(awards, (true, true), "the achievements still count; tables {tables}");
    if tables == 2 && reads.is_empty() {
        return; // skipped: no genisoimage
    }
    let lo = 0x8c10_0000u32;
    let covered: u32 = reads
        .iter()
        .filter(|&&(a, _)| (lo..lo + 2400).contains(&a))
        .map(|&(_, n)| n)
        .sum();
    assert!(covered >= 2400, "the rich presence's words are read: {reads:x?}");
}

/// A 32-bit pointer (`0xX`), which the loader does not follow itself: its target
/// is found by reading it, and the table grows to a second generation.
const SET_32: &str = r#"{"Success":true,"GameId":42,"Title":"Test Game","ConsoleId":40,
"ImageIconUrl":"/Images/000001.png","RichPresencePatch":"",
"Sets":[{"AchievementSetId":7,"GameId":42,"Title":"Test Game","Type":"core",
"ImageIconUrl":"/Images/000001.png",
"Achievements":[
{"ID":1,"Title":"Direct","Description":"d","Flags":3,"Points":5,
 "MemAddr":"0xH001000=5","Author":"a","BadgeName":"00001","Created":1,"Modified":1,"Type":""},
{"ID":2,"Title":"Pointer","Description":"p","Flags":3,"Points":10,
 "MemAddr":"I:0xX002000_0xH000010=1","Author":"a","BadgeName":"00002","Created":1,"Modified":1,"Type":""}
],"Leaderboards":[]}]}"#;

/// The second table's first `RACT` is lost while the console goes on sampling
/// the first: the host must send it again. Frames of the old table are no proof
/// that the new one arrived (Sega Rally 2, 2026-10-08: never sent again, nothing
/// judged for the rest of the session).
#[test]
fn a_lost_table_is_sent_again_while_the_old_one_is_sampled() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let (awards, tables, _) = session_run_slow(Some(SET_32), console_value, false, 248, 20, Some(2));
    assert_eq!(awards, (true, true), "tables {tables}");
    if tables == 2 {
        return; // skipped: no genisoimage
    }
    assert!(tables >= 3, "the lost table was sent again: {tables}");
}

/// A synthetic Dreamcast ISO whose IP.BIN carries `tag`: two discs of one game differ
/// in their headers, and the hash starts with the header.
fn make_iso(dir: &std::path::Path, tag: u8) -> Option<std::path::PathBuf> {
    let work = dir.join(format!("disc{tag}"));
    std::fs::create_dir_all(work.join("iso")).unwrap();
    let mut ip = vec![0u8; 32768];
    ip[..16].copy_from_slice(b"SEGA SEGAKATANA ");
    ip[0x80] = tag;
    ip[96..112].copy_from_slice(b"1ST_READ.BIN    ");
    std::fs::write(work.join("IP.BIN"), &ip).unwrap();
    std::fs::write(work.join("iso/1ST_READ.BIN"), vec![tag; 8192]).unwrap();
    let iso = work.join("t.iso");
    let made = std::process::Command::new("genisoimage")
        .args(["-quiet", "-V", "RATEST", "-G"])
        .arg(work.join("IP.BIN"))
        .arg("-l")
        .arg("-o")
        .arg(&iso)
        .arg(work.join("iso"))
        .status();
    made.is_ok_and(|s| s.success()).then_some(iso)
}

/// What a disc swap did, as the fake console and server saw it.
struct Swap {
    requests: Vec<String>,
    /// Each table the console was sent: its generation and its ranges' offsets.
    tables: Vec<(u32, Vec<u32>)>,
}

/// Start a session on disc 1 of a two-disc game, wait until the console has its
/// table, swap to disc 2 and watch what follows. `second_game`: the game
/// RetroAchievements says disc 2 belongs to, and the set it then serves.
fn swap_scenario(second_game: u32, second_set: &str) -> Option<Swap> {
    let dir = std::env::temp_dir().join(format!("dcload-ra-swap-{}-{second_game}", std::process::id()));
    let (disc1, disc2) = (make_iso(&dir, 1)?, make_iso(&dir, 2)?);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let plan = Arc::new(Mutex::new(Plan::default()));
    plan.lock().unwrap().sets.extend([SET.to_string(), second_set.to_string()]);
    plan.lock().unwrap().game_ids.push_back(second_game);
    let port = fake_server(requests.clone(), plan);

    let console = UdpSocket::bind("127.0.0.1:0").unwrap();
    console.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    host.connect(console.local_addr().unwrap()).unwrap();
    let handle = session::start(
        Config {
            hardcore: false,
            ce: false,
            host: Some(format!("http://127.0.0.1:{port}")),
            login: Some(("tester".to_string(), "tok".to_string())),
            discord: None,
        },
        Some(disc1.to_string_lossy().into()),
        host,
    )
    .expect("the session starts");
    let sink = handle.sink();

    let mut tables: Vec<(u32, Vec<u32>)> = Vec::new();
    let mut parts = Assembler::default();
    let (mut seq, mut frame) = (0u32, 0u16);
    let mut current: Option<(u32, usize)> = None; // generation, words
    let mut swapped_at: Option<Instant> = None;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(25) {
        let mut buf = [0u8; 2048];
        if let Ok((_, _)) = console.recv_from(&mut buf) {
            assert_eq!(&buf[..4], b"RACT");
            let generation = u32::from_be_bytes(buf[4..8].try_into().unwrap());
            let size = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
            let Some((ranges, specs)) = parts.push(generation, &buf[12..12 + size]) else {
                continue;
            };
            let offsets: Vec<u32> = ranges.iter().map(|r| r.0).collect();
            let words: usize = ranges.iter().map(|r| r.1 as usize).sum();
            let nc = specs.len();
            tables.push((generation, offsets));
            let mut reply = b"RACT".to_vec();
            reply.extend_from_slice(&generation.to_be_bytes());
            reply.extend_from_slice(&0u32.to_be_bytes());
            reply.extend_from_slice(&512u32.to_be_bytes());
            reply.extend_from_slice(&248u32.to_be_bytes());
            sink.lock().unwrap().claim(&DCReturnCmd::try_from(reply).unwrap());
            current = Some((generation, words + nc));
            // the table is there: swap discs, once
            if swapped_at.is_none() && tables.len() == 1 {
                super::session::disc_changed(&disc2.to_string_lossy());
                swapped_at = Some(Instant::now());
            }
        }
        if let Some((generation, words)) = current {
            frame += 1;
            let cmd = DCReturnCmd::try_from(rafr(seq, generation, frame, &vec![0u32; words])).unwrap();
            seq += 1;
            sink.lock().unwrap().claim(&cmd);
        }
        if swapped_at.is_some_and(|t| t.elapsed() > Duration::from_secs(4)) {
            break;
        }
    }
    drop(handle);
    let _ = std::fs::remove_dir_all(&dir);
    let requests = requests.lock().unwrap().clone();
    Some(Swap { requests, tables })
}

#[test]
fn a_disc_swap_keeps_the_set_for_the_same_game_and_loads_another_for_another() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    // Disc 2 of the SAME game (RetroAchievements answers the same id as disc 1's):
    // the set stays, no new table, and the new hash was looked up.
    let Some(same) = swap_scenario(42, SET) else { return };
    let n = |r: &[String], what: &str| r.iter().filter(|l| l.starts_with(what)).count();
    assert_eq!(n(&same.requests, "gameid"), 1, "the new disc's hash is looked up: {:?}", same.requests);
    assert_eq!(n(&same.requests, "achievementsets"), 1, "no second set: {:?}", same.requests);
    assert_eq!(same.tables.len(), 1, "the table is the same one: {:?}", same.tables);

    // A disc that RetroAchievements puts under ANOTHER game: its set is loaded and
    // its table sent, a new generation.
    let Some(other) = swap_scenario(77, super::tests::CHAINS) else { return };
    assert_eq!(n(&other.requests, "gameid"), 1, "{:?}", other.requests);
    assert_eq!(n(&other.requests, "achievementsets"), 2, "the other game's set: {:?}", other.requests);
    assert!(other.tables.len() >= 2, "a new table: {:?}", other.tables);
    let (first, last) = (&other.tables[0], other.tables.last().unwrap());
    assert!(last.0 > first.0, "a new generation");
    assert!(last.1.contains(&0x3000), "the second game's ranges: {:?}", last.1);
    assert!(!first.1.contains(&0x3000), "and not the first's: {:?}", first.1);
}
