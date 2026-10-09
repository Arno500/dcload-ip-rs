//! Discord Rich Presence (`--discord <application id>`): what the
//! RetroAchievements session knows -- the game, its rich presence, the
//! achievements earned -- shown on the user's Discord profile.
//!
//! Discord's local IPC, written here rather than taken from a crate (the usual
//! one brings serde, uuid and thiserror for five messages): a named pipe
//! `\\.\pipe\discord-ipc-N` on Windows, a Unix socket `discord-ipc-N` in the
//! runtime directory elsewhere, N from 0 to 9. A frame is an opcode and a
//! length, both u32 little-endian, then that many bytes of JSON. Opcodes: 0
//! handshake, 1 frame (commands and their answers), 2 close (Discord refused:
//! a wrong application id), 3 ping, 4 pong.
//!
//! The pipe lives on its own thread: Discord may not be running, may start or
//! quit during the session, and a blocking write to it must never hold the
//! RetroAchievements thread. Discord takes about one activity update every 15
//! seconds per client; anything faster is dropped there, so updates are
//! coalesced here and the last one wins.

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

/// The least time between two updates Discord honours.
const UPDATE_EVERY: Duration = Duration::from_secs(15);
/// How long after a failed connection to look for Discord again.
const RETRY_EVERY: Duration = Duration::from_secs(30);

/// What the profile shows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Presence {
    /// First line: the game.
    pub details: String,
    /// Second line: the game's rich presence.
    pub state: String,
    /// The game's badge (a URL: Discord fetches external images itself).
    pub image: Option<String>,
    /// Shown over the badge: the achievements earned.
    pub image_text: Option<String>,
    /// A button to the game's page on retroachievements.org.
    pub url: Option<String>,
    /// Unix seconds: Discord counts the time played from it.
    pub start: u64,
}

impl Presence {
    /// The `activity` object of `SET_ACTIVITY`. Discord refuses a text shorter
    /// than 2 characters or longer than 128, so those are left out or cut.
    fn activity(&self) -> Value {
        fn text(s: &str) -> Option<String> {
            let s: String = s.trim().chars().take(128).collect();
            (s.chars().count() >= 2).then_some(s)
        }
        let mut a = json!({ "type": 0, "timestamps": { "start": self.start } });
        if let Some(d) = text(&self.details) {
            a["details"] = d.into();
        }
        if let Some(s) = text(&self.state) {
            a["state"] = s.into();
        }
        if let Some(img) = &self.image {
            a["assets"] = json!({ "large_image": img });
            if let Some(t) = self.image_text.as_deref().and_then(text) {
                a["assets"]["large_text"] = t.into();
            }
        }
        if let Some(url) = &self.url {
            a["buttons"] = json!([{ "label": "RetroAchievements", "url": url }]);
        }
        a
    }
}

/// Now, in Unix seconds.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The thread that owns the pipe. Dropping it clears the profile.
pub struct Discord {
    tx: Sender<Option<Presence>>,
}

impl Discord {
    pub fn start(app_id: String) -> Discord {
        let (tx, rx) = channel();
        let spawned = std::thread::Builder::new()
            .name("discord".into())
            .spawn(move || run(&app_id, rx, connect));
        if let Err(e) = spawned {
            warn!("Discord: cannot start its thread: {e}");
        }
        Discord { tx }
    }

    /// Show this; only the latest is sent, and not before Discord takes it.
    pub fn show(&self, p: Presence) {
        let _ = self.tx.send(Some(p));
    }
}

impl Drop for Discord {
    fn drop(&mut self) {
        let _ = self.tx.send(None);
    }
}

/// A connected pipe, with the handshake done.
struct Ipc<S: Read + Write> {
    s: S,
    nonce: u64,
}

impl<S: Read + Write> Ipc<S> {
    fn handshake(s: S, app_id: &str) -> Result<Self, String> {
        let mut ipc = Ipc { s, nonce: 0 };
        ipc.write(0, &json!({ "v": 1, "client_id": app_id }))?;
        let (op, v) = ipc.read()?;
        match (op, v["evt"].as_str()) {
            (1, Some("READY")) => Ok(ipc),
            _ => Err(format!("Discord refused the connection: {}", message(&v))),
        }
    }

    /// `SET_ACTIVITY`; `None` clears the profile.
    fn set_activity(&mut self, p: Option<&Presence>) -> Result<(), String> {
        self.nonce += 1;
        let activity = p.map(Presence::activity).unwrap_or(Value::Null);
        let cmd = json!({
            "cmd": "SET_ACTIVITY",
            "args": { "pid": std::process::id(), "activity": activity },
            "nonce": self.nonce.to_string(),
        });
        self.write(1, &cmd)?;
        let (_, v) = self.read()?;
        if v["evt"].as_str() == Some("ERROR") {
            return Err(message(&v));
        }
        Ok(())
    }

    fn write(&mut self, op: u32, v: &Value) -> Result<(), String> {
        let body = v.to_string();
        let mut frame = Vec::with_capacity(8 + body.len());
        frame.extend_from_slice(&op.to_le_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(body.as_bytes());
        self.s.write_all(&frame).and_then(|_| self.s.flush()).map_err(|e| e.to_string())
    }

    /// The next answer, past any ping (answered) on the way.
    fn read(&mut self) -> Result<(u32, Value), String> {
        loop {
            let mut hdr = [0u8; 8];
            self.s.read_exact(&mut hdr).map_err(|e| e.to_string())?;
            let op = u32::from_le_bytes(hdr[..4].try_into().unwrap());
            let len = u32::from_le_bytes(hdr[4..].try_into().unwrap()) as usize;
            if len > 1 << 20 {
                return Err(format!("a frame of {len} bytes"));
            }
            let mut body = vec![0u8; len];
            self.s.read_exact(&mut body).map_err(|e| e.to_string())?;
            let v: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            match op {
                3 => self.write(4, &v)?,
                2 => return Err(format!("Discord closed the connection: {}", message(&v))),
                _ => return Ok((op, v)),
            }
        }
    }
}

fn message(v: &Value) -> String {
    v["data"]["message"].as_str().or(v["message"].as_str()).unwrap_or("no reason given").to_string()
}

/// One pipe or socket of a running Discord, if any.
#[cfg(windows)]
fn connect() -> Option<std::fs::File> {
    (0..10).find_map(|i| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!(r"\\.\pipe\discord-ipc-{i}"))
            .ok()
    })
}

#[cfg(unix)]
fn connect() -> Option<std::os::unix::net::UnixStream> {
    let mut dirs: Vec<std::path::PathBuf> = ["XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"]
        .iter()
        .filter_map(std::env::var_os)
        .map(Into::into)
        .collect();
    dirs.push("/tmp".into());
    // Discord installed as a Flatpak or a Snap puts its socket one level down.
    let sub = ["", "app/com.discordapp.Discord", "snap.discord"];
    dirs.iter()
        .flat_map(|d| sub.iter().map(move |s| d.join(s)))
        .flat_map(|d| (0..10).map(move |i| d.join(format!("discord-ipc-{i}"))))
        .find_map(|p| std::os::unix::net::UnixStream::connect(p).ok())
}

/// The thread: keep Discord showing the latest presence, connecting when it
/// appears and again when it goes away. `connect` finds the pipe (a test
/// gives its own).
fn run<S: Read + Write>(app_id: &str, rx: Receiver<Option<Presence>>, connect: fn() -> Option<S>) {
    let mut want: Option<Presence> = None;
    let mut shown: Option<Presence> = None;
    let mut ipc: Option<Ipc<S>> = None;
    let mut tried: Option<Instant> = None;
    let mut sent: Option<Instant> = None;
    let mut said_absent = false;
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Some(p)) => want = Some(p),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                if let Some(ipc) = ipc.as_mut() {
                    let _ = ipc.set_activity(None);
                }
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        if want.is_none() || want == shown || sent.is_some_and(|t| t.elapsed() < UPDATE_EVERY) {
            continue;
        }
        if ipc.is_none() {
            if tried.is_some_and(|t| t.elapsed() < RETRY_EVERY) {
                continue;
            }
            tried = Some(Instant::now());
            match connect().map(|s| Ipc::handshake(s, app_id)) {
                None => {
                    if !said_absent {
                        info!("Discord: not running; looking again every 30 s");
                        said_absent = true;
                    }
                    continue;
                }
                Some(Err(e)) => {
                    warn!("Discord: {e} (is {app_id} the application id from the developer portal?)");
                    continue;
                }
                Some(Ok(c)) => {
                    info!("Discord: connected, showing the game on the profile");
                    said_absent = false;
                    ipc = Some(c);
                }
            }
        }
        let c = ipc.as_mut().unwrap();
        sent = Some(Instant::now());
        match c.set_activity(want.as_ref()) {
            Ok(()) => {
                let p = want.as_ref().unwrap();
                debug!("Discord: {} | {}", p.details, p.state);
                shown = want.clone();
            }
            Err(e) => {
                warn!("Discord: update refused or pipe lost ({e}); reconnecting");
                ipc = None;
                shown = None;
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    fn read_frame(s: &mut UnixStream) -> (u32, Value) {
        let mut hdr = [0u8; 8];
        s.read_exact(&mut hdr).unwrap();
        let len = u32::from_le_bytes(hdr[4..].try_into().unwrap()) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).unwrap();
        (u32::from_le_bytes(hdr[..4].try_into().unwrap()), serde_json::from_slice(&body).unwrap())
    }

    fn write_frame(s: &mut UnixStream, op: u32, v: Value) {
        let body = v.to_string();
        s.write_all(&op.to_le_bytes()).unwrap();
        s.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
        s.write_all(body.as_bytes()).unwrap();
    }

    /// The client's end of the pipe a test hands to `run`.
    static PIPE: Mutex<Option<UnixStream>> = Mutex::new(None);
    fn take_pipe() -> Option<UnixStream> {
        PIPE.lock().unwrap().take()
    }

    /// A Discord on the other end: the handshake carries the application id,
    /// a ping is answered, the activity has the game, the text cut to 128, no
    /// one-character state, the badge and the button; at the end the profile
    /// is cleared.
    #[test]
    fn the_profile_shows_the_game_and_is_cleared_at_the_end() {
        let (client, mut discord) = UnixStream::pair().unwrap();
        *PIPE.lock().unwrap() = Some(client);
        let (tx, rx) = channel();
        let t = std::thread::spawn(move || run("1234", rx, take_pipe));
        tx.send(Some(Presence {
            details: "Sonic Adventure 2".into(),
            state: "x".repeat(200),
            image: Some("https://media.retroachievements.org/Images/1.png".into()),
            image_text: Some("1 of 147 achievements".into()),
            url: Some("https://retroachievements.org/game/3417".into()),
            start: 1_700_000_000,
        }))
        .unwrap();

        let (op, v) = read_frame(&mut discord);
        assert_eq!((op, v["client_id"].as_str()), (0, Some("1234")));
        write_frame(&mut discord, 1, json!({ "cmd": "DISPATCH", "evt": "READY" }));

        let (op, v) = read_frame(&mut discord);
        assert_eq!((op, v["cmd"].as_str()), (1, Some("SET_ACTIVITY")));
        let a = &v["args"]["activity"];
        assert_eq!(a["details"], "Sonic Adventure 2");
        assert_eq!(a["state"].as_str().unwrap().len(), 128);
        assert_eq!(a["assets"]["large_text"], "1 of 147 achievements");
        assert_eq!(a["buttons"][0]["url"], "https://retroachievements.org/game/3417");
        assert_eq!(a["timestamps"]["start"], 1_700_000_000u64);
        // a ping before the answer is answered with a pong
        write_frame(&mut discord, 3, json!({ "p": 1 }));
        let (op, v) = read_frame(&mut discord);
        assert_eq!((op, v["p"].as_u64()), (4, Some(1)));
        write_frame(&mut discord, 1, json!({ "cmd": "SET_ACTIVITY", "evt": null }));

        drop(tx);
        let (op, v) = read_frame(&mut discord);
        assert_eq!((op, v["args"]["activity"].is_null()), (1, true), "cleared at the end");
        write_frame(&mut discord, 1, json!({ "cmd": "SET_ACTIVITY", "evt": null }));
        t.join().unwrap();
    }

    #[test]
    fn short_texts_are_left_out() {
        let a = Presence { details: "Game".into(), state: " x ".into(), ..Default::default() }.activity();
        assert_eq!(a["details"], "Game");
        assert!(a.get("state").is_none() && a.get("assets").is_none() && a.get("buttons").is_none());
    }
}
