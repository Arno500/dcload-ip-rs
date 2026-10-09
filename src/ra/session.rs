//! The RA thread: login, hash, load, then judge the console's frames.
//!
//! Everything that touches rcheevos happens here, on one thread. The packet
//! sink (`io::PacketSink`) only forwards what the console sent, so the
//! syscall loop never waits on RetroAchievements.
//!
//! EACH FRAME RUNS TWICE, in this order:
//!   1. the PROBE -- a private runtime holding the whole set -- reads the
//!      frame. Whatever it reads that the table lacks (a pointer chain moved)
//!      is added to the table, and the frame is NOT given to the real client:
//!      it would have been judged on zeros, and an achievement that fires on
//!      zeros is awarded for good.
//!   2. only if the table held everything, the real client judges it.
//! A grown table is a new generation: the console starts it with a keyframe.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::net::UdpSocket;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::chains::{Chain, Walk};
use super::env::{Client, Env, Event, Probe, Shared};
use super::ffi;
use super::slow::Slow;
use crate::discord::{self, Discord, Presence};
use super::frames::{Applied, Mirror};
use super::store;
use super::table::{MAX_CHAINS, MAX_RANGES, MAX_WORDS, Table, TableError, distinct_words};
use crate::cmds::{DCLoadCmd, DCLoadCmds, DCReturnCmd};
use crate::io::{PacketSink, SharedSink};

/// rc_client's "unknown emulator" notice is an achievement from this id up
/// (`RC_CLIENT_ACHIEVEMENT_WARNING_ID`).
const WARNING_ID: u32 = 101_000_001;

/// What of a set is served when the whole does not fit the loader. First the
/// rich presence leaves the TABLE but not the game: the probe builds the table
/// without it, and the real client, which keeps it, reads what the table lacks
/// slowly (`slow.rs`) -- it can read more than every achievement together:
/// Sega Rally 2's reads ~900 words. Then the leaderboards leave the game. The
/// achievements are never dropped. The game is loaded again with the set
/// trimmed before rcheevos sees it (`trim_sets`), so nothing left out can
/// submit a score read on zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Keep {
    All,
    SlowRichPresence,
    NoLeaderboards,
}

impl Keep {
    fn next(self) -> Option<(Keep, &'static str)> {
        match self {
            Keep::All => Some((
                Keep::SlowRichPresence,
                "its rich presence in the table: it will be read slowly, every few seconds",
            )),
            Keep::SlowRichPresence => Some((Keep::NoLeaderboards, "its leaderboards too")),
            Keep::NoLeaderboards => None,
        }
    }

    /// What the real client's copy of the set leaves out: (rich presence,
    /// leaderboards).
    fn client_drops(self) -> (bool, bool) {
        (false, self == Keep::NoLeaderboards)
    }

    /// What the probe's copy leaves out, and so the table.
    fn probe_drops(self) -> (bool, bool) {
        (self != Keep::All, self == Keep::NoLeaderboards)
    }
}

/// The game-sets answer without its rich presence and/or its leaderboards;
/// unchanged if it is not the JSON expected.
fn trim_sets(body: &[u8], (drop_rp, drop_lb): (bool, bool)) -> Vec<u8> {
    if !drop_rp && !drop_lb {
        return body.to_vec();
    }
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    if drop_rp && v.get("RichPresencePatch").is_some() {
        v["RichPresencePatch"] = "".into();
    }
    if drop_lb {
        if let Some(sets) = v.get_mut("Sets").and_then(|s| s.as_array_mut()) {
            for s in sets {
                if s.get("Leaderboards").is_some() {
                    s["Leaderboards"] = serde_json::json!([]);
                }
            }
        }
    }
    v.to_string().into_bytes()
}

/// Where the slow path reads title RAM on the wire: through P1 under a Katana
/// title (the cache is coherent with what the title wrote, no MMU), through P2
/// under Windows CE, whose MMU is on (a P0 address would be translated in the
/// loader) and whose cache is indexed by virtual address (a P1 read can miss a
/// dirty line and leave a stale copy; P2 reads RAM and touches no line).
fn slow_base(ce: bool) -> u32 {
    if ce { 0xac00_0000 } else { 0x8c00_0000 }
}

pub enum Msg {
    /// The served disc was swapped (`swap-disc`): the new image's spec.
    Disc(String),
    Frame { seq: u32, payload: Vec<u8> },
    /// The loader's answer to a table; `limits` = the most words it can take under
    /// a Katana title and under Windows CE.
    Ract { generation: u32, size: u32, limits: Option<(u32, u32)> },
    Http { token: u64, status: i32, body: Vec<u8> },
    /// Bytes of title RAM read for the slow path, at their wire address.
    SlowData { addr: u32, data: Vec<u8> },
    Stop,
}

pub struct Config {
    pub hardcore: bool,
    /// The title is Windows CE: the loader has less room for the table.
    pub ce: bool,
    /// Another server than retroachievements.org (`DCLOAD_RA_HOST`; tests).
    pub host: Option<String>,
    /// `(user, token)`; `None` reads the file `ra-login` wrote.
    pub login: Option<(String, String)>,
    /// Show the game on Discord through this application id (`--discord`).
    pub discord: Option<String>,
}

impl Config {
    pub fn new(hardcore: bool, ce: bool) -> Config {
        Config {
            hardcore,
            ce,
            host: std::env::var("DCLOAD_RA_HOST").ok(),
            login: None,
            discord: None,
        }
    }
}

/// The slow path's reads in flight, at their wire addresses: what an `SBIN` must
/// fall in to be ours, and what our `DBIN` names.
type Flight = Arc<Mutex<Vec<(u32, u32)>>>;

/// Claims `RAFR` and `RACT` replies, and the answers to the slow path's `SBIQ`
/// -- data inside the read in flight, and the terminator naming exactly it (a
/// disc read's DoneBinary names a title buffer too, but never this range and
/// size, and disc reads no longer ask for one: AGENTS.md 16).
struct RaSink(Sender<Msg>, Flight);

impl PacketSink for RaSink {
    fn claim(&mut self, cmd: &DCReturnCmd) -> bool {
        let Some(inner) = cmd.cmd.as_ref() else { return false };
        match &inner.cmd {
            DCLoadCmds::Rafr(payload) => {
                let _ = self.0.send(Msg::Frame { seq: inner.address, payload: payload.clone() });
                true
            }
            DCLoadCmds::SendBinary(Some(chunk)) => {
                let ours = self.1.lock().expect("flight poisoned").iter().any(|&(lo, len)| {
                    inner.address >= lo && inner.address - lo < len
                });
                if !ours {
                    return false;
                }
                let n = (inner.size as usize).min(chunk.len());
                let _ = self.0.send(Msg::SlowData { addr: inner.address, data: chunk[..n].to_vec() });
                true
            }
            DCLoadCmds::DoneBinary() => {
                self.1.lock().expect("flight poisoned").contains(&(inner.address, inner.size))
            }
            DCLoadCmds::Ract(data) => {
                let limits = data.as_ref().filter(|d| d.len() >= 8).map(|d| {
                    (
                        u32::from_be_bytes(d[0..4].try_into().unwrap()),
                        u32::from_be_bytes(d[4..8].try_into().unwrap()),
                    )
                });
                let _ = self.0.send(Msg::Ract { generation: inner.address, size: inner.size, limits });
                true
            }
            _ => false,
        }
    }
}

/// The running session's mailbox, for what happens outside it: a disc swap.
static CONTROL: Mutex<Option<Sender<Msg>>> = Mutex::new(None);

/// A `swap-disc` was accepted by the loader and the new image is now the one
/// served: tell the achievements, which must follow the game to its next disc.
pub fn disc_changed(spec: &str) {
    if let Some(tx) = CONTROL.lock().expect("control poisoned").as_ref() {
        let _ = tx.send(Msg::Disc(spec.to_string()));
    }
}

pub struct Handle {
    tx: Sender<Msg>,
    flight: Flight,
    join: Option<JoinHandle<()>>,
}

impl Handle {
    /// To register on the connection (`ExternalDcIo::add_sink`).
    pub fn sink(&self) -> SharedSink {
        Arc::new(Mutex::new(RaSink(self.tx.clone(), self.flight.clone())))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        *CONTROL.lock().expect("control poisoned") = None;
        let _ = self.tx.send(Msg::Stop);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Start a session: `socket` is a clone of the console connection, used only
/// to send the table.
pub fn start(cfg: Config, disc_spec: Option<String>, socket: UdpSocket) -> Result<Handle, String> {
    let (user, token) = cfg
        .login
        .clone()
        .or_else(store::load)
        .ok_or("no RetroAchievements login saved: run `ra-login <user>` first")?;
    let (tx, rx) = channel();
    let tx2 = tx.clone();
    *CONTROL.lock().expect("control poisoned") = Some(tx.clone());
    let flight: Flight = Arc::new(Mutex::new(vec![]));
    let flight2 = flight.clone();
    let join = std::thread::Builder::new()
        .name("retroachievements".into())
        .spawn(move || {
            let mut s = Session::new(cfg, user, token, disc_spec, Some(socket), tx2, rx);
            s.flight = flight2;
            s.run();
        })
        .map_err(|e| e.to_string())?;
    Ok(Handle { tx, flight, join: Some(join) })
}

fn new_env(tx: Sender<Msg>, disc_spec: Option<&str>) -> Shared {
    let disc = disc_spec.and_then(|s| match crate::dispatch::open_disc(s) {
        Ok(d) => Some(d),
        Err(e) => {
            warn!("RetroAchievements: cannot open the disc to hash it: {e}");
            None
        }
    });
    Rc::new(RefCell::new(Env {
        table: Table { ranges: vec![], chains: vec![] },
        words: vec![],
        chain_addr: vec![],
        missed: vec![],
        real_missed: false,
        in_real: false,
        events: vec![],
        tx,
        user_agent: String::new(),
        disc,
        sets_requests: vec![],
        slow_mode: false,
        slow_vals: Default::default(),
        slow_new: Default::default(),
    }))
}

#[derive(PartialEq)]
enum Phase {
    LoggingIn,
    Loading,
    Running,
    Dead,
}

struct Session {
    ce: bool,
    /// The most words the loader will take, from its first answer; until then,
    /// the Katana figure.
    max_words: usize,
    user: String,
    token: String,
    client: Client,
    env: Shared,
    rx: Receiver<Msg>,
    socket: Option<UdpSocket>,
    probe: Option<Probe>,
    /// Word-aligned RAM addresses the table reads directly: what the set's own
    /// structure names, and what discovery added.
    direct: BTreeSet<u32>,
    /// The pointer chains the loader follows itself.
    chains: Vec<Chain>,
    /// Indirect reads the walk could not make chains of: only those can need the
    /// table to grow once it is built.
    unsupported: usize,
    /// Frames judged while a pointer held a value that is not a multiple of 4.
    skewed_frames: u64,
    mirror: Option<Mirror>,
    phase: Phase,
    generation: u32,
    acked: bool,
    last_sent: Instant,
    sends: u32,
    peak_words: usize,
    peak_ranges: usize,
    /// The last table sent: (direct words, ranges, chains).
    summary: (usize, usize, usize),
    /// Print the table and stop, touching no console (`ra-count`).
    count_only: bool,
    /// A hash given instead of a disc (`ra-count <32 hex digits>`).
    forced_hash: Option<String>,
    /// A disc swap in progress: the new disc's hash, and the game RetroAchievements
    /// says it belongs to (reported while the media change is looked up).
    media_hash: Option<String>,
    media_game: Option<u32>,
    /// The disc's hash, to load the set again trimmed (`Keep`).
    hash: Option<String>,
    keep: Keep,
    /// The slow path (`Keep::SlowRichPresence` on), and its read in flight as
    /// the packet sink sees it.
    slow: Slow,
    flight: Flight,
    /// The rich presence last logged, and when it was last looked at.
    presence: String,
    presence_at: Instant,
    /// The Discord profile (`--discord`), and when the game was loaded.
    discord: Option<Discord>,
    started: u64,
    /// Frames completed by the mirror, judged, and skipped (table growing; a
    /// pointer that is not an address while discovery is still needed), as of
    /// the last report and now.
    counts: [u64; 4],
    counts_logged: [u64; 4],
    counts_at: Instant,
}

impl Session {
    fn new(
        cfg: Config,
        user: String,
        token: String,
        disc_spec: Option<String>,
        socket: Option<UdpSocket>,
        tx: Sender<Msg>,
        rx: Receiver<Msg>,
    ) -> Session {
        let env = new_env(tx, disc_spec.as_deref());
        let client = Client::new(env.clone(), cfg.hardcore, cfg.host.as_deref());
        Session {
            ce: cfg.ce,
            max_words: MAX_WORDS,
            user,
            token,
            client,
            env,
            rx,
            socket,
            probe: None,
            direct: BTreeSet::new(),
            chains: Vec::new(),
            unsupported: 0,
            skewed_frames: 0,
            mirror: None,
            phase: Phase::LoggingIn,
            generation: 0,
            acked: false,
            last_sent: Instant::now(),
            sends: 0,
            peak_words: 0,
            peak_ranges: 0,
            summary: (0, 0, 0),
            count_only: false,
            forced_hash: None,
            media_hash: None,
            media_game: None,
            hash: None,
            keep: Keep::All,
            slow: Slow::default(),
            flight: Arc::new(Mutex::new(vec![])),
            presence: String::new(),
            presence_at: Instant::now(),
            discord: cfg.discord.clone().map(Discord::start),
            started: discord::now(),
            counts: [0; 4],
            counts_logged: [0; 4],
            counts_at: Instant::now(),
        }
    }

    fn run(&mut self) {
        self.client.login_token(&self.user.clone(), &self.token.clone());
        loop {
            match self.rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Ok(Msg::Http { token, status, body }) => {
                    let sets = {
                        let mut e = self.env.borrow_mut();
                        let at = e.sets_requests.iter().position(|&t| t == token);
                        at.map(|i| e.sets_requests.swap_remove(i)).is_some()
                    };
                    let body = if sets && status == 200 {
                        trim_sets(&body, self.keep.client_drops())
                    } else {
                        body
                    };
                    self.client.http_done(token, status, &body)
                }
                Ok(Msg::SlowData { addr, data }) => self.on_slow_data(addr, &data),
                Ok(Msg::Ract { generation, size, limits }) => self.on_ract_reply(generation, size, limits),
                Ok(Msg::Disc(spec)) => self.on_disc(&spec),
                Ok(Msg::Frame { seq, payload }) => self.on_frame(seq, &payload),
                Err(RecvTimeoutError::Timeout) => self.client.idle(),
            }
            if self.drain_events() {
                break;
            }
            self.log_presence();
            self.service_slow();
            // On every turn, not only when nothing arrives: the old table's frames
            // arrive ten times a second, and a lost table was never sent again.
            self.resend_table();
        }
        if self.peak_words > 0 {
            info!(
                "RetroAchievements: the table peaked at {} of {} words",
                self.peak_words, self.max_words
            );
        }
        if self.skewed_frames > 0 {
            info!(
                "RetroAchievements: {} frames judged while a pointer did not hold an address",
                self.skewed_frames
            );
        }
    }

    /// Returns true when the session should end.
    fn drain_events(&mut self) -> bool {
        let events: Vec<Event> = std::mem::take(&mut self.env.borrow_mut().events);
        for ev in events {
            match ev {
                Event::Login { ok: true, .. } => {
                    info!("RetroAchievements: logged in as {}", self.client.display_name());
                    self.phase = Phase::Loading;
                    match self.forced_hash.clone().or_else(|| self.client.hash_disc()) {
                        Some(h) => {
                            info!("RetroAchievements: disc hash {h}");
                            self.client.load_game(&h);
                            self.hash = Some(h);
                        }
                        None => {
                            error!(
                                "RetroAchievements: cannot hash the disc (is it a Dreamcast \
                                 image the host serves?); no achievements this session"
                            );
                            self.phase = Phase::Dead;
                        }
                    }
                }
                Event::Login { ok: false, message } => {
                    error!("RetroAchievements: login failed: {message} (run `ra-login` again)");
                    self.phase = Phase::Dead;
                    return self.count_only;
                }
                Event::GameSets => self.build_probe(),
                Event::Load { ok: true, .. } => {
                    if let Some((id, title)) = self.client.game() {
                        info!("RetroAchievements: {title} (game {id})");
                        self.log_earned();
                        self.started = discord::now();
                        self.show_discord();
                    }
                    if self.phase == Phase::Loading && self.probe.is_some() {
                        self.phase = Phase::Running;
                        self.grow(true);
                        if self.count_only && self.phase != Phase::Loading {
                            return true;
                        }
                    }
                }
                Event::Load { ok: false, message } => {
                    error!("RetroAchievements: no set for this disc: {message}");
                    self.phase = Phase::Dead;
                    return self.count_only;
                }
                Event::Achievement { points, title, description, .. } => {
                    info!("*** ACHIEVEMENT UNLOCKED: {title} ({points} pts) -- {description}");
                    self.show_discord();
                }
                Event::LeaderboardStarted(t) => info!("RetroAchievements: leaderboard started: {t}"),
                Event::LeaderboardFailed(t) => info!("RetroAchievements: leaderboard failed: {t}"),
                Event::LeaderboardSubmitted(t) => info!("RetroAchievements: score submitted: {t}"),
                Event::Progress { title, progress } => debug!("RetroAchievements: {title}: {progress}"),
                Event::Completed => info!("RetroAchievements: every achievement earned!"),
                Event::HashGame(id) => self.media_game = Some(id),
                Event::Media { result, message } => self.on_media(result, &message),
                Event::ServerError { api, message } => {
                    warn!("RetroAchievements: server error in {api}: {message}")
                }
                Event::Disconnected => warn!("RetroAchievements: server unreachable, unlocks are queued"),
                Event::Reconnected => info!("RetroAchievements: server reachable again, unlocks sent"),
                Event::Reset => debug!("RetroAchievements: reset requested (ignored)"),
                Event::Log(m) => debug!("rcheevos: {m}"),
            }
        }
        false
    }

    /// What the user already has: rcheevos does not watch an achievement earned
    /// in this mode again, so it cannot unlock a second time.
    fn log_earned(&self) {
        let (core, unlocked, unsupported, hardcore) = self.client.summary();
        let mode = if hardcore { "hardcore" } else { "softcore" };
        info!(
            "RetroAchievements: {unlocked} of {core} achievements already earned ({mode}); \
             only the other {} are watched",
            core.saturating_sub(unlocked + unsupported)
        );
        if unsupported > 0 {
            info!("RetroAchievements: {unsupported} achievements not supported by this rcheevos");
        }
        for (id, state, title) in self.client.achievements() {
            if id >= WARNING_ID {
                continue; // rc_client's own notice, not one of the set's
            }
            match state {
                ffi::STATE_UNLOCKED => debug!("RetroAchievements: earned already: {title} ({id})"),
                ffi::STATE_DISABLED => debug!("RetroAchievements: unsupported: {title} ({id})"),
                _ => trace!("RetroAchievements: watched: {title} ({id})"),
            }
        }
    }

    /// Every 10 s, at `debug`: what became of the frames that arrived. A frame
    /// that is not judged is one rcheevos never saw: an achievement whose
    /// conditions hold only then cannot fire.
    fn log_counts(&mut self) {
        if self.counts_at.elapsed() < Duration::from_secs(10) {
            return;
        }
        self.counts_at = Instant::now();
        let d: Vec<u64> = (0..4).map(|i| self.counts[i] - self.counts_logged[i]).collect();
        self.counts_logged = self.counts;
        debug!(
            "RetroAchievements: last 10 s: {} frames, {} judged, {} skipped while the table \
             grew, {} skipped on a pointer that is not an address (generation {})",
            d[0], d[1], d[2], d[3], self.generation
        );
    }

    /// The rich presence as evaluated here, logged when it changes (looked at
    /// once a second). The site shows it only at the next ping, every 2 minutes.
    fn log_presence(&mut self) {
        if self.phase != Phase::Running || self.presence_at.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.presence_at = Instant::now();
        let now = self.client.rich_presence();
        if now != self.presence {
            debug!("RetroAchievements: rich presence: {now}");
            self.presence = now;
            self.show_discord();
        }
    }

    /// The game, its rich presence and the achievements earned, to Discord
    /// (which takes them at most every 15 s; `discord.rs`).
    fn show_discord(&self) {
        let (Some(d), Some((id, title))) = (&self.discord, self.client.game()) else { return };
        let (core, unlocked, _, _) = self.client.summary();
        d.show(Presence {
            details: title,
            state: self.presence.clone(),
            image: self.client.game_badge(),
            image_text: Some(format!("{unlocked} of {core} achievements")),
            url: Some(format!("https://retroachievements.org/game/{id}")),
            start: self.started,
        });
    }

    /// The served disc changed. A multi-disc game's next disc keeps its set:
    /// `rc_client_begin_change_media` notes the new hash and, if RetroAchievements
    /// puts it under another game, `on_media` loads that game's set instead.
    fn on_disc(&mut self, spec: &str) {
        match crate::dispatch::open_disc(spec) {
            Ok(d) => self.env.borrow_mut().disc = Some(d),
            Err(e) => {
                warn!("RetroAchievements: cannot open the new disc to hash it: {e}");
                return;
            }
        }
        if self.phase == Phase::LoggingIn {
            return; // the hash is taken, from this disc, once logged in
        }
        let Some(hash) = self.client.hash_disc() else {
            warn!("RetroAchievements: cannot hash the new disc; the set stays as it was");
            return;
        };
        info!("RetroAchievements: the disc changed, new hash {hash}");
        if self.client.game().is_none() {
            // Nothing loaded yet (the first disc was not recognised, or is loading):
            // this one is a first load.
            self.phase = Phase::Loading;
            self.client.load_game(&hash);
            self.hash = Some(hash);
            self.keep = Keep::All;
            return;
        }
        self.media_game = None;
        self.media_hash = Some(hash.clone());
        self.client.change_media(&hash);
    }

    fn on_media(&mut self, result: i32, message: &str) {
        let Some(hash) = self.media_hash.take() else { return };
        let current = self.client.game().map(|g| g.0);
        match (self.media_game.take(), current) {
            (Some(id), Some(cur)) if id != 0 && id != cur => {
                info!(
                    "RetroAchievements: the new disc belongs to game {id}, not {cur}: loading its set"
                );
                self.keep = Keep::All;
                self.hash = Some(hash.clone());
                self.reload(&hash);
            }
            _ if result == 0 => info!("RetroAchievements: same game, next disc"),
            _ => warn!("RetroAchievements: the new disc was not taken as it was: {message}"),
        }
    }

    /// Another game's set: forget this one, and start over from the new disc's hash.
    /// The loader goes on sampling the old table until the new one arrives; its
    /// frames are ignored meanwhile (`Phase::Loading`).
    fn reload(&mut self, hash: &str) {
        self.client.unload_game();
        self.probe = None;
        self.mirror = None;
        self.direct.clear();
        self.chains.clear();
        self.acked = false;
        self.peak_words = 0;
        self.peak_ranges = 0;
        self.slow = Slow::default();
        self.flight.lock().expect("flight poisoned").clear();
        {
            let mut e = self.env.borrow_mut();
            e.slow_mode = self.keep != Keep::All;
            e.slow_vals.clear();
            e.slow_new.clear();
        }
        self.phase = Phase::Loading;
        self.client.load_game(hash);
    }

    fn build_probe(&mut self) {
        let Some(sets) = self.client.game_sets() else { return };
        // The real client has the set as `client_drops` left it; the table
        // leaves out more when the rich presence is read slowly.
        let sets = trim_sets(&sets, self.keep.probe_drops());
        match Probe::new(&sets) {
            Some(mut p) => {
                let (a, l, rp) = p.counts();
                info!(
                    "RetroAchievements: {a} achievements, {l} leaderboards{}{}",
                    if rp { ", rich presence" } else { "" },
                    match self.keep {
                        Keep::All => "",
                        Keep::SlowRichPresence => {
                            " (the set does not fit the loader: its rich presence is read slowly)"
                        }
                        Keep::NoLeaderboards => {
                            " (the set does not fit the loader: its rich presence is read slowly, \
                             its leaderboards are left out)"
                        }
                    }
                );
                let Walk { direct, chains, unsupported, .. } = p.walk();
                info!(
                    "RetroAchievements: the set reads {} words directly and through {} pointer \
                     words the loader follows itself{}",
                    direct.len(),
                    chains.len(),
                    if unsupported != 0 {
                        format!(" ({unsupported} constructs left to discovery)")
                    } else {
                        String::new()
                    }
                );
                self.direct = direct;
                self.chains = chains;
                self.unsupported = unsupported;
                self.probe = Some(p);
            }
            None => error!("RetroAchievements: cannot read the set's definitions"),
        }
    }

    /// Ask the loader for every word the table lacks. `first` is the very
    /// first table: nothing has been read yet, so the probe runs once on zeros
    /// to find out WHERE the set reads. Otherwise the misses of the frame that
    /// just failed (`env.missed`) are what to add -- running the probe again
    /// here would read different memory and find nothing new.
    fn grow(&mut self, first: bool) {
        if first {
            let Some(probe) = self.probe.as_mut() else { return };
            // The table the set's own structure gives, before anything is read:
            // the direct words and the pointer chains. The pass on zeros that
            // follows only finds what that structure did not name.
            match Table::build(self.direct.iter().copied(), &self.chains, self.max_words) {
                Ok(t) => {
                    let mut e = self.env.borrow_mut();
                    e.table = t;
                    e.zero_words();
                    e.missed.clear();
                }
                Err(err) => return self.too_big(err),
            }
            probe.frame(&self.env);
            let e = self.env.borrow();
            if !e.missed.is_empty() {
                let mut sorted = e.missed.clone();
                sorted.sort_unstable();
                info!(
                    "RetroAchievements: {} words the set's structure did not name, found by \
                     reading it: {:x?}",
                    sorted.len(),
                    &sorted[..sorted.len().min(24)]
                );
            }
        }
        let mut e = self.env.borrow_mut();
        let found: Vec<u32> = e.missed.iter().map(|a| a & !3).collect();
        self.direct.extend(found);
        match Table::build(self.direct.iter().copied(), &self.chains, self.max_words) {
            Ok(t) => {
                if t == e.table && self.mirror.is_some() {
                    e.missed.clear();
                    return;
                }
                self.generation += 1;
                let words = t.words();
                self.peak_words = self.peak_words.max(words);
                self.peak_ranges = self.peak_ranges.max(t.ranges.len());
                self.summary = (t.direct_words(), t.ranges.len(), t.chains.len());
                info!(
                    "RetroAchievements: watching {} words in {} ranges and {} pointer words \
                     (generation {})",
                    t.direct_words(),
                    t.ranges.len(),
                    t.chains.len(),
                    self.generation
                );
                e.table = t;
                e.zero_words();
                e.missed.clear();
                self.mirror = Some(Mirror::new(self.generation, words));
                drop(e);
                self.acked = false;
                self.sends = 0;
                self.send_table();
            }
            Err(err) => {
                drop(e);
                self.too_big(err);
            }
        }
    }

    fn too_big(&mut self, err: TableError) {
        let TableError::TooBig { words, ranges } = err;
        if self.step_down(words, ranges) {
            return;
        }
        // `words` counts what merging the ranges added: say what the set reads too.
        let read = distinct_words(self.direct.iter().copied()) + self.chains.len();
        error!(
            "RetroAchievements: this set reads {read} distinct words; its table takes {words} \
             words in {ranges} ranges (nearby reads merged into one range) and the loader's \
             room is {} words in {MAX_RANGES} ranges{} (loader AGENTS.md 4.20): no \
             achievements this session",
            self.max_words,
            if self.ce { " under Windows CE" } else { "" }
        );
        self.peak_words = self.peak_words.max(words);
        self.peak_ranges = self.peak_ranges.max(ranges);
        self.phase = Phase::Dead;
    }

    /// The slow path's turn: take what the real client asked for and has not got,
    /// and ask the console for the next piece if one is due.
    fn service_slow(&mut self) {
        if self.keep == Keep::All || self.phase != Phase::Running {
            return;
        }
        let new = std::mem::take(&mut self.env.borrow_mut().slow_new);
        let added = new.into_iter().filter(|&w| self.slow.want(w)).count();
        if added > 0 {
            trace!("RetroAchievements: {added} more words to read slowly");
        }
        let ask = self.slow.poll(Instant::now());
        if ask.is_empty() {
            return;
        }
        let Some(socket) = self.socket.as_ref() else { return };
        let base = slow_base(self.ce);
        *self.flight.lock().expect("flight poisoned") =
            self.slow.in_flight().into_iter().map(|(o, l)| (base | o, l)).collect();
        for (off, len) in ask {
            let bytes: Vec<u8> =
                DCLoadCmd::new(DCLoadCmds::SendBinaryQuiet(None), base | off, len).into();
            if let Err(e) = socket.send(&bytes) {
                debug!("RetroAchievements: slow read not sent: {e}");
            }
        }
    }

    fn on_slow_data(&mut self, addr: u32, data: &[u8]) {
        let off = addr & 0x00ff_ffff;
        let Some(words) = self.slow.on_data(off, data, Instant::now()) else { return };
        let base = slow_base(self.ce);
        *self.flight.lock().expect("flight poisoned") =
            self.slow.in_flight().into_iter().map(|(o, l)| (base | o, l)).collect();
        let mut e = self.env.borrow_mut();
        e.slow_vals.extend(words);
        let n = e.slow_vals.len();
        drop(e);
        let s = &self.slow;
        if s.cycle_done() && (s.cycles == 1 || s.cycles % 60 == 0) {
            debug!(
                "RetroAchievements: rich presence read slowly: {n} words in {} reads, the \
                 cycle took {} ms ({} cycles so far)",
                s.pieces(),
                s.last_took.as_millis(),
                s.cycles
            );
        }
        self.service_slow();
    }

    /// The set does not fit: load it again with less of it (`Keep`). False when
    /// only achievements are left already, or nothing can be loaded again.
    fn step_down(&mut self, words: usize, ranges: usize) -> bool {
        let (Some((next, what)), Some(hash)) = (self.keep.next(), self.hash.clone()) else {
            return false;
        };
        warn!(
            "RetroAchievements: this set reads {words} words in {ranges} ranges, more than the \
             loader samples ({} words{}); loading it again without {what}",
            self.max_words,
            if self.ce { " under Windows CE" } else { "" }
        );
        self.keep = next;
        self.reload(&hash);
        true
    }

    /// The whole table, in as many `RACT` parts as it takes (`Table::parts`).
    /// Only the last is answered; a part lost on the way leaves the table
    /// unanswered and `resend_table()` sends all of it again.
    fn send_table(&mut self) {
        let Some(socket) = self.socket.as_ref() else { return };
        let parts = self.env.borrow().table.parts();
        for part in parts {
            let size = part.len() as u32;
            let bytes: Vec<u8> =
                DCLoadCmd::new(DCLoadCmds::Ract(Some(part)), self.generation, size).into();
            if let Err(e) = socket.send(&bytes) {
                debug!("RetroAchievements: table not sent: {e}");
                break;
            }
        }
        self.last_sent = Instant::now();
        self.sends += 1;
    }

    fn resend_table(&mut self) {
        if self.phase != Phase::Running || self.acked || self.mirror.is_none() {
            return;
        }
        if self.last_sent.elapsed() < Duration::from_secs(1) {
            return;
        }
        if self.sends == 20 {
            warn!(
                "RetroAchievements: the loader has not answered the table 20 times: is it \
                 built with WITH_RCHEEVOS and is the title listening (loader AGENTS.md 4.20)?"
            );
        }
        self.send_table();
    }

    fn on_ract_reply(&mut self, generation: u32, size: u32, limits: Option<(u32, u32)>) {
        if let Some((katana, ce)) = limits {
            let room = if self.ce { ce } else { katana } as usize;
            if room != self.max_words && room != 0 {
                debug!(
                    "RetroAchievements: the loader's room is {katana} words (Katana), {ce} (Windows CE)"
                );
                self.max_words = room;
            }
            // The first table was made before this was known (accepted for the other
            // kind of title, or refused for both).
            if self.peak_words > self.max_words {
                if self.step_down(self.peak_words, self.peak_ranges) {
                    return;
                }
                error!(
                    "RetroAchievements: this set reads {} words and the loader has room for {} \
                     {} (loader AGENTS.md 4.20): no achievements this session",
                    self.peak_words,
                    self.max_words,
                    if self.ce { "under Windows CE" } else { "" }
                );
                self.phase = Phase::Dead;
                return;
            }
        }
        if generation != self.generation {
            return;
        }
        if size == 0 {
            self.acked = true;
        } else {
            error!("RetroAchievements: the loader refused the table (too many ranges or words)");
            self.phase = Phase::Dead;
        }
    }

    fn on_frame(&mut self, seq: u32, payload: &[u8]) {
        if self.phase != Phase::Running {
            return;
        }
        let Some(mut mirror) = self.mirror.take() else { return };
        // Frames of THIS table prove the loader holds it. Frames of the previous
        // one prove the opposite: the new table has not arrived. Taking any frame
        // as proof stopped the resends, and a first `RACT` lost while the old
        // table's frames kept coming left the session judging nothing, for good
        // (Sega Rally 2 on the console, 2026-10-08: host at generation 2, loader
        // at 1, `last 10 s: 0 frames` while `g_ra_frames` ran at 60 a second).
        let mut current = false;
        let mut need_grow = false;
        // Every read a pointer holding an address can lead to is in the table
        // once the walk has made chains of all of them: a miss is then a read
        // through a pointer whose value is not a multiple of 4 (`Env::skewed`).
        let complete = self.unsupported == 0;
        let skewed_frames = &mut self.skewed_frames;
        let counts = &mut self.counts;
        let (client, env, probe) = (&mut self.client, &self.env, self.probe.as_mut());
        if let Some(probe) = probe {
            let res = mirror.apply(seq, payload, |_no, m| {
                counts[0] += 1;
                if need_grow {
                    counts[2] += 1;
                    return;
                }
                {
                    let mut e = env.borrow_mut();
                    e.set_words(m.words());
                    e.missed.clear();
                }
                probe.frame(env);
                let skewed = env.borrow().skewed();
                if !env.borrow().missed.is_empty() {
                    // A misaligned pointer is not an address (a pointer field holding
                    // something else, between levels): the loader read the word its
                    // value falls in, rcheevos reads across two words, and what it
                    // reads moves with the value every frame. Growing the table after
                    // it never ends, and a frame that grows the table is not judged:
                    // nothing was ever awarded (SA2 on the console, 2026-10-07).
                    if !skewed {
                        counts[2] += 1;
                        need_grow = true;
                        return;
                    }
                    if !complete {
                        counts[3] += 1;
                        return; // a real miss may hide among them: neither grow nor judge
                    }
                    *skewed_frames += 1;
                }
                counts[1] += 1;
                client.do_frame();
                if env.borrow().real_missed && !skewed {
                    debug!("RetroAchievements: the judged frame read outside the table");
                    need_grow = true;
                }
            });
            if res == Applied::Malformed {
                warn!("RetroAchievements: malformed frame datagram {seq}");
            }
            current = !matches!(res, Applied::OldGeneration | Applied::Malformed);
        }
        if mirror.lost > 0 {
            debug!("RetroAchievements: {} datagrams lost so far", mirror.lost);
        }
        self.mirror = Some(mirror);
        if current {
            self.acked = true;
        }
        self.log_counts();
        if need_grow {
            self.grow(false);
        }
    }
}

/// `ra-login`: ask for the password once, keep the token.
pub fn login(user: &str, password: &str) -> Result<(), String> {
    let (tx, rx) = channel();
    let mut s = Session::new(Config::new(false, false), user.into(), String::new(), None, None, tx, rx);
    s.client.login_password(user, password);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(Msg::Http { token, status, body }) = s.rx.recv_timeout(Duration::from_millis(250)) {
            s.client.http_done(token, status, &body);
        }
        let events: Vec<Event> = std::mem::take(&mut s.env.borrow_mut().events);
        for ev in events {
            match ev {
                Event::Login { ok: true, .. } => {
                    let token = s.client.token().ok_or("the server sent no token")?;
                    let name = s.client.display_name();
                    let path = store::save(user, &token).map_err(|e| e.to_string())?;
                    info!("Logged in as {name}; token saved in {}", path.display());
                    return Ok(());
                }
                Event::Login { ok: false, message } => return Err(message),
                _ => {}
            }
        }
    }
    Err("no answer from retroachievements.org".into())
}

/// `ra-count`: load the disc's set and say how many words it needs.
pub fn count(disc_spec: &str) -> Result<(), String> {
    let (user, token) = store::load().ok_or("run `ra-login <user>` first")?;
    let (tx, rx) = channel();
    // A hash may stand for the disc: 32 hex digits, no file.
    let is_hash = disc_spec.len() == 32 && disc_spec.bytes().all(|b| b.is_ascii_hexdigit());
    let mut s = Session::new(
        Config::new(false, false),
        user,
        token,
        (!is_hash).then(|| disc_spec.to_string()),
        None,
        tx,
        rx,
    );
    s.forced_hash = is_hash.then(|| disc_spec.to_lowercase());
    s.count_only = true;
    s.run();
    match (&s.probe, s.peak_words) {
        (None, _) => Err("no set loaded".into()),
        (Some(_), w) => {
            let (direct, ranges, chains) = s.summary;
            info!(
                "The table for this set: {w} words (at most {MAX_WORDS}; the loader's room, \
                 which it tells a session, is less) -- {direct} read from RAM in {ranges} ranges \
                 (of {MAX_RANGES}; nearby reads are merged only as far as that budget needs) and \
                 {chains} pointer words the loader works out itself (of {MAX_CHAINS}).\n\
                 {}{}",
                if s.unsupported == 0 {
                    "Where a pointer points does not change this: the table stays that size."
                } else {
                    "Pointers the loader cannot follow itself are found by reading them: \
                     where they point adds to this while the game runs."
                },
                match s.keep {
                    Keep::All => "",
                    Keep::SlowRichPresence => {
                        "\nWithout the rich presence, which a session reads slowly: the whole set does not fit."
                    }
                    Keep::NoLeaderboards => {
                        "\nWithout the rich presence (read slowly) and the leaderboards (left out): \
                         the whole set does not fit."
                    }
                }
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod trim_tests {
    use super::*;

    #[test]
    fn trimming_takes_the_rich_presence_out_of_the_table_then_the_leaderboards_out_of_the_game() {
        let set = br#"{"Success":true,"RichPresencePatch":"Display:\nx","Sets":[
            {"Achievements":[{"ID":1}],"Leaderboards":[{"ID":9}]}]}"#;
        let v = |b: Vec<u8>| serde_json::from_slice::<serde_json::Value>(&b).unwrap();
        assert_eq!(trim_sets(set, Keep::All.client_drops()), set.to_vec());
        assert_eq!(trim_sets(set, Keep::All.probe_drops()), set.to_vec());
        // the rich presence read slowly: the real client keeps it, the table not
        assert_eq!(trim_sets(set, Keep::SlowRichPresence.client_drops()), set.to_vec());
        let a = v(trim_sets(set, Keep::SlowRichPresence.probe_drops()));
        assert_eq!((a["RichPresencePatch"].as_str(), a["Sets"][0]["Leaderboards"][0]["ID"].as_u64()), (Some(""), Some(9)));
        // then the leaderboards leave both
        let a = v(trim_sets(set, Keep::NoLeaderboards.client_drops()));
        assert_eq!(a["Sets"][0]["Leaderboards"], serde_json::json!([]));
        assert_eq!(a["RichPresencePatch"], "Display:\nx", "still read slowly");
        assert_eq!(a["Sets"][0]["Achievements"][0]["ID"], 1, "achievements are never dropped");
        let a = v(trim_sets(set, Keep::NoLeaderboards.probe_drops()));
        assert_eq!((a["RichPresencePatch"].as_str(), &a["Sets"][0]["Leaderboards"]), (Some(""), &serde_json::json!([])));
        assert_eq!(trim_sets(b"not json", (true, true)), b"not json".to_vec());
    }
}
