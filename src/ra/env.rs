//! What the C callbacks reach: the console's memory as of the frame being
//! judged, the disc (for the hash), the HTTP channel and the event log. Shared
//! by `Rc<RefCell<..>>` between the RA thread's own code and the callbacks; no
//! borrow is ever held across a call into C.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::rc::Rc;
use std::sync::mpsc::Sender;

use super::chains::{self, Event as WalkEvent, RAM, Walk};
use super::ffi;
use super::session::Msg;
use super::table::Table;
use crate::disc_formats::types::DiscFormat;

/// One thing rcheevos wants the player told, or the thread told.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Achievement { id: u32, points: u32, title: String, description: String },
    LeaderboardStarted(String),
    LeaderboardFailed(String),
    LeaderboardSubmitted(String),
    Progress { title: String, progress: String },
    Completed,
    ServerError { api: String, message: String },
    Disconnected,
    Reconnected,
    Reset,
    /// The game's set was fetched: the probe can be built from it.
    GameSets,
    Login { ok: bool, message: String },
    Load { ok: bool, message: String },
    /// A hash was looked up: the game it belongs to (0: none).
    HashGame(u32),
    /// A multi-disc game's new disc was taken (`result` 0) or not.
    Media { result: i32, message: String },
    Log(String),
}

pub struct Env {
    pub table: Table,
    /// The table's words (the ranges', then the chains'), as of the frame being
    /// judged. Set through `set_words`.
    pub words: Vec<u32>,
    /// Where each chain's word is, under `words`; `None` outside RAM.
    pub chain_addr: Vec<Option<u32>>,
    /// Byte addresses read that the table does not hold.
    pub missed: Vec<u32>,
    /// A read by the REAL client missed: its frame was judged on zeros.
    pub real_missed: bool,
    pub in_real: bool,
    pub events: Vec<Event>,
    pub tx: Sender<Msg>,
    pub user_agent: String,
    pub disc: Option<Box<dyn DiscFormat>>,
    /// Requests for the game's sets, whose answers the session may trim before
    /// rcheevos sees them (`session::trim_sets`).
    pub sets_requests: Vec<u64>,
    /// The slow path (`slow.rs`): the real client reads what the table lacks
    /// from `slow_vals` (the last complete cycle) instead of missing it, and
    /// what it has not got yet is noted in `slow_new`.
    pub slow_mode: bool,
    pub slow_vals: std::collections::HashMap<u32, u32>,
    pub slow_new: std::collections::BTreeSet<u32>,
}

pub type Shared = Rc<RefCell<Env>>;

impl Env {
    /// The words of the frame to judge: the loader's, in table order. The address
    /// of each chain's word is worked out here, from its parent's value, as the
    /// loader worked it out.
    pub fn set_words(&mut self, words: &[u32]) {
        self.words.clear();
        self.words.extend_from_slice(words);
        self.update_chains();
    }

    /// `words` zeroed for the current table (a first pass finds where a set reads).
    pub fn zero_words(&mut self) {
        self.words = vec![0; self.table.words()];
        self.update_chains();
    }

    fn update_chains(&mut self) {
        self.chain_addr = chains::resolve(
            &self.table.chains,
            |a| self.table.index_of(a),
            self.table.direct_words(),
            &self.words,
        );
    }

    /// The table word holding RAM address `a`: a range's, or a chain's. A chain's
    /// word is the one the loader read, at its address rounded down to a word
    /// (ra.c: `& 0x00fffffc`): what a pointer that is not a multiple of 4 names is
    /// not on a word boundary, and the loader reads the word it falls in.
    fn word_at(&self, a: u32) -> Option<usize> {
        self.table.index_of(a).or_else(|| {
            let w = a & !3;
            self.chain_addr
                .iter()
                .position(|x| x.map(|x| x & !3) == Some(w))
                .map(|i| self.table.direct_words() + i)
        })
    }

    /// Whether a pointer of this frame holds a value that is not a multiple of 4.
    /// The loader reads the word that value falls in; rcheevos reads at the value
    /// itself, across two words, and a pointer it reads there is not the one the
    /// loader followed. (Every chain's offset is a multiple of 4, so a misaligned
    /// pointer shows as a misaligned chain address one level down.)
    pub fn skewed(&self) -> bool {
        self.chain_addr.iter().flatten().any(|x| x & 3 != 0)
    }

    /// `n` bytes at the RA address `addr` (an offset into RAM), little-endian.
    /// An address past RAM is not memory: it reads nothing, as on the console. A
    /// byte of RAM the table lacks reads 0 and is noted: it is what the table must
    /// grow by.
    fn read(&mut self, addr: u32, out: &mut [u8]) {
        for (i, b) in out.iter_mut().enumerate() {
            let a = addr.wrapping_add(i as u32);
            if a >= RAM {
                *b = 0;
                continue;
            }
            match self.word_at(a).and_then(|ix| self.words.get(ix)) {
                Some(w) => *b = (*w >> (8 * (a & 3))) as u8,
                // The real client, with the slow path on: what the probe's table
                // left out (the rich presence) is read slowly, never grown for.
                None if self.in_real && self.slow_mode => {
                    let w = a & !3;
                    *b = match self.slow_vals.get(&w) {
                        Some(v) => (*v >> (8 * (a & 3))) as u8,
                        None => {
                            self.slow_new.insert(w);
                            0
                        }
                    };
                }
                None => {
                    *b = 0;
                    if !self.missed.contains(&(a & !3)) {
                        self.missed.push(a & !3);
                    }
                    if self.in_real {
                        self.real_missed = true;
                    }
                }
            }
        }
    }
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

unsafe fn env<'a>(ud: *mut c_void) -> &'a RefCell<Env> {
    unsafe { &*(ud as *const RefCell<Env>) }
}

unsafe extern "C" fn cb_read(ud: *mut c_void, addr: u32, buf: *mut u8, n: u32) -> u32 {
    let out = unsafe { std::slice::from_raw_parts_mut(buf, n as usize) };
    unsafe { env(ud) }.borrow_mut().read(addr, out);
    n
}

/// The probe's peek: same memory, same notes, not the real client's.
pub unsafe extern "C" fn probe_peek(addr: u32, buf: *mut u8, n: u32, ud: *mut c_void) -> u32 {
    unsafe { cb_read(ud, addr, buf, n) }
}

unsafe extern "C" fn cb_http(
    ud: *mut c_void,
    token: u64,
    url: *const c_char,
    post: *const c_char,
    ctype: *const c_char,
) {
    let mut e = unsafe { env(ud) }.borrow_mut();
    let (url, post, ctype) = (cstr(url), (!post.is_null()).then(|| cstr(post)), cstr(ctype));
    if post.as_deref().is_some_and(|p| p.contains("r=achievementsets")) {
        e.sets_requests.push(token);
    }
    let (tx, ua) = (e.tx.clone(), e.user_agent.clone());
    drop(e);
    std::thread::spawn(move || {
        let (status, body) = request(&url, post.as_deref(), &ctype, &ua);
        let _ = tx.send(Msg::Http { token, status, body });
    });
}

/// RC_API_SERVER_RESPONSE_RETRYABLE_CLIENT_ERROR: nothing came back, try again.
const RETRYABLE: i32 = -2;

fn request(url: &str, post: Option<&str>, ctype: &str, ua: &str) -> (i32, Vec<u8>) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .user_agent(ua)
        .build()
        .into();
    let result = match post {
        Some(body) => agent
            .post(url)
            .header("Content-Type", if ctype.is_empty() { "application/x-www-form-urlencoded" } else { ctype })
            .send(body),
        None => agent.get(url).call(),
    };
    match result {
        Ok(mut resp) => {
            let status = resp.status().as_u16() as i32;
            let body = resp.body_mut().read_to_vec().unwrap_or_default();
            (status, body)
        }
        Err(e) => (RETRYABLE, e.to_string().into_bytes()),
    }
}

unsafe extern "C" fn cb_event(
    ud: *mut c_void,
    kind: c_int,
    id: u32,
    points: u32,
    a: *const c_char,
    b: *const c_char,
) {
    let (a, b) = (cstr(a), cstr(b));
    let ev = match kind {
        ffi::EV_ACHIEVEMENT => Event::Achievement { id, points, title: a, description: b },
        ffi::EV_LB_STARTED => Event::LeaderboardStarted(a),
        ffi::EV_LB_FAILED => Event::LeaderboardFailed(a),
        ffi::EV_LB_SUBMITTED => Event::LeaderboardSubmitted(a),
        ffi::EV_PROGRESS => Event::Progress { title: a, progress: b },
        ffi::EV_COMPLETED => Event::Completed,
        ffi::EV_SERVER_ERROR => Event::ServerError { api: a, message: b },
        ffi::EV_DISCONNECTED => Event::Disconnected,
        ffi::EV_RECONNECTED => Event::Reconnected,
        ffi::EV_RESET => Event::Reset,
        ffi::EV_GAME_SETS => Event::GameSets,
        ffi::EV_HASH_GAME => Event::HashGame(id),
        _ => return,
    };
    unsafe { env(ud) }.borrow_mut().events.push(ev);
}

unsafe extern "C" fn cb_log(ud: *mut c_void, msg: *const c_char) {
    unsafe { env(ud) }.borrow_mut().events.push(Event::Log(cstr(msg)));
}

unsafe extern "C" fn cb_done(ud: *mut c_void, what: c_int, result: c_int, msg: *const c_char) {
    let (ok, message) = (result == 0, cstr(msg));
    let ev = match what {
        ffi::DONE_LOGIN => Event::Login { ok, message },
        ffi::DONE_MEDIA => Event::Media { result, message },
        _ => Event::Load { ok, message },
    };
    unsafe { env(ud) }.borrow_mut().events.push(ev);
}

unsafe extern "C" fn cb_sector(ud: *mut c_void, lba: u32, buf: *mut u8, n: usize) -> usize {
    let e = unsafe { env(ud) }.borrow();
    let Some(disc) = e.disc.as_deref() else { return 0 };
    match disc.read_sector(disc.fs_lba(lba), 1) {
        Ok(data) => {
            let k = data.len().min(n);
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf, k) };
            k
        }
        Err(_) => 0,
    }
}

/// The first sector, in the filesystem's own numbering, of the disc's `track`:
/// 3 is a GD-ROM's high-density data track, -1 (as a u32) the first data track
/// of anything else. `-1` back: no such track.
unsafe extern "C" fn cb_track_first(ud: *mut c_void, track: u32) -> i64 {
    let e = unsafe { env(ud) }.borrow();
    let Some(disc) = e.disc.as_deref() else { return -1 };
    let boot = disc.boot_sector() as i64 - disc.fs_lba(0) as i64;
    let start = disc.start_sector() as i64 - disc.fs_lba(0) as i64;
    match track {
        3 if disc.boot_sector() != disc.start_sector() => boot,
        3 => -1,
        u32::MAX => start,
        _ => -1,
    }
}

/// An `rc_client` and the state its callbacks reach.
pub struct Client {
    ctx: *mut ffi::Ctx,
    pub env: Shared,
}

impl Client {
    pub fn new(env: Shared, hardcore: bool, server: Option<&str>) -> Client {
        let host = ffi::Host {
            ud: Rc::as_ptr(&env) as *mut c_void,
            read: cb_read,
            http: cb_http,
            event: cb_event,
            log: cb_log,
            done: cb_done,
            sector: cb_sector,
            track_first: cb_track_first,
        };
        let ctx = unsafe { ffi::ra_new(&host, hardcore as c_int) };
        // Another server: tests point the client at a local fake one.
        if let Some(h) = server {
            let h = CString::new(h).unwrap();
            unsafe { ffi::ra_set_host(ctx, h.as_ptr()) };
        }
        let mut clause = [0 as c_char; 64];
        unsafe { ffi::ra_user_agent_clause(ctx, clause.as_mut_ptr(), clause.len()) };
        env.borrow_mut().user_agent = format!(
            "dcload-ip-rs/{} {}",
            env!("CARGO_PKG_VERSION"),
            cstr(clause.as_ptr())
        );
        Client { ctx, env }
    }

    pub fn login_password(&mut self, user: &str, password: &str) {
        let (u, p) = (CString::new(user).unwrap(), CString::new(password).unwrap());
        unsafe { ffi::ra_login_password(self.ctx, u.as_ptr(), p.as_ptr()) };
    }

    pub fn login_token(&mut self, user: &str, token: &str) {
        let (u, t) = (CString::new(user).unwrap(), CString::new(token).unwrap());
        unsafe { ffi::ra_login_token(self.ctx, u.as_ptr(), t.as_ptr()) };
    }

    pub fn token(&self) -> Option<String> {
        let t = cstr(unsafe { ffi::ra_token(self.ctx) });
        (!t.is_empty()).then_some(t)
    }

    pub fn display_name(&self) -> String {
        cstr(unsafe { ffi::ra_display_name(self.ctx) })
    }

    /// The Dreamcast hash of the disc in `env`, as RetroAchievements knows it.
    pub fn hash_disc(&mut self) -> Option<String> {
        let mut out = [0 as c_char; 33];
        (unsafe { ffi::ra_hash_dreamcast(self.ctx, out.as_mut_ptr()) } != 0)
            .then(|| cstr(out.as_ptr()))
    }

    pub fn load_game(&mut self, hash: &str) {
        let h = CString::new(hash).unwrap();
        unsafe { ffi::ra_load_game(self.ctx, h.as_ptr()) };
    }

    /// The next disc of the loaded game (by hash); see `ra_change_media`.
    pub fn change_media(&mut self, hash: &str) {
        let h = CString::new(hash).unwrap();
        unsafe { ffi::ra_change_media(self.ctx, h.as_ptr()) };
    }

    /// Forget the loaded game (the next `load_game` starts another).
    pub fn unload_game(&mut self) {
        unsafe { ffi::ra_unload_game(self.ctx) };
    }

    pub fn game(&self) -> Option<(u32, String)> {
        let mut title: *const c_char = std::ptr::null();
        let id = unsafe { ffi::ra_game_id(self.ctx, &mut title) };
        (id != 0).then(|| (id, cstr(title)))
    }

    /// The loaded game's badge URL.
    pub fn game_badge(&self) -> Option<String> {
        let p = unsafe { ffi::ra_game_badge(self.ctx) };
        (!p.is_null()).then(|| cstr(p)).filter(|s| !s.is_empty())
    }

    /// (core achievements, earned in this mode, unsupported, hardcore).
    pub fn summary(&self) -> (u32, u32, u32, bool) {
        let (mut core, mut unlocked, mut unsupported, mut hardcore) = (0, 0, 0, 0);
        unsafe {
            ffi::ra_game_summary(self.ctx, &mut core, &mut unlocked, &mut unsupported, &mut hardcore)
        };
        (core, unlocked, unsupported, hardcore != 0)
    }

    /// Each core achievement: (id, rc_client state, title).
    pub fn achievements(&self) -> Vec<(u32, c_int, String)> {
        unsafe extern "C" fn one(ud: *mut c_void, id: u32, state: c_int, title: *const c_char) {
            let out = unsafe { &mut *(ud as *mut Vec<(u32, c_int, String)>) };
            out.push((id, state, cstr(title)));
        }
        let mut out: Vec<(u32, c_int, String)> = Vec::new();
        unsafe { ffi::ra_each_achievement(self.ctx, &mut out as *mut _ as *mut c_void, one) };
        out
    }

    /// The rich presence as rcheevos evaluates it now; the site only gets it
    /// at rc_client's next ping, every 2 minutes.
    pub fn rich_presence(&self) -> String {
        let mut buf = [0u8; 256];
        let n = unsafe { ffi::ra_rich_presence(self.ctx, buf.as_mut_ptr() as *mut c_char, buf.len()) };
        String::from_utf8_lossy(&buf[..n.min(buf.len() - 1)]).into_owned()
    }

    /// Judge one frame. The caller has put the frame's memory in `env.words`.
    pub fn do_frame(&mut self) {
        {
            let mut e = self.env.borrow_mut();
            e.in_real = true;
            e.real_missed = false;
        }
        unsafe { ffi::ra_do_frame(self.ctx) };
        self.env.borrow_mut().in_real = false;
    }

    pub fn idle(&mut self) {
        unsafe { ffi::ra_idle(self.ctx) };
    }

    pub fn http_done(&mut self, token: u64, status: i32, body: &[u8]) {
        unsafe {
            ffi::ra_http_done(self.ctx, token, status, body.as_ptr() as *const c_char, body.len())
        };
    }

    /// The raw game-sets response, kept by the shim for the probe.
    pub fn game_sets(&self) -> Option<Vec<u8>> {
        let mut len = 0usize;
        let p = unsafe { ffi::ra_game_sets(self.ctx, &mut len) };
        (!p.is_null()).then(|| unsafe { std::slice::from_raw_parts(p as *const u8, len) }.to_vec())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { ffi::ra_destroy(self.ctx) };
    }
}

/// The probe: the whole set run a frame ahead of the real client.
pub struct Probe(*mut ffi::Probe);

impl Probe {
    pub fn new(sets: &[u8]) -> Option<Probe> {
        let p = unsafe { ffi::ra_probe_new(sets.as_ptr() as *const c_char, sets.len()) };
        (!p.is_null()).then_some(Probe(p))
    }

    /// (achievements, leaderboards, has rich presence) it holds.
    pub fn counts(&self) -> (u32, u32, bool) {
        let (mut a, mut l, mut r) = (0u32, 0u32, 0 as c_int);
        unsafe { ffi::ra_probe_counts(self.0, &mut a, &mut l, &mut r) };
        (a, l, r != 0)
    }

    /// Where the set reads, from the public structures rcheevos exposes: the
    /// direct words and the pointer chains (`chains.rs`).
    pub fn walk(&mut self) -> Walk {
        unsafe extern "C" fn cb(ud: *mut c_void, kind: c_int, node: c_int, parent: c_int, value: u32, bytes: u32) {
            let events = unsafe { &mut *(ud as *mut Vec<WalkEvent>) };
            events.push(match kind {
                1 => WalkEvent::Root { node, addr: value },
                2 => WalkEvent::Ptr { node, parent, off: value },
                3 => WalkEvent::Indirect { parent, off: value, bytes },
                4 => WalkEvent::Direct { addr: value, bytes },
                _ => WalkEvent::Unsupported,
            });
        }
        let mut events: Vec<WalkEvent> = Vec::new();
        unsafe { ffi::ra_probe_walk(self.0, cb, &mut events as *mut _ as *mut c_void) };
        Walk::from_events(events)
    }

    pub fn frame(&mut self, env: &Shared) {
        unsafe { ffi::ra_probe_frame(self.0, probe_peek, Rc::as_ptr(env) as *mut c_void) };
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        unsafe { ffi::ra_probe_free(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ra::chains::{Chain, Parent};
    use std::sync::mpsc::channel;

    #[test]
    fn a_misaligned_pointer_reads_the_word_the_loader_read() {
        let (tx, _rx) = channel();
        let chains = [Chain { parent: Parent::Direct(0x2000), shift: 0, word_off: 0x10 }];
        let mut e = Env {
            table: Table::build([0x2000], &chains, 512).unwrap(),
            words: vec![],
            chain_addr: vec![],
            missed: vec![],
            real_missed: false,
            in_real: false,
            events: vec![],
            tx,
            user_agent: String::new(),
            disc: None,
            sets_requests: vec![],
            slow_mode: false,
            slow_vals: Default::default(),
            slow_new: Default::default(),
        };
        // the pointer is 0x3001: the chain names 0x3011, the loader read the word
        // at 0x3010 (ra.c rounds down), whose bytes 0x3010..0x3013 are RAM's
        e.set_words(&[0x0000_3001, 0x4433_2211]);
        assert!(e.skewed());
        let mut b = [0u8; 1];
        e.read(0x3011, &mut b);
        assert_eq!((b[0], e.missed.len()), (0x22, 0), "byte 1 of the loader's word");
        e.read(0x3013, &mut b);
        assert_eq!((b[0], e.missed.len()), (0x44, 0));
        // past that word nothing was sampled
        e.read(0x3014, &mut b);
        assert_eq!((b[0], e.missed.clone()), (0, vec![0x3014]));
        // an aligned pointer: nothing skewed
        e.set_words(&[0x0000_3000, 0]);
        assert!(!e.skewed());
    }

    /// With the slow path on, the real client reads what the table lacks from
    /// the last slow cycle, or notes it for the next one -- never a miss, so
    /// never a reason to grow; the probe still misses it.
    #[test]
    fn the_slow_path_serves_the_real_client_and_not_the_probe() {
        let (tx, _rx) = channel();
        let mut e = Env {
            table: Table::build([0x2000], &[], 512).unwrap(),
            words: vec![],
            chain_addr: vec![],
            missed: vec![],
            real_missed: false,
            in_real: true,
            events: vec![],
            tx,
            user_agent: String::new(),
            disc: None,
            sets_requests: vec![],
            slow_mode: true,
            slow_vals: [(0x5000, 0x4433_2211)].into_iter().collect(),
            slow_new: Default::default(),
        };
        e.set_words(&[7]);
        let mut b = [0u8; 2];
        e.read(0x5001, &mut b);
        assert_eq!(b, [0x22, 0x33], "the slow cycle's value");
        e.read(0x6000, &mut b);
        assert_eq!((b, e.slow_new.iter().copied().collect::<Vec<_>>()), ([0, 0], vec![0x6000]));
        assert!(e.missed.is_empty() && !e.real_missed, "not a miss");
        e.in_real = false;
        e.read(0x6000, &mut b);
        assert_eq!(e.missed, vec![0x6000], "the probe still misses it");
    }
}
