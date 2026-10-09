//! The flat C face (`shim.c`) and nothing else: no logic here.

use std::ffi::{c_char, c_int, c_void};

pub enum Ctx {}
pub enum Probe {}

pub const EV_ACHIEVEMENT: c_int = 1;
pub const EV_LB_STARTED: c_int = 2;
pub const EV_LB_FAILED: c_int = 3;
pub const EV_LB_SUBMITTED: c_int = 4;
pub const EV_PROGRESS: c_int = 5;
pub const EV_COMPLETED: c_int = 6;
pub const EV_SERVER_ERROR: c_int = 7;
pub const EV_DISCONNECTED: c_int = 8;
pub const EV_RECONNECTED: c_int = 9;
pub const EV_RESET: c_int = 10;
pub const EV_GAME_SETS: c_int = 11;
pub const EV_HASH_GAME: c_int = 12;

pub const DONE_LOGIN: c_int = 1;
pub const DONE_LOAD: c_int = 2;
pub const DONE_MEDIA: c_int = 3;

/// `ra_host` in shim.c, field for field.
#[repr(C)]
pub struct Host {
    pub ud: *mut c_void,
    pub read: unsafe extern "C" fn(*mut c_void, u32, *mut u8, u32) -> u32,
    pub http: unsafe extern "C" fn(*mut c_void, u64, *const c_char, *const c_char, *const c_char),
    pub event:
        unsafe extern "C" fn(*mut c_void, c_int, u32, u32, *const c_char, *const c_char),
    pub log: unsafe extern "C" fn(*mut c_void, *const c_char),
    pub done: unsafe extern "C" fn(*mut c_void, c_int, c_int, *const c_char),
    pub sector: unsafe extern "C" fn(*mut c_void, u32, *mut u8, usize) -> usize,
    pub track_first: unsafe extern "C" fn(*mut c_void, u32) -> i64,
}

/// `(ud, kind, node, parent, value, bytes)`; see `ra_probe_walk` in shim.c.
pub type WalkCb = unsafe extern "C" fn(*mut c_void, c_int, c_int, c_int, u32, u32);

pub type Peek = unsafe extern "C" fn(u32, *mut u8, u32, *mut c_void) -> u32;

/// `(ud, id, state, title)`; see `ra_each_achievement` in shim.c.
pub type AchievementCb = unsafe extern "C" fn(*mut c_void, u32, c_int, *const c_char);

/// `RC_CLIENT_ACHIEVEMENT_STATE_UNLOCKED`, `_DISABLED`.
pub const STATE_UNLOCKED: c_int = 2;
pub const STATE_DISABLED: c_int = 3;

unsafe extern "C" {
    pub fn ra_new(host: *const Host, hardcore: c_int) -> *mut Ctx;
    pub fn ra_set_host(c: *mut Ctx, host: *const c_char);
    pub fn ra_destroy(c: *mut Ctx);
    pub fn ra_user_agent_clause(c: *mut Ctx, buf: *mut c_char, n: usize) -> usize;
    pub fn ra_http_done(c: *mut Ctx, token: u64, status: c_int, body: *const c_char, len: usize);
    pub fn ra_game_sets(c: *mut Ctx, len: *mut usize) -> *const c_char;
    pub fn ra_login_password(c: *mut Ctx, user: *const c_char, password: *const c_char);
    pub fn ra_login_token(c: *mut Ctx, user: *const c_char, token: *const c_char);
    pub fn ra_token(c: *mut Ctx) -> *const c_char;
    pub fn ra_display_name(c: *mut Ctx) -> *const c_char;
    pub fn ra_load_game(c: *mut Ctx, hash: *const c_char);
    pub fn ra_change_media(c: *mut Ctx, hash: *const c_char);
    pub fn ra_unload_game(c: *mut Ctx);
    pub fn ra_game_id(c: *mut Ctx, title: *mut *const c_char) -> u32;
    pub fn ra_game_badge(c: *mut Ctx) -> *const c_char;
    pub fn ra_game_summary(
        c: *mut Ctx,
        core: *mut u32,
        unlocked: *mut u32,
        unsupported: *mut u32,
        hardcore: *mut c_int,
    );
    pub fn ra_each_achievement(c: *mut Ctx, ud: *mut c_void, cb: AchievementCb);
    pub fn ra_rich_presence(c: *mut Ctx, buf: *mut c_char, n: usize) -> usize;
    pub fn ra_do_frame(c: *mut Ctx);
    pub fn ra_idle(c: *mut Ctx);
    pub fn ra_hash_dreamcast(c: *mut Ctx, out: *mut c_char) -> c_int;

    pub fn ra_probe_new(json: *const c_char, len: usize) -> *mut Probe;
    pub fn ra_probe_counts(p: *const Probe, ach: *mut u32, lb: *mut u32, rp: *mut c_int);
    pub fn ra_probe_frame(p: *mut Probe, peek: Peek, ud: *mut c_void);
    pub fn ra_probe_free(p: *mut Probe);
    pub fn ra_probe_walk(p: *mut Probe, cb: WalkCb, ud: *mut c_void);
}
