//! RetroAchievements bridge (loader AGENTS.md 4.20).
//!
//! The loader samples; this side judges, with rcheevos (vendor/rcheevos, linked
//! through the flat shim `shim.c`).
//!
//! * `table`   -- the RAM ranges the loader is asked to sample (`RACT`).
//! * `frames`  -- the console's memory, rebuilt from its `RAFR` frames, and
//!   knowing when a lost datagram makes it untrustworthy.
//! * `env`     -- what rcheevos' callbacks reach: memory, disc, HTTP, events.
//! * `session` -- the thread that logs in, hashes the disc, loads the set and
//!   judges frames; `ra-login` and `ra-count`.
//! * `slow`    -- what the table has no room for, read with `SBIQ` (the rich
//!   presence of a set too big for the loader).
//! * `store`   -- the login token file.

pub mod chains;
pub mod env;
pub mod ffi;
pub mod frames;
pub mod session;
pub mod slow;
pub mod store;
pub mod table;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod loader_c;
