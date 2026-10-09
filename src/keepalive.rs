//! `--keepalive`: end a session whose console has stopped saying anything.
//!
//! IT ASKS WHEN NOTHING ELSE DOES. The title's own reads and audio fetches,
//! the stack watch's SendBinQ every ten seconds and the witness words' checks
//! all make the console speak; once a third of the limit has passed without a
//! word, this asks too -- four bytes, `g_irq_hooked`, every half second until
//! something arrives -- so a 10-second limit does not depend on any other
//! instrument's period. But a loader hears questions only while it looks at the
//! network, and between two disc reads it looks only from its interrupt
//! hook's idle listen (loader AGENTS.md 4.15, `IRQ_IDLE_LISTEN`). Without
//! that, a title that does not read is silent and alive, and silence says
//! nothing.
//!
//! So the count is ARMED ONLY ONCE THE CONSOLE HAS SAID ITS HOOK IS IN: the
//! running loader must have the idle listen compiled in (`gd_idle_listen` in
//! its ELF, checked by `main.rs`), and `g_irq_hooked` must read non-zero --
//! asked with a four-byte SendBinQ until it does. A title whose interrupt
//! entry the loader refuses (KOS, homebrew) never arms it. KOS titles are not
//! even asked: the hook never recognises KOS's table.
//!
//! AND IT IS DISARMED WHEN THE HOOK GOES. A title can replace the entry the
//! loader hooked with one it refuses (Jet Set Radio, 2026-10-09: hooked during
//! its first loads, two interrupts through it, then refused at the same VBR
//! before its SEGA logo); the loader is then deaf between reads again, and a
//! count armed on the first answer ended a live session 10 s into the logo
//! while the panel's own sample already read `g_irq_hooked` 0. So, armed, this
//! asks again every `ARMED_CHECK_EVERY` while the console talks (each answer
//! comes from inside a read's wait), takes the panel's reading too, and goes
//! back to checking on a 0.
//!
//! THE COUNTER PANEL DOES NOT SUSPEND IT: a console that answers nothing has
//! nothing more to show the panel either (Sonic Adventure 2, 2026-10-05: an
//! hour of "sample timed out"). While the panel samples, the hook check gives
//! way to it -- its range contains `g_irq_hooked`, and two sinks claiming by
//! address would eat each other's replies -- and reads the word out of the
//! panel's last sample instead. The syscall loop writes the panel's last
//! sample to `dcload-diag.txt` when the keepalive ends a session.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::cmds::{DCLoadCmd, DCLoadCmds, DCReturnCmd};
use crate::io::{ExternalDcIo, PacketSink};

/// What `main.rs` hands the syscall loop when the keepalive may be armed.
pub struct Config {
    pub limit: Duration,
    /// `g_irq_hooked` in the running loader.
    pub hooked_at: u32,
}

/// How often the hook is asked about while it is not in, and once nothing
/// answers. The hook goes in on the title's first GD syscall, seconds in.
const CHECK_EVERY: Duration = Duration::from_secs(10);
const QUIET_CHECK_EVERY: Duration = Duration::from_secs(60);
const QUIET_AFTER: u32 = 6;
/// Armed: how often the hook is asked about while the console still talks,
/// so that a title which replaced its interrupt entry is noticed before its
/// loads end.
const ARMED_CHECK_EVERY: Duration = Duration::from_secs(2);
/// One question's life, and how often it is asked again inside it -- the
/// stack watch's figures, for the same link.
const TIMEOUT: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_millis(500);

/// The silence count itself.
struct Silence {
    limit: Duration,
    /// The moment silence is counted from: the last input, or the start of
    /// the count, whichever is later.
    since: Instant,
}

impl Silence {
    fn new(limit: Duration, now: Instant) -> Self {
        Silence { limit, since: now }
    }

    /// The silence so far once it has reached the limit, `None` otherwise.
    fn check(&mut self, now: Instant, last_input: Option<Instant>) -> Option<Duration> {
        if let Some(t) = last_input
            && t > self.since
        {
            self.since = t;
        }
        let quiet = now.saturating_duration_since(self.since);
        (quiet >= self.limit).then_some(quiet)
    }

    /// When to look again.
    fn poll_timeout(&self, now: Instant) -> Duration {
        (self.since + self.limit).saturating_duration_since(now)
    }
}

/// Claims the answer to our four-byte read of `g_irq_hooked`, by address.
struct HookSink {
    addr: u32,
    value: Option<u32>,
    active: bool,
}

impl PacketSink for HookSink {
    fn claim(&mut self, cmd: &DCReturnCmd) -> bool {
        if !self.active {
            return false;
        }
        let Some(inner) = cmd.cmd.as_ref() else {
            return false;
        };
        if inner.address != self.addr {
            return false;
        }
        match &inner.cmd {
            DCLoadCmds::SendBinary(Some(chunk)) if inner.size >= 4 => {
                self.value = Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                true
            }
            // The terminator of our own read.
            DCLoadCmds::DoneBinary() => true,
            _ => false,
        }
    }
}

enum State {
    /// Asking whether the hook is in. `asked` is when the open question was
    /// first sent, `None` between questions.
    Checking {
        next_at: Instant,
        asked: Option<Instant>,
        last_sent: Instant,
        misses: u32,
    },
    /// Counting; `last_ping` is when this last asked for itself.
    Armed(Silence, Instant),
}

pub struct Keepalive {
    limit: Duration,
    sink: Arc<Mutex<HookSink>>,
    state: State,
}

impl Keepalive {
    pub fn new(cfg: &Config) -> Self {
        let now = Instant::now();
        Keepalive {
            limit: cfg.limit,
            sink: Arc::new(Mutex::new(HookSink {
                addr: cfg.hooked_at,
                value: None,
                active: true,
            })),
            state: State::Checking {
                next_at: now + Duration::from_secs(2),
                asked: None,
                last_sent: now,
                misses: 0,
            },
        }
    }

    pub fn install(&self, conn: &mut impl ExternalDcIo) {
        conn.add_sink(self.sink.clone() as crate::io::SharedSink);
    }

    /// From the top of the syscall loop, where no transfer owns the
    /// conversation. Returns the silence once it has reached the limit.
    ///
    /// `panel_hooked` is `g_irq_hooked` from the counter panel's last sample,
    /// `None` when the panel is not sampling: then this asks for itself.
    pub fn tick(&mut self, conn: &mut impl ExternalDcIo, panel_hooked: Option<u64>) -> Option<Duration> {
        let now = Instant::now();
        let paused = crate::ui::sampling_wanted();
        let answer = {
            let mut sink = self.sink.lock().expect("sink poisoned");
            // Armed, the reply is claimed even while the panel samples (its
            // sink comes first in the list and takes it when it has a sample
            // open over the same word; then its reading stands in).
            sink.active = !paused || matches!(self.state, State::Armed(..));
            sink.value.take()
        };
        let answer = answer.or(panel_hooked.map(|v| v as u32));
        let State::Checking { next_at, asked, last_sent, misses } = &mut self.state else {
            let State::Armed(silence, last_ping) = &mut self.state else { unreachable!() };
            if answer == Some(0) {
                info!(
                    "keepalive: the loader's hook is out (the title replaced its interrupt \
                     entry), so the console is deaf between disc reads; silence is not counted \
                     until the hook is back"
                );
                self.state = State::Checking {
                    next_at: now + CHECK_EVERY,
                    asked: None,
                    last_sent: now,
                    misses: 0,
                };
                return None;
            }
            if let Some(quiet) = silence.check(now, conn.last_input()) {
                return Some(quiet);
            }
            let silent = now.duration_since(silence.since) >= silence.limit / 3;
            if (silent && now.duration_since(*last_ping) >= RETRY)
                || (!silent && !paused && now.duration_since(*last_ping) >= ARMED_CHECK_EVERY)
            {
                *last_ping = now;
                let addr = self.sink.lock().expect("sink poisoned").addr;
                ask(conn, addr);
            }
            return None;
        };
        match answer {
            Some(v) if v != 0 => {
                info!(
                    "keepalive: the loader's hook is in, so it hears this host while the title \
                     runs -- the session ends after {}s without a word from the console \
                     (--keepalive 0 to keep it)",
                    self.limit.as_secs()
                );
                self.state = State::Armed(Silence::new(self.limit, now), now);
                return None;
            }
            Some(_) if panel_hooked.is_some() => {}
            Some(_) => {
                debug!("keepalive: the loader's hook is not in yet; not counting silence");
                *asked = None;
                *misses = 0;
                *next_at = now + CHECK_EVERY;
            }
            None => {}
        }
        if paused {
            // The panel has the wire and reads the word; ask again once it is
            // off.
            *asked = None;
            return None;
        }
        if let Some(t) = *asked
            && now.duration_since(t) > TIMEOUT
        {
            *asked = None;
            *misses = misses.saturating_add(1);
            *next_at = now + if *misses >= QUIET_AFTER { QUIET_CHECK_EVERY } else { CHECK_EVERY };
        }
        if asked.is_none() {
            if now < *next_at {
                return None;
            }
            *asked = Some(now);
            *last_sent = now - RETRY;
        }
        if now.duration_since(*last_sent) < RETRY {
            return None;
        }
        let addr = self.sink.lock().expect("sink poisoned").addr;
        ask(conn, addr);
        *last_sent = now;
        None
    }

    /// When the loop must wake for this.
    pub fn poll_timeout(&self) -> Option<Duration> {
        let now = Instant::now();
        let paused = crate::ui::sampling_wanted();
        match &self.state {
            State::Armed(s, last_ping) => {
                let mut ping = (s.since + s.limit / 3).max(*last_ping + RETRY);
                if !paused {
                    ping = ping.min(*last_ping + ARMED_CHECK_EVERY);
                }
                Some(s.poll_timeout(now).min(ping.saturating_duration_since(now)))
            }
            State::Checking { .. } if paused => None,
            State::Checking { next_at, asked: None, .. } => Some(next_at.saturating_duration_since(now)),
            State::Checking { asked: Some(t), last_sent, .. } => Some(
                (*last_sent + RETRY)
                    .min(*t + TIMEOUT)
                    .saturating_duration_since(now),
            ),
        }
    }
}

/// Four bytes of `g_irq_hooked`: the question both phases ask.
fn ask(conn: &mut impl ExternalDcIo, addr: u32) {
    let cmd = DCLoadCmd {
        cmd: DCLoadCmds::SendBinaryQuiet(None),
        address: addr,
        size: 4,
    };
    if let Err(e) = conn.send_command(cmd) {
        debug!("keepalive: could not ask the console: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Duration = Duration::from_secs(120);

    #[test]
    fn silence_ends_the_session_only_past_the_limit() {
        let t0 = Instant::now();
        let mut k = Silence::new(LIMIT, t0);
        assert_eq!(k.check(t0 + Duration::from_secs(119), None), None);
        assert_eq!(k.check(t0 + LIMIT, None), Some(LIMIT));
    }

    #[test]
    fn any_input_restarts_the_count() {
        let t0 = Instant::now();
        let mut k = Silence::new(LIMIT, t0);
        let heard = t0 + Duration::from_secs(100);
        assert_eq!(k.check(t0 + LIMIT, Some(heard)), None);
        assert_eq!(k.poll_timeout(t0 + LIMIT), Duration::from_secs(100));
        assert!(k.check(heard + LIMIT, Some(heard)).is_some());
    }

    #[test]
    fn input_from_before_the_count_does_not_age_it() {
        let t0 = Instant::now() + Duration::from_secs(1000);
        let mut k = Silence::new(LIMIT, t0);
        let old = t0 - Duration::from_secs(500);
        assert_eq!(k.check(t0 + Duration::from_secs(10), Some(old)), None);
    }

    fn reply(cmd: DCLoadCmds, address: u32, size: u32) -> DCReturnCmd {
        DCReturnCmd {
            cmd: Some(DCLoadCmd { cmd, address, size }),
            request: None,
            error_code: None,
        }
    }

    /// A console that talks (`last_input` is now) and counts what it is asked.
    struct Talking {
        sent: std::cell::Cell<u32>,
        heard: Instant,
    }

    impl ExternalDcIo for Talking {
        fn poll(&self, _t: Option<Duration>) -> Result<polling::Events, std::io::Error> {
            unreachable!()
        }
        fn handle_data(&mut self, _e: &polling::Events) -> Result<Vec<DCReturnCmd>, std::io::Error> {
            unreachable!()
        }
        fn send_command(&self, _c: DCLoadCmd) -> Result<usize, Box<dyn std::error::Error>> {
            self.sent.set(self.sent.get() + 1);
            Ok(0)
        }
        fn last_input(&self) -> Option<Instant> {
            Some(self.heard)
        }
    }

    fn keepalive() -> Keepalive {
        Keepalive::new(&Config { limit: Duration::from_secs(10), hooked_at: 0x8ce0_9fcc })
    }

    /// Jet Set Radio, 2026-10-09: hooked during its first loads, refused once
    /// its second program had copied its entry again; the panel read 0 and the
    /// count, armed, ended the session in the SEGA logo.
    #[test]
    fn the_panel_reading_the_hook_out_disarms_the_count() {
        let mut c = Talking { sent: Default::default(), heard: Instant::now() };
        let mut k = keepalive();
        assert_eq!(k.tick(&mut c, Some(1)), None);
        assert!(matches!(k.state, State::Armed(..)));
        assert_eq!(k.tick(&mut c, Some(0)), None);
        assert!(matches!(k.state, State::Checking { .. }));
        // Back in, armed again.
        assert_eq!(k.tick(&mut c, Some(1)), None);
        assert!(matches!(k.state, State::Armed(..)));
    }

    #[test]
    fn armed_it_asks_while_the_console_talks_and_disarms_on_a_zero() {
        let mut c = Talking { sent: Default::default(), heard: Instant::now() };
        let mut k = keepalive();
        let now = Instant::now();
        k.state = State::Armed(Silence::new(k.limit, now), now - ARMED_CHECK_EVERY);
        assert_eq!(k.tick(&mut c, None), None);
        assert_eq!(c.sent.get(), 1, "the hook is asked although the console is not silent");
        assert_eq!(k.tick(&mut c, None), None);
        assert_eq!(c.sent.get(), 1, "not again before ARMED_CHECK_EVERY");
        k.sink.lock().unwrap().value = Some(1);
        assert_eq!(k.tick(&mut c, None), None);
        assert!(matches!(k.state, State::Armed(..)));
        k.sink.lock().unwrap().value = Some(0);
        assert_eq!(k.tick(&mut c, None), None);
        assert!(matches!(k.state, State::Checking { .. }));
    }

    #[test]
    fn the_hook_sink_claims_only_its_own_word() {
        let mut s = HookSink { addr: 0x8ce0_9fcc, value: None, active: true };
        let mut chunk = Box::new([0u8; crate::CHUNK_SIZE]);
        chunk[0] = 1;
        assert!(!s.claim(&reply(DCLoadCmds::SendBinary(Some(chunk.clone())), 0x8ce0_9fd0, 4)));
        assert!(!s.claim(&reply(DCLoadCmds::DoneBinary(), 0x0c01_0000, 0)));
        assert_eq!(s.value, None);
        assert!(s.claim(&reply(DCLoadCmds::SendBinary(Some(chunk.clone())), 0x8ce0_9fcc, 4)));
        assert!(s.claim(&reply(DCLoadCmds::DoneBinary(), 0x8ce0_9fcc, 4)));
        assert_eq!(s.value, Some(1));
        s.active = false;
        s.value = None;
        assert!(!s.claim(&reply(DCLoadCmds::SendBinary(Some(chunk)), 0x8ce0_9fcc, 4)));
    }
}
