//! Changing the served disc image while a title runs (loader AGENTS.md 4.17).
//!
//! `swap-disc` reaches the session through `control.rs`. The new image is
//! opened and validated FIRST, then the loader is told with `DISC`; the old
//! image goes on serving until the loader answers 0. The loader answers 0 only
//! between GD commands, so every read served before the answer belongs to the
//! old disc and every read after it to the new one: no read can mix the two.
//! "Busy" (1) is asked again every `RETRY`; the whole attempt gives up after
//! `GIVE_UP` (the loader listens only in its own network windows).

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::control::{Reply, SwapRequest};
use crate::io::PacketSink;

const RETRY: Duration = Duration::from_millis(250);
const GIVE_UP: Duration = Duration::from_secs(10);
const IDLE_POLL: Duration = Duration::from_millis(100);
const BUSY_POLL: Duration = Duration::from_millis(50);
/// `size` of a refusal.
const REFUSED: u32 = 0xffff_ffff;

/// Where the replies land: inside whatever transfer is polling.
struct Sink {
    want: Option<u32>,
    answer: Option<u32>,
}

impl PacketSink for Sink {
    /// Every DISC is ours; a late answer to an attempt given up on must not
    /// reach the syscall loop.
    fn claim(&mut self, cmd: &DCReturnCmd) -> bool {
        let Some(inner) = cmd.cmd.as_ref() else {
            return false;
        };
        if !matches!(inner.cmd, DCLoadCmds::Disc()) {
            return false;
        }
        if self.want == Some(inner.address) {
            self.answer = Some(inner.size);
        }
        true
    }
}

struct Pending {
    generation: u32,
    disc: Box<dyn DiscFormat>,
    spec: String,
    reply: Reply,
    started: Instant,
    last_sent: Instant,
}

/// A swap the loader accepted: the caller installs `disc` and answers.
pub(super) struct Accepted {
    pub disc: Box<dyn DiscFormat>,
    pub spec: String,
    pub reply: Reply,
}

pub(super) struct DiscSwap {
    requests: Receiver<SwapRequest>,
    sink: Arc<Mutex<Sink>>,
    generation: u32,
    pending: Option<Pending>,
}

impl DiscSwap {
    pub fn new(requests: Receiver<SwapRequest>) -> Self {
        DiscSwap {
            requests,
            sink: Arc::new(Mutex::new(Sink { want: None, answer: None })),
            generation: 0,
            pending: None,
        }
    }

    pub fn install(&self, conn: &mut impl ExternalDcIo) {
        conn.add_sink(self.sink.clone() as crate::io::SharedSink);
    }

    pub fn poll_timeout(&self) -> Duration {
        if self.pending.is_some() { BUSY_POLL } else { IDLE_POLL }
    }

    fn fail(&mut self, why: String) {
        self.sink.lock().expect("sink poisoned").want = None;
        if let Some(p) = self.pending.take() {
            warn!("disc swap abandoned: {why}");
            p.reply.send(Err(why));
        }
    }

    /// Ticked from the top of the syscall loop. Returns the swap once the
    /// loader has accepted it.
    pub fn tick(&mut self, conn: &mut impl ExternalDcIo) -> Option<Accepted> {
        while let Ok(req) = self.requests.try_recv() {
            if self.pending.is_some() {
                req.reply.send(Err("a disc swap is already in progress".into()));
                continue;
            }
            // Through the disc patches, like the session's own image.
            match crate::dcp::open_served(&req.spec) {
                Err(e) => req.reply.send(Err(e)),
                Ok(disc) => {
                    self.generation = self.generation.wrapping_add(1).max(1);
                    self.sink.lock().expect("sink poisoned").want = Some(self.generation);
                    self.pending = Some(Pending {
                        generation: self.generation,
                        disc,
                        spec: req.spec,
                        reply: req.reply,
                        started: Instant::now(),
                        last_sent: Instant::now() - RETRY,
                    });
                }
            }
        }
        let answer = self.sink.lock().expect("sink poisoned").answer.take();
        let p = self.pending.as_mut()?;
        match answer {
            Some(0) => {
                self.sink.lock().expect("sink poisoned").want = None;
                let p = self.pending.take()?;
                return Some(Accepted { disc: p.disc, spec: p.spec, reply: p.reply });
            }
            Some(REFUSED) => {
                self.fail("the loader refused the swap (is the title served from a disc?)".into());
                return None;
            }
            Some(_) => debug!("disc swap: the loader is busy, asking again"),
            None => {}
        }
        if p.started.elapsed() > GIVE_UP {
            self.fail("no answer from the loader (is it still listening? an older loader \
                       does not know DISC)".into());
            return None;
        }
        if p.last_sent.elapsed() >= RETRY {
            let cmd = DCLoadCmd::new(DCLoadCmds::Disc(), p.generation, 0);
            match conn.send_command(cmd) {
                Ok(_) => p.last_sent = Instant::now(),
                Err(e) => self.fail(format!("could not send DISC: {e}")),
            }
        }
        None
    }
}
