use std::{
    io::ErrorKind,
    net::UdpSocket,
    sync::{Arc, Mutex},
    time,
};

use polling::{Event, Events, Poller};

use crate::cmds::{DCLoadCmd, DCReturnCmd};

/// Something that claims packets before anybody else sees them.
///
/// THE ONLY PLACE THIS CAN LIVE IS HERE. A reply to a command the host issued
/// out of band -- the counter probe's SendBinQ -- arrives whenever dcload
/// happens to look at the wire, and dcload only looks at the wire while it is
/// itself waiting for a host transfer (`cdfs_syscalls.c`: "bb->loop() is
/// reached from the READ PATH ONLY"). So the reply lands, by construction,
/// INSIDE `send_data`'s own polling -- which drops what it did not ask for.
/// Filtering in the syscall loop instead therefore claims nothing at all:
/// measured on a title streaming CD-DA, 43 samples posted and 43 lost.
///
/// `handle_data` is the single funnel every poll site shares, so a sink
/// registered here is consulted from all of them.
pub trait PacketSink {
    /// Returns true when the packet was the sink's, and nobody else should see
    /// it. A sink MUST claim only what it asked for: eating somebody else's
    /// reply is a transfer that never completes.
    fn claim(&mut self, cmd: &DCReturnCmd) -> bool;
}

/// A sink shared between whoever posts the requests and the IO layer.
pub type SharedSink = Arc<Mutex<dyn PacketSink + Send>>;

pub trait ExternalDcIo {
    fn poll(&self, timeout: Option<time::Duration>) -> Result<Events, std::io::Error>;
    fn handle_data(&mut self, events: &Events) -> Result<Vec<DCReturnCmd>, std::io::Error>;
    fn send_command(&self, command: DCLoadCmd) -> Result<usize, Box<dyn std::error::Error>>;
    /// Add one more out-of-band packet sink. Default: none, and nothing is
    /// claimed -- which is what every fake in the tests wants.
    ///
    /// MORE THAN ONE, because there is more than one thing reading the loader's
    /// memory while a title runs: the counter panel, and the stack watch that
    /// is on in every session. A single slot made the second one silently
    /// evict the first -- and an evicted sink does not fail, it just never
    /// claims anything again, which reads as a console that stopped answering.
    fn add_sink(&mut self, _sink: SharedSink) {}
}

pub struct DcIoUDP {
    socket: UdpSocket,
    key: usize,
    poller: Poller,
    buf: [u8; 65527],
    sinks: Vec<SharedSink>,
}

impl DcIoUDP {
    pub fn new(host: String, port: u16, local_port: Option<u16>) -> Result<Self, std::io::Error> {
        let bind_addr = match local_port {
            Some(p) => format!("0.0.0.0:{p}"),
            None => "0.0.0.0:0".to_string(),
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(format!("{host}:{port}"))?;
        socket.set_nonblocking(true)?;
        let key = 6867; // Arbitrary key identifying the socket.

        // Create a poller and register interest in readability on the socket.
        let poller = Poller::new()?;
        unsafe {
            poller.add(&socket, Event::readable(key))?;
        }

        let buf = [0u8; 65527];
        Ok(DcIoUDP {
            socket,
            poller,
            key,
            buf,
            sinks: Vec::new(),
        })
    }
}

/// The errors a connected UDP socket raises for "there is nobody at that
/// address", as opposed to something being wrong with the socket itself.
fn nobody_there(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
    )
}

impl ExternalDcIo for DcIoUDP {
    fn poll(&self, timeout: Option<std::time::Duration>) -> Result<Events, std::io::Error> {
        self.poller
            .modify(&self.socket, Event::readable(self.key))?;
        // One socket is registered: the default capacity (1024) is a ~40 KB
        // allocation per poll on Windows.
        let mut events = Events::with_capacity(std::num::NonZeroUsize::MIN);
        // Wait for at least one I/O event.
        self.poller.wait(&mut events, timeout)?;

        Ok(events)
    }
    fn handle_data(&mut self, events: &Events) -> Result<Vec<DCReturnCmd>, std::io::Error> {
        trace!("Handling {} events", events.len());
        let mut cmds = Vec::<DCReturnCmd>::new();
        for ev in events.iter() {
            if ev.key != self.key {
                trace!("Ignoring event with unknown key: {}", ev.key);
                continue;
            }
            // DRAIN THE SOCKET, do not take one datagram and leave.
            //
            // The poller is one-shot, so one wakeup used to mean exactly one
            // `recv_from` however many datagrams were queued. Under a runtime
            // CDFS load that is a backlog that only ever grows: whatever the
            // caller is waiting for surfaces some number of wakeups after it
            // actually arrived. It is also what makes an out-of-band reply
            // (`PacketSink`) expensive -- claiming it consumed the caller's
            // whole wakeup and it saw an empty result, which the LoadBinary
            // echo loop reads as "not acknowledged yet" and answers with a
            // retransmission.
            //
            // The socket is non-blocking, so this ends on WouldBlock.
            loop {
                match self.socket.recv_from(&mut self.buf) {
                    Ok((n, addr)) => {
                        trace!("Received {} bytes from {}", n, addr);
                        match DCReturnCmd::try_from(self.buf[..n].to_vec()) {
                            Ok(cmd) => {
                                // First claimer wins, and the ranges are
                                // disjoint by construction: each sink asks
                                // about its own bytes of loader RAM.
                                let claimed = self
                                    .sinks
                                    .iter()
                                    .any(|s| s.lock().expect("sink poisoned").claim(&cmd));
                                if !claimed {
                                    cmds.push(cmd);
                                }
                            }
                            Err(err) => warn!("Failed to parse command: {}", err),
                        }
                        continue;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        // Drained.
                    }
                    Err(e) if nobody_there(e.kind()) => {
                        // "NOTHING IS LISTENING THERE" IS NOT A FAULT HERE, IT
                        // IS THE ANSWER. A connected UDP socket reports the
                        // ICMP unreachable from a previous datagram on the next
                        // call -- WSAECONNRESET on Windows, ECONNREFUSED on
                        // Linux -- and the poller wakes for it, so a console
                        // that is off produces one of these per poll. That is
                        // the normal state of the `--infinite` wait, twice a
                        // second, and at error level it buried everything else.
                        // A genuinely unreachable target still fails, loudly,
                        // where the command times out.
                        debug!("no listener at the target: {}", e);
                    }
                    Err(e) => {
                        error!("recv_from error: {}", e);
                    }
                }
                break;
            }
        }
        Ok(cmds)
    }

    fn send_command(&self, command: DCLoadCmd) -> Result<usize, Box<dyn std::error::Error>> {
        let data: Vec<u8> = command.into();
        Ok(self.socket.send(&data)?)
    }

    fn add_sink(&mut self, sink: SharedSink) {
        self.sinks.push(sink);
    }
}
