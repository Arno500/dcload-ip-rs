use std::{io::ErrorKind, net::UdpSocket, time};

use polling::{Event, Events, Poller};

use crate::cmds::{DCLoadCmd, DCReturnCmd};

pub trait ExternalDcIo {
    fn poll(&self, timeout: Option<time::Duration>) -> Result<Events, std::io::Error>;
    fn handle_data(&mut self, events: &Events) -> Result<Vec<DCReturnCmd>, std::io::Error>;
    fn send_command(&self, command: DCLoadCmd) -> Result<usize, Box<dyn std::error::Error>>;
}

pub struct DcIoUDP {
    socket: UdpSocket,
    key: usize,
    poller: Poller,
    buf: [u8; 65527],
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
        })
    }
}

impl ExternalDcIo for DcIoUDP {
    fn poll(&self, timeout: Option<std::time::Duration>) -> Result<Events, std::io::Error> {
        self.poller
            .modify(&self.socket, Event::readable(self.key))?;
        let mut events = Events::new();
        // Wait for at least one I/O event.
        self.poller.wait(&mut events, timeout)?;

        Ok(events)
    }
    fn handle_data(&mut self, events: &Events) -> Result<Vec<DCReturnCmd>, std::io::Error> {
        trace!("Handling {} events", events.len());
        let mut cmds = Vec::<DCReturnCmd>::new();
        for ev in events.iter() {
            if ev.key == self.key {
                match self.socket.recv_from(&mut self.buf) {
                    Ok((n, addr)) => {
                        trace!("Received {} bytes from {}", n, addr);
                        match DCReturnCmd::try_from(self.buf[..n].to_vec()) {
                            Ok(cmd) => cmds.push(cmd),
                            Err(err) => warn!("Failed to parse command: {}", err),
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        // No data available right now.
                    }
                    Err(e) => {
                        error!("recv_from error: {}", e);
                    }
                }
            } else {
                trace!("Ignoring event with unknown key: {}", ev.key);
            }
        }
        Ok(cmds)
    }

    fn send_command(&self, command: DCLoadCmd) -> Result<usize, Box<dyn std::error::Error>> {
        let data: Vec<u8> = command.into();
        Ok(self.socket.send(&data)?)
    }
}
