//! The session's control socket: how `swap-disc` reaches a running `u-exec`.
//!
//! Loopback TCP only. A client sends one line, `SWAP <image>\n`, and gets one
//! line back, `OK <message>` or `ERR <reason>`, once the loader has taken the
//! new disc (or the attempt failed). The image is opened by the session's own
//! thread (`dispatch::swap`), because a `DiscFormat` is not `Send`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use log::{info, warn};

const DEFAULT_PORT: u16 = 53536;

/// `DCLOAD_CONTROL_PORT`, else 53536.
pub fn default_port() -> u16 {
    std::env::var("DCLOAD_CONTROL_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// How long a client waits for the session: the 10 s the loader gets, and the
/// time to open an image.
const CLIENT_WAIT: Duration = Duration::from_secs(60);

/// Where the session says how a request ended.
pub struct Reply(Sender<Result<String, String>>);

impl Reply {
    pub fn send(&self, result: Result<String, String>) {
        let _ = self.0.send(result);
    }
}

pub struct SwapRequest {
    pub spec: String,
    pub reply: Reply,
}

/// Listen for swap requests. `None` (and a warning) if the port is off or taken:
/// the session does not depend on it.
pub fn serve(port: u16) -> Option<Receiver<SwapRequest>> {
    if port == 0 {
        return None;
    }
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
        Ok(l) => l,
        Err(e) => {
            warn!("disc swap: cannot listen on 127.0.0.1:{port} ({e}); `swap-disc` is unavailable");
            return None;
        }
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || handle(stream, tx));
        }
    });
    info!("disc swap: `dcload-ip-rs swap-disc <image>` is listening on 127.0.0.1:{port}");
    Some(rx)
}

fn handle(stream: TcpStream, requests: Sender<SwapRequest>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut line = String::new();
    let mut out = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    if BufReader::new(stream.take(65536)).read_line(&mut line).is_err() {
        return;
    }
    let answer = match parse_request(&line) {
        Err(e) => Err(e),
        Ok(spec) => {
            let (tx, rx) = mpsc::channel();
            if requests.send(SwapRequest { spec, reply: Reply(tx) }).is_err() {
                Err("the session has ended".to_string())
            } else {
                rx.recv_timeout(CLIENT_WAIT)
                    .unwrap_or_else(|_| Err("the session did not answer".to_string()))
            }
        }
    };
    let _ = match answer {
        Ok(m) => writeln!(out, "OK {m}"),
        Err(e) => writeln!(out, "ERR {e}"),
    };
}

/// `SWAP <image>` -> the image spec.
fn parse_request(line: &str) -> Result<String, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    match line.strip_prefix("SWAP ") {
        Some(spec) if !spec.trim().is_empty() => Ok(spec.to_string()),
        _ => Err("expected `SWAP <image>`".to_string()),
    }
}

/// An image spec (`path` or `path#member`) with its path made absolute: the
/// session runs in another directory.
fn absolute_spec(spec: &str) -> String {
    let abs = |p: &str| std::fs::canonicalize(p).ok().map(|p| p.display().to_string());
    if let Some(a) = abs(spec) {
        return a;
    }
    if let Some((path, member)) = spec.rsplit_once('#')
        && let Some(a) = abs(path)
    {
        return format!("{a}#{member}");
    }
    spec.to_string()
}

/// `swap-disc`: ask the session on this machine to change disc.
pub fn swap_disc_client(port: u16, spec: &str) -> ExitCode {
    if port == 0 {
        eprintln!("the control port is off (--control-port 0)");
        return ExitCode::FAILURE;
    }
    let mut stream = match TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "no session is listening on 127.0.0.1:{port} ({e}); `swap-disc` needs a \
                 running `u-exec <image>` (same --control-port)"
            );
            return ExitCode::FAILURE;
        }
    };
    let _ = stream.set_read_timeout(Some(CLIENT_WAIT + Duration::from_secs(5)));
    if writeln!(stream, "SWAP {}", absolute_spec(spec)).is_err() {
        eprintln!("could not talk to the session");
        return ExitCode::FAILURE;
    }
    let mut answer = String::new();
    if BufReader::new(stream).read_line(&mut answer).is_err() || answer.is_empty() {
        eprintln!("the session closed the connection without answering");
        return ExitCode::FAILURE;
    }
    let answer = answer.trim_end();
    match answer.strip_prefix("OK ") {
        Some(m) => {
            println!("{m}");
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("{}", answer.strip_prefix("ERR ").unwrap_or(answer));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_swap_line() {
        assert_eq!(parse_request("SWAP /a b/c.gdi\r\n").unwrap(), "/a b/c.gdi");
        assert!(parse_request("SWAP \n").is_err());
        assert!(parse_request("HELLO x\n").is_err());
    }

    #[test]
    fn keeps_a_zip_member() {
        let dir = std::env::temp_dir().join("dcload-control-test.zip");
        std::fs::write(&dir, b"x").unwrap();
        let spec = format!("{}#disc2.gdi", dir.display());
        assert!(absolute_spec(&spec).ends_with("#disc2.gdi"));
        let _ = std::fs::remove_file(dir);
    }
}
