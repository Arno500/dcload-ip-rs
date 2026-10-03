//! Everything that happens on the wire after the socket is open; see
//! AGENTS.md 1 for the order a session runs in.

use std::{
    collections::{HashMap, HashSet},
    io::{Error, ErrorKind},
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use elf::{ElfBytes, endian::AnyEndian, section::SectionHeader};
use indicatif::{HumanBytes, ProgressBar};

use crate::{
    CHUNK_SIZE,
    cd::build_dc_toc,
    cmds::{AudioFormat, DCLoadClientCmds, DCLoadCmd, DCLoadCmds, DCReturnCmd},
    disc_formats::{
        boot,
        cdi::Cdi,
        gdi::Gdi,
        iso::Iso,
        source::{Container, FileSource, ImageSource},
        types::{DiscFormat, RAW_SECTOR_SIZE, StubDisc, get_disc_format},
        zip::{ZipArchive, ZipContainer},
    },
    fs::{self, FSSyscallState},
    io::ExternalDcIo,
    protocol_version, ui,
};

/// What every exchange with the console returns.
pub(crate) type DcResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A boxed `TimedOut` I/O error.
fn timed_out(msg: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(Error::new(ErrorKind::TimedOut, msg.into()))
}

fn is_timeout(e: &(dyn std::error::Error + 'static)) -> bool {
    e.downcast_ref::<Error>().is_some_and(|e| e.kind() == ErrorKind::TimedOut)
}

/// `a` in the cached window (P1), the one disassemblies and logs use.
fn p1(a: u32) -> u32 {
    (a & 0x1fff_ffff) | 0x8c00_0000
}

/// `a` in the physical window, the one transfers use (P2 is unreliable past
/// 8 bytes, see `selftest_readback`).
fn phys(a: u32) -> u32 {
    (a & 0x1fff_ffff) | 0x0c00_0000
}

/// Bytes as space-separated hex.
fn hex<'a>(bytes: impl IntoIterator<Item = &'a u8>) -> String {
    bytes
        .into_iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

mod cdda;
mod image;
mod patches;
mod probes;
mod sectors;
mod session;
mod syscalls;
mod transfer;

pub use cdda::*;
pub use image::*;
pub use patches::*;
pub use probes::*;
use sectors::*;
pub use session::*;
pub use syscalls::*;
pub use transfer::*;
