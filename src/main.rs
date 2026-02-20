use std::{process::ExitCode};

use crate::{dispatch::send_version, io::DcIoUDP};

use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use pretty_env_logger::formatted_timed_builder;

#[macro_use]
extern crate log;

mod cmds;
mod fs;
mod disc_formats;
mod dispatch;
mod io;
mod types;

// const PROTOCOL_VERSION: [u8; 3] = [2, 0, 3];
const PROTOCOL_VERSION: [u8; 3] = [0, 0, 0];
// const CHUNK_SIZE: usize = 1440;
const CHUNK_SIZE: usize = 1024;

// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Verbosity level (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: Option<u8>,

    /// UDP port to connect to
    #[arg(short, long, default_value_t = 53535)]
    port: u16,

    /// Host to connect to
    #[arg(short = 'H', long, default_value = "", value_hint = clap::ValueHint::Hostname)]
    host: String,

    /// Address to execute code at
    #[arg(short, long, default_value_t = 0x0c010000, default_value = "0x0c010000", value_parser = maybe_hex::<u32>)]
    address: u32,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Upload a binary and execute it immediately
    UExec {
        /// Path to file to upload and execute
        #[arg(value_hint = clap::ValueHint::FilePath)]
        file: String,

        /// Path to file to redirect the reads to
        #[arg(short, long, value_hint = clap::ValueHint::FilePath, conflicts_with = "mount")]
        disc: Option<String>,

        #[arg(short, long, value_hint = clap::ValueHint::DirPath)]
        mount: Option<String>,

        /// Enable console redirection
        #[arg(short, long)]
        console: bool,
    },
    /// Upload a binary
    Upload {
        /// Path to file to upload
        #[arg(value_hint = clap::ValueHint::FilePath)]
        file: String,
    },
    /// Reboot the console (only works when dcload is in control)
    Reboot {},
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.verbose {
        Some(0) | None => {
            if ::std::env::var("RUST_LOG").is_ok() {
                pretty_env_logger::init_timed();
            } else {
                formatted_timed_builder()
                    .filter_level(log::LevelFilter::Info)
                    .init();
            }
        }
        Some(1) => formatted_timed_builder()
            .filter_level(log::LevelFilter::Debug)
            .init(),
        Some(_) => formatted_timed_builder()
            .filter_level(log::LevelFilter::Trace)
            .init(),
    }
    let mut udpsender = DcIoUDP::new(args.host.clone(), args.port)?;
    let version = match send_version(&mut udpsender) {
        Err(err) => {
            error!("Failed to contact the client: {}", err);
            return Ok(ExitCode::FAILURE);
        }
        Ok(val) => val.into_iter().next(),
    };
    info!(
        "Successfully connected to dcload-ip on host {} using port {}",
        args.host, args.port
    );
    if let Some(ver_cmd) = version {
        if let Some(cmd) = ver_cmd.cmd
            && let cmds::DCLoadCmds::Version(Some(data)) = cmd.cmd
        {
            let version_info = String::from_utf8(data.to_vec());
            if let Ok(version_info) = version_info {
                info!(
                    "dcload-ip version: {}",
                    version_info.trim_end_matches(char::from(0))
                );
            }
        }
    } else {
        warn!("No version information received from dcload-ip");
    }
    let result: Result<ExitCode, Box<dyn std::error::Error>> = match args.command {
        Commands::UExec {
            file,
            disc,
            mount,
            console,
        } => match dispatch::upload(&mut udpsender, file, args.address) {
            Err(e) => Err(e),
            Ok((addr, _size)) => {
                info!("Upload complete, executing at 0x{:08x}", addr);
                match dispatch::execute(&mut udpsender, addr, console || disc.is_some() || mount.is_some(), disc.is_some()) {
                    Err(e) => Err(e),
                    Ok(_) => {
                        if disc.is_some() || mount.is_some() || console {
                            dispatch::receive_syscalls(&mut udpsender, disc, mount)?;
                            return Ok(ExitCode::SUCCESS);
                        }
                        Ok(ExitCode::SUCCESS)
                    }
                }
            }
        },
        Commands::Upload { file } => {
            return match dispatch::upload(&mut udpsender, file, args.address)
                .map(|_s| ExitCode::SUCCESS)
            {
                Err(e) => Err(e),
                Ok(code) => {
                    info!("Upload complete");
                    Ok(code)
                }
            };
        }
        Commands::Reboot {} => {
            info!("Sending reboot command");
            dispatch::reboot(&mut udpsender)?;
            info!("Reboot command sent");
            return Ok(ExitCode::SUCCESS);
        } // _ => Err(Box::new(NotImplemented {
          //     feature: "Unknown command".to_string(),
          // })),
    };
    if let Err(returned_error) = result {
        error!("{}", returned_error);
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}
