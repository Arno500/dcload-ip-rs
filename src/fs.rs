use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    mem::ManuallyDrop,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
    u32,
};

use crate::{
    cmds::{DCLoadClientFSCmds, DCLoadCmd},
    dispatch::{receive_data, send_data},
    io::ExternalDcIo,
    types::{DCLoadStat, ExceptionStruct},
};

// Cross-platform file descriptor abstraction
#[cfg(target_family = "unix")]
mod fd_impl {
    use std::fs::File;
    use std::mem::ManuallyDrop;
    use std::os::unix::io::FromRawFd;

    pub struct FileDescriptor {
        file: ManuallyDrop<File>,
    }

    impl FileDescriptor {
        /// Create a FileDescriptor from a raw file descriptor on Linux.
        /// This uses the actual FD passed from the client.
        pub fn from_raw_fd(fd: u32) -> Self {
            let file = unsafe { File::from_raw_fd(fd as i32) };
            FileDescriptor {
                file: ManuallyDrop::new(file),
            }
        }

        pub fn from_file(file: File) -> Self {
            FileDescriptor {
                file: ManuallyDrop::new(file),
            }
        }

        pub fn get_file(&self) -> &File {
            &self.file
        }

        pub fn get_droppable_file(&mut self) -> &mut ManuallyDrop<File> {
            &mut self.file
        }

        pub fn get_fd(&self) -> u32 {
            use std::os::unix::io::AsRawFd;
            self.file.as_raw_fd() as u32
        }
    }
}

#[cfg(target_family = "windows")]
mod fd_impl {
    use std::fs::File;
    use std::mem::ManuallyDrop;
    use std::os::windows::io::FromRawHandle;

    pub struct FileDescriptor {
        file: ManuallyDrop<File>,
    }

    impl FileDescriptor {
        /// Create a FileDescriptor from an emulated file descriptor on Windows.
        /// On Windows, the fd parameter is interpreted as a HANDLE value.
        pub fn from_raw_fd(fd: u32) -> Self {
            // Cast the fd to a HANDLE pointer value
            let handle = fd as *mut std::ffi::c_void;
            let file = unsafe { File::from_raw_handle(handle) };
            FileDescriptor {
                file: ManuallyDrop::new(file),
            }
        }

        pub fn from_file(file: File) -> Self {
            FileDescriptor {
                file: ManuallyDrop::new(file),
            }
        }

        pub fn get_file(&self) -> &File {
            &self.file
        }

        pub fn get_droppable_file(&mut self) -> &mut ManuallyDrop<File> {
            &mut self.file
        }

        pub fn get_fd(&self) -> u32 {
            use std::os::windows::io::AsRawHandle;
            self.file.as_raw_handle() as u32
        }
    }
}

#[cfg(not(any(target_family = "unix", target_family = "windows")))]
mod fd_impl {
    use std::fs::File;
    use std::mem::ManuallyDrop;

    pub struct FileDescriptor {
        file: File,
    }

    impl FileDescriptor {
        pub fn from_raw_fd(_fd: u32) -> Self {
            panic!("File descriptor handling not implemented for this platform")
        }

        pub fn from_file(file: File) -> Self {
            FileDescriptor { file }
        }

        pub fn get_file(&self) -> &File {
            &self.file
        }

        pub fn get_droppable_file(&mut self) -> &mut ManuallyDrop<File> {
            &mut self.file
        }

        pub fn get_fd(&self) -> u32 {
            panic!("File descriptor handling not implemented for this platform")
        }
    }
}

pub use fd_impl::FileDescriptor;

fn metadata_to_stat(stat: std::fs::Metadata) -> DCLoadStat {
    DCLoadStat {
        st_uid: {
            #[cfg(target_family = "unix")]
            {
                use std::os::unix::fs::MetadataExt;
                stat.uid() as u16
            }
            #[cfg(not(target_family = "unix"))]
            {
                0
            }
        },
        st_gid: {
            #[cfg(target_family = "unix")]
            {
                use std::os::unix::fs::MetadataExt;
                stat.gid() as u16
            }
            #[cfg(not(target_family = "unix"))]
            {
                0
            }
        },
        st_mode: {
            #[cfg(target_family = "unix")]
            {
                use std::os::unix::fs::MetadataExt;
                stat.mode() as i32
            }
            #[cfg(not(target_family = "unix"))]
            {
                0
            }
        },
        st_size: stat.len() as i32,
        st_atime_priv: stat
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0),
        st_mtime_priv: stat
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0),
        st_ctime_priv: stat
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0),
        ..Default::default()
    }
}

pub struct FSSyscallState {
    pub base_path: Option<PathBuf>,
    pub emulated_current_dir: PathBuf,
}

pub fn handle_fs_syscall(
    conn: &mut impl ExternalDcIo,
    cmd: DCLoadClientFSCmds,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    if state.base_path.is_none() {
        Ok(DCLoadCmd {
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            address: u32::MAX,
            size: u32::MAX,
        })
    } else {
        match cmd {
            DCLoadClientFSCmds::FStat(fd, address, size) => fstat(conn, fd, address, size),
            // Placeholder implementations for other FS commands
            DCLoadClientFSCmds::Write(fd, address, size) => write(conn, fd, address, size),
            DCLoadClientFSCmds::Read(fd, address, size) => read(conn, fd, address, size),
            DCLoadClientFSCmds::Open(flags, mode, path) => open(flags, mode, path, state, false),
            DCLoadClientFSCmds::Close(fd) => close(fd),
            DCLoadClientFSCmds::Create(flags, path) => create(flags, path, state),
            DCLoadClientFSCmds::Link(path) => link(path, state),
            DCLoadClientFSCmds::Unlink(path) => unlink(path, state),
            DCLoadClientFSCmds::ChDir(path) => chdir(path, state),
            DCLoadClientFSCmds::ChMod(_, _) => Err("ChMod not implemented".into()),
            DCLoadClientFSCmds::LSeek(_, _, _) => Err("LSeek not implemented".into()),
            DCLoadClientFSCmds::Time() => Err("Time not implemented".into()),
            DCLoadClientFSCmds::Stat(_, _, _) => Err("Stat not implemented".into()),
            DCLoadClientFSCmds::UTime(_, _, _, _) => Err("UTime not implemented".into()),
            DCLoadClientFSCmds::OpenDir(_) => Err("OpenDir not implemented".into()),
            DCLoadClientFSCmds::CloseDir(_) => Err("CloseDir not implemented".into()),
            DCLoadClientFSCmds::ReadDir(_, _, _) => Err("ReadDir not implemented".into()),
            DCLoadClientFSCmds::RewindDir(_) => Err("RewindDir not implemented".into()),
        }
    }
}

fn fstat(
    conn: &mut impl ExternalDcIo,
    fd: u32,
    address: u32,
    _size: u32,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let fd_wrapper = FileDescriptor::from_raw_fd(fd);
    let file = fd_wrapper.get_file();
    let stat = file.metadata()?;

    let stat_data = metadata_to_stat(stat);
    push_data_and_return(conn, stat_data.into(), address)
}

fn write(
    conn: &mut impl ExternalDcIo,
    fd: u32,
    address: u32,
    size: u32,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let fd_wrapper = FileDescriptor::from_raw_fd(fd);
    let mut file = fd_wrapper.get_file();

    let data = download_data(conn, address, size)?;
    let bytes_written = file.write(&data)? as u32;

    Ok(DCLoadCmd {
        address: bytes_written,
        size: bytes_written,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn read(
    conn: &mut impl ExternalDcIo,
    fd: u32,
    address: u32,
    size: u32,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let fd_wrapper = FileDescriptor::from_raw_fd(fd);
    let mut file = fd_wrapper.get_file();

    let mut buffer = vec![0u8; size as usize];
    let bytes_read = file.read(&mut buffer)? as u32;
    buffer.truncate(bytes_read as usize);

    push_data_and_return(conn, buffer, address)
}

fn open(
    flags: u32,
    _mode: u32,
    path: String,
    state: &FSSyscallState,
    create: bool,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let safe_path = join_and_check_path(state, path)?;
    let mut file_options = match parse_file_flags(flags, safe_path.clone()) {
        Ok(file_options) => file_options,
        Err(e) => return Ok(e),
    };
    if create {
        file_options.create(true).write(true).truncate(true);
    }
    match file_options.open(safe_path) {
        Ok(file) => {
            #[cfg(target_family = "unix")]
            {
                let mut perms = file.metadata()?.permissions();
                perms.set_mode(_mode as u32);
                file.set_permissions(perms)?;
            }
            let fd = FileDescriptor::from_file(file).get_fd();
            Ok(DCLoadCmd {
                address: fd,
                size: fd,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            })
        }
        Err(_) => Ok(DCLoadCmd {
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            address: u32::MAX,
            size: u32::MAX,
        }),
    }
}

fn close(fd: u32) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let mut filedescriptor = FileDescriptor::from_raw_fd(fd);
    let file = filedescriptor.get_droppable_file();
    unsafe {
        ManuallyDrop::drop(file);
    }

    // Unfortunately in Rust, the possible errors are swallowed, so we consider a close() to always succeed
    Ok(DCLoadCmd {
        address: 0,
        size: 0,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn create(
    flags: u32,
    path: String,
    state: &FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    open(flags, 0, path, state, true)
}

fn link(path: String, state: &FSSyscallState) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let [source, target]: [&str; 2] = path
        .split("\0")
        .collect::<Vec<&str>>()
        .try_into()
        .unwrap_or_default();
    if source.is_empty() || target.is_empty() {
        return Ok(DCLoadCmd {
            address: u32::MAX,
            size: u32::MAX,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        });
    }
    #[cfg(target_family = "windows")]
    {
        let source_relative = join_and_check_path(state, source.to_string())?;
        match if source_relative.is_file() {
            std::os::windows::fs::symlink_file(
                source_relative,
                join_and_check_path(state, target.to_string())?,
            )
        } else {
            std::os::windows::fs::symlink_dir(
                source_relative,
                join_and_check_path(state, target.to_string())?,
            )
        } {
            Ok(_) => Ok(DCLoadCmd {
                address: 0,
                size: 0,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            }),
            Err(_) => Ok(DCLoadCmd {
                address: u32::MAX,
                size: u32::MAX,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            }),
        }
    }
    #[cfg(target_family = "unix")]
    {
        match std::os::unix::fs::symlink(
            join_and_check_path(state, source.to_string())?,
            join_and_check_path(state, target.to_string())?,
        ) {
            Ok(_) => Ok(DCLoadCmd {
                address: 0,
                size: 0,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            }),
            Err(_) => Ok(DCLoadCmd {
                address: u32::MAX,
                size: u32::MAX,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            }),
        };
    }
}

fn unlink(path: String, state: &FSSyscallState) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    match std::fs::remove_file(join_and_check_path(state, path)?) {
        Ok(_) => Ok(DCLoadCmd {
            address: 0,
            size: 0,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        }),
        Err(_) => Ok(DCLoadCmd {
            address: u32::MAX,
            size: u32::MAX,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        }),
    }
}

fn chdir(
    path: String,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let new_path = join_and_check_path(state, path.clone())?;
    if new_path.is_dir() {
        state.emulated_current_dir = Path::new(&path).to_path_buf();
        Ok(DCLoadCmd {
            address: 0,
            size: 0,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        })
    } else {
        Ok(DCLoadCmd {
            address: u32::MAX,
            size: u32::MAX,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        })
    }
}

fn parse_file_flags(flags: u32, path: PathBuf) -> Result<OpenOptions, DCLoadCmd> {
    let mut file_options = File::options();
    if flags & 0x0001 != 0 {
        file_options.write(true);
    }
    if flags & 0x0002 != 0 {
        file_options.read(true).write(true);
    }
    if flags & 0x0008 != 0 {
        file_options.append(true);
    }
    if flags & 0x0200 != 0 {
        file_options.create(true);
    }
    if flags & 0x0400 != 0 {
        file_options.truncate(true);
    }
    if flags & 0x0800 != 0 {
        // O_EXCL is not directly supported in Rust's standard library.
        // It can be handled by checking if the file exists before creating it.
        if std::path::Path::new(&path).exists() {
            // https://docs.rs/libc/latest/libc/constant.EEXIST.html
            return Err(DCLoadCmd {
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
                address: 17,
                size: 17,
            });
        }
    }
    Ok(file_options)
}

fn join_and_check_path(
    state: &FSSyscallState,
    relative: String,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if let Some(base) = &state.base_path {
        let full_path = base.join(relative).join(&state.emulated_current_dir);
        let canonical_base = base.canonicalize()?;
        let canonical_full = full_path.canonicalize()?;

        if !canonical_full.starts_with(&canonical_base) {
            return Err("Attempted directory traversal outside of base path".into());
        }

        Ok(full_path)
    } else {
        panic!("Base path should not be empty there, that should have been catched above")
    }
}

fn push_data_and_return(
    conn: &mut impl ExternalDcIo,
    data: Vec<u8>,
    address: u32,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    send_data(conn, data.as_slice(), address, None)?;

    Ok(DCLoadCmd {
        address: 0,
        size: 0,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn download_data(
    conn: &mut impl ExternalDcIo,
    address: u32,
    size: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = receive_data(
        conn,
        Some(Duration::from_millis(250)),
        address,
        size as usize,
        true,
    )?;

    if &data[0..4] == b"EXPT" {
        let exception_frame: ExceptionStruct = unsafe {
            std::mem::transmute::<[u8; 2176 / 8], ExceptionStruct>(*<&[u8; 2176 / 8]>::try_from(
                &data[..2176],
            )?)
        };
        let error_string = exception_code_to_string(exception_frame.expt_code);

        error!(
            "Received exception from client: {} (code: 0x{:x})",
            error_string, exception_frame.expt_code
        );
        error!("Exception frame:");
        error!("{:#?}", exception_frame);

        // Write raw exception data to a file for further analysis
        std::fs::write(
            format!(
                "dc_exception_dump-{}.bin",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs()
            ),
            &data,
        )?;

        return Err("Received error from client".into());
    }

    Ok(data)
}

fn exception_code_to_string(code: u32) -> &'static str {
    match code {
        0x1e0 => "User break",
        0x0e0 => "Address error (read)",
        0x040 => "TLB miss exception (read)",
        0x0a0 => "TLB protection violation exception (read)",
        0x180 => "General illegal instruction exception",
        0x1a0 => "Slot illegal instruction exception",
        0x800 => "General FPU disable exception",
        0x820 => "Slot FPU disable exception",
        0x100 => "Address error (write)",
        0x060 => "TLB miss exception (write)",
        0x0c0 => "TLB protection violation exception (write)",
        0x120 => "FPU exception",
        0x080 => "Initial page write exception",
        0x160 => "Unconditional trap (TRAPA)",
        _ => "Unknown exception",
    }
}
