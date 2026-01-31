use std::{io::Write, time::Duration};

use crate::{
    cmds::{DCLoadClientFSCmds, DCLoadCmd},
    dispatch::{receive_data, send_data},
    io::ExternalDcIo,
    types::DCLoadStat,
};

// Cross-platform file descriptor abstraction
#[cfg(target_os = "linux")]
mod fd_impl {
    use std::fs::File;
    use std::os::unix::io::FromRawFd;

    pub struct FileDescriptor {
        file: File,
    }

    impl FileDescriptor {
        /// Create a FileDescriptor from a raw file descriptor on Linux.
        /// This uses the actual FD passed from the client.
        pub fn from_raw_fd(fd: u32) -> Self {
            let file = unsafe { File::from_raw_fd(fd as i32) };
            FileDescriptor { file }
        }

        pub fn get_file(&self) -> &File {
            &self.file
        }
    }
}

#[cfg(target_os = "windows")]
mod fd_impl {
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;

    pub struct FileDescriptor {
        file: File,
    }

    impl FileDescriptor {
        /// Create a FileDescriptor from an emulated file descriptor on Windows.
        /// On Windows, the fd parameter is interpreted as a HANDLE value.
        pub fn from_raw_fd(fd: u32) -> Self {
            // Cast the fd to a HANDLE pointer value
            let handle = fd as *mut std::ffi::c_void;
            let file = unsafe { File::from_raw_handle(handle) };
            FileDescriptor { file }
        }

        pub fn get_file(&self) -> &File {
            &self.file
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod fd_impl {
    use std::fs::File;

    pub struct FileDescriptor {
        file: File,
    }

    impl FileDescriptor {
        pub fn from_raw_fd(_fd: u32) -> Self {
            panic!("File descriptor handling not implemented for this platform")
        }

        pub fn get_file(&self) -> &File {
            &self.file
        }
    }
}

pub use fd_impl::FileDescriptor;

fn metadata_to_stat(stat: std::fs::Metadata) -> DCLoadStat {
    DCLoadStat {
        st_uid: {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt;
                stat.uid() as u16
            }
            #[cfg(not(target_os = "linux"))]
            {
                0
            }
        },
        st_gid: {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt;
                stat.gid() as u16
            }
            #[cfg(not(target_os = "linux"))]
            {
                0
            }
        },
        st_mode: {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt;
                stat.mode() as i32
            }
            #[cfg(not(target_os = "linux"))]
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
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_rdev: 0,
        st_spare1: 0,
        st_mtime_priv: stat
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0),
        st_spare2: 0,
        st_ctime_priv: stat
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0),
        st_spare3: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_spare4: [0; 2],
        ..Default::default()
    }
}

pub fn handle_fs_syscall(
    conn: &mut impl ExternalDcIo,
    cmd: DCLoadClientFSCmds,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    match cmd {
        DCLoadClientFSCmds::FStat(fd, address, size) => fstat(conn, fd, address, size),
        // Placeholder implementations for other FS commands
        DCLoadClientFSCmds::Write(fd, address, size) => write(conn, fd, address, size),
        DCLoadClientFSCmds::Read(_, _, _) => Err("Read not implemented".into()),
        DCLoadClientFSCmds::Open(_, _, _) => Err("Open not implemented".into()),
        DCLoadClientFSCmds::Close(_) => Err("Close not implemented".into()),
        DCLoadClientFSCmds::Create(_, _) => Err("Create not implemented".into()),
        DCLoadClientFSCmds::Link(_) => Err("Link not implemented".into()),
        DCLoadClientFSCmds::Unlink(_) => Err("Unlink not implemented".into()),
        DCLoadClientFSCmds::ChDir(_) => Err("ChDir not implemented".into()),
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
    push_data_and_return(
        conn,
        stat_data.into(),
        address,
    )
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
    let data = receive_data(conn, Some(Duration::from_millis(250)), address, size as usize, true)?;

    // Need to handle exceptions

    Ok(data)
}
