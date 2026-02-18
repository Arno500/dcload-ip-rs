use std::{
    fs::{self, File, FileTimes, FileType, Metadata, OpenOptions, ReadDir}, io::{Read, Seek, SeekFrom, Write}, path::{Component, Path, PathBuf}, time::{Duration, SystemTime}
};

use crate::{
    cmds::{DCLoadClientFSCmds, DCLoadCmd},
    dispatch::{receive_data, send_data},
    io::ExternalDcIo,
    types::{DCLoadDirEnt, DCLoadStat, ExceptionStruct},
};

// It seems KOS struggles with dirent <= 100, so let's offset
const DIR_OFFSET: u32 = 1337;
// To leave some space for traditional FDs like stdout and stderr
const FILE_OFFSET: u32 = 10;

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
                filemeta_to_int(&stat)
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
    pub openfiles: Vec<Option<File>>,
    pub opendirs: Vec<Option<(PathBuf, ReadDir)>>,
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
            DCLoadClientFSCmds::FStat(fd, address, size) => fstat(conn, fd, address, size, state),
            DCLoadClientFSCmds::Write(fd, address, size) => write(conn, fd, address, size, state),
            DCLoadClientFSCmds::Read(fd, address, size) => read(conn, fd, address, size, state),
            DCLoadClientFSCmds::Open(flags, mode, path) => open(flags, mode, path, state, false),
            DCLoadClientFSCmds::Close(fd) => close(fd, state),
            DCLoadClientFSCmds::Create(flags, path) => create(flags, path, state),
            DCLoadClientFSCmds::Link(path) => link(path, state),
            DCLoadClientFSCmds::Unlink(path) => unlink(path, state),
            DCLoadClientFSCmds::ChDir(path) => chdir(path, state),
            DCLoadClientFSCmds::ChMod(mode, path) => chmod(mode, path, state),
            DCLoadClientFSCmds::LSeek(fd, offset, whence) => lseek(fd, offset, whence, state),
            DCLoadClientFSCmds::Time() => time(),
            DCLoadClientFSCmds::Stat(address, size, path) => stat(conn, address, size, path, state),
            DCLoadClientFSCmds::UTime(mode, access_time, modif_time, path) => {
                utime(mode, access_time, modif_time, path, state)
            }
            DCLoadClientFSCmds::OpenDir(path) => wrapped_opendir(path, state),
            DCLoadClientFSCmds::CloseDir(dirent) => closedir(state, dirent),
            DCLoadClientFSCmds::ReadDir(dirent, address, size) => {
                readdir(conn, dirent, address, size, state)
            }
            DCLoadClientFSCmds::RewindDir(dirent) => rewinddir(dirent, state),
        }
    }
}

fn fstat(
    conn: &mut impl ExternalDcIo,
    fd: u32,
    address: u32,
    _size: u32,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let file = state
        .openfiles
        .get_mut((fd - FILE_OFFSET) as usize)
        .ok_or("Invalid FD")?
        .as_mut()
        .ok_or("Invalid FD")?;
    let stat = file.metadata()?;
    let stat_data = metadata_to_stat(stat);
    push_data_and_return(conn, stat_data.into(), address, 0)
}

fn write(
    conn: &mut impl ExternalDcIo,
    fd: u32,
    address: u32,
    size: u32,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    if fd < FILE_OFFSET {
        let data = download_data(conn, address, size)?;

        match fd {
            1 => info!("{}", String::from_utf8(data)?),
            2 => error!("{}", String::from_utf8(data)?),
            _ => return Err("Invalid FD".into()),
        }

        return Ok(DCLoadCmd {
            address: size,
            size,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        });
    }

    let file = state
        .openfiles
        .get_mut((fd - FILE_OFFSET) as usize)
        .ok_or("Invalid FD")?
        .as_mut()
        .ok_or("Invalid FD")?;

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
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let file = state
        .openfiles
        .get_mut((fd - FILE_OFFSET) as usize)
        .ok_or("Invalid FD")?
        .as_mut()
        .ok_or("Invalid FD")?;

    let mut buffer = vec![0u8; size as usize];
    // Not fully confident that it will respect the seek, and if it will properly fill the buffer (but it should as of today)
    let bytes_read = file.read(&mut buffer)? as u32;
    buffer.truncate(bytes_read as usize);

    debug!("Reading file: {:?}", file);

    push_data_and_return(conn, buffer, address, bytes_read)
}

fn open(
    flags: u32,
    _mode: u32,
    path: String,
    state: &mut FSSyscallState,
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

    let file = file_options.open(safe_path)?;
    #[cfg(target_family = "unix")]
    {
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(_mode);
        file.set_permissions(perms)?;
    }
    for (i, entry) in state.openfiles.iter().enumerate() {
        if entry.is_none() {
            state.openfiles[i] = Some(file);
            return Ok(DCLoadCmd {
                address: i as u32 + FILE_OFFSET,
                size: i as u32 + FILE_OFFSET,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            });
        }
    }

    Err("Too many open files".into())
}

fn close(fd: u32, state: &mut FSSyscallState) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let file_entry = state
        .openfiles
        .get_mut((fd - FILE_OFFSET) as usize)
        .ok_or("Invalid FD")?;
    if file_entry.is_some() {
        *file_entry = None;
    } else {
        return Err("Invalid FD".into());
    }

    Ok(DCLoadCmd {
        address: 0,
        size: 0,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn create(
    flags: u32,
    path: String,
    state: &mut FSSyscallState,
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

fn chmod(
    _mode: u32,
    _path: String,
    _state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    #[cfg(target_family = "unix")]
    {
        let path = join_and_check_path(_state, _path);
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(_mode);
        fs::set_permissions(path, perms)?;
    }
    Ok(DCLoadCmd {
        address: 0,
        size: 0,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn lseek(
    fd: u32,
    offset: u32,
    whence: u32,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let file = state
        .openfiles
        .get_mut((fd - FILE_OFFSET) as usize)
        .ok_or("Invalid FD")?
        .as_mut()
        .ok_or("Invalid FD")?;

    let result = match whence {
        0 => file.seek(SeekFrom::Start(offset as u64))?,
        1 => file.seek(SeekFrom::Current(offset as i64))?,
        2 => file.seek(SeekFrom::End(offset as i64))?,
        _ => return Err(format!("Invalid whence: {}", whence).into()),
    } as u32;
    Ok(DCLoadCmd {
        address: result,
        size: result,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn time() -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as u32;
    Ok(DCLoadCmd {
        address: time,
        size: time,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn stat(
    conn: &mut impl ExternalDcIo,
    address: u32,
    _size: u32,
    path: String,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let file = join_and_check_path(state, path)?;
    let stat = file.metadata()?;

    let stat_data = metadata_to_stat(stat);
    push_data_and_return(conn, stat_data.into(), address, 0)
}

fn utime(
    mode: u32,
    access_time: u32,
    modif_time: u32,
    path: String,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let file = join_and_check_path(state, path)?;
    let file = File::open(file)?;
    let times = match mode {
        0 => FileTimes::new()
            .set_accessed(SystemTime::now())
            .set_modified(SystemTime::now()),
        1 => FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH + Duration::from_secs(access_time as u64))
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(modif_time as u64)),
        _ => return Err(format!("Invalid mode while setting timestamp on file: {}", mode).into()),
    };
    file.set_times(times)?;
    Ok(DCLoadCmd {
        address: 0,
        size: 0,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

// Specifically this one should return 0 when there is an error
fn wrapped_opendir(
    path: String,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    match opendir(path, state) {
        Ok(res) => Ok(res),
        Err(err) => {
            warn!("{}", err);
            Ok(DCLoadCmd {
                address: 0,
                size: 0,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            })
        }
    }
}

fn opendir(
    path: String,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let path = join_and_check_path(state, path)?;
    let dir = fs::read_dir(&path)?;

    for (i, entry) in state.opendirs.iter().enumerate() {
        if entry.is_none() {
            state.opendirs[i] = Some((path, dir));
            return Ok(DCLoadCmd {
                address: i as u32 + DIR_OFFSET,
                size: i as u32 + DIR_OFFSET,
                cmd: crate::cmds::DCLoadCmds::ReturnValue(),
            });
        }
    }

    Err("Too many open directories".into())
}

fn closedir(
    state: &mut FSSyscallState,
    dirent: u32,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let index = (dirent - DIR_OFFSET) as usize;
    if state.opendirs[index].is_some() {
        state.opendirs[index] = None;
        return Ok(DCLoadCmd {
            address: 0,
            size: 0,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        });
    }
    Err(format!("No open directory at {}", index).into())
}

fn readdir(
    conn: &mut impl ExternalDcIo,
    dirent: u32,
    address: u32,
    _size: u32,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let index = dirent
        .checked_sub(DIR_OFFSET)
        .ok_or("Invalid dirent value")? as usize;
    let dir: &mut (PathBuf, ReadDir) = state.opendirs[index]
        .as_mut()
        .ok_or::<String>(format!("No open directory at {}", index))?;
    let entry = dir.1.next();

    if let Some(entry) = entry
        && let Ok(unwrapped_entry) = entry
    {
        let filename = unwrapped_entry
                .file_name()
                .into_string()
                .map_err(|_e| -> String {
                    format!(
                        "Could not convert directory name: {:?}",
                        unwrapped_entry.file_name()
                    )
                })?;
        if filename.len() > 255 {
            return Err("Invalid filename".into());
        }
        let mut buffer = [0u8; 256];
        buffer[..filename.len()].copy_from_slice(filename.as_bytes());
        buffer[filename.len()] = 0;
        let out = DCLoadDirEnt {
            d_name: buffer,
            // Have some doubts on this one if it should be required, hopefully not
            d_ino: 0,
            d_off: 0,
            d_reclen: 0,
            d_type: dirent_filetype_to_int(unwrapped_entry.file_type()?),
        };
        push_data_and_return(conn, out.into(), address, 1)
    } else {
        Ok(DCLoadCmd {
            address: 0,
            size: 0,
            cmd: crate::cmds::DCLoadCmds::ReturnValue(),
        })
    }
}

fn rewinddir(
    dirent: u32,
    state: &mut FSSyscallState,
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    let index = dirent
        .checked_sub(DIR_OFFSET)
        .ok_or("Invalid dirent value")? as usize;
    let dir: &mut (PathBuf, ReadDir) = state.opendirs[index]
        .as_mut()
        .ok_or::<String>(format!("No open directory at {}", index))?;

    dir.1 = fs::read_dir(&dir.0)?;

    Ok(DCLoadCmd {
        address: 0,
        size: 0,
        cmd: crate::cmds::DCLoadCmds::ReturnValue(),
    })
}

fn dirent_filetype_to_int(filetype: FileType) -> u8 {
    if filetype.is_dir() {
        return 4;
    }
    if filetype.is_file() {
        return 8;
    }
    if filetype.is_symlink() {
        return 10;
    }
    0
}

fn filemeta_to_int(file_meta: &Metadata) -> i32 {
    if file_meta.is_dir() {
        return 0o040755;
    }
    if file_meta.is_file() {
        return 0o100644;
    }
    if file_meta.is_symlink() {
        return 0o120777;
    }
    0
}

fn parse_file_flags(flags: u32, path: PathBuf) -> Result<OpenOptions, DCLoadCmd> {
    let mut file_options = File::options();
    if flags == 0 {
        file_options.read(true);
    }
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

fn sanitize_relative(path: &Path) -> PathBuf {
    path.components()
        .filter(|c| !matches!(c, Component::RootDir))
        .collect()
}

fn join_and_check_path(
    state: &FSSyscallState,
    relative: String,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let base = state
        .base_path
        .as_ref()
        .expect("Base path should not be empty there");

    let sanitized = sanitize_relative(Path::new(&relative));

    let full_path = base
        .canonicalize()? // resolve real base
        .join(&state.emulated_current_dir)
        .join(sanitized);

    let canonical_full = full_path.canonicalize()?;
    let canonical_base = base.canonicalize()?;

    if !canonical_full.starts_with(&canonical_base) {
        return Err("Attempted directory traversal outside of base path".into());
    }

    Ok(full_path)
}

fn push_data_and_return(
    conn: &mut impl ExternalDcIo,
    data: Vec<u8>,
    address: u32,
    return_code: u32
) -> Result<DCLoadCmd, Box<dyn std::error::Error>> {
    send_data(conn, data.as_slice(), address, None)?;

    Ok(DCLoadCmd {
        address: return_code,
        size: return_code,
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

    if data.len() >= 4 && &data[0..4] == b"EXPT" {
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
