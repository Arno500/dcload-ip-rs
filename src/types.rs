use std::{error, fmt};

#[derive(Debug)]
pub struct DCLoadDirEnt {
    d_ino: u32,
    d_off: u32,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 256],
}

#[derive(Debug, Default)]
pub struct DCLoadStat {
    pub st_dev: u16,
    pub st_ino: u16,
    pub st_mode: i32,
    pub st_nlink: u16,
    pub st_uid: u16,
    pub st_gid: u16,
    pub st_rdev: u16,
    pub st_size: i32,
    pub st_atime_priv: i32,
    pub st_spare1: i32,
    pub st_mtime_priv: i32,
    pub st_spare2: i32,
    pub st_ctime_priv: i32,
    pub st_spare3: i32,
    pub st_blksize: i32,
    pub st_blocks: i32,
    pub st_spare4: [i32; 2],
}

impl From<DCLoadStat> for Vec<u8> {
    fn from(stat: DCLoadStat) -> Self {
        let mut buf = Vec::with_capacity(88);
        buf.extend_from_slice(&stat.st_dev.to_le_bytes());
        buf.extend_from_slice(&stat.st_ino.to_le_bytes());
        buf.extend_from_slice(&stat.st_mode.to_le_bytes());
        buf.extend_from_slice(&stat.st_nlink.to_le_bytes());
        buf.extend_from_slice(&stat.st_uid.to_le_bytes());
        buf.extend_from_slice(&stat.st_gid.to_le_bytes());
        buf.extend_from_slice(&stat.st_rdev.to_le_bytes());
        buf.extend_from_slice(&stat.st_size.to_le_bytes());
        buf.extend_from_slice(&stat.st_atime_priv.to_le_bytes());
        buf.extend_from_slice(&stat.st_spare1.to_le_bytes());
        buf.extend_from_slice(&stat.st_mtime_priv.to_le_bytes());
        buf.extend_from_slice(&stat.st_spare2.to_le_bytes());
        buf.extend_from_slice(&stat.st_ctime_priv.to_le_bytes());
        buf.extend_from_slice(&stat.st_spare3.to_le_bytes());
        buf.extend_from_slice(&stat.st_blksize.to_le_bytes());
        buf.extend_from_slice(&stat.st_blocks.to_le_bytes());
        for spare in &stat.st_spare4 {
            buf.extend_from_slice(&spare.to_le_bytes());
        }
        buf
    }
}

#[derive(Debug, Clone)]
pub struct NotImplemented {
    pub feature: String,
}

impl fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} not implemented", self.feature)
    }
}
impl error::Error for NotImplemented {}
