use std::{error, fmt};

#[repr(C)]
#[derive(Debug)]
pub struct DCLoadDirEnt {
    d_ino: u32,
    d_off: u32,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 256],
}

#[repr(C)]
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

#[repr(C)]
#[derive(Debug)]
pub struct ExceptionStruct {
    pub id: [u8; 4],
    pub expt_code: u32,
    pub pc: u32,
    pub pr: u32,
    pub sr: u32,
    pub gbr: u32,
    pub vbr: u32,
    pub dbr: u32,
    pub mach: u32,
    pub macl: u32,
    pub r0b0: u32,
    pub r1b0: u32,
    pub r2b0: u32,
    pub r3b0: u32,
    pub r4b0: u32,
    pub r5b0: u32,
    pub r6b0: u32,
    pub r7b0: u32,
    pub r0b1: u32,
    pub r1b1: u32,
    pub r2b1: u32,
    pub r3b1: u32,
    pub r4b1: u32,
    pub r5b1: u32,
    pub r6b1: u32,
    pub r7b1: u32,
    pub r8: u32,
    pub r9: u32,
    pub r10: u32,
    pub r11: u32,
    pub r12: u32,
    pub r13: u32,
    pub r14: u32,
    pub r15: u32, // saved from SGR
    pub fpscr: u32,
    pub fr0: u32,
    pub fr1: u32,
    pub fr2: u32,
    pub fr3: u32,
    pub fr4: u32,
    pub fr5: u32,
    pub fr6: u32,
    pub fr7: u32,
    pub fr8: u32,
    pub fr9: u32,
    pub fr10: u32,
    pub fr11: u32,
    pub fr12: u32,
    pub fr13: u32,
    pub fr14: u32,
    pub fr15: u32,
    pub fpul: u32,
    pub xf0: u32,
    pub xf1: u32,
    pub xf2: u32,
    pub xf3: u32,
    pub xf4: u32,
    pub xf5: u32,
    pub xf6: u32,
    pub xf7: u32,
    pub xf8: u32,
    pub xf9: u32,
    pub xf10: u32,
    pub xf11: u32,
    pub xf12: u32,
    pub xf13: u32,
    pub xf14: u32,
    pub xf15: u32,
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
