use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::disc_formats::types::DiscFormat;

pub struct Iso {
    file: RefCell<File>,
    start_sector: u32,
    num_sectors: u32,
}

impl Iso {
    pub fn new(filename: String) -> Result<Self, std::io::Error> {
        let mut file = File::open(filename)?;
        let metadata = file.metadata()?;
        let num_sectors = (metadata.len() / 2048) as u32;
        let start_sector = Self::detect_start_sector(&mut file).unwrap_or(150);
        Ok(Self {
            file: RefCell::new(file),
            start_sector,
            num_sectors,
        })
    }

    fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buf)
    }

    fn detect_start_sector(file: &mut File) -> Option<u32> {
        let mut pvd_sig = [0_u8; 6];
        let mut root_sig = [0_u8; 0x22];
        let mut next_sig = [0_u8; 0x22];
        let mut pvd_sector = None;

        for sec in 16_u32..500 {
            if Self::read_at(file, (sec as u64) * 2048, &mut pvd_sig).is_err() {
                return None;
            }
            if &pvd_sig == b"\x01CD001" {
                pvd_sector = Some(sec);
                break;
            }
            if &pvd_sig == b"\xffCD001" {
                return Some(150);
            }
        }

        let mut sec = pvd_sector?;
        if Self::read_at(file, (sec as u64) * 2048 + 0x9c, &mut root_sig).is_err() {
            return None;
        }

        while sec < 499 {
            sec += 1;
            if Self::read_at(file, (sec as u64) * 2048, &mut next_sig).is_err() {
                return None;
            }
            if root_sig[0..0x12] == next_sig[0..0x12] && root_sig[0x19..0x22] == next_sig[0x19..0x22] {
                let root_lba = ((root_sig[5] as u32) << 24)
                    | ((root_sig[4] as u32) << 16)
                    | ((root_sig[3] as u32) << 8)
                    | root_sig[2] as u32;
                if root_lba + 150 >= sec {
                    return Some(root_lba + 150 - sec);
                }
                return Some(150);
            }
        }

        Some(150)
    }
}

impl DiscFormat for Iso {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if lba < self.start_sector {
            return Err(format!(
                "Requested LBA {} before start sector {}",
                lba, self.start_sector
            )
            .into());
        }

        let rel_lba = lba - self.start_sector;
        let end = rel_lba.saturating_add(num_sectors);
        if end > self.num_sectors {
            return Err(format!(
                "Requested sectors [{}..{}) past ISO length {}",
                rel_lba, end, self.num_sectors
            )
            .into());
        }

        let mut out = vec![0_u8; (num_sectors as usize) * 2048];
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start((rel_lba as u64) * 2048))?;
        file.read_exact(&mut out)?;
        Ok(out)
    }

    fn start_sector(&self) -> u32 {
        self.start_sector
    }

    fn num_sectors(&self) -> u32 {
        self.num_sectors
    }
}
