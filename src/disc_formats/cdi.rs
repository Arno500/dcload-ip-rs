use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::disc_formats::types::DiscFormat;

const SYNC_HEADER: [u8; 12] = [
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
];

pub struct Cdi {
    file: RefCell<File>,
    sector_size: u32,
    data_offset: u32,
    start_sector: u32,
    num_sectors: u32,
}

impl Cdi {
    pub fn new(filename: String) -> Result<Self, std::io::Error> {
        let mut file = File::open(&filename)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        let mut header_buf = [0u8; 16];
        file.read_exact(&mut header_buf)?;

        let (sector_size, data_offset, _seek_ecc) = if &header_buf[0..12] == &SYNC_HEADER {
            file.seek(SeekFrom::Start(2352))?;
            file.read_exact(&mut header_buf)?;

            if &header_buf[0..12] == &SYNC_HEADER {
                (2352, 16, 288)
            } else {
                file.seek(SeekFrom::Start(2368))?;
                file.read_exact(&mut header_buf)?;

                if &header_buf[0..12] == &SYNC_HEADER {
                    (2368, 16, 304)
                } else {
                    (2448, 16, 384)
                }
            }
        } else {
            (2048, 0, 0)
        };

        let total_sectors = file_size / (sector_size as u64);
        let num_sectors = total_sectors as u32;
        let start_sector = 150;

        file.seek(SeekFrom::Start(0))?;

        Ok(Self {
            file: RefCell::new(file),
            sector_size,
            data_offset,
            start_sector,
            num_sectors,
        })
    }
}

impl DiscFormat for Cdi {
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
                "Requested sectors [{}..{}) past CDI length {}",
                rel_lba, end, self.num_sectors
            )
            .into());
        }

        let mut out = vec![0_u8; (num_sectors as usize) * 2048];
        let mut file = self.file.borrow_mut();

        for (i, chunk) in out.chunks_mut(2048).enumerate() {
            let sector_lba = rel_lba + (i as u32);
            let file_offset =
                (sector_lba as u64) * (self.sector_size as u64) + (self.data_offset as u64);

            file.seek(SeekFrom::Start(file_offset))?;

            if self.sector_size == 2048 {
                file.read_exact(chunk)?;
            } else {
                let mut raw_sector = vec![0u8; self.sector_size as usize];
                file.read_exact(&mut raw_sector)?;

                let payload_offset: usize = match self.sector_size {
                    2056 | 2336 => 8,
                    2352 | 2368 | 2448 => 16,
                    s => return Err(format!("Unsupported CDI sector size: {}", s).into()),
                };

                let payload_end = payload_offset + 2048;
                if payload_end > raw_sector.len() {
                    return Err(format!(
                        "Raw sector too small for payload extraction: {} bytes (offset {})",
                        raw_sector.len(),
                        payload_offset
                    )
                    .into());
                }
                chunk.copy_from_slice(&raw_sector[payload_offset..payload_end]);
            }
        }

        Ok(out)
    }

    fn start_sector(&self) -> u32 {
        self.start_sector
    }

    fn num_sectors(&self) -> u32 {
        self.num_sectors
    }
}
