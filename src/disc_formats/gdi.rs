use std::cell::RefCell;
use std::fs::{File, read_to_string};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::disc_formats::types::{DiscFormat, Track};
pub struct Gdi {
    tracks: RefCell<Vec<Track>>,
}

impl Gdi {
    pub fn new(filename: String) -> Result<Self, std::io::Error> {
        let parent_path = Path::new(&filename).parent().unwrap_or(Path::new(""));
        match read_to_string(&filename) {
            Err(e) => Err(e),
            Ok(f) => {
                let mut lines = f.lines();
                let number_of_tracks = lines.next();
                if let Some(num_tracks) = number_of_tracks {
                    let num_tracks: usize = num_tracks.trim().parse().unwrap_or(0);
                    let mut tracks = Vec::with_capacity(num_tracks);
                    for _ in 0..num_tracks {
                        if let Some(line) = lines.next() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 6 {
                                let track_number: u8 = parts[0].parse().unwrap_or(0);
                                let start_lba = parts[1].parse().unwrap_or(0);
                                let track_type: u8 = parts[2].parse().unwrap_or(0);
                                let sector_size: u32 = parts[3].parse().unwrap_or(2048);
                                let track = Path::join(parent_path, parts[4])
                                    .to_string_lossy()
                                    .into();
                                let offset: u32 = parts[5].parse().unwrap_or(0);
                                tracks.push(Track {
                                    track_number,
                                    start_lba,
                                    track_type,
                                    sector_size,
                                    track,
                                    offset,
                                    file: None,
                                });
                            }
                        }
                    }
                    Ok(Gdi {
                        tracks: RefCell::new(tracks),
                    })
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid GDI file: missing number of tracks",
                    ))
                }
            }
        }
    }
}
impl DiscFormat for Gdi {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut tracks = self.tracks.borrow_mut();
        let len = tracks.len();
        for track_num in 0..len {
            if lba >= tracks[track_num].start_lba
                && (track_num + 1 >= len || tracks[track_num + 1].start_lba > lba)
            {
                let current_track = &mut tracks[track_num];
                let mut buffer = vec![0_u8; (num_sectors * 2048).try_into()?];
                if current_track.file.is_none() {
                    current_track.file = Some(File::open(current_track.track.clone())?);
                }

                let file = current_track.file.as_mut().unwrap();
                let in_track_lba = lba - current_track.start_lba;
                file.seek(SeekFrom::Start(
                    (in_track_lba as u64) * (current_track.sector_size as u64),
                ))?;

                if current_track.sector_size == 2048 {
                    file.read_exact(&mut buffer)?;
                } else if current_track.sector_size >= 2064 {
                    let mut raw_sector = vec![0_u8; current_track.sector_size as usize];
                    for chunk in buffer.chunks_mut(2048) {
                        file.read_exact(&mut raw_sector)?;
                        chunk.copy_from_slice(&raw_sector[16..16 + 2048]);
                    }
                } else {
                    return Err(format!(
                        "Unsupported GDI sector size: {}",
                        current_track.sector_size
                    )
                    .into());
                }
                return Ok(buffer);
            }
        }
        Err(format!("Could not find track file for LBA 0x{:08x}", lba).into())
    }

    fn start_sector(&self) -> u32 {
        let tracks = self.tracks.borrow();
        tracks
            .iter()
            .filter(|t| t.track_type == 4)
            .map(|t| t.start_lba)
            .min()
            .unwrap_or(150)
    }

    fn num_sectors(&self) -> u32 {
        let mut tracks = self.tracks.borrow_mut();
        let data_track_index = tracks
            .iter()
            .position(|t| t.track_type == 4)
            .unwrap_or(0);
        if tracks.is_empty() {
            return 0;
        }
        let t = &mut tracks[data_track_index];
        if t.file.is_none()
            && let Ok(f) = File::open(t.track.clone())
        {
            t.file = Some(f);
        }
        if let Some(f) = t.file.as_ref()
            && let Ok(meta) = f.metadata()
        {
            return (meta.len() / (t.sector_size as u64)) as u32;
        }
        0
    }
}
