#[derive(Debug)]
pub struct Track {
    #[allow(unused)]
    pub(crate) track_number: u8,
    pub(crate) start_lba: u32,
    #[allow(unused)]
    pub(crate) track_type: u8,
    #[allow(unused)]
    pub(crate) sector_size: u32,
    pub(crate) track: String,
    #[allow(unused)]
    pub(crate) offset: u32,
    pub(crate) file: Option<std::fs::File>,
}

pub trait DiscFormat {
    fn read_sector(
        &self,
        lba: u32,
        num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn start_sector(&self) -> u32 {
        150
    }

    fn num_sectors(&self) -> u32 {
        0
    }
}

pub struct StubDisc {}
impl DiscFormat for StubDisc {
    fn read_sector(
        &self,
        _lba: u32,
        _num_sectors: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Err("CDFS redirection is not enabled, this should never be called from the client".into())
    }
}

pub fn get_disc_format<D: DiscFormat + 'static>(disc: D) -> Box<dyn DiscFormat> {
    Box::new(disc)
}
