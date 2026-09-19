use crate::{CHUNK_SIZE, types::NotImplemented};

#[derive(Debug, Clone, PartialEq)]
pub enum DCLoadCmds {
    Execute(),
    LoadBinary(),
    PartBinary(Box<[u8; CHUNK_SIZE]>),
    DoneBinary(),
    SendBinary(Option<Box<[u8; CHUNK_SIZE]>>),
    SendBinaryQuiet(Option<Box<[u8; CHUNK_SIZE]>>),
    Version(Option<Box<[u8; CHUNK_SIZE]>>),
    ReturnValue(),
    Reboot(),
    Mapl(),
    PerformanceCounter(),
}

#[derive(Debug, Clone)]
pub struct DCLoadCmd {
    pub cmd: DCLoadCmds,
    pub address: u32,
    pub size: u32,
}

impl DCLoadCmds {
    /// The four-character code as it goes on the wire.
    pub fn name(&self) -> &'static str {
        match self {
            DCLoadCmds::Execute() => "EXEC",
            DCLoadCmds::LoadBinary() => "LBIN",
            DCLoadCmds::PartBinary(_) => "PBIN",
            DCLoadCmds::DoneBinary() => "DBIN",
            DCLoadCmds::SendBinary(_) => "SBIN",
            DCLoadCmds::SendBinaryQuiet(_) => "SBIQ",
            DCLoadCmds::Version(_) => "VERS",
            DCLoadCmds::ReturnValue() => "RETV",
            DCLoadCmds::Reboot() => "RBOT",
            DCLoadCmds::Mapl() => "MAPL",
            DCLoadCmds::PerformanceCounter() => "PMCR",
        }
    }
}

/// One command, one short line -- for logs meant to be read.
///
/// `{:?}` is the wrong tool here twice over. It prints `address` in decimal,
/// so `LoadBinary { address: 201392128 }` has to be converted by hand before it
/// can be compared with anything else in this codebase, all of which speaks
/// hex; and for `PartBinary` it walks the payload, which is a `[u8; CHUNK_SIZE]`
/// -- 1440 numbers per line, per packet.
impl std::fmt::Display for DCLoadCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} 0x{:08x} +{}",
            self.cmd.name(),
            self.address,
            self.size
        )
    }
}

impl From<DCLoadCmd> for Vec<u8> {
    fn from(val: DCLoadCmd) -> Self {
        let mut data: Vec<u8> = Vec::new();
        let mut cmd_bytes = match val.cmd {
            DCLoadCmds::Execute() => b"EXEC".to_vec(),
            DCLoadCmds::LoadBinary() => b"LBIN".to_vec(),
            DCLoadCmds::PartBinary(bin) => {
                data = bin.to_vec();
                b"PBIN".to_vec()
            }
            DCLoadCmds::DoneBinary() => b"DBIN".to_vec(),
            DCLoadCmds::SendBinary(_) => b"SBIN".to_vec(),
            DCLoadCmds::SendBinaryQuiet(_) => b"SBIQ".to_vec(),
            DCLoadCmds::Version(None) => b"VERS".to_vec(),
            DCLoadCmds::Version(Some(ver)) => {
                data = ver.to_vec();
                b"VERS".to_vec()
            }
            DCLoadCmds::ReturnValue() => b"RETV".to_vec(),
            DCLoadCmds::Reboot() => b"RBOT".to_vec(),
            DCLoadCmds::Mapl() => b"MAPL".to_vec(),
            DCLoadCmds::PerformanceCounter() => b"PMCR".to_vec(),
        };
        // cmd_bytes.append(&mut val.address.to_ne_bytes().to_vec());
        // cmd_bytes.append(&mut val.size.to_ne_bytes().to_vec());
        unsafe {
            cmd_bytes.append(&mut val.address.to_be_bytes().align_to_mut::<u8>().1.to_vec());
            cmd_bytes.append(&mut val.size.to_be_bytes().align_to_mut::<u8>().1.to_vec());
        }
        if !data.is_empty() {
            cmd_bytes.append(&mut data);
        }
        cmd_bytes
    }
}

pub struct DCReturnCmd {
    pub cmd: Option<DCLoadCmd>,
    pub request: Option<DCLoadClientCmds>,
    pub error_code: Option<u32>,
}

impl TryFrom<Vec<u8>> for DCReturnCmd {
    type Error = String;

    fn try_from(input: Vec<u8>) -> Result<DCReturnCmd, Self::Error> {
        if input.len() < 5 {
            if input.len() >= 4 {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&input[0..4]);
                let return_code = u32::from_be_bytes(buf);
                return Ok(DCReturnCmd {
                    cmd: None,
                    request: None,
                    error_code: Some(u32::from_be(return_code)),
                });
            }
            return Err("Input data invalid for DCReturnCmd".to_string());
        }

        if &input[0..2] == b"DC" {
            let client_cmd = DCLoadClientCmds::try_from(input.clone());
            if let Ok(client_cmd) = client_cmd {
                return Ok(DCReturnCmd {
                    cmd: None,
                    request: Some(client_cmd),
                    error_code: None,
                });
            }
            if let Err(err) = client_cmd {
                return Err(format!("Failed to parse syscall command: {:?}", err));
            }
        }
        if input.len() < 12 {
            debug!("{:?}", input);
            return Err("Input data too short to be a valid DCLoadCmd".to_string());
        }
        let cmd = match &input[0..4] {
            b"EXEC" => DCLoadCmds::Execute(),
            b"LBIN" => DCLoadCmds::LoadBinary(),
            b"PBIN" => {
                let mut bin = [0u8; CHUNK_SIZE];
                let len = input.len() - 12;
                if len > CHUNK_SIZE {
                    return Err("Input data too long for PBIN command".to_string());
                }
                bin[..len].copy_from_slice(&input[12..]);
                DCLoadCmds::PartBinary(Box::new(bin))
            }
            b"DBIN" => DCLoadCmds::DoneBinary(),
            b"SBIN" => {
                let mut bin = [0u8; CHUNK_SIZE];
                let len = input.len() - 12;
                if len > CHUNK_SIZE {
                    return Err("Input data too long for SBIN command".to_string());
                } else if len == 0 {
                    DCLoadCmds::SendBinary(None)
                } else {
                    bin[..len].copy_from_slice(&input[12..]);
                    DCLoadCmds::SendBinary(Some(Box::new(bin)))
                }
            },
            b"SBIQ" => {
                let mut bin = [0u8; CHUNK_SIZE];
                let len = input.len() - 12;
                if len > CHUNK_SIZE {
                    return Err("Input data too long for SBIQ command".to_string());
                } else if len == 0 {
                    DCLoadCmds::SendBinaryQuiet(None)
                } else {
                    bin[..len].copy_from_slice(&input[12..]);
                    DCLoadCmds::SendBinaryQuiet(Some(Box::new(bin)))
                }
            },
            b"VERS" => {
                let mut bin = [0u8; CHUNK_SIZE];
                let len = input.len() - 12;
                if len > CHUNK_SIZE {
                    return Err("Input data too long for VERS command".to_string());
                }
                bin[..len].copy_from_slice(&input[12..]);
                DCLoadCmds::Version(Some(Box::new(bin)))
            }
            b"RETV" => DCLoadCmds::ReturnValue(),
            b"RBOT" => DCLoadCmds::Reboot(),
            b"MAPL" => DCLoadCmds::Mapl(),
            b"PMCR" => DCLoadCmds::PerformanceCounter(),
            _ => return Err("Unknown command".to_string()),
        };
        let address = u32::from_be_bytes(input[4..8].try_into().unwrap());
        let size = u32::from_be_bytes(input[8..12].try_into().unwrap());
        Ok(DCReturnCmd {
            cmd: Some(DCLoadCmd { cmd, address, size }),
            request: None,
            error_code: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DCLoadClientFSCmds {
    FStat(u32, u32, u32),
    Write(u32, u32, u32),
    Read(u32, u32, u32),
    Open(u32, u32, String),
    Close(u32),
    Create(u32, String),
    Link(String),
    Unlink(String),
    ChDir(String),
    ChMod(u32, String),
    LSeek(u32, u32, u32),
    Time(),
    Stat(u32, u32, String),
    UTime(u32, u32, u32, String),
    OpenDir(String),
    CloseDir(u32),
    ReadDir(u32, u32, u32),
    RewindDir(u32),
}

/// How the loader wants its audio, which is a property of the command it sent
/// rather than a host-side option: `DC23` is raw 16-bit stereo straight off the
/// disc, `DC24` is 4-bit Yamaha ADPCM with the two channels already split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    /// Interleaved signed 16-bit little-endian, 2352 bytes to the sector.
    Pcm,
    /// 4-bit Yamaha ADPCM, one byte per stereo frame, left block then right.
    ///
    /// `restart` is bit 31 of the loader's size field. The format carries a
    /// running predictor shared with the AICA's decoder, so the encoder may be
    /// reset only at the one event that resets the console's: keying the
    /// channels on.
    Adpcm { restart: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub enum DCLoadClientCmds {
    Exit,
    ReadSector(u32, u32, u32),
    /// Audio for the CD-DA engine: LBA, destination, bytes, and the format the
    /// loader asked for. See `read_audio` and `adpcm::Stream`.
    ReadAudio(u32, u32, u32, AudioFormat),
    ReadToc(u32, u32, u32),
    FSCommand(DCLoadClientFSCmds),
}

impl TryFrom<Vec<u8>> for DCLoadClientCmds {
    type Error = Box<dyn std::error::Error>;

    fn try_from(input: Vec<u8>) -> Result<DCLoadClientCmds, Self::Error> {
        if input.len() < 4 {
            return Err("Input data too short to be a valid DCLoadClientCmds".into());
        }
        match &input[0..4] {
            b"DC00" => Ok(DCLoadClientCmds::Exit),
            b"DC01" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::FStat(param1, param2, param3)))
            }
            b"DC02" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Write(param1, param2, param3)))
            }
            b"DC03" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Read(param1, param2, param3)))
            }
            b"DC04" => {
                let (param1, param2, param3) = extract_2_u32_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Open(param1, param2, param3)))
            }
            b"DC05" => {
                let param1 = extract_1_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Close(param1)))
            }
            b"DC06" => {
                let (param1, param2) = extract_1_u32_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Create(param1, param2)))
            }
            b"DC07" => {
                let param1 = extract_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Link(param1)))
            }
            b"DC08" => {
                let param1 = extract_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Unlink(param1)))
            }
            b"DC09" => {
                let param1 = extract_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::ChDir(param1)))
            }
            b"DC10" => {
                let (param1, param2) = extract_1_u32_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::ChMod(param1, param2)))
            }
            b"DC11" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::LSeek(param1, param2, param3)))
            }
            b"DC12" => Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Time())),
            b"DC13" => {
                let (param1, param2, param3) = extract_2_u32_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::Stat(param1, param2, param3)))
            }
            b"DC14" => {
                let (param1, param2, param3, param4) = extract_3_u32_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::UTime(param1, param2, param3, param4)))
            }
            b"DC16" => {
                let param1 = extract_1_string(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::OpenDir(param1)))
            }
            b"DC17" => {
                let param1 = extract_1_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::CloseDir(param1)))
            }
            b"DC18" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::ReadDir(param1, param2, param3)))
            }
            b"DC19" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::ReadSector(param1, param2, param3))
            }
            b"DC23" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::ReadAudio(param1, param2, param3, AudioFormat::Pcm))
            }
            b"DC24" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::ReadAudio(
                    param1,
                    param2,
                    param3 & 0x7fff_ffff,
                    AudioFormat::Adpcm { restart: param3 & 0x8000_0000 != 0 },
                ))
            }
            b"DC22" => {
                let (param1, param2, param3) = extract_3_u32(&input[4..])?;
                Ok(DCLoadClientCmds::ReadToc(param1, param2, param3))
            }
            b"DC21" => {
                let param1 = extract_1_u32(&input[4..])?;
                Ok(DCLoadClientCmds::FSCommand(DCLoadClientFSCmds::RewindDir(param1)))
            }
            _ => {
                let cmd_str = String::from_utf8(input[0..4].to_vec())?;
                Err(Box::new(NotImplemented {
                    feature: format!("Runtime command {} from dc-load", cmd_str),
                }))
            }
        }
    }
}

fn extract_1_u32(input: &[u8]) -> Result<u32, Box<dyn std::error::Error>> {
    if input.len() < 4 {
        return Err("Input data too short to extract u32 value".into());
    }
    let val = u32::from_be_bytes(input[0..4].try_into().unwrap());
    Ok(val)
}

fn extract_1_string(input: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let string_data = input;
    let string_end = string_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(string_data.len());
    let string_value = String::from_utf8(string_data[0..string_end].to_vec())?;
    Ok(string_value)
}

fn extract_1_u32_1_string(
    input: &[u8],
) -> Result<(u32, String), Box<dyn std::error::Error>> {
    if input.len() < 4 {
        return Err("Input data too short to extract u32 value".into());
    }
    let val = u32::from_be_bytes(input[0..4].try_into().unwrap());
    let string_data = &input[4..];
    let string_end = string_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(string_data.len());
    let string_value = String::from_utf8(string_data[0..string_end].to_vec())?;
    Ok((val, string_value))
}

fn extract_3_u32(input: &[u8]) -> Result<(u32, u32, u32), Box<dyn std::error::Error>> {
    if input.len() < 12 {
        return Err("Input data too short to extract three u32 values".into());
    }
    let val1 = u32::from_be_bytes(input[0..4].try_into().unwrap());
    let val2 = u32::from_be_bytes(input[4..8].try_into().unwrap());
    let val3 = u32::from_be_bytes(input[8..12].try_into().unwrap());
    Ok((val1, val2, val3))
}

fn extract_2_u32_1_string(
    input: &[u8],
) -> Result<(u32, u32, String), Box<dyn std::error::Error>> {
    if input.len() < 8 {
        return Err("Input data too short to extract two u32 values".into());
    }
    let val1 = u32::from_be_bytes(input[0..4].try_into().unwrap());
    let val2 = u32::from_be_bytes(input[4..8].try_into().unwrap());
    let string_data = &input[8..];
    let string_end = string_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(string_data.len());
    let string_value = String::from_utf8(string_data[0..string_end].to_vec())?;
    Ok((val1, val2, string_value))
}

fn extract_3_u32_1_string(
    input: &[u8],
) -> Result<(u32, u32, u32, String), Box<dyn std::error::Error>> {
    if input.len() < 12 {
        return Err("Input data too short to extract three u32 values".into());
    }
    let val1 = u32::from_be_bytes(input[0..4].try_into().unwrap());
    let val2 = u32::from_be_bytes(input[4..8].try_into().unwrap());
    let val3 = u32::from_be_bytes(input[8..12].try_into().unwrap());
    let string_data = &input[12..];
    let string_end = string_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(string_data.len());
    let string_value = String::from_utf8(string_data[0..string_end].to_vec())?;
    Ok((val1, val2, val3, string_value))
}
