use crate::entropy::calculate_entropy;
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachoReport {
    pub is_64bit: bool,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub ncmds: u32,
    pub overall_entropy: f64,
    pub is_packed: bool,
}

pub struct MachoParser;

impl MachoParser {
    pub fn parse(bytes: &[u8]) -> Result<MachoReport, anyhow::Error> {
        if bytes.len() < 32 {
            return Err(anyhow::anyhow!("file too small for Mach-O header"));
        }

        let magic = LittleEndian::read_u32(&bytes[0..4]);
        let is_64bit = magic == 0xFEEDFACF || magic == 0xCFFACEDF;
        let is_32bit = magic == 0xFEEDFACE || magic == 0xCEFAEDFE;

        if !is_64bit && !is_32bit {
            return Err(anyhow::anyhow!("not a valid Mach-O binary"));
        }

        let cpu_type = LittleEndian::read_u32(&bytes[4..8]);
        let cpu_subtype = LittleEndian::read_u32(&bytes[8..12]);
        let file_type = LittleEndian::read_u32(&bytes[12..16]);
        let ncmds = LittleEndian::read_u32(&bytes[16..20]);

        let overall_entropy = calculate_entropy(bytes);
        let is_packed = overall_entropy > 7.35;

        Ok(MachoReport {
            is_64bit,
            cpu_type,
            cpu_subtype,
            file_type,
            ncmds,
            overall_entropy,
            is_packed,
        })
    }
}
