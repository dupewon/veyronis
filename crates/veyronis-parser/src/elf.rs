use crate::entropy::calculate_entropy;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfReport {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub os_abi: u8,
    pub elf_type: u16,
    pub machine: u16,
    pub entry_point: u64,
    pub overall_entropy: f64,
    pub is_packed: bool,
}

pub struct ElfParser;

impl ElfParser {
    pub fn parse(bytes: &[u8]) -> Result<ElfReport, anyhow::Error> {
        if bytes.len() < 52 || &bytes[0..4] != b"\x7fELF" {
            return Err(anyhow::anyhow!("not a valid ELF binary"));
        }

        let is_64bit = bytes[4] == 2;
        let is_little_endian = bytes[5] == 1;
        let os_abi = bytes[7];

        let (elf_type, machine, entry_point) = if is_little_endian {
            let t = LittleEndian::read_u16(&bytes[16..18]);
            let m = LittleEndian::read_u16(&bytes[18..20]);
            let e = if is_64bit && bytes.len() >= 32 {
                LittleEndian::read_u64(&bytes[24..32])
            } else {
                LittleEndian::read_u32(&bytes[24..28]) as u64
            };
            (t, m, e)
        } else {
            let t = BigEndian::read_u16(&bytes[16..18]);
            let m = BigEndian::read_u16(&bytes[18..20]);
            let e = if is_64bit && bytes.len() >= 32 {
                BigEndian::read_u64(&bytes[24..32])
            } else {
                BigEndian::read_u32(&bytes[24..28]) as u64
            };
            (t, m, e)
        };

        let overall_entropy = calculate_entropy(bytes);
        let is_packed = overall_entropy > 7.35;

        Ok(ElfReport {
            is_64bit,
            is_little_endian,
            os_abi,
            elf_type,
            machine,
            entry_point,
            overall_entropy,
            is_packed,
        })
    }
}
