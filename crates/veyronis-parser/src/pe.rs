use crate::entropy::calculate_entropy;
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_ptr: u32,
    pub entropy: f64,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeReport {
    pub is_64bit: bool,
    pub machine: u16,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub entry_point: u32,
    pub image_base: u64,
    pub overall_entropy: f64,
    pub sections: Vec<PeSection>,
    pub detected_suspicious_apis: Vec<String>,
    pub is_packed: bool,
}

pub struct PeParser;

impl PeParser {
    pub fn parse(bytes: &[u8]) -> Result<PeReport, anyhow::Error> {
        if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
            return Err(anyhow::anyhow!("not a valid DOS/PE executable"));
        }

        let e_lfanew = LittleEndian::read_u32(&bytes[0x3C..0x40]) as usize;
        if bytes.len() < e_lfanew + 24 || &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(anyhow::anyhow!("invalid PE signature offset"));
        }

        let file_header_offset = e_lfanew + 4;
        let machine = LittleEndian::read_u16(&bytes[file_header_offset..file_header_offset + 2]);
        let number_of_sections =
            LittleEndian::read_u16(&bytes[file_header_offset + 2..file_header_offset + 4]);
        let timestamp =
            LittleEndian::read_u32(&bytes[file_header_offset + 4..file_header_offset + 8]);
        let size_of_opt_header =
            LittleEndian::read_u16(&bytes[file_header_offset + 16..file_header_offset + 18])
                as usize;

        let opt_header_offset = file_header_offset + 20;
        let magic = LittleEndian::read_u16(&bytes[opt_header_offset..opt_header_offset + 2]);
        let is_64bit = magic == 0x20B;

        let entry_point =
            LittleEndian::read_u32(&bytes[opt_header_offset + 16..opt_header_offset + 20]);
        let image_base = if is_64bit {
            if bytes.len() >= opt_header_offset + 32 {
                LittleEndian::read_u64(&bytes[opt_header_offset + 24..opt_header_offset + 32])
            } else {
                0
            }
        } else if bytes.len() >= opt_header_offset + 32 {
            LittleEndian::read_u32(&bytes[opt_header_offset + 28..opt_header_offset + 32]) as u64
        } else {
            0
        };

        // Section Headers
        let mut sections = Vec::new();
        let section_table_offset = opt_header_offset + size_of_opt_header;

        let mut high_entropy_section_count = 0;

        for i in 0..number_of_sections as usize {
            let sec_off = section_table_offset + (i * 40);
            if bytes.len() < sec_off + 40 {
                break;
            }

            let name_bytes = &bytes[sec_off..sec_off + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_matches('\0')
                .to_string();

            let virtual_size = LittleEndian::read_u32(&bytes[sec_off + 8..sec_off + 12]);
            let virtual_address = LittleEndian::read_u32(&bytes[sec_off + 12..sec_off + 16]);
            let raw_data_size = LittleEndian::read_u32(&bytes[sec_off + 16..sec_off + 20]);
            let raw_data_ptr = LittleEndian::read_u32(&bytes[sec_off + 20..sec_off + 24]) as usize;
            let characteristics = LittleEndian::read_u32(&bytes[sec_off + 36..sec_off + 40]);

            let section_data = if raw_data_ptr + (raw_data_size as usize) <= bytes.len() {
                &bytes[raw_data_ptr..raw_data_ptr + (raw_data_size as usize)]
            } else {
                &[]
            };

            let sec_entropy = calculate_entropy(section_data);
            if sec_entropy >= 7.2 {
                high_entropy_section_count += 1;
            }

            sections.push(PeSection {
                name,
                virtual_size,
                virtual_address,
                raw_data_size,
                raw_data_ptr: raw_data_ptr as u32,
                entropy: sec_entropy,
                characteristics,
            });
        }

        // Suspicious API patterns scan
        let suspicious_indicators = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "QueueUserAPC",
            "SetWindowsHookEx",
            "NtUnmapViewOfSection",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "AdjustTokenPrivileges",
        ];

        let mut detected_suspicious_apis = Vec::new();
        let bytes_str = String::from_utf8_lossy(bytes);
        for &api in &suspicious_indicators {
            if bytes_str.contains(api) {
                detected_suspicious_apis.push(api.to_string());
            }
        }

        let overall_entropy = calculate_entropy(bytes);
        let is_packed = overall_entropy > 7.3 || high_entropy_section_count > 0;

        Ok(PeReport {
            is_64bit,
            machine,
            number_of_sections,
            timestamp,
            entry_point,
            image_base,
            overall_entropy,
            sections,
            detected_suspicious_apis,
            is_packed,
        })
    }
}
