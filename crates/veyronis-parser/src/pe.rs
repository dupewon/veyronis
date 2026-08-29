use crate::entropy::calculate_entropy;
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_ptr: u32,
    pub entropy: f64,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDataDirectory {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeReport {
    pub is_64bit: bool,
    pub machine: u16,
    pub machine_name: String,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub entry_point: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub subsystem_name: String,
    pub dll_characteristics: u16,
    pub data_directories: HashMap<String, PeDataDirectory>,
    pub overall_entropy: f64,
    pub sections: Vec<PeSection>,
    pub detected_suspicious_apis: Vec<String>,
    pub debug_pdb_path: Option<String>,
    pub tls_callbacks_present: bool,
    pub rich_header_hash: Option<String>,
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

        let size_of_image = if is_64bit {
            LittleEndian::read_u32(&bytes[opt_header_offset + 56..opt_header_offset + 60])
        } else {
            LittleEndian::read_u32(&bytes[opt_header_offset + 56..opt_header_offset + 60])
        };

        let size_of_headers =
            LittleEndian::read_u32(&bytes[opt_header_offset + 60..opt_header_offset + 64]);
        let checksum =
            LittleEndian::read_u32(&bytes[opt_header_offset + 64..opt_header_offset + 68]);
        let subsystem =
            LittleEndian::read_u16(&bytes[opt_header_offset + 68..opt_header_offset + 70]);
        let dll_characteristics =
            LittleEndian::read_u16(&bytes[opt_header_offset + 70..opt_header_offset + 72]);

        // Parse Data Directories
        let data_dir_offset = if is_64bit {
            opt_header_offset + 112
        } else {
            opt_header_offset + 96
        };

        let dir_names = [
            "EXPORT_TABLE",
            "IMPORT_TABLE",
            "RESOURCE_TABLE",
            "EXCEPTION_TABLE",
            "CERTIFICATE_TABLE",
            "BASE_RELOCATION_TABLE",
            "DEBUG",
            "ARCHITECTURE",
            "GLOBAL_PTR",
            "TLS_TABLE",
            "LOAD_CONFIG_TABLE",
            "BOUND_IMPORT",
            "IAT",
            "DELAY_IMPORT_DESCRIPTOR",
            "CLR_RUNTIME_HEADER",
            "RESERVED",
        ];

        let mut data_directories = HashMap::new();
        let mut tls_callbacks_present = false;

        for (idx, &dir_name) in dir_names.iter().enumerate() {
            let offset = data_dir_offset + (idx * 8);
            if offset + 8 <= bytes.len() && offset + 8 <= opt_header_offset + size_of_opt_header {
                let rva = LittleEndian::read_u32(&bytes[offset..offset + 4]);
                let size = LittleEndian::read_u32(&bytes[offset + 4..offset + 8]);
                if rva > 0 && size > 0 {
                    if dir_name == "TLS_TABLE" {
                        tls_callbacks_present = true;
                    }
                    data_directories.insert(
                        dir_name.to_string(),
                        PeDataDirectory {
                            name: dir_name.to_string(),
                            rva,
                            size,
                        },
                    );
                }
            }
        }

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

            let is_executable = (characteristics & 0x2000_0000) != 0; // IMAGE_SCN_MEM_EXECUTE
            let is_readable = (characteristics & 0x4000_0000) != 0; // IMAGE_SCN_MEM_READ
            let is_writable = (characteristics & 0x8000_0000) != 0; // IMAGE_SCN_MEM_WRITE

            sections.push(PeSection {
                name,
                virtual_size,
                virtual_address,
                raw_data_size,
                raw_data_ptr: raw_data_ptr as u32,
                entropy: sec_entropy,
                characteristics,
                is_executable,
                is_writable,
                is_readable,
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
            "NtQueryInformationProcess",
            "MiniDumpWriteDump",
            "LdrLoadDll",
        ];

        let mut detected_suspicious_apis = Vec::new();
        let bytes_str = String::from_utf8_lossy(bytes);
        for &api in &suspicious_indicators {
            if bytes_str.contains(api) {
                detected_suspicious_apis.push(api.to_string());
            }
        }

        // Scan for PDB Path in Debug Directory or strings
        let mut debug_pdb_path = None;
        if let Some(pos) = bytes_str.find(".pdb") {
            let start = bytes_str[..pos].rfind(['\\', '/']).unwrap_or(0);
            let pdb_sub = &bytes_str[start..pos + 4]
                .trim_matches(|c: char| c.is_control() || c == '\\' || c == '/');
            if !pdb_sub.is_empty() && pdb_sub.len() < 128 {
                debug_pdb_path = Some(pdb_sub.to_string());
            }
        }

        // Calculate Rich Header Hash if present (between DOS stub and e_lfanew)
        let mut rich_header_hash = None;
        if e_lfanew > 0x80 && e_lfanew <= bytes.len() {
            let stub_region = &bytes[0x80..e_lfanew];
            if stub_region.windows(4).any(|w| w == b"Rich") {
                let hash = blake3::hash(stub_region).to_hex().to_string();
                rich_header_hash = Some(hash);
            }
        }

        let overall_entropy = calculate_entropy(bytes);
        let is_packed = overall_entropy > 7.3 || high_entropy_section_count > 0;

        let machine_name = match machine {
            0x8664 => "AMD64 / x86_64".to_string(),
            0x014C => "i386 / x86".to_string(),
            0xAA64 => "ARM64".to_string(),
            0x0200 => "IA64".to_string(),
            _ => format!("Unknown (0x{:X})", machine),
        };

        let subsystem_name = match subsystem {
            1 => "Native Driver".to_string(),
            2 => "Windows GUI".to_string(),
            3 => "Windows Console".to_string(),
            7 => "POSIX Console".to_string(),
            9 => "Windows CE GUI".to_string(),
            10 => "EFI Application".to_string(),
            11 => "EFI Boot Service Driver".to_string(),
            12 => "EFI Runtime Driver".to_string(),
            _ => format!("Other ({})", subsystem),
        };

        Ok(PeReport {
            is_64bit,
            machine,
            machine_name,
            number_of_sections,
            timestamp,
            entry_point,
            image_base,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            subsystem_name,
            dll_characteristics,
            data_directories,
            overall_entropy,
            sections,
            detected_suspicious_apis,
            debug_pdb_path,
            tls_callbacks_present,
            rich_header_hash,
            is_packed,
        })
    }
}
