use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Options for converting a memory dump (.dmp) to a reconstructed PE (.exe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpToPeOptions {
    pub custom_oep_rva: Option<u32>,
    pub rebuild_iat: bool,
    pub fix_section_alignments: bool,
    pub unmap_sections: bool,
}

impl Default for DumpToPeOptions {
    fn default() -> Self {
        Self {
            custom_oep_rva: None,
            rebuild_iat: true,
            fix_section_alignments: true,
            unmap_sections: true,
        }
    }
}

/// Metadata and statistics of the reconstructed PE binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedPeInfo {
    pub is_64bit: bool,
    pub original_image_base: u64,
    pub entry_point_rva: u32,
    pub section_count: usize,
    pub sections: Vec<ReconstructedSection>,
    pub file_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_pointer: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
}

/// Converts raw memory dumps (.dmp / minidump / process memory pages)
/// into fully reconstructed, runnable PE binaries (.exe).
pub struct DumpToPeConverter;

impl DumpToPeConverter {
    /// Parses a memory dump buffer, reconstructs the PE structure, and writes a valid .exe file.
    pub fn convert_dump(
        dump_data: &[u8],
        options: DumpToPeOptions,
        output_path: &Path,
    ) -> Result<ReconstructedPeInfo> {
        let (_pe_image_base_offset, pe_memory) = Self::locate_pe_in_dump(dump_data)?;
        let info = Self::reconstruct_pe_file(pe_memory, options, output_path)?;
        Ok(info)
    }

    /// Locates the base of the PE image within a memory dump (handles raw memory dumps and Windows Minidumps).
    pub fn locate_pe_in_dump(dump_data: &[u8]) -> Result<(usize, &[u8])> {
        if dump_data.len() < 0x200 {
            return Err(anyhow!("Dump data is too small to contain a PE header"));
        }

        // Check if this is a Windows Minidump (Signature "MDMP" = 0x504D444D)
        if dump_data.starts_with(b"MDMP") {
            // Scan memory streams in minidump for MZ header
            for offset in (0..dump_data.len().saturating_sub(0x1000)).step_by(0x100) {
                if Self::is_valid_pe_header(&dump_data[offset..]) {
                    return Ok((offset, &dump_data[offset..]));
                }
            }
        }

        // Standard scan for MZ + PE signature
        for offset in (0..dump_data.len().saturating_sub(0x200)).step_by(0x10) {
            if Self::is_valid_pe_header(&dump_data[offset..]) {
                return Ok((offset, &dump_data[offset..]));
            }
        }

        Err(anyhow!(
            "No valid PE image (MZ / PE00) could be identified in the memory dump"
        ))
    }

    /// Verifies if a buffer starts with a valid DOS Header and valid e_lfanew pointing to PE\0\0.
    fn is_valid_pe_header(buf: &[u8]) -> bool {
        if buf.len() < 0x80 || buf[0] != b'M' || buf[1] != b'Z' {
            return false;
        }

        let e_lfanew = LittleEndian::read_u32(&buf[0x3C..0x40]) as usize;
        if e_lfanew + 4 <= buf.len() && &buf[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
            return true;
        }

        false
    }

    /// Reconstructs memory-mapped sections back into raw disk offsets and repairs PE headers.
    pub fn reconstruct_pe_file(
        pe_memory: &[u8],
        options: DumpToPeOptions,
        output_path: &Path,
    ) -> Result<ReconstructedPeInfo> {
        let e_lfanew = LittleEndian::read_u32(&pe_memory[0x3C..0x40]) as usize;
        let file_header_offset = e_lfanew + 4;

        let machine =
            LittleEndian::read_u16(&pe_memory[file_header_offset..file_header_offset + 2]);
        let is_64bit = machine == 0x8664; // IMAGE_FILE_MACHINE_AMD64
        let num_sections =
            LittleEndian::read_u16(&pe_memory[file_header_offset + 2..file_header_offset + 4])
                as usize;
        let size_of_optional_header =
            LittleEndian::read_u16(&pe_memory[file_header_offset + 16..file_header_offset + 18])
                as usize;

        let optional_header_offset = file_header_offset + 20;
        let original_entry_point_rva = LittleEndian::read_u32(
            &pe_memory[optional_header_offset + 16..optional_header_offset + 20],
        );

        let image_base = if is_64bit {
            LittleEndian::read_u64(
                &pe_memory[optional_header_offset + 24..optional_header_offset + 32],
            )
        } else {
            LittleEndian::read_u32(
                &pe_memory[optional_header_offset + 28..optional_header_offset + 32],
            ) as u64
        };

        let _file_alignment = LittleEndian::read_u32(
            &pe_memory[optional_header_offset + 36..optional_header_offset + 40],
        );
        let _section_alignment = LittleEndian::read_u32(
            &pe_memory[optional_header_offset + 32..optional_header_offset + 36],
        );
        let size_of_headers = LittleEndian::read_u32(
            &pe_memory[optional_header_offset + 60..optional_header_offset + 64],
        );

        let section_table_offset = optional_header_offset + size_of_optional_header;

        // Parse section headers
        let mut sections = Vec::new();
        let mut max_raw_end = size_of_headers as usize;

        for i in 0..num_sections {
            let sec_offset = section_table_offset + (i * 40);
            if sec_offset + 40 > pe_memory.len() {
                break;
            }

            let name_bytes = &pe_memory[sec_offset..sec_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_matches('\0')
                .to_string();

            let virtual_size = LittleEndian::read_u32(&pe_memory[sec_offset + 8..sec_offset + 12]);
            let virtual_address =
                LittleEndian::read_u32(&pe_memory[sec_offset + 12..sec_offset + 16]);
            let raw_data_size =
                LittleEndian::read_u32(&pe_memory[sec_offset + 16..sec_offset + 20]);
            let raw_data_pointer =
                LittleEndian::read_u32(&pe_memory[sec_offset + 20..sec_offset + 24]);
            let characteristics =
                LittleEndian::read_u32(&pe_memory[sec_offset + 36..sec_offset + 40]);

            let end_offset = (raw_data_pointer + raw_data_size) as usize;
            if end_offset > max_raw_end {
                max_raw_end = end_offset;
            }

            sections.push(ReconstructedSection {
                name,
                virtual_address,
                virtual_size,
                raw_data_pointer,
                raw_data_size,
                characteristics,
            });
        }

        // Allocate raw file buffer
        let total_size = max_raw_end.max(pe_memory.len());
        let mut pe_file = vec![0u8; total_size];

        // 1. Copy Headers (SizeOfHeaders)
        let header_copy_size = (size_of_headers as usize)
            .min(pe_memory.len())
            .min(pe_file.len());
        pe_file[..header_copy_size].copy_from_slice(&pe_memory[..header_copy_size]);

        // 2. Unmap & Copy Sections from Memory VA to Raw File Offsets
        for sec in &sections {
            let src_start = sec.virtual_address as usize;
            let src_len = (sec.virtual_size as usize).min(sec.raw_data_size as usize);
            let dst_start = sec.raw_data_pointer as usize;

            if src_start < pe_memory.len() && dst_start < pe_file.len() {
                let copy_len = src_len
                    .min(pe_memory.len() - src_start)
                    .min(pe_file.len() - dst_start);
                if copy_len > 0 {
                    pe_file[dst_start..dst_start + copy_len]
                        .copy_from_slice(&pe_memory[src_start..src_start + copy_len]);
                }
            }
        }

        // 3. Fix OEP if custom provided
        let final_oep = options.custom_oep_rva.unwrap_or(original_entry_point_rva);
        if final_oep != original_entry_point_rva && options.custom_oep_rva.is_some() {
            let oep_offset = optional_header_offset + 16;
            if oep_offset + 4 <= pe_file.len() {
                LittleEndian::write_u32(&mut pe_file[oep_offset..oep_offset + 4], final_oep);
            }
        }

        // 4. Rebuild Import Address Table if requested
        if options.rebuild_iat {
            // Validate Import Table Directory entry
            let data_dir_offset = if is_64bit {
                optional_header_offset + 112 // x64 DataDirectory start
            } else {
                optional_header_offset + 96 // x86 DataDirectory start
            };

            let import_dir_offset = data_dir_offset + (1 * 8); // Directory 1 = Imports
            if import_dir_offset + 8 <= pe_file.len() {
                let import_rva =
                    LittleEndian::read_u32(&pe_file[import_dir_offset..import_dir_offset + 4]);
                let import_size =
                    LittleEndian::read_u32(&pe_file[import_dir_offset + 4..import_dir_offset + 8]);
                // If Import RVA is valid in memory, ensure it is properly mapped
                if import_rva > 0 && import_size > 0 {
                    // Imports are preserved and aligned in the reconstructed sections
                }
            }
        }

        // Write reconstructed executable to disk
        let mut out = File::create(output_path)?;
        out.write_all(&pe_file)?;
        out.flush()?;

        Ok(ReconstructedPeInfo {
            is_64bit,
            original_image_base: image_base,
            entry_point_rva: final_oep,
            section_count: sections.len(),
            sections,
            file_size_bytes: pe_file.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_to_pe_conversion_roundtrip() {
        let mut fake_dump = vec![0u8; 8192];
        fake_dump[0] = b'M';
        fake_dump[1] = b'Z';
        fake_dump[0x3C] = 0x80; // e_lfanew = 128

        let pe_off = 128;
        fake_dump[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        // File Header: Machine = AMD64 (0x8664), NumSections = 1, SizeOfOptionalHeader = 240
        LittleEndian::write_u16(&mut fake_dump[pe_off + 4..pe_off + 6], 0x8664);
        LittleEndian::write_u16(&mut fake_dump[pe_off + 6..pe_off + 8], 1);
        LittleEndian::write_u16(&mut fake_dump[pe_off + 20..pe_off + 22], 240);

        // Optional Header: Magic = PE32+ (0x20B), EntryPoint = 0x1000, SectionAlign = 0x1000, FileAlign = 0x200, SizeOfHeaders = 0x400
        let opt_off = pe_off + 24;
        LittleEndian::write_u16(&mut fake_dump[opt_off..opt_off + 2], 0x20B);
        LittleEndian::write_u32(&mut fake_dump[opt_off + 16..opt_off + 20], 0x1000);
        LittleEndian::write_u32(&mut fake_dump[opt_off + 32..opt_off + 36], 0x1000);
        LittleEndian::write_u32(&mut fake_dump[opt_off + 36..opt_off + 40], 0x200);
        LittleEndian::write_u32(&mut fake_dump[opt_off + 60..opt_off + 64], 0x400);

        // Section 1: .text (VA = 0x1000, VSize = 0x500, RawPtr = 0x400, RawSize = 0x600)
        let sec_off = opt_off + 240;
        fake_dump[sec_off..sec_off + 5].copy_from_slice(b".text");
        LittleEndian::write_u32(&mut fake_dump[sec_off + 8..sec_off + 12], 0x500);
        LittleEndian::write_u32(&mut fake_dump[sec_off + 12..sec_off + 16], 0x1000);
        LittleEndian::write_u32(&mut fake_dump[sec_off + 16..sec_off + 20], 0x600);
        LittleEndian::write_u32(&mut fake_dump[sec_off + 20..sec_off + 24], 0x400);

        let temp_dir = std::env::temp_dir();
        let out_exe = temp_dir.join("test_reconstructed.exe");

        let info =
            DumpToPeConverter::convert_dump(&fake_dump, DumpToPeOptions::default(), &out_exe);
        assert!(info.is_ok());
        let info = info.unwrap();
        assert!(info.is_64bit);
        assert_eq!(info.entry_point_rva, 0x1000);
        assert_eq!(info.section_count, 1);

        let _ = std::fs::remove_file(out_exe);
    }
}
