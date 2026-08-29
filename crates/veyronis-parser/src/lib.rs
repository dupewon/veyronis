pub mod elf;
pub mod entropy;
pub mod macho;
pub mod pe;
pub mod unpacker;

pub use elf::{ElfParser, ElfReport};
pub use entropy::{calculate_entropy, is_likely_packed, ENTROPY_PACKED_THRESHOLD};
pub use macho::{MachoParser, MachoReport};
pub use pe::{PeParser, PeReport, PeSection};
pub use unpacker::MemoryUnpacker;

use colored::*;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub enum BinaryType {
    Pe(PeReport),
    Elf(ElfReport),
    Macho(MachoReport),
    Unknown { entropy: f64, size_bytes: usize },
}

#[derive(Debug, Clone)]
pub struct BinaryInspectionReport {
    pub file_path: String,
    pub size_bytes: usize,
    pub overall_entropy: f64,
    pub is_packed: bool,
    pub binary_type: BinaryType,
}

impl BinaryInspectionReport {
    pub fn render_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{}\n",
            "=== VEYRONIS STATIC BINARY FORENSICS ===".bold().white()
        ));
        out.push_str(&format!("File:               {}\n", self.file_path.cyan()));
        out.push_str(&format!("Size:               {} bytes\n", self.size_bytes));
        out.push_str(&format!(
            "Overall Entropy:    {:.4} bits/byte ({})\n",
            self.overall_entropy,
            if self.is_packed {
                "SUSPICIOUS / PACKED".red().bold()
            } else {
                "NORMAL".green()
            }
        ));

        match &self.binary_type {
            BinaryType::Pe(pe) => {
                out.push_str(&format!(
                    "Format:             Windows PE (Arch: {})\n",
                    if pe.is_64bit {
                        "x86_64 / PE32+"
                    } else {
                        "x86 / PE32"
                    }
                ));
                out.push_str(&format!("Entry Point:        0x{:08X}\n", pe.entry_point));
                out.push_str(&format!("Image Base:         0x{:016X}\n", pe.image_base));
                out.push_str(&format!("Sections Count:     {}\n\n", pe.sections.len()));

                let mut rows = Vec::new();
                for s in &pe.sections {
                    let is_sec_packed = s.entropy >= ENTROPY_PACKED_THRESHOLD;
                    rows.push(format!(
                        "| {:<7} | 0x{:08X}   | {:<11} | {:<7.2} | {:<6} |",
                        s.name,
                        s.virtual_address,
                        format!("{} bytes", s.raw_data_size),
                        s.entropy,
                        if is_sec_packed { "PACKED" } else { "NORMAL" }
                    ));
                }

                out.push_str("+---------+--------------+-------------+---------+--------+\n");
                out.push_str("| Section | Virtual Addr | Raw Size    | Entropy | Status |\n");
                out.push_str("+---------+--------------+-------------+---------+--------+\n");
                for r in rows {
                    out.push_str(&format!("{}\n", r));
                }
                out.push_str("+---------+--------------+-------------+---------+--------+\n");

                if !pe.detected_suspicious_apis.is_empty() {
                    out.push_str(&format!(
                        "\n{}\n",
                        "SUSPICIOUS HIGH-RISK API IMPORTS FOUND:".yellow().bold()
                    ));
                    for api in &pe.detected_suspicious_apis {
                        out.push_str(&format!("  [!] {}\n", api.red()));
                    }
                }
            }
            BinaryType::Elf(elf) => {
                out.push_str(&format!(
                    "Format:             Linux ELF ({}-bit, {})\n",
                    if elf.is_64bit { "64" } else { "32" },
                    if elf.is_little_endian {
                        "Little Endian"
                    } else {
                        "Big Endian"
                    }
                ));
                out.push_str(&format!("Entry Point:        0x{:016X}\n", elf.entry_point));
            }
            BinaryType::Macho(macho) => {
                out.push_str(&format!(
                    "Format:             macOS Mach-O ({}-bit)\n",
                    if macho.is_64bit { "64" } else { "32" }
                ));
                out.push_str(&format!("CPU Type:           0x{:08X}\n", macho.cpu_type));
                out.push_str(&format!("Commands Count:     {}\n", macho.ncmds));
            }
            BinaryType::Unknown { entropy, .. } => {
                out.push_str(&format!(
                    "Format:             Unknown / Raw Binary (Entropy: {:.4})\n",
                    entropy
                ));
            }
        }

        out
    }
}

pub struct BinaryInspector;

impl BinaryInspector {
    pub fn inspect_file(path: &Path) -> Result<BinaryInspectionReport, anyhow::Error> {
        let bytes = fs::read(path)?;
        let size_bytes = bytes.len();
        let overall_entropy = calculate_entropy(&bytes);

        let (binary_type, is_packed) = if let Ok(pe) = PeParser::parse(&bytes) {
            let packed = pe.is_packed || is_likely_packed(overall_entropy);
            (BinaryType::Pe(pe), packed)
        } else if let Ok(elf) = ElfParser::parse(&bytes) {
            let packed = elf.is_packed || is_likely_packed(overall_entropy);
            (BinaryType::Elf(elf), packed)
        } else if let Ok(macho) = MachoParser::parse(&bytes) {
            let packed = macho.is_packed || is_likely_packed(overall_entropy);
            (BinaryType::Macho(macho), packed)
        } else {
            let packed = is_likely_packed(overall_entropy);
            (
                BinaryType::Unknown {
                    entropy: overall_entropy,
                    size_bytes,
                },
                packed,
            )
        };

        Ok(BinaryInspectionReport {
            file_path: path.display().to_string(),
            size_bytes,
            overall_entropy,
            is_packed,
            binary_type,
        })
    }
}
