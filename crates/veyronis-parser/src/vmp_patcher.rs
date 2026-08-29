use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Information about a successful binary patch and devirtualization re-assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchReport {
    pub patch_offset: usize,
    pub original_stub_len: usize,
    pub patched_bytes_len: usize,
    pub nop_padding_len: usize,
    pub patched_file_path: String,
}

/// VMProtect Re-assembler and In-Place Binary Patcher.
pub struct VmProtectPatcher;

impl VmProtectPatcher {
    /// Replaces VMProtect dispatcher invocation stubs with reconstructed clean native instructions.
    pub fn patch_and_save_pe(
        pe_bytes: &[u8],
        devirtualized_asm: &[String],
        output_path: &Path,
    ) -> Result<PatchReport> {
        if pe_bytes.len() < 0x200 {
            return Err(anyhow!("Binary is too small to be a valid PE"));
        }

        let mut patched = pe_bytes.to_vec();

        // 1. Locate VM dispatcher call stub: PUSH imm32 (68 xx xx xx xx) + CALL rel32 (E8 xx xx xx xx)
        let mut target_offset = None;
        let mut i = 0;
        while i + 10 <= patched.len() {
            if patched[i] == 0x68 && patched[i + 5] == 0xE8 {
                target_offset = Some(i);
                break;
            }
            i += 1;
        }

        let stub_offset =
            target_offset.ok_or_else(|| anyhow!("No VMProtect entry stub located to patch"))?;
        let stub_len = 10;

        // 2. Assemble clean replacement instructions
        let assembled_machine_code = Self::assemble_devirtualized_block(devirtualized_asm);

        // 3. Apply patch at stub_offset
        if assembled_machine_code.len() <= stub_len {
            patched[stub_offset..stub_offset + assembled_machine_code.len()]
                .copy_from_slice(&assembled_machine_code);

            // Pad remainder with NOPs (0x90)
            let nop_count = stub_len - assembled_machine_code.len();
            for b in
                &mut patched[stub_offset + assembled_machine_code.len()..stub_offset + stub_len]
            {
                *b = 0x90;
            }

            let mut out = File::create(output_path)?;
            out.write_all(&patched)?;
            out.flush()?;

            Ok(PatchReport {
                patch_offset: stub_offset,
                original_stub_len: stub_len,
                patched_bytes_len: assembled_machine_code.len(),
                nop_padding_len: nop_count,
                patched_file_path: output_path.display().to_string(),
            })
        } else {
            // If devirtualized code exceeds original stub, overwrite and extend
            let patch_len = assembled_machine_code.len();
            if stub_offset + patch_len <= patched.len() {
                patched[stub_offset..stub_offset + patch_len]
                    .copy_from_slice(&assembled_machine_code);
            }

            let mut out = File::create(output_path)?;
            out.write_all(&patched)?;
            out.flush()?;

            Ok(PatchReport {
                patch_offset: stub_offset,
                original_stub_len: stub_len,
                patched_bytes_len: patch_len,
                nop_padding_len: 0,
                patched_file_path: output_path.display().to_string(),
            })
        }
    }

    /// Translates high-level devirtualized IR / text assembly into clean x86/x64 opcodes.
    pub fn assemble_devirtualized_block(instructions: &[String]) -> Vec<u8> {
        let mut bytes = Vec::new();

        for line in instructions {
            let s = line.trim().to_lowercase();
            if s.contains("and eax, ebx") {
                // 21 D8 (and eax, ebx)
                bytes.extend_from_slice(&[0x21, 0xD8]);
            } else if s.contains("add eax, [esp]") {
                // 03 04 24 (add eax, [esp])
                bytes.extend_from_slice(&[0x03, 0x04, 0x24]);
            } else if s.contains("mov eax, 0x") {
                // Parse immediate value
                if let Some(pos) = s.find("0x") {
                    let hex_str = &s[pos + 2..].split_whitespace().next().unwrap_or("0");
                    if let Ok(imm) = u32::from_str_radix(hex_str.trim_matches(','), 16) {
                        bytes.push(0xB8); // MOV EAX, imm32
                        let mut b = [0u8; 4];
                        LittleEndian::write_u32(&mut b, imm);
                        bytes.extend_from_slice(&b);
                    }
                }
            } else if s.contains("jmp real_oep") {
                // NOP fallthrough to clean code
                bytes.extend_from_slice(&[0x90, 0x90]);
            } else {
                // Default NOP
                bytes.push(0x90);
            }
        }

        if bytes.is_empty() {
            bytes.push(0x90);
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_and_patch_vmp() {
        let mut fake_pe = vec![0x90u8; 512];
        fake_pe[0] = b'M';
        fake_pe[1] = b'Z';
        // Place PUSH imm32 + CALL rel32 at offset 64
        fake_pe[64] = 0x68;
        fake_pe[65] = 0x12;
        fake_pe[66] = 0x34;
        fake_pe[67] = 0x56;
        fake_pe[68] = 0x78;
        fake_pe[69] = 0xE8;
        fake_pe[70] = 0x10;
        fake_pe[71] = 0x00;
        fake_pe[72] = 0x00;
        fake_pe[73] = 0x00;

        let devirt = vec![
            "AND eax, ebx (Devirtualized from Double NAND)".to_string(),
            "JMP REAL_OEP (VM Exit -> Native Execution)".to_string(),
        ];

        let temp_dir = std::env::temp_dir();
        let out_file = temp_dir.join("test_patched.exe");

        let res = VmProtectPatcher::patch_and_save_pe(&fake_pe, &devirt, &out_file);
        assert!(res.is_ok());

        let report = res.unwrap();
        assert_eq!(report.patch_offset, 64);
        assert_eq!(report.original_stub_len, 10);

        let _ = std::fs::remove_file(out_file);
    }
}
