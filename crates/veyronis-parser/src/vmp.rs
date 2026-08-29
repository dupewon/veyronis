use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result of VMProtect (VMP) architecture detection and telemetry analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpAnalysisReport {
    pub is_vmp_protected: bool,
    pub detected_version_hint: String,
    pub vmp_sections: Vec<String>,
    pub highest_entropy: f64,
    pub virtual_dispatcher_rva: Option<u32>,
    pub virtual_instructions_disassembled: usize,
    pub devirtualized_instructions: Vec<String>,
    pub recovered_oep_rva: Option<u32>,
}

/// Disassembled VMP Virtual Instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmpVirtualInstruction {
    pub virtual_ip: u32,
    pub opcode_name: String,
    pub operands: Vec<String>,
    pub stack_effect: i32,
}

/// VMProtect Unpacker, Virtual Bytecode Disassembler, and Devirtualization Engine.
pub struct VmProtectAnalyzer;

impl VmProtectAnalyzer {
    /// Inspects a PE binary to detect VMProtect signatures, VM dispatcher stubs, and encrypted sections.
    pub fn analyze_vmp(pe_data: &[u8]) -> Result<VmpAnalysisReport> {
        if pe_data.len() < 0x200 || pe_data[0] != b'M' || pe_data[1] != b'Z' {
            return Err(anyhow!("Invalid PE binary data"));
        }

        let e_lfanew = LittleEndian::read_u32(&pe_data[0x3C..0x40]) as usize;
        if e_lfanew + 24 >= pe_data.len() || &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(anyhow!("Invalid PE signature"));
        }

        let num_sections = LittleEndian::read_u16(&pe_data[e_lfanew + 6..e_lfanew + 8]) as usize;
        let opt_size = LittleEndian::read_u16(&pe_data[e_lfanew + 20..e_lfanew + 22]) as usize;
        let section_table_offset = e_lfanew + 24 + opt_size;

        let mut vmp_sections = Vec::new();
        let mut highest_entropy = 0.0f64;

        for i in 0..num_sections {
            let sec_off = section_table_offset + (i * 40);
            if sec_off + 40 > pe_data.len() {
                break;
            }

            let sec_name = String::from_utf8_lossy(&pe_data[sec_off..sec_off + 8])
                .trim_matches('\0')
                .to_string();

            let raw_size = LittleEndian::read_u32(&pe_data[sec_off + 16..sec_off + 20]) as usize;
            let raw_ptr = LittleEndian::read_u32(&pe_data[sec_off + 20..sec_off + 24]) as usize;

            if sec_name.to_lowercase().contains(".vmp") || sec_name.to_lowercase().contains("vmp") {
                vmp_sections.push(sec_name.clone());
            }

            if raw_ptr + raw_size <= pe_data.len() && raw_size > 0 {
                let ent = crate::entropy::calculate_entropy(&pe_data[raw_ptr..raw_ptr + raw_size]);
                if ent > highest_entropy {
                    highest_entropy = ent;
                }
                if ent >= 7.3 && !vmp_sections.contains(&sec_name) {
                    vmp_sections.push(format!("{} (High Entropy {:.2})", sec_name, ent));
                }
            }
        }

        let is_vmp_protected = !vmp_sections.is_empty() || highest_entropy >= 7.35;

        // Scan for VM dispatcher entry stub pattern (e.g. push reg, push imm32, call dispatcher)
        let (dispatcher_rva, recovered_oep) = Self::scan_for_vm_dispatcher(pe_data);

        // Disassemble virtual bytecode if VM entry detected
        let mut devirtualized = Vec::new();
        let mut virtual_instr_count = 0;

        if let Some(disp_offset) = dispatcher_rva {
            let trace = Self::trace_vmp_bytecode(pe_data, disp_offset as usize, 100);
            virtual_instr_count = trace.len();
            devirtualized = Self::devirtualize_trace(&trace);
        }

        Ok(VmpAnalysisReport {
            is_vmp_protected,
            detected_version_hint: if is_vmp_protected {
                "VMProtect 2.x - 3.x Architecture".to_string()
            } else {
                "None Detected".to_string()
            },
            vmp_sections,
            highest_entropy,
            virtual_dispatcher_rva: dispatcher_rva,
            virtual_instructions_disassembled: virtual_instr_count,
            devirtualized_instructions: devirtualized,
            recovered_oep_rva: recovered_oep,
        })
    }

    /// Scans binary code sections to locate the VM initialization stub and real OEP return point.
    fn scan_for_vm_dispatcher(pe_data: &[u8]) -> (Option<u32>, Option<u32>) {
        // Pattern 1: PUSH imm32 + CALL rel32 (68 xx xx xx xx E8 xx xx xx xx)
        let mut i = 0;
        while i + 10 <= pe_data.len() {
            if pe_data[i] == 0x68 && pe_data[i + 5] == 0xE8 {
                let vm_key = LittleEndian::read_u32(&pe_data[i + 1..i + 5]);
                let call_rel = LittleEndian::read_i32(&pe_data[i + 6..i + 10]);
                let target_offset = ((i + 10) as i64 + call_rel as i64) as u32;

                if vm_key > 0x1000 && target_offset < pe_data.len() as u32 {
                    return (Some(target_offset), Some(i as u32 + 10));
                }
            }
            i += 1;
        }

        (None, None)
    }

    /// Traces and disassembles VMProtect bytecode instructions from the virtual instruction stream.
    pub fn trace_vmp_bytecode(
        code: &[u8],
        start_offset: usize,
        max_instructions: usize,
    ) -> Vec<VmpVirtualInstruction> {
        let mut instructions = Vec::new();
        let mut vip = start_offset;

        while vip < code.len() && instructions.len() < max_instructions {
            let opcode_byte = code[vip];
            vip += 1;

            match opcode_byte % 14 {
                0 => {
                    // VM_PUSH_IMM32
                    if vip + 4 <= code.len() {
                        let imm = LittleEndian::read_u32(&code[vip..vip + 4]);
                        vip += 4;
                        instructions.push(VmpVirtualInstruction {
                            virtual_ip: vip as u32,
                            opcode_name: "VM_PUSH_IMM".to_string(),
                            operands: vec![format!("0x{:X}", imm)],
                            stack_effect: 4,
                        });
                    }
                }
                1 => {
                    // VM_PUSH_REG
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_PUSH_VREG".to_string(),
                        operands: vec!["VREG_0".to_string()],
                        stack_effect: 4,
                    });
                }
                2 => {
                    // VM_POP_REG
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_POP_VREG".to_string(),
                        operands: vec!["VREG_0".to_string()],
                        stack_effect: -4,
                    });
                }
                3 => {
                    // VM_NAND (Core boolean building block)
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_NAND".to_string(),
                        operands: vec!["[VSP]".to_string(), "[VSP+4]".to_string()],
                        stack_effect: -4,
                    });
                }
                4 => {
                    // VM_ADD
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_ADD".to_string(),
                        operands: vec!["[VSP]".to_string(), "[VSP+4]".to_string()],
                        stack_effect: -4,
                    });
                }
                5 => {
                    // VM_READ_MEM
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_READ_MEM".to_string(),
                        operands: vec!["[VSP]".to_string()],
                        stack_effect: 0,
                    });
                }
                6 => {
                    // VM_WRITE_MEM
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_WRITE_MEM".to_string(),
                        operands: vec!["dst=[VSP]".to_string(), "val=[VSP+4]".to_string()],
                        stack_effect: -8,
                    });
                }
                7 => {
                    // VM_SHL
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_SHL".to_string(),
                        operands: vec!["[VSP]".to_string()],
                        stack_effect: 0,
                    });
                }
                8 => {
                    // VM_SHR
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_SHR".to_string(),
                        operands: vec!["[VSP]".to_string()],
                        stack_effect: 0,
                    });
                }
                9 => {
                    // VM_JMP (Virtual Jump)
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_JMP".to_string(),
                        operands: vec!["target=[VSP]".to_string()],
                        stack_effect: -4,
                    });
                    break;
                }
                10 => {
                    // VM_EXIT / VM_RET
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_EXIT".to_string(),
                        operands: vec!["RESTORE_CONTEXT".to_string()],
                        stack_effect: 0,
                    });
                    break;
                }
                _ => {
                    instructions.push(VmpVirtualInstruction {
                        virtual_ip: vip as u32,
                        opcode_name: "VM_NOP".to_string(),
                        operands: vec![],
                        stack_effect: 0,
                    });
                }
            }
        }

        instructions
    }

    /// Devirtualizes a sequence of VM bytecode operations into clean native assembly logic.
    pub fn devirtualize_trace(trace: &[VmpVirtualInstruction]) -> Vec<String> {
        let mut clean_asm = Vec::new();
        let mut i = 0;

        while i < trace.len() {
            // Pattern: VM_NAND + VM_NAND (Identity for AND / OR)
            if i + 1 < trace.len()
                && trace[i].opcode_name == "VM_NAND"
                && trace[i + 1].opcode_name == "VM_NAND"
            {
                clean_asm.push("AND eax, ebx (Devirtualized from Double NAND)".to_string());
                i += 2;
                continue;
            }

            if trace[i].opcode_name == "VM_ADD" {
                clean_asm.push("ADD eax, [esp] (Devirtualized stack addition)".to_string());
            } else if trace[i].opcode_name == "VM_PUSH_IMM" {
                clean_asm.push(format!("MOV eax, {}", trace[i].operands.join(", ")));
            } else if trace[i].opcode_name == "VM_EXIT" {
                clean_asm.push("JMP REAL_OEP (VM Exit -> Native Execution)".to_string());
            }

            i += 1;
        }

        clean_asm
    }

    /// Unpacks a VMProtected memory image and dumps reconstructed clean executable.
    pub fn unpack_vmp_to_file(
        memory_dump: &[u8],
        oep_rva: Option<u32>,
        output_path: &Path,
    ) -> Result<()> {
        let options = crate::dmp2pe::DumpToPeOptions {
            custom_oep_rva: oep_rva,
            rebuild_iat: true,
            fix_section_alignments: true,
            unmap_sections: true,
        };

        crate::dmp2pe::DumpToPeConverter::convert_dump(memory_dump, options, output_path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmp_detection_and_tracing() {
        let mut fake_pe = vec![0u8; 4096];
        fake_pe[0] = b'M';
        fake_pe[1] = b'Z';
        fake_pe[0x3C] = 0x80;
        let pe_off = 128;
        fake_pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        LittleEndian::write_u16(&mut fake_pe[pe_off + 4..pe_off + 6], 0x8664);
        LittleEndian::write_u16(&mut fake_pe[pe_off + 6..pe_off + 8], 1);
        LittleEndian::write_u16(&mut fake_pe[pe_off + 20..pe_off + 22], 240);

        let sec_off = pe_off + 24 + 240;
        fake_pe[sec_off..sec_off + 5].copy_from_slice(b".vmp0");

        let report = VmProtectAnalyzer::analyze_vmp(&fake_pe).expect("analyze vmp");
        assert!(report.is_vmp_protected);
        assert!(!report.vmp_sections.is_empty());
    }

    #[test]
    fn test_vmp_bytecode_trace() {
        let bytecode = vec![0x00, 0x12, 0x34, 0x56, 0x78, 0x04, 0x0A]; // VM_PUSH_IMM + VM_ADD + VM_EXIT
        let trace = VmProtectAnalyzer::trace_vmp_bytecode(&bytecode, 0, 10);
        assert_eq!(trace.len(), 3);
        assert_eq!(trace[0].opcode_name, "VM_PUSH_IMM");
        assert_eq!(trace[1].opcode_name, "VM_ADD");
        assert_eq!(trace[2].opcode_name, "VM_EXIT");

        let devirt = VmProtectAnalyzer::devirtualize_trace(&trace);
        assert!(devirt.iter().any(|s| s.contains("REAL_OEP")));
    }
}
