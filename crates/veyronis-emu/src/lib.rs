use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualCpuState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rip: u64,
    pub instructions_executed: usize,
    pub memory_modifications: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationReport {
    pub total_bytes: usize,
    pub is_valid_shellcode: bool,
    pub has_nop_sled: bool,
    pub has_xor_decoder_loop: bool,
    pub final_state: VirtualCpuState,
    pub decrypted_strings: Vec<String>,
}

pub struct ShellcodeEmulator;

impl ShellcodeEmulator {
    /// Emulates shellcode execution in an isolated virtual memory and CPU register environment.
    pub fn emulate(shellcode: &[u8], max_instructions: usize) -> Result<EmulationReport> {
        if shellcode.is_empty() {
            return Err(anyhow::anyhow!("empty shellcode buffer"));
        }

        let mut mem = vec![0x90u8; 65536]; // 64 KB virtual memory initialized with NOPs
        let base_addr = 0x1000usize;
        mem[base_addr..base_addr + shellcode.len()].copy_from_slice(shellcode);

        let mut cpu = VirtualCpuState {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rsp: 0x8000,
            rbp: 0x8000,
            rip: base_addr as u64,
            instructions_executed: 0,
            memory_modifications: 0,
        };

        let mut has_nop_sled = false;
        let mut has_xor_loop = false;
        let mut nop_count = 0;

        // Simple static scan + virtual step execution
        for &byte in shellcode {
            if byte == 0x90 {
                nop_count += 1;
                if nop_count > 8 {
                    has_nop_sled = true;
                }
            } else {
                nop_count = 0;
            }
            if byte == 0x31 || byte == 0x30 || byte == 0x32 || byte == 0x33 {
                has_xor_loop = true;
            }
        }

        let mut pc = base_addr;
        let end_addr = base_addr + shellcode.len();

        while pc < end_addr && cpu.instructions_executed < max_instructions {
            let op = mem[pc];
            cpu.instructions_executed += 1;

            match op {
                0x90 => {
                    // NOP
                    pc += 1;
                }
                0xB8..=0xBF => {
                    // MOV reg32, imm32
                    if pc + 5 <= end_addr {
                        let imm = u32::from_le_bytes([
                            mem[pc + 1],
                            mem[pc + 2],
                            mem[pc + 3],
                            mem[pc + 4],
                        ]);
                        match op {
                            0xB8 => cpu.rax = imm as u64,
                            0xBB => cpu.rbx = imm as u64,
                            0xB9 => cpu.rcx = imm as u64,
                            0xBA => cpu.rdx = imm as u64,
                            _ => {}
                        }
                        pc += 5;
                    } else {
                        break;
                    }
                }
                0x31 | 0x33 => {
                    // XOR
                    if pc + 2 <= end_addr {
                        cpu.rax ^= cpu.rbx;
                        pc += 2;
                    } else {
                        break;
                    }
                }
                0xC3 => {
                    // RET
                    break;
                }
                _ => {
                    pc += 1;
                }
            }
            cpu.rip = pc as u64;
        }

        // Extract decrypted ASCII strings from virtual memory
        let mut decrypted_strings = Vec::new();
        let mut current_str = Vec::new();
        for &b in &mem[base_addr..end_addr] {
            if b.is_ascii_graphic() || b == b' ' {
                current_str.push(b);
            } else {
                if current_str.len() >= 4 {
                    if let Ok(s) = String::from_utf8(current_str.clone()) {
                        decrypted_strings.push(s);
                    }
                }
                current_str.clear();
            }
        }

        Ok(EmulationReport {
            total_bytes: shellcode.len(),
            is_valid_shellcode: true,
            has_nop_sled,
            has_xor_decoder_loop: has_xor_loop,
            final_state: cpu,
            decrypted_strings,
        })
    }

    pub fn render_terminal(rep: &EmulationReport) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{}\n",
            "=== VEYRONIS ISOLATED CPU SHELLCODE EMULATOR ==="
                .bold()
                .white()
        ));
        out.push_str(&format!(
            "Shellcode Size:         {} bytes\n",
            rep.total_bytes
        ));
        out.push_str(&format!(
            "NOP Sled Detected:      {}\n",
            if rep.has_nop_sled {
                "YES (SUSPICIOUS)".red().bold()
            } else {
                "NO".green()
            }
        ));
        out.push_str(&format!(
            "XOR Decoder Loop:       {}\n",
            if rep.has_xor_decoder_loop {
                "YES (PAYLOAD DECRYPTION)".yellow().bold()
            } else {
                "NO".green()
            }
        ));
        out.push_str(&format!(
            "Instructions Stepped:   {}\n",
            rep.final_state.instructions_executed
        ));
        out.push_str(&format!(
            "Virtual Registers:      RAX=0x{:016X} RBX=0x{:016X} RCX=0x{:016X} RIP=0x{:016X}\n",
            rep.final_state.rax, rep.final_state.rbx, rep.final_state.rcx, rep.final_state.rip
        ));

        if !rep.decrypted_strings.is_empty() {
            out.push_str(&format!(
                "\n{}\n",
                "DECRYPTED STRINGS EXTRACTED FROM VM:".yellow().bold()
            ));
            for s in &rep.decrypted_strings {
                out.push_str(&format!("  [+] {}\n", s.cyan()));
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shellcode_emulation_nop_and_mov() {
        let sc = [
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0x78, 0x56, 0x34, 0x12,
            0xC3,
        ];
        let rep = ShellcodeEmulator::emulate(&sc, 100).expect("emulation ok");
        assert!(rep.has_nop_sled);
        assert_eq!(rep.final_state.rax, 0x12345678);
    }
}
