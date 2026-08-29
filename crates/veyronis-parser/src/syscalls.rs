use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of detected low-level syscall or execution transition mechanism.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyscallInvocationType {
    DirectSyscall,
    IndirectSyscallGadget,
    HeavensGate32To64,
    Int2EGate,
}

/// Information about a detected raw NT Syscall or Heaven's Gate stub in binary code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSyscallStub {
    pub offset: usize,
    pub invocation_type: SyscallInvocationType,
    pub ssn: Option<u32>,
    pub resolved_nt_api_name: String,
    pub raw_bytes: Vec<u8>,
    pub description: String,
}

/// Advanced Static and Dynamic NT Syscall Resolver & Heaven's Gate Hunter.
pub struct SyscallHunter;

impl SyscallHunter {
    /// Scans raw binary code or memory pages for direct/indirect syscall stubs and Heaven's Gate transitions.
    pub fn hunt_syscalls(code: &[u8]) -> Vec<DetectedSyscallStub> {
        let mut stubs = Vec::new();
        let ssn_map = Self::build_known_ssn_database();

        let mut i = 0;
        while i + 7 <= code.len() {
            // Pattern 1: Direct x64 Syscall Stub
            // 4C 8B D1          (mov r10, rcx)
            // B8 [SSN 4-bytes]  (mov eax, ssn)
            // 0F 05             (syscall)
            // C3                (ret)
            if i + 8 <= code.len()
                && code[i] == 0x4C
                && code[i + 1] == 0x8B
                && code[i + 2] == 0xD1
                && code[i + 3] == 0xB8
            {
                let ssn = u32::from_le_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]);
                let mut stub_len = 8;

                let is_indirect =
                    if i + 10 <= code.len() && code[i + 8] == 0x0F && code[i + 9] == 0x05 {
                        stub_len = 10;
                        false
                    } else if i + 12 <= code.len()
                        && code[i + 8] == 0xFF
                        && (code[i + 9] == 0x25 || code[i + 9] == 0xE0)
                    {
                        // Indirect jump to syscall gadget (SysWhispers2 / TartarusGate)
                        stub_len = 12;
                        true
                    } else {
                        false
                    };

                let api_name = ssn_map
                    .get(&ssn)
                    .cloned()
                    .unwrap_or_else(|| format!("NtUnknownSyscall_0x{:04X}", ssn));

                stubs.push(DetectedSyscallStub {
                    offset: i,
                    invocation_type: if is_indirect {
                        SyscallInvocationType::IndirectSyscallGadget
                    } else {
                        SyscallInvocationType::DirectSyscall
                    },
                    ssn: Some(ssn),
                    resolved_nt_api_name: api_name,
                    raw_bytes: code[i..i + stub_len.min(code.len() - i)].to_vec(),
                    description: if is_indirect {
                        "Indirect Syscall (SysWhispers/TartarusGate Gadget Jump)".to_string()
                    } else {
                        "Direct Native x64 Syscall Stub (EDR Hook Bypass)".to_string()
                    },
                });

                i += stub_len;
                continue;
            }

            // Pattern 2: Heaven's Gate 32-to-64 bit segment transition
            // 6A 33             (push 0x33)
            // E8 00 00 00 00    (call $+5)
            // 83 04 24 05       (add dword ptr [esp], 5)
            // CB                (retf)
            if i + 11 <= code.len()
                && code[i] == 0x6A
                && code[i + 1] == 0x33
                && code[i + 2] == 0xE8
                && code[i + 3] == 0x00
                && code[i + 4] == 0x00
                && code[i + 5] == 0x00
                && code[i + 6] == 0x00
                && code[i + 7] == 0x83
                && code[i + 8] == 0x04
                && code[i + 9] == 0x24
            {
                stubs.push(DetectedSyscallStub {
                    offset: i,
                    invocation_type: SyscallInvocationType::HeavensGate32To64,
                    ssn: None,
                    resolved_nt_api_name: "Heaven's Gate (CS 0x33 x64 Transition)".to_string(),
                    raw_bytes: code[i..i + 11].to_vec(),
                    description: "32-bit to 64-bit Heaven's Gate WOW64 Far Return Transition"
                        .to_string(),
                });
                i += 11;
                continue;
            }

            // Pattern 3: Legacy WOW64 / Int 2E Gate
            // B8 [SSN] | CD 2E
            if i + 6 <= code.len() && code[i] == 0xB8 && code[i + 5] == 0xCD && code[i + 6] == 0x2E
            {
                let ssn = u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
                stubs.push(DetectedSyscallStub {
                    offset: i,
                    invocation_type: SyscallInvocationType::Int2EGate,
                    ssn: Some(ssn),
                    resolved_nt_api_name: ssn_map
                        .get(&ssn)
                        .cloned()
                        .unwrap_or_else(|| format!("NtLegacySyscall_0x{:04X}", ssn)),
                    raw_bytes: code[i..i + 7].to_vec(),
                    description: "Legacy Interrupt 0x2E System Service Gate".to_string(),
                });
                i += 7;
                continue;
            }

            i += 1;
        }

        stubs
    }

    /// Builds a map of Windows 10/11 x64 System Service Numbers (SSNs) to native API names.
    fn build_known_ssn_database() -> HashMap<u32, String> {
        let mut map = HashMap::new();
        map.insert(0x0018, "NtAllocateVirtualMemory".to_string());
        map.insert(0x0050, "NtProtectVirtualMemory".to_string());
        map.insert(0x003A, "NtWriteVirtualMemory".to_string());
        map.insert(0x003F, "NtReadVirtualMemory".to_string());
        map.insert(0x0023, "NtCreateThreadEx".to_string());
        map.insert(0x002B, "NtOpenProcess".to_string());
        map.insert(0x00C7, "NtQueueApcThread".to_string());
        map.insert(0x0055, "NtMapViewOfSection".to_string());
        map.insert(0x002A, "NtUnmapViewOfSection".to_string());
        map.insert(0x00C1, "NtResumeThread".to_string());
        map.insert(0x00B0, "NtSuspendThread".to_string());
        map.insert(0x002C, "NtOpenThread".to_string());
        map.insert(0x0019, "NtFreeVirtualMemory".to_string());
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hunt_direct_syscall() {
        // MOV R10, RCX (4C 8B D1) | MOV EAX, 0x18 (B8 18 00 00 00) | SYSCALL (0F 05) | RET (C3)
        let code = vec![
            0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        ];
        let stubs = SyscallHunter::hunt_syscalls(&code);
        assert_eq!(stubs.len(), 1);
        assert_eq!(
            stubs[0].invocation_type,
            SyscallInvocationType::DirectSyscall
        );
        assert_eq!(stubs[0].ssn, Some(0x18));
        assert_eq!(stubs[0].resolved_nt_api_name, "NtAllocateVirtualMemory");
    }

    #[test]
    fn test_hunt_heavens_gate() {
        let code = vec![
            0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,
        ];
        let stubs = SyscallHunter::hunt_syscalls(&code);
        assert_eq!(stubs.len(), 1);
        assert_eq!(
            stubs[0].invocation_type,
            SyscallInvocationType::HeavensGate32To64
        );
    }
}
