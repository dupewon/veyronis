use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Details of a detected inline hook or trampoline in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedInlineHook {
    pub rva: usize,
    pub hook_type: String,
    pub original_bytes: Vec<u8>,
    pub hooked_bytes: Vec<u8>,
    pub target_address: Option<u64>,
}

/// Report produced by comparing in-memory DLL `.text` section with clean on-disk file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnhookReport {
    pub module_name: String,
    pub total_hooks_detected: usize,
    pub hooks: Vec<DetectedInlineHook>,
    pub is_clean: bool,
}

/// Automated Memory Unhooking and EDR / Malware Trampoline Restorer.
pub struct UnhookEngine;

impl UnhookEngine {
    /// Compares in-memory loaded bytes with original on-disk clean bytes to detect and restore hooks.
    pub fn diff_and_restore(
        module_name: &str,
        memory_bytes: &[u8],
        disk_bytes: &[u8],
    ) -> Result<(UnhookReport, Vec<u8>)> {
        if memory_bytes.is_empty() || disk_bytes.is_empty() {
            return Err(anyhow!("Memory or disk byte buffer is empty"));
        }

        let mut restored_bytes = memory_bytes.to_vec();
        let mut detected_hooks = Vec::new();
        let check_len = memory_bytes.len().min(disk_bytes.len());

        let mut i = 0;
        while i < check_len {
            if memory_bytes[i] != disk_bytes[i] {
                // Determine hook pattern
                let hook_type = if memory_bytes[i] == 0xE9 {
                    "Direct JMP rel32 Trampoline".to_string()
                } else if i + 5 < check_len
                    && memory_bytes[i] == 0xFF
                    && memory_bytes[i + 1] == 0x25
                {
                    "Indirect JMP [RIP+rel32] EDR Hook".to_string()
                } else if i + 11 < check_len
                    && memory_bytes[i] == 0x48
                    && memory_bytes[i + 1] == 0xB8
                    && memory_bytes[i + 10] == 0xFF
                    && memory_bytes[i + 11] == 0xE0
                {
                    "64-bit Absolute MOV RAX + JMP RAX Trampoline".to_string()
                } else {
                    "Inline Byte Modification / Patch".to_string()
                };

                let patch_len = 5.min(check_len - i);
                let orig_slice = disk_bytes[i..i + patch_len].to_vec();
                let hooked_slice = memory_bytes[i..i + patch_len].to_vec();

                // Restore clean bytes from disk
                restored_bytes[i..i + patch_len].copy_from_slice(&orig_slice);

                detected_hooks.push(DetectedInlineHook {
                    rva: i,
                    hook_type,
                    original_bytes: orig_slice,
                    hooked_bytes: hooked_slice,
                    target_address: None,
                });

                i += patch_len;
            } else {
                i += 1;
            }
        }

        let is_clean = detected_hooks.is_empty();
        let report = UnhookReport {
            module_name: module_name.to_string(),
            total_hooks_detected: detected_hooks.len(),
            hooks: detected_hooks,
            is_clean,
        };

        Ok((report, restored_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unhook_engine_restoration() {
        let clean_disk = vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10];
        let mut hooked_mem = clean_disk.clone();
        // Place EDR JMP Hook at offset 0
        hooked_mem[0] = 0xE9;
        hooked_mem[1] = 0x50;
        hooked_mem[2] = 0x10;
        hooked_mem[3] = 0x00;
        hooked_mem[4] = 0x00;

        let (report, restored) =
            UnhookEngine::diff_and_restore("ntdll.dll", &hooked_mem, &clean_disk).unwrap();
        assert_eq!(report.total_hooks_detected, 1);
        assert_eq!(report.hooks[0].hook_type, "Direct JMP rel32 Trampoline");
        assert_eq!(restored, clean_disk);
    }
}
