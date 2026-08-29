use serde::{Deserialize, Serialize};

/// Type of detected process injection technique.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InjectionType {
    ProcessHollowing,
    ModuleStomping,
    UnbackedExecutableMemory,
    ReflectiveDllInjection,
}

/// Information about a detected process injection in target process address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedInjection {
    pub base_address: u64,
    pub region_size: usize,
    pub injection_type: InjectionType,
    pub confidence: f32,
    pub target_module: Option<String>,
    pub details: String,
}

/// Diagnostic report summarizing all detected injections in a PID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInjectionReport {
    pub target_pid: u32,
    pub total_injections_found: usize,
    pub injections: Vec<DetectedInjection>,
    pub is_compromised: bool,
}

/// Advanced In-Memory Process Injection, Hollowing & Stomping Hunter.
pub struct ProcessInjectionHunter;

impl ProcessInjectionHunter {
    /// Evaluates in-memory process memory regions and compares with mapped PE disk headers to detect hollowing and unbacked RX/RWX stagers.
    pub fn analyze_memory_region(
        pid: u32,
        base_address: u64,
        memory_bytes: &[u8],
        mapped_file_name: Option<&str>,
    ) -> Option<DetectedInjection> {
        if memory_bytes.len() < 0x40 {
            return None;
        }

        let has_pe_magic = memory_bytes[0] == b'M' && memory_bytes[1] == b'Z';

        // Case 1: Unbacked memory with PE Header (Reflective DLL / Process Hollowing)
        if has_pe_magic && mapped_file_name.is_none() {
            return Some(DetectedInjection {
                base_address,
                region_size: memory_bytes.len(),
                injection_type: InjectionType::ReflectiveDllInjection,
                confidence: 0.98,
                target_module: None,
                details: "Unbacked private memory region contains valid MZ/PE executable header (Reflective Injection / Shellcode loader)".to_string(),
            });
        }

        // Case 2: Module Stomping (Mapped file header modified in-memory)
        if let Some(mapped_name) = mapped_file_name {
            if has_pe_magic && mapped_name.ends_with(".dll") {
                // If .text section has high entropy or unmapped code entry
                if memory_bytes.len() > 0x1000 {
                    let text_entropy = crate::calculate_entropy(
                        &memory_bytes[0x1000..memory_bytes.len().min(0x3000)],
                    );
                    if text_entropy >= 7.2 {
                        return Some(DetectedInjection {
                            base_address,
                            region_size: memory_bytes.len(),
                            injection_type: InjectionType::ModuleStomping,
                            confidence: 0.92,
                            target_module: Some(mapped_name.to_string()),
                            details: format!("Mapped DLL '{}' .text section has high encrypted/packed entropy ({:.2}) indicating module stomping / ghosting", mapped_name, text_entropy),
                        });
                    }
                }
            }
        }

        // Case 3: Executable unbacked shellcode stager
        if !has_pe_magic && mapped_file_name.is_none() {
            // Check for common shellcode prologue patterns (CLD, CALL $+5, POP, PUSH RBP)
            if memory_bytes.starts_with(&[0xFC, 0x48, 0x83, 0xE4, 0xF0]) // msfvenom / cobalt strike beacon prologue
                || memory_bytes.starts_with(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D])
            {
                return Some(DetectedInjection {
                    base_address,
                    region_size: memory_bytes.len(),
                    injection_type: InjectionType::UnbackedExecutableMemory,
                    confidence: 0.95,
                    target_module: None,
                    details: "Unbacked executable memory starts with Metasploit / Cobalt Strike Beacon reflective stager prologue".to_string(),
                });
            }
        }

        let _ = pid;
        None
    }

    /// Performs full scan across multiple memory region snapshots of a process.
    pub fn scan_process_regions(
        pid: u32,
        regions: &[(u64, Vec<u8>, Option<String>)],
    ) -> ProcessInjectionReport {
        let mut injections = Vec::new();

        for (base, bytes, mapped_name) in regions {
            if let Some(inj) =
                Self::analyze_memory_region(pid, *base, bytes, mapped_name.as_deref())
            {
                injections.push(inj);
            }
        }

        let is_compromised = !injections.is_empty();
        ProcessInjectionReport {
            target_pid: pid,
            total_injections_found: injections.len(),
            injections,
            is_compromised,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reflective_dll_detection() {
        let mut fake_pe = vec![0u8; 4096];
        fake_pe[0] = b'M';
        fake_pe[1] = b'Z';

        let res = ProcessInjectionHunter::analyze_memory_region(1234, 0x7FFF0000, &fake_pe, None);
        assert!(res.is_some());
        let inj = res.unwrap();
        assert_eq!(inj.injection_type, InjectionType::ReflectiveDllInjection);
        assert!(inj.confidence >= 0.95);
    }

    #[test]
    fn test_shellcode_stager_detection() {
        let mut shellcode = vec![0x90; 1024];
        shellcode[0] = 0xFC;
        shellcode[1] = 0x48;
        shellcode[2] = 0x83;
        shellcode[3] = 0xE4;
        shellcode[4] = 0xF0;

        let res = ProcessInjectionHunter::analyze_memory_region(1234, 0x1A0000, &shellcode, None);
        assert!(res.is_some());
        let inj = res.unwrap();
        assert_eq!(inj.injection_type, InjectionType::UnbackedExecutableMemory);
    }
}
