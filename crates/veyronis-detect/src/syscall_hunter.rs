use serde::{Deserialize, Serialize};
use veyronis_ir::categories::EventData;
use veyronis_ir::event::VirEvent;

/// Detector for Direct Syscall & EDR User-Mode Hook Evasion (Hell's Gate, Halo's Gate, SysWhispers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectSyscallAlert {
    pub process_name: String,
    pub pid: u32,
    pub suspected_technique: String,
    pub mitre_id: String,
    pub description: String,
}

pub struct SyscallHunter;

impl SyscallHunter {
    /// Inspects event stream for unbacked direct syscall indicators and memory transitions.
    pub fn scan(events: &[VirEvent]) -> Vec<DirectSyscallAlert> {
        let mut alerts = Vec::new();

        for ev in events {
            match &ev.data {
                EventData::MemoryProtect(m)
                    if m.new_permissions.contains("PAGE_EXECUTE_READWRITE")
                        || m.new_permissions.contains("RWX") =>
                {
                    alerts.push(DirectSyscallAlert {
                        process_name: ev.process_identity.canonical_name().to_string(),
                        pid: ev.process_identity.pid,
                        suspected_technique: "Direct Syscall / Unbacked Memory Stager".into(),
                        mitre_id: "T1106 / T1055".into(),
                        description: format!(
                            "Process '{}' modified memory permissions to executable RWX: addr=0x{:X} size={}",
                            ev.process_identity.canonical_name(),
                            m.address,
                            m.size_bytes
                        ),
                    });
                }
                EventData::MemoryMap(m)
                    if m.permissions.contains("PAGE_EXECUTE_READWRITE")
                        || m.permissions.contains("RWX") =>
                {
                    alerts.push(DirectSyscallAlert {
                        process_name: ev.process_identity.canonical_name().to_string(),
                        pid: ev.process_identity.pid,
                        suspected_technique: "Direct Syscall / Executable RWX Mapping".into(),
                        mitre_id: "T1106 / T1055".into(),
                        description: format!(
                            "Process '{}' mapped memory with RWX permissions: addr=0x{:X} size={}",
                            ev.process_identity.canonical_name(),
                            m.address,
                            m.size_bytes
                        ),
                    });
                }
                _ => {}
            }
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veyronis_ir::categories::MemoryProtectData;
    use veyronis_ir::event::EventType;
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_syscall_hunter_detects_rwx_stager() {
        let p = ProcessIdentity::new(100, None, 1000, "malware.exe", 1);
        let ev = VirEvent::new(
            p,
            EventType::MemoryProtect,
            EventData::MemoryProtect(MemoryProtectData {
                address: 0x00400000,
                size_bytes: 4096,
                old_permissions: Some("PAGE_READWRITE".into()),
                new_permissions: "PAGE_EXECUTE_READWRITE".into(),
            }),
            "etw",
        );

        let alerts = SyscallHunter::scan(&[ev]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].mitre_id, "T1106 / T1055");
    }
}
