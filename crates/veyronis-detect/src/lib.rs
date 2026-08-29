pub mod builtin;
pub mod dga;
pub mod engine;
pub mod ja3;
pub mod report;
pub mod rule;
pub mod syscall_hunter;

pub use dga::DgaDetector;
pub use engine::DetectionEngine;
pub use ja3::{check_known_malicious_ja3, Ja3Fingerprint};
pub use report::{DetectionAlert, DetectionReport};
pub use rule::{DetectionCriterion, MitreAttack, SecurityRule, Severity};
pub use syscall_hunter::{DirectSyscallAlert, SyscallHunter};

#[cfg(test)]
mod tests {
    use super::*;
    use veyronis_ir::categories::{CryptoCategory, CryptoOperationData, EventData, FileWriteData};
    use veyronis_ir::event::{EventType, VirEvent};
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_ransomware_detection_rule() {
        let engine = DetectionEngine::new();
        let p = ProcessIdentity::new(100, None, 1000, "evil.exe", 1);

        let mut events = Vec::new();
        for i in 0..5 {
            events.push(VirEvent::new(
                p.clone(),
                EventType::FileWrite,
                EventData::FileWrite(FileWriteData {
                    path: format!("c:\\files\\doc_{}.vyr_locked", i),
                    bytes_written: 1024,
                    offset: 0,
                    content_hash: None,
                }),
                "etw",
            ));
        }

        events.push(VirEvent::new(
            p.clone(),
            EventType::CryptoOperation,
            EventData::CryptoOperation(CryptoOperationData {
                category: CryptoCategory::Encrypt,
                algorithm: "AES-256-CBC".into(),
                provider: "BCrypt".into(),
                key_size_bits: Some(256),
                mode: Some("CBC".into()),
            }),
            "etw",
        ));

        let report = engine.scan(&events, None);
        assert!(report.risk_score >= 80);
        assert!(!report.alerts.is_empty());
    }
}
