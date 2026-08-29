pub mod categories;
pub mod event;
pub mod identity;
pub mod privacy;

pub use categories::*;
pub use event::{Confidence, EventType, Platform, VirEvent};
pub use identity::{ProcessIdentity, ThreadIdentity};
pub use privacy::PrivacyClassification;

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_process_identity_canonical_name() {
        let id = ProcessIdentity::new(
            1234,
            Some(100),
            1000000,
            "C:\\Windows\\System32\\cmd.exe",
            1,
        );
        assert_eq!(id.canonical_name(), "cmd.exe");

        let linux_id = ProcessIdentity::new(4321, Some(1), 2000000, "/usr/bin/curl", 1);
        assert_eq!(linux_id.canonical_name(), "curl");
    }

    #[test]
    fn test_vir_event_serialization_roundtrip() {
        let proc_id = ProcessIdentity::new(100, None, 50000, "/usr/bin/curl", 1)
            .with_command_line(vec!["curl".into(), "https://example.com".into()]);

        let event = VirEvent::new(
            proc_id,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "/usr/bin/curl".into(),
                command_line: vec!["curl".into(), "https://example.com".into()],
                working_directory: Some("/home/user".into()),
                parent_pid: Some(1),
                environment_keys: vec!["PATH".into(), "USER".into()],
            }),
            "collector-linux",
        );

        let serialized = serde_json::to_string(&event).expect("must serialize");
        let deserialized: VirEvent = serde_json::from_str(&serialized).expect("must deserialize");

        assert_eq!(event.event_id, deserialized.event_id);
        assert_eq!(event.event_type, deserialized.event_type);
        assert_eq!(event.process_identity, deserialized.process_identity);
    }

    #[test]
    fn test_event_canonical_hash_determinism() {
        let id = Uuid::nil();
        let proc_id = ProcessIdentity::new(10, None, 0, "test", 1);
        let mut event = VirEvent::new(
            proc_id,
            EventType::FileOpen,
            EventData::FileOpen(FileOpenData {
                path: "/etc/passwd".into(),
                normalized_path: "/etc/passwd".into(),
                read: true,
                write: false,
                create: false,
                truncate: false,
                append: false,
            }),
            "test-collector",
        );
        event.event_id = id;

        let hash1 = event.canonical_hash();
        let hash2 = event.canonical_hash();
        assert_eq!(hash1, hash2);
    }
}
