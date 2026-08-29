pub mod sanitizer;

pub use sanitizer::PrivacySanitizer;

#[cfg(test)]
mod tests {
    use super::*;
    use veyronis_ir::categories::{EventData, ProcessStartData};
    use veyronis_ir::event::{EventType, VirEvent};
    use veyronis_ir::identity::ProcessIdentity;
    use veyronis_ir::privacy::PrivacyClassification;

    #[test]
    fn test_sanitizer_drops_secret_events() {
        let sanitizer = PrivacySanitizer::new(PrivacyClassification::Public);
        let proc = ProcessIdentity::new(10, None, 1, "test", 1);
        let secret_event = VirEvent::new(
            proc,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "test".into(),
                command_line: vec![],
                working_directory: None,
                parent_pid: None,
                environment_keys: vec!["SECRET_KEY".into()],
            }),
            "test",
        )
        .with_privacy(PrivacyClassification::Secret);

        assert!(sanitizer.sanitize_event(&secret_event).is_none());
    }
}
