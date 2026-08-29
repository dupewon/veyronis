use veyronis_ir::categories::EventData;
use veyronis_ir::event::VirEvent;
use veyronis_ir::privacy::PrivacyClassification;

/// Configurable privacy sanitizer for removing sensitive operational telemetry prior to export.
#[derive(Debug, Clone)]
pub struct PrivacySanitizer {
    pub max_allowed_privacy: PrivacyClassification,
    pub redact_usernames: bool,
    pub redact_raw_evidence: bool,
}

impl Default for PrivacySanitizer {
    fn default() -> Self {
        Self {
            max_allowed_privacy: PrivacyClassification::Internal,
            redact_usernames: false,
            redact_raw_evidence: false,
        }
    }
}

impl PrivacySanitizer {
    pub fn new(max_allowed_privacy: PrivacyClassification) -> Self {
        Self {
            max_allowed_privacy,
            redact_usernames: false,
            redact_raw_evidence: false,
        }
    }

    pub fn sanitize_event(&self, event: &VirEvent) -> Option<VirEvent> {
        if event.privacy > self.max_allowed_privacy {
            return None;
        }

        let mut sanitized = event.clone();

        if self.redact_raw_evidence {
            sanitized.raw_evidence.clear();
        }

        if self.redact_usernames {
            if let Some(user) = &mut sanitized.process_identity.user {
                *user = "[REDACTED_USER]".to_string();
            }
        }

        // Sanitize sensitive fields in payload
        match &mut sanitized.data {
            EventData::ProcessStart(p) => {
                p.environment_keys.retain(|k| {
                    let upper = k.to_uppercase();
                    !upper.contains("TOKEN") && !upper.contains("SECRET") && !upper.contains("KEY")
                });
            }
            EventData::FileWrite(f) if sanitized.privacy == PrivacyClassification::Sensitive => {
                f.content_hash = Some("[REDACTED_HASH]".to_string());
            }
            _ => {}
        }

        Some(sanitized)
    }

    pub fn sanitize_events(&self, events: &[VirEvent]) -> Vec<VirEvent> {
        events
            .iter()
            .filter_map(|e| self.sanitize_event(e))
            .collect()
    }
}
