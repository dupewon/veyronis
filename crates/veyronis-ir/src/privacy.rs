use serde::{Deserialize, Serialize};
use std::fmt;

/// Privacy classification levels for VIR events and associated evidence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyClassification {
    /// Safe for public distribution and reporting without redaction.
    #[default]
    Public,
    /// Internal operational context, reasonable for internal review.
    Internal,
    /// Sensitive operational data (e.g. usernames, internal IP ranges) requiring redaction.
    Sensitive,
    /// Highly confidential data (e.g. keys, plaintext secrets) - strictly forbidden.
    Secret,
}

impl fmt::Display for PrivacyClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "PUBLIC"),
            Self::Internal => write!(f, "INTERNAL"),
            Self::Sensitive => write!(f, "SENSITIVE"),
            Self::Secret => write!(f, "SECRET"),
        }
    }
}
