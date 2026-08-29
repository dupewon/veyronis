use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    pub fn score(&self) -> u32 {
        match self {
            Self::Info => 5,
            Self::Low => 15,
            Self::Medium => 40,
            Self::High => 75,
            Self::Critical => 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttack {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCriterion {
    pub event_type: Option<String>,
    pub process_name_contains: Option<String>,
    pub target_resource_contains: Option<String>,
    pub is_external_network: Option<bool>,
    pub crypto_algorithm: Option<String>,
    pub min_event_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub author: String,
    pub severity: Severity,
    pub mitre: Option<MitreAttack>,
    pub criteria: Vec<DetectionCriterion>,
    pub remediation: String,
}

impl SecurityRule {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}
