use serde::{Deserialize, Serialize};
use std::fmt;

/// Honest operational capability rating of a platform telemetry provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityLevel {
    /// Full native kernel or OS event instrumentation available.
    Full,
    /// Partial telemetry available (e.g. polling or metadata sampling).
    Partial,
    /// Telemetry category completely unsupported or disabled.
    Unavailable,
    /// Requires elevated privileges (e.g. root, Administrator, CAP_BPF).
    RequiresPrivilege,
    /// Requires OS entitlement (e.g. Apple EndpointSecurity entitlement).
    RequiresEntitlement,
    /// Operating in degraded user-space fallback mode.
    Degraded,
}

impl fmt::Display for CapabilityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "FULL"),
            Self::Partial => write!(f, "PARTIAL"),
            Self::Unavailable => write!(f, "UNAVAILABLE"),
            Self::RequiresPrivilege => write!(f, "REQUIRES_PRIVILEGE"),
            Self::RequiresEntitlement => write!(f, "REQUIRES_ENTITLEMENT"),
            Self::Degraded => write!(f, "DEGRADED"),
        }
    }
}

/// Capability report covering all primary observation vectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorCapabilities {
    pub process: CapabilityLevel,
    pub filesystem: CapabilityLevel,
    pub network: CapabilityLevel,
    pub dns: CapabilityLevel,
    pub memory: CapabilityLevel,
    pub crypto: CapabilityLevel,
    pub kernel_telemetry: CapabilityLevel,
}

impl Default for CollectorCapabilities {
    fn default() -> Self {
        Self {
            process: CapabilityLevel::Partial,
            filesystem: CapabilityLevel::Partial,
            network: CapabilityLevel::Partial,
            dns: CapabilityLevel::Partial,
            memory: CapabilityLevel::Degraded,
            crypto: CapabilityLevel::Partial,
            kernel_telemetry: CapabilityLevel::Unavailable,
        }
    }
}
