use crate::categories::EventData;
use crate::identity::{ProcessIdentity, ThreadIdentity};
use crate::privacy::PrivacyClassification;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;

/// Supported OS execution platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    Unknown,
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOs
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Self::Unknown
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::Windows => write!(f, "Windows"),
            Self::MacOs => write!(f, "macOS"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Confidence rating of the captured telemetry.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    Unknown,
    Low,
    Medium,
    #[default]
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Discrete event classification identifier in VIR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EventType {
    ProcessStart,
    ProcessExit,
    ProcessSpawn,
    FileOpen,
    FileRead,
    FileWrite,
    FileDelete,
    FileRename,
    DnsQuery,
    DnsResponse,
    NetworkConnect,
    NetworkAccept,
    NetworkClose,
    SocketCreate,
    CryptoOperation,
    TlsObserved,
    MemoryMap,
    MemoryProtect,
    IpcConnect,
    IpcSend,
    UserSession,
    SystemMetadata,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Normalized event record in Veyronis Intermediate Representation (VIR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirEvent {
    pub event_id: Uuid,
    pub parent_event_id: Option<Uuid>,
    pub causal_parent_ids: Vec<Uuid>,
    pub timestamp_wall: DateTime<Utc>,
    pub timestamp_monotonic_ns: u64,
    pub process_identity: ProcessIdentity,
    pub thread_identity: Option<ThreadIdentity>,
    pub platform: Platform,
    pub event_type: EventType,
    pub data: EventData,
    pub raw_evidence: BTreeMap<String, String>,
    pub collector: String,
    pub confidence: Confidence,
    pub privacy: PrivacyClassification,
}

impl VirEvent {
    pub fn new(
        process_identity: ProcessIdentity,
        event_type: EventType,
        data: EventData,
        collector: impl Into<String>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            parent_event_id: None,
            causal_parent_ids: Vec::new(),
            timestamp_wall: Utc::now(),
            timestamp_monotonic_ns: 0,
            process_identity,
            thread_identity: None,
            platform: Platform::current(),
            event_type,
            data,
            raw_evidence: BTreeMap::new(),
            collector: collector.into(),
            confidence: Confidence::High,
            privacy: PrivacyClassification::Public,
        }
    }

    pub fn with_parent(mut self, parent_id: Uuid) -> Self {
        self.parent_event_id = Some(parent_id);
        self
    }

    pub fn with_causal_parent(mut self, causal_id: Uuid) -> Self {
        self.causal_parent_ids.push(causal_id);
        self
    }

    pub fn with_monotonic(mut self, ns: u64) -> Self {
        self.timestamp_monotonic_ns = ns;
        self
    }

    pub fn with_thread(mut self, thread: ThreadIdentity) -> Self {
        self.thread_identity = Some(thread);
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_privacy(mut self, privacy: PrivacyClassification) -> Self {
        self.privacy = privacy;
        self
    }

    pub fn with_raw_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.raw_evidence.insert(key.into(), value.into());
        self
    }

    /// Computes canonical deterministic hash of normalized fields.
    pub fn canonical_hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.event_id.as_bytes());
        hasher.update(self.event_type.to_string().as_bytes());
        hasher.update(self.process_identity.canonical_name().as_bytes());
        if let Ok(serialized) = serde_json::to_string(&self.data) {
            hasher.update(serialized.as_bytes());
        }
        hasher.finalize()
    }
}
