use serde::{Deserialize, Serialize};

/// Operational health and dropped event statistics of a running collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CollectorHealth {
    pub is_running: bool,
    pub events_captured: usize,
    pub events_dropped: usize,
    pub error_count: usize,
    pub last_error_message: Option<String>,
}
