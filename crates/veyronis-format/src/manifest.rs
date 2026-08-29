use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use veyronis_ir::event::Platform;

/// Execution manifest capturing artifact metadata, command details, and collector performance metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub target_command: Vec<String>,
    pub target_pid: u32,
    pub platform: Platform,
    pub start_time_wall: DateTime<Utc>,
    pub end_time_wall: DateTime<Utc>,
    pub duration_ms: u64,
    pub total_events: usize,
    pub dropped_events: usize,
    pub event_category_counts: BTreeMap<String, usize>,
    pub collector_capabilities: BTreeMap<String, String>,
}

impl ArtifactManifest {
    pub fn new(
        target_command: Vec<String>,
        target_pid: u32,
        platform: Platform,
        start_time_wall: DateTime<Utc>,
        end_time_wall: DateTime<Utc>,
    ) -> Self {
        let duration_ms = (end_time_wall - start_time_wall).num_milliseconds().max(0) as u64;

        Self {
            target_command,
            target_pid,
            platform,
            start_time_wall,
            end_time_wall,
            duration_ms,
            total_events: 0,
            dropped_events: 0,
            event_category_counts: BTreeMap::new(),
            collector_capabilities: BTreeMap::new(),
        }
    }
}
