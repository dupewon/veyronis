use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Behavioral relationship between two VIR events in the directed graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeKind {
    /// Direct hierarchical structural parent event.
    Parent,
    /// Explicit causal dependency (event A induced event B).
    Causal,
    /// Parent process spawning or controlling a child process.
    ProcessLineage,
    /// Shared operating system resource (e.g. file path, memory descriptor).
    ResourceRelationship,
    /// Shared network endpoint or socket connection context.
    NetworkRelationship,
    /// Temporal sequential ordering within the same thread or process.
    Temporal,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parent => write!(f, "PARENT"),
            Self::Causal => write!(f, "CAUSAL"),
            Self::ProcessLineage => write!(f, "PROCESS_LINEAGE"),
            Self::ResourceRelationship => write!(f, "RESOURCE"),
            Self::NetworkRelationship => write!(f, "NETWORK"),
            Self::Temporal => write!(f, "TEMPORAL"),
        }
    }
}

/// Directed edge connecting two VIR event nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub kind: EdgeKind,
    pub weight: u32,
}

impl GraphEdge {
    pub fn new(source_id: Uuid, target_id: Uuid, kind: EdgeKind) -> Self {
        Self {
            source_id,
            target_id,
            kind,
            weight: 1,
        }
    }
}
