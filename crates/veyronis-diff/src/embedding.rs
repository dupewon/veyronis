use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use veyronis_ir::categories::EventData;
use veyronis_ir::event::{EventType, VirEvent};

/// A 32-dimensional normalized behavioral feature embedding vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehaviorEmbedding {
    pub vector: Vec<f32>,
    pub dimensions: usize,
}

impl BehaviorEmbedding {
    /// Extracts a normalized behavioral vector embedding from a stream of VIR events.
    pub fn from_events(events: &[VirEvent]) -> Self {
        const DIMS: usize = 32;
        let mut counts = vec![0.0f32; DIMS];

        let mut process_names: HashMap<&str, usize> = HashMap::new();
        let mut distinct_ips: HashMap<String, usize> = HashMap::new();
        let mut distinct_files: HashMap<String, usize> = HashMap::new();

        for ev in events {
            *process_names
                .entry(ev.process_identity.canonical_name())
                .or_insert(0) += 1;

            let type_idx = match ev.event_type {
                EventType::ProcessStart => 0,
                EventType::ProcessExit => 1,
                EventType::ProcessSpawn => 2,
                EventType::FileOpen => 3,
                EventType::FileRead => 4,
                EventType::FileWrite => 5,
                EventType::FileDelete => 6,
                EventType::FileRename => 7,
                EventType::NetworkConnect => 8,
                EventType::NetworkAccept => 9,
                EventType::NetworkClose => 10,
                EventType::DnsQuery => 11,
                EventType::DnsResponse => 12,
                EventType::MemoryMap => 13,
                EventType::MemoryProtect => 14,
                EventType::CryptoOperation => 15,
                EventType::TlsObserved => 16,
                EventType::IpcConnect => 17,
                EventType::IpcSend => 18,
                _ => 19,
            };
            counts[type_idx] += 1.0;

            match &ev.data {
                EventData::FileOpen(f) => {
                    *distinct_files.entry(f.path.clone()).or_insert(0) += 1;
                }
                EventData::FileWrite(f) => {
                    *distinct_files.entry(f.path.clone()).or_insert(0) += 1;
                }
                EventData::NetworkConnect(n) => {
                    *distinct_ips
                        .entry(n.remote_address.to_string())
                        .or_insert(0) += 1;
                }
                _ => {}
            }
        }

        counts[20] = distinct_files.len() as f32;
        counts[21] = distinct_ips.len() as f32;
        counts[22] = process_names.len() as f32;
        counts[23] = events.len() as f32;

        // L2 normalization
        let norm_sq: f32 = counts.iter().map(|x| x * x).sum();
        let norm = norm_sq.sqrt();

        let normalized = if norm > 0.0 {
            counts.iter().map(|x| x / norm).collect()
        } else {
            counts
        };

        Self {
            vector: normalized,
            dimensions: DIMS,
        }
    }

    /// Computes the Cosine Similarity between two behavioral embeddings (returns 0.0 to 1.0).
    pub fn cosine_similarity(&self, other: &Self) -> f32 {
        if self.vector.len() != other.vector.len() {
            return 0.0;
        }

        let dot_product: f32 = self
            .vector
            .iter()
            .zip(other.vector.iter())
            .map(|(a, b)| a * b)
            .sum();

        dot_product.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veyronis_ir::categories::ProcessStartData;
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_behavior_embedding_similarity() {
        let p = ProcessIdentity::new(100, None, 1000, "target.exe", 1);

        let ev1 = VirEvent::new(
            p,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "target.exe".into(),
                command_line: vec!["target.exe".into()],
                working_directory: None,
                parent_pid: None,
                environment_keys: vec![],
            }),
            "collector",
        );

        let emb_a = BehaviorEmbedding::from_events(std::slice::from_ref(&ev1));
        let emb_b = BehaviorEmbedding::from_events(std::slice::from_ref(&ev1));

        let sim = emb_a.cosine_similarity(&emb_b);
        assert!((sim - 1.0).abs() < 1e-4);
    }
}
