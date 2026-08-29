use crate::model::{BehaviorDiffResult, CanonicalBehavior, ChangedBehavior};
use std::collections::BTreeSet;
use veyronis_ir::categories::EventData;
use veyronis_ir::event::VirEvent;

pub struct DiffEngine;

impl DiffEngine {
    pub fn diff_events(old_events: &[VirEvent], new_events: &[VirEvent]) -> BehaviorDiffResult {
        let old_set = Self::extract_canonical_behaviors(old_events);
        let new_set = Self::extract_canonical_behaviors(new_events);

        let intersection_count = old_set.intersection(&new_set).count();
        let total_count = old_set.len() + new_set.len();

        let similarity_score = if total_count == 0 {
            100.0
        } else {
            (2.0 * intersection_count as f64 / total_count as f64) * 100.0
        };

        let mut added_behaviors = Vec::new();
        let mut removed_behaviors = Vec::new();
        let mut high_risk_divergences = Vec::new();

        for item in new_set.difference(&old_set) {
            let desc = format_behavior_description(item);
            added_behaviors.push(desc.clone());

            // High risk checks
            if item.behavior_type == "NetworkConnect" {
                high_risk_divergences.push(format!(
                    "process {} established new external network destination: {}",
                    item.process_name, item.target_resource
                ));
            } else if item.behavior_type == "ProcessSpawn" {
                high_risk_divergences.push(format!(
                    "process {} spawned unexpected child process: {}",
                    item.process_name, item.target_resource
                ));
            } else if item.behavior_type == "CryptoOperation" {
                high_risk_divergences.push(format!(
                    "process {} invoked new cryptographic algorithm: {}",
                    item.process_name, item.target_resource
                ));
            }
        }

        for item in old_set.difference(&new_set) {
            removed_behaviors.push(format_behavior_description(item));
        }

        // Detect TLS or property modifications
        let changed_behaviors = Self::detect_changed_properties(old_events, new_events);

        BehaviorDiffResult {
            similarity_score,
            added_behaviors,
            removed_behaviors,
            changed_behaviors,
            high_risk_divergences,
        }
    }

    fn extract_canonical_behaviors(events: &[VirEvent]) -> BTreeSet<CanonicalBehavior> {
        let mut set = BTreeSet::new();

        for event in events {
            let proc_name = event.process_identity.canonical_name().to_string();

            match &event.data {
                EventData::ProcessStart(p) => {
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "ProcessStart".into(),
                        target_resource: p.executable_path.clone(),
                        secondary_attribute: None,
                    });
                }
                EventData::ProcessSpawn(s) => {
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "ProcessSpawn".into(),
                        target_resource: s.child_executable_path.clone(),
                        secondary_attribute: None,
                    });
                }
                EventData::FileOpen(f) => {
                    let norm_path = normalize_temp_path(&f.normalized_path);
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "FileOpen".into(),
                        target_resource: norm_path,
                        secondary_attribute: Some(format!("r:{} w:{}", f.read, f.write)),
                    });
                }
                EventData::FileWrite(f) => {
                    let norm_path = normalize_temp_path(&f.path);
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "FileWrite".into(),
                        target_resource: norm_path,
                        secondary_attribute: None,
                    });
                }
                EventData::DnsQuery(d) => {
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "DnsQuery".into(),
                        target_resource: d.query_name.to_lowercase(),
                        secondary_attribute: None,
                    });
                }
                EventData::NetworkConnect(n) => {
                    let target = if n.is_external {
                        format!("{}:{}", n.remote_address, n.remote_port)
                    } else {
                        format!("localhost:{}", n.remote_port)
                    };
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "NetworkConnect".into(),
                        target_resource: target,
                        secondary_attribute: n.remote_hostname.clone(),
                    });
                }
                EventData::CryptoOperation(c) => {
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "CryptoOperation".into(),
                        target_resource: c.algorithm.to_uppercase(),
                        secondary_attribute: Some(c.provider.clone()),
                    });
                }
                EventData::TlsObserved(t) => {
                    set.insert(CanonicalBehavior {
                        process_name: proc_name,
                        behavior_type: "TlsObserved".into(),
                        target_resource: t.version.clone(),
                        secondary_attribute: t.cipher_suite.clone(),
                    });
                }
                _ => {}
            }
        }

        set
    }

    fn detect_changed_properties(
        old_events: &[VirEvent],
        new_events: &[VirEvent],
    ) -> Vec<ChangedBehavior> {
        let mut changes = Vec::new();

        let old_tls = old_events.iter().find_map(|e| {
            if let EventData::TlsObserved(t) = &e.data {
                Some(t.version.clone())
            } else {
                None
            }
        });

        let new_tls = new_events.iter().find_map(|e| {
            if let EventData::TlsObserved(t) = &e.data {
                Some(t.version.clone())
            } else {
                None
            }
        });

        if let (Some(o), Some(n)) = (old_tls, new_tls) {
            if o != n {
                changes.push(ChangedBehavior {
                    category: "TLS Protocol".into(),
                    old_value: o,
                    new_value: n,
                });
            }
        }

        changes
    }
}

fn normalize_temp_path(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.contains("temp") || lower.contains("tmp") {
        if let Some(filename) = std::path::Path::new(path).file_name() {
            return format!("<TEMP_DIR>/{}", filename.to_string_lossy());
        }
    }
    path.to_string()
}

fn format_behavior_description(b: &CanonicalBehavior) -> String {
    match b.behavior_type.as_str() {
        "NetworkConnect" => format!("{} -> network {}", b.process_name, b.target_resource),
        "ProcessSpawn" => format!("{} -> spawn {}", b.process_name, b.target_resource),
        "CryptoOperation" => {
            if let Some(prov) = &b.secondary_attribute {
                format!(
                    "{} -> crypto {} ({})",
                    b.process_name, b.target_resource, prov
                )
            } else {
                format!("{} -> crypto {}", b.process_name, b.target_resource)
            }
        }
        "FileOpen" => format!("{} -> open file {}", b.process_name, b.target_resource),
        "FileWrite" => format!("{} -> write file {}", b.process_name, b.target_resource),
        "DnsQuery" => format!("{} -> resolve dns {}", b.process_name, b.target_resource),
        _ => format!(
            "{} -> {} {}",
            b.process_name, b.behavior_type, b.target_resource
        ),
    }
}
