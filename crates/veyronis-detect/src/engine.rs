use crate::builtin::get_builtin_rules;
use crate::report::{DetectionAlert, DetectionReport};
use crate::rule::SecurityRule;
use std::fs;
use std::path::Path;
use veyronis_graph::BehaviorGraph;
use veyronis_ir::categories::EventData;
use veyronis_ir::event::VirEvent;

pub struct DetectionEngine {
    rules: Vec<SecurityRule>,
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            rules: get_builtin_rules(),
        }
    }

    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<usize, anyhow::Error> {
        let mut count = 0;
        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|ext| ext == "yml" || ext == "yaml")
                {
                    let content = fs::read_to_string(&path)?;
                    if let Ok(rule) = SecurityRule::from_yaml_str(&content) {
                        self.rules.push(rule);
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    pub fn scan(&self, events: &[VirEvent], _graph: Option<&BehaviorGraph>) -> DetectionReport {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            let mut matched_events = Vec::new();

            for criterion in &rule.criteria {
                let mut criterion_matches = Vec::new();

                for event in events {
                    let mut is_match = true;

                    if let Some(target_type) = &criterion.event_type {
                        if !event
                            .event_type
                            .to_string()
                            .eq_ignore_ascii_case(target_type)
                        {
                            is_match = false;
                        }
                    }

                    if let Some(proc_filter) = &criterion.process_name_contains {
                        let proc_name = event.process_identity.canonical_name();
                        if !proc_name
                            .to_lowercase()
                            .contains(&proc_filter.to_lowercase())
                        {
                            is_match = false;
                        }
                    }

                    if let Some(ext) = criterion.is_external_network {
                        if let EventData::NetworkConnect(n) = &event.data {
                            if n.is_external != ext {
                                is_match = false;
                            }
                        } else {
                            is_match = false;
                        }
                    }

                    if let Some(res_filter) = &criterion.target_resource_contains {
                        let res_str = match &event.data {
                            EventData::FileOpen(f) => f.path.to_lowercase(),
                            EventData::FileWrite(f) => f.path.to_lowercase(),
                            EventData::ProcessSpawn(s) => s.child_executable_path.to_lowercase(),
                            EventData::DnsQuery(d) => d.query_name.to_lowercase(),
                            _ => String::new(),
                        };
                        if !res_str.contains(&res_filter.to_lowercase()) {
                            is_match = false;
                        }
                    }

                    if is_match {
                        criterion_matches.push(event.event_id.to_string()[..8].to_string());
                    }
                }

                let min_count = criterion.min_event_count.unwrap_or(1);
                if criterion_matches.len() >= min_count {
                    matched_events.extend(criterion_matches);
                } else {
                    matched_events.clear();
                    break;
                }
            }

            if !matched_events.is_empty() {
                alerts.push(DetectionAlert {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity,
                    mitre_tactic: rule.mitre.as_ref().map(|m| m.tactic.clone()),
                    mitre_technique: rule
                        .mitre
                        .as_ref()
                        .map(|m| format!("{}: {}", m.technique_id, m.technique_name)),
                    matched_event_ids: matched_events,
                    remediation: rule.remediation.clone(),
                });
            }
        }

        // Calculate overall risk score (0-100)
        let total_score: u32 = alerts.iter().map(|a| a.severity.score()).sum();
        let risk_score = total_score.min(100);

        DetectionReport {
            risk_score,
            total_rules_evaluated: self.rules.len(),
            alerts,
        }
    }
}
