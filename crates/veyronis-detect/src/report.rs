use crate::rule::Severity;
use colored::*;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionAlert {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub matched_event_ids: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    pub risk_score: u32,
    pub total_rules_evaluated: usize,
    pub alerts: Vec<DetectionAlert>,
}

#[derive(Tabled)]
struct AlertTableRow {
    #[tabled(rename = "Rule ID")]
    rule_id: String,
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Threat Title")]
    title: String,
    #[tabled(rename = "MITRE ATT&CK")]
    mitre: String,
    #[tabled(rename = "Matched Events")]
    matched_count: usize,
}

impl DetectionReport {
    pub fn render_terminal(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "{}\n",
            "VEYRONIS BEHAVIORAL THREAT SCAN".bold().white()
        ));

        let score_colored = if self.risk_score >= 75 {
            format!("{}/100 (CRITICAL)", self.risk_score).red().bold()
        } else if self.risk_score >= 40 {
            format!("{}/100 (ELEVATED)", self.risk_score)
                .yellow()
                .bold()
        } else if self.risk_score > 0 {
            format!("{}/100 (LOW RISK)", self.risk_score).cyan()
        } else {
            format!("{}/100 (BENIGN / CLEAN)", self.risk_score)
                .green()
                .bold()
        };

        out.push_str(&format!("Risk Score:             {}\n", score_colored));
        out.push_str(&format!(
            "Rules Evaluated:        {}\n",
            self.total_rules_evaluated
        ));
        out.push_str(&format!(
            "Detections Triggered:   {}\n\n",
            self.alerts.len()
        ));

        if self.alerts.is_empty() {
            out.push_str(&format!(
                "{}\n",
                "  [+] No behavioral security threats detected."
                    .green()
                    .bold()
            ));
            return out;
        }

        let rows: Vec<AlertTableRow> = self
            .alerts
            .iter()
            .map(|a| {
                let sev_str = match a.severity {
                    Severity::Critical => "CRITICAL".red().bold().to_string(),
                    Severity::High => "HIGH".red().to_string(),
                    Severity::Medium => "MEDIUM".yellow().to_string(),
                    Severity::Low => "LOW".cyan().to_string(),
                    Severity::Info => "INFO".white().to_string(),
                };

                let mitre_str = a.mitre_technique.as_deref().unwrap_or("N/A").to_string();

                AlertTableRow {
                    rule_id: a.rule_id.clone(),
                    severity: sev_str,
                    title: a.title.clone(),
                    mitre: mitre_str,
                    matched_count: a.matched_event_ids.len(),
                }
            })
            .collect();

        out.push_str(&Table::new(rows).to_string());
        out.push('\n');

        out.push_str(&format!(
            "\n{}\n",
            "REMEDIATION & INVESTIGATION GUIDANCE:".bold().white()
        ));
        for alert in &self.alerts {
            out.push_str(&format!(
                "  • [{}] {}: {}\n",
                alert.rule_id.bold(),
                alert.title,
                alert.remediation.italic()
            ));
        }

        out
    }
}
