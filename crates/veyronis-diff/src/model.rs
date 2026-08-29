use serde::{Deserialize, Serialize};

/// Canonical representation of a behavior stripped of ephemeral execution artifacts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalBehavior {
    pub process_name: String,
    pub behavior_type: String,
    pub target_resource: String,
    pub secondary_attribute: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedBehavior {
    pub category: String,
    pub old_value: String,
    pub new_value: String,
}

/// Structured semantic behavioral diff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorDiffResult {
    pub similarity_score: f64,
    pub added_behaviors: Vec<String>,
    pub removed_behaviors: Vec<String>,
    pub changed_behaviors: Vec<ChangedBehavior>,
    pub high_risk_divergences: Vec<String>,
}

impl BehaviorDiffResult {
    pub fn render_terminal(&self) -> String {
        use colored::*;
        let mut out = String::new();

        out.push_str(&format!("{}\n", "BEHAVIOR DIFF".bold().white()));
        out.push_str(&format!("Similarity: {:.1}%\n\n", self.similarity_score));

        if !self.added_behaviors.is_empty() {
            out.push_str(&format!("{}\n", "Added:".green().bold()));
            for item in &self.added_behaviors {
                out.push_str(&format!("  {} {}\n", "+".green(), item));
            }
            out.push('\n');
        }

        if !self.removed_behaviors.is_empty() {
            out.push_str(&format!("{}\n", "Removed:".red().bold()));
            for item in &self.removed_behaviors {
                out.push_str(&format!("  {} {}\n", "-".red(), item));
            }
            out.push('\n');
        }

        if !self.changed_behaviors.is_empty() {
            out.push_str(&format!("{}\n", "Changed:".yellow().bold()));
            for item in &self.changed_behaviors {
                out.push_str(&format!(
                    "  {} {}: {} -> {}\n",
                    "~".yellow(),
                    item.category,
                    item.old_value,
                    item.new_value
                ));
            }
            out.push('\n');
        }

        if !self.high_risk_divergences.is_empty() {
            out.push_str(&format!("{}\n", "HIGH-RISK DIVERGENCES".red().bold()));
            for item in &self.high_risk_divergences {
                out.push_str(&format!("  {} {}\n", "!".red().bold(), item));
            }
            out.push('\n');
        }

        out
    }
}
