use serde_json::json;
use std::fs;
use std::path::Path;
use veyronis_detect::DetectionReport;

pub struct SarifExporter;

impl SarifExporter {
    pub fn export(report: &DetectionReport, output_path: &Path) -> Result<(), anyhow::Error> {
        let mut results = Vec::new();

        for alert in &report.alerts {
            let level = match alert.severity {
                veyronis_detect::Severity::Critical | veyronis_detect::Severity::High => "error",
                veyronis_detect::Severity::Medium => "warning",
                _ => "note",
            };

            results.push(json!({
                "ruleId": alert.rule_id,
                "level": level,
                "message": {
                    "text": format!("{}: {}", alert.title, alert.remediation)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "session.vyr"
                        }
                    }
                }]
            }));
        }

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VEYRONIS",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/dupewon/veyronis"
                    }
                },
                "results": results
            }]
        });

        let json_str = serde_json::to_string_pretty(&sarif)?;
        fs::write(output_path, json_str)?;
        Ok(())
    }
}
