use serde_json::json;
use std::fs;
use std::path::Path;
use uuid::Uuid;
use veyronis_format::DecryptedArtifact;

pub struct StixExporter;

impl StixExporter {
    pub fn export(artifact: &DecryptedArtifact, output_path: &Path) -> Result<(), anyhow::Error> {
        let bundle_id = format!("bundle--{}", Uuid::new_v4());
        let mut objects = Vec::new();

        // 1. Observed Data SDO
        let report_time = chrono::Utc::now().to_rfc3339();
        let mut sco_map = serde_json::Map::new();

        for (sco_index, event) in artifact.events.iter().enumerate() {
            let proc_sco = json!({
                "type": "process",
                "pid": event.process_identity.pid,
                "name": event.process_identity.canonical_name(),
                "command_line": event.process_identity.executable_path,
            });

            sco_map.insert(sco_index.to_string(), proc_sco);
        }

        let observed_data = json!({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": format!("observed-data--{}", Uuid::new_v4()),
            "created": report_time,
            "modified": report_time,
            "first_observed": report_time,
            "last_observed": report_time,
            "number_observed": artifact.events.len(),
            "objects": sco_map,
        });
        objects.push(observed_data);

        let bundle = json!({
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        });

        let json_str = serde_json::to_string_pretty(&bundle)?;
        fs::write(output_path, json_str)?;
        Ok(())
    }
}
