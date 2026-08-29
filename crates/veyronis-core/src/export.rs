use crate::html_report::HtmlReportGenerator;
use crate::sarif_export::SarifExporter;
use crate::stix_export::StixExporter;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use veyronis_detect::DetectionEngine;
use veyronis_format::VyrReader;
use veyronis_keystore::KeyStore;
use veyronis_policy::PrivacySanitizer;

pub struct VyrExporter;

impl VyrExporter {
    pub fn export(
        artifact_path: &Path,
        output_path: &Path,
        format: &str,
        key_label: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let label = key_label.unwrap_or("default");
        let keystore = KeyStore::open_default()?;
        let reader = VyrReader::open_file(artifact_path)?;

        let decrypted = if let Some(pass) = passphrase {
            reader.decrypt_with_passphrase(pass.as_bytes())?
        } else if let Ok(recipient_key) = keystore.load_recipient_key(label, None) {
            reader.decrypt_with_key(&recipient_key)?
        } else {
            return Err(anyhow::anyhow!(
                "cannot decrypt artifact: recipient key '{}' not found in keystore and no passphrase provided",
                label
            ));
        };

        let sanitizer = PrivacySanitizer::default();
        let sanitized_events = sanitizer.sanitize_events(&decrypted.events);

        let mut export_artifact = decrypted.clone();
        export_artifact.events = sanitized_events;

        match format.to_lowercase().as_str() {
            "json" => {
                let json_data = serde_json::to_string_pretty(&export_artifact.events)?;
                let mut file = File::create(output_path)?;
                file.write_all(json_data.as_bytes())?;
                println!(
                    "Exported {} events to {}",
                    export_artifact.events.len(),
                    output_path.display()
                );
            }
            "html" => {
                let detection_engine = DetectionEngine::new();
                let detection_report =
                    detection_engine.scan(&export_artifact.events, export_artifact.graph.as_ref());
                HtmlReportGenerator::generate(&export_artifact, &detection_report, output_path)?;
                println!(
                    "Exported interactive security report to {}",
                    output_path.display()
                );
            }
            "stix" => {
                StixExporter::export(&export_artifact, output_path)?;
                println!("Exported STIX 2.1 JSON bundle to {}", output_path.display());
            }
            "sarif" => {
                let detection_engine = DetectionEngine::new();
                let detection_report =
                    detection_engine.scan(&export_artifact.events, export_artifact.graph.as_ref());
                SarifExporter::export(&detection_report, output_path)?;
                println!("Exported SARIF 2.1.0 report to {}", output_path.display());
            }
            "ndjson" => {
                let mut file = File::create(output_path)?;
                for event in &export_artifact.events {
                    let line = serde_json::to_string(event)?;
                    writeln!(file, "{}", line)?;
                }
                println!(
                    "Exported {} events as NDJSON to {}",
                    export_artifact.events.len(),
                    output_path.display()
                );
            }
            "csv" => {
                let mut file = File::create(output_path)?;
                writeln!(
                    file,
                    "event_id,event_type,process_name,pid,confidence,privacy"
                )?;
                for event in &export_artifact.events {
                    writeln!(
                        file,
                        "{},{},{},{},{},{}",
                        event.event_id,
                        event.event_type,
                        event.process_identity.canonical_name(),
                        event.process_identity.pid,
                        event.confidence,
                        event.privacy
                    )?;
                }
                println!(
                    "Exported {} events as CSV to {}",
                    export_artifact.events.len(),
                    output_path.display()
                );
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported export format '{}': supported formats are json, html, stix, sarif, ndjson, csv",
                    format
                ));
            }
        }

        Ok(())
    }
}
