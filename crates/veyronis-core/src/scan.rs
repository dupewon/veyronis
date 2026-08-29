use std::path::Path;
use veyronis_detect::{DetectionEngine, DetectionReport};
use veyronis_format::VyrReader;
use veyronis_keystore::KeyStore;

pub struct VyrScanner;

impl VyrScanner {
    pub fn scan(
        artifact_path: &Path,
        custom_rules_dir: Option<&Path>,
        key_label: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<DetectionReport, anyhow::Error> {
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

        let mut engine = DetectionEngine::new();
        if let Some(dir) = custom_rules_dir {
            let loaded = engine.load_rules_from_dir(dir)?;
            tracing::info!(
                "Loaded {} custom detection rules from {}",
                loaded,
                dir.display()
            );
        }

        let report = engine.scan(&decrypted.events, decrypted.graph.as_ref());
        Ok(report)
    }
}
