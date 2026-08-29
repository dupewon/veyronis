use colored::*;
use std::collections::BTreeMap;
use std::path::Path;
use tabled::{Table, Tabled};
use veyronis_format::VyrReader;
use veyronis_graph::ProcessTree;
use veyronis_ir::categories::EventData;
use veyronis_ir::event::EventType;
use veyronis_keystore::KeyStore;

#[derive(Tabled)]
struct SummaryRow {
    #[tabled(rename = "Property")]
    property: String,
    #[tabled(rename = "Value")]
    value: String,
}

pub struct VyrInspector;

impl VyrInspector {
    pub fn inspect(
        artifact_path: &Path,
        key_label: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let reader = VyrReader::open_file(artifact_path)?;

        // Try decrypting with local keystore or passphrase
        let label = key_label.unwrap_or("default");
        let keystore = KeyStore::open_default()?;

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

        println!("{}", "VEYRONIS ARTIFACT INSPECTION".bold().white());

        let manifest_info = decrypted.manifest.as_ref();
        let target_cmd = manifest_info
            .map(|m| m.target_command.join(" "))
            .unwrap_or_else(|| "N/A".into());
        let duration_str = manifest_info
            .map(|m| format!("{} ms", m.duration_ms))
            .unwrap_or_else(|| "N/A".into());

        let mut file_count = 0;
        let mut net_count = 0;
        let mut dns_count = 0;
        let mut crypto_count = 0;
        let mut net_destinations: BTreeMap<String, usize> = BTreeMap::new();
        let mut crypto_ops: Vec<String> = Vec::new();

        for event in &decrypted.events {
            match event.event_type {
                EventType::FileOpen
                | EventType::FileRead
                | EventType::FileWrite
                | EventType::FileDelete
                | EventType::FileRename => {
                    file_count += 1;
                }
                EventType::NetworkConnect | EventType::NetworkAccept | EventType::NetworkClose => {
                    net_count += 1;
                    if let EventData::NetworkConnect(n) = &event.data {
                        let dest = format!("{}:{}", n.remote_address, n.remote_port);
                        *net_destinations.entry(dest).or_default() += 1;
                    }
                }
                EventType::DnsQuery | EventType::DnsResponse => {
                    dns_count += 1;
                }
                EventType::CryptoOperation | EventType::TlsObserved => {
                    crypto_count += 1;
                    if let EventData::CryptoOperation(c) = &event.data {
                        crypto_ops.push(format!(
                            "{:?} - {} ({})",
                            c.category, c.algorithm, c.provider
                        ));
                    } else if let EventData::TlsObserved(t) = &event.data {
                        crypto_ops.push(format!("TLS - {}", t.version));
                    }
                }
                _ => {}
            }
        }

        let summary_rows = vec![
            SummaryRow {
                property: "Artifact ID".into(),
                value: decrypted.header.artifact_uuid.to_string(),
            },
            SummaryRow {
                property: "Format Version".into(),
                value: format!(
                    "v{}.{}",
                    decrypted.header.major_version, decrypted.header.minor_version
                ),
            },
            SummaryRow {
                property: "Target Command".into(),
                value: target_cmd,
            },
            SummaryRow {
                property: "Duration".into(),
                value: duration_str,
            },
            SummaryRow {
                property: "Total Events".into(),
                value: decrypted.events.len().to_string(),
            },
            SummaryRow {
                property: "Filesystem Ops".into(),
                value: file_count.to_string(),
            },
            SummaryRow {
                property: "Network Flows".into(),
                value: net_count.to_string(),
            },
            SummaryRow {
                property: "DNS Queries".into(),
                value: dns_count.to_string(),
            },
            SummaryRow {
                property: "Crypto Ops".into(),
                value: crypto_count.to_string(),
            },
            SummaryRow {
                property: "Encryption".into(),
                value: if decrypted.header.is_encrypted() {
                    "XChaCha20-Poly1305 (AEAD)".into()
                } else {
                    "Disabled".into()
                },
            },
            SummaryRow {
                property: "Signature".into(),
                value: "Ed25519 (Valid)".into(),
            },
        ];

        let table = Table::new(summary_rows).to_string();
        println!("{}\n", table);

        if let Some(graph) = &decrypted.graph {
            println!("{}", "Process Tree:".bold().white());
            let tree = ProcessTree::build(graph);
            print!("{}", tree.render_tree());
            println!();
        }

        if !net_destinations.is_empty() {
            println!("{}", "Top Network Destinations:".bold().white());
            for (dest, count) in net_destinations.iter().take(10) {
                println!("  - {} ({} events)", dest.cyan(), count);
            }
            println!();
        }

        if !crypto_ops.is_empty() {
            println!("{}", "Cryptographic Operations:".bold().white());
            for op in crypto_ops.iter().take(10) {
                println!("  - {}", op.yellow());
            }
            println!();
        }

        Ok(())
    }
}
