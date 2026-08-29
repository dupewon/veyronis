use chrono::Utc;
use colored::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use veyronis_collector_api::{Collector, TargetProcess};
use veyronis_format::{ArtifactManifest, VyrWriter};
use veyronis_graph::BehaviorGraph;
use veyronis_ir::categories::*;
use veyronis_ir::event::{EventType, Platform, VirEvent};
use veyronis_ir::identity::ProcessIdentity;
use veyronis_keystore::KeyStore;

pub struct RecordSessionOptions {
    pub command: Vec<String>,
    pub output_path: Option<PathBuf>,
    pub key_label: Option<String>,
    pub passphrase: Option<String>,
    pub inject_threat: Option<String>,
}

pub struct RecordSession;

impl RecordSession {
    pub fn record(options: RecordSessionOptions) -> Result<PathBuf, anyhow::Error> {
        if options.command.is_empty() {
            return Err(anyhow::anyhow!("no target command provided for recording"));
        }

        let exe = &options.command[0];
        let args = &options.command[1..];

        let start_wall = Utc::now();
        let _start_instant = Instant::now();

        // 1. Setup collector
        let mut collector: Box<dyn Collector> = Self::create_collector();
        collector
            .initialize()
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // 2. Spawn target child process
        let mut child = Command::new(exe)
            .args(args)
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to execute '{}': {}", exe, e))?;

        let target_pid = child.id();
        let target_process = TargetProcess::new(
            target_pid,
            exe,
            options.command.clone(),
            start_wall.timestamp_nanos_opt().unwrap_or(0) as u64,
        );

        // 3. Start collector
        collector
            .start(&target_process)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let mut collected_events: Vec<VirEvent> = Vec::new();

        // 4. Poll events while process runs
        loop {
            match child.try_wait()? {
                Some(status) => {
                    let exit_code = status.code().unwrap_or(-1);

                    // Add ProcessExit event
                    let exit_event = VirEvent::new(
                        ProcessIdentity::new(
                            target_pid,
                            None,
                            start_wall.timestamp_nanos_opt().unwrap_or(0) as u64,
                            exe,
                            1,
                        ),
                        EventType::ProcessExit,
                        EventData::ProcessExit(ProcessExitData {
                            exit_code,
                            termination_signal: None,
                            cpu_user_time_ms: 0,
                            cpu_system_time_ms: 0,
                            max_resident_set_size_bytes: 0,
                        }),
                        collector.name(),
                    );
                    collected_events.push(exit_event);
                    break;
                }
                None => {
                    if let Ok(mut batch) = collector.poll_events(1000) {
                        collected_events.append(&mut batch);
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }

        // 5. Stop collector and drain remaining telemetry
        let health = collector.stop().map_err(|e| anyhow::anyhow!("{}", e))?;
        if let Ok(mut final_batch) = collector.poll_events(10000) {
            collected_events.append(&mut final_batch);
        }

        // 5b. If threat simulation is requested, synthesize pattern events
        if let Some(threat) = &options.inject_threat {
            let proc = ProcessIdentity::new(
                target_pid,
                None,
                start_wall.timestamp_nanos_opt().unwrap_or(0) as u64,
                exe,
                1,
            );
            match threat.to_lowercase().as_str() {
                "ransomware" => {
                    collected_events.push(VirEvent::new(
                        proc.clone(),
                        EventType::FileWrite,
                        EventData::FileWrite(FileWriteData {
                            path: "C:\\Users\\User\\Documents\\confidential.docx.encrypted".into(),
                            bytes_written: 4096,
                            offset: 0,
                            content_hash: None,
                        }),
                        "simulator",
                    ));
                    collected_events.push(VirEvent::new(
                        proc,
                        EventType::CryptoOperation,
                        EventData::CryptoOperation(CryptoOperationData {
                            category: CryptoCategory::Encrypt,
                            algorithm: "ChaCha20-Poly1305".into(),
                            provider: "Internal".into(),
                            key_size_bits: Some(256),
                            mode: None,
                        }),
                        "simulator",
                    ));
                }
                "revshell" | "c2" => {
                    collected_events.push(VirEvent::new(
                        proc,
                        EventType::NetworkConnect,
                        EventData::NetworkConnect(NetworkConnectData {
                            protocol: NetworkProtocol::Tcp,
                            local_address: None,
                            local_port: None,
                            remote_address: "198.51.100.44".parse().unwrap(),
                            remote_port: 4444,
                            remote_hostname: Some("c2.attacker.com".into()),
                            is_external: true,
                        }),
                        "simulator",
                    ));
                }
                _ => {}
            }
        }

        let end_wall = Utc::now();

        // 6. Build Behavior Graph
        let graph = BehaviorGraph::from_events(collected_events.clone());

        // 7. Calculate category counts
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut proc_count = 0;
        let mut file_count = 0;
        let mut net_count = 0;
        let mut dns_count = 0;
        let mut crypto_count = 0;

        for event in &collected_events {
            *counts.entry(event.event_type.to_string()).or_default() += 1;
            match event.event_type {
                EventType::ProcessStart | EventType::ProcessSpawn | EventType::ProcessExit => {
                    proc_count += 1;
                }
                EventType::FileOpen
                | EventType::FileRead
                | EventType::FileWrite
                | EventType::FileDelete
                | EventType::FileRename => {
                    file_count += 1;
                }
                EventType::NetworkConnect
                | EventType::NetworkAccept
                | EventType::NetworkClose
                | EventType::SocketCreate => {
                    net_count += 1;
                }
                EventType::DnsQuery | EventType::DnsResponse => {
                    dns_count += 1;
                }
                EventType::CryptoOperation | EventType::TlsObserved => {
                    crypto_count += 1;
                }
                _ => {}
            }
        }

        // 8. Build Manifest
        let mut manifest = ArtifactManifest::new(
            options.command.clone(),
            target_pid,
            Platform::current(),
            start_wall,
            end_wall,
        );
        manifest.total_events = collected_events.len();
        manifest.dropped_events = health.events_dropped;
        manifest.event_category_counts = counts;

        // 9. Load signing and recipient keys from keystore
        let mut keystore = KeyStore::open_default()?;
        let key_label = options.key_label.as_deref().unwrap_or("default");

        let signing_key = if let Ok(key) = keystore.load_signing_key(key_label, None) {
            key
        } else {
            keystore.generate_key(key_label, None)?;
            keystore.load_signing_key(key_label, None)?
        };

        let recipient_pub = keystore.get_recipient_public_key(key_label)?;

        // 10. Write .vyr artifact
        let mut writer = VyrWriter::new(signing_key);
        writer.add_recipient_public_key(&recipient_pub)?;

        if let Some(pass) = &options.passphrase {
            writer.add_passphrase_recipient(pass.as_bytes())?;
        }

        writer.write_manifest(&manifest)?;
        writer.write_events(&collected_events)?;
        writer.write_graph(&graph)?;

        let final_path = options.output_path.unwrap_or_else(|| {
            let sanitized_name = std::path::Path::new(exe)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("session");
            PathBuf::from(format!("{}-session.vyr", sanitized_name))
        });

        writer.write_to_file(&final_path)?;

        // 11. Print output report
        println!("{}", "VEYRONIS RECORDING".bold().white());
        println!("Target:\n  {}", options.command.join(" ").cyan());
        println!(
            "Platform:\n  {} {}",
            Platform::current(),
            std::env::consts::ARCH
        );
        println!("Events:");
        println!("  Processes {}", proc_count);
        println!("  Files     {}", file_count);
        println!("  Network   {}", net_count);
        println!("  DNS       {}", dns_count);
        println!("  Crypto    {}", crypto_count);
        println!("Artifact:\n  {}", final_path.display().to_string().green());
        println!("Integrity:\n  {}", "SIGNED".green().bold());
        println!("Encryption:\n  {}", "ENABLED".green().bold());

        Ok(final_path)
    }

    fn create_collector() -> Box<dyn Collector> {
        #[cfg(target_os = "windows")]
        {
            Box::new(collector_windows::WindowsCollector::new())
        }
        #[cfg(target_os = "linux")]
        {
            Box::new(collector_linux::LinuxCollector::new())
        }
        #[cfg(target_os = "macos")]
        {
            Box::new(collector_macos::MacOsCollector::new())
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Box::new(collector_portable::PortableCollector::new())
        }
    }
}
