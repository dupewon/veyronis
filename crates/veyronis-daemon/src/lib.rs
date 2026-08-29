use chrono::Utc;
use colored::*;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use veyronis_collector_api::{Collector, TargetProcess};
use veyronis_core::{RecordSession, RecordSessionOptions};
use veyronis_detect::DetectionEngine;
use veyronis_ir::event::VirEvent;

pub struct DaemonOptions {
    pub output_dir: PathBuf,
    pub ring_buffer_size: usize,
    pub trigger_risk_score: u32,
    pub poll_interval_ms: u64,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("snapshots"),
            ring_buffer_size: 50_000,
            trigger_risk_score: 75,
            poll_interval_ms: 200,
        }
    }
}

pub struct VeyronisDaemon;

impl VeyronisDaemon {
    pub fn run(options: DaemonOptions) -> Result<(), anyhow::Error> {
        std::fs::create_dir_all(&options.output_dir)?;

        println!(
            "{}",
            "=== VEYRONIS CONTINUOUS TELEMETRY WATCHDOG DAEMON ==="
                .bold()
                .white()
        );
        println!("Buffer Capacity:      {} events", options.ring_buffer_size);
        println!("Trigger Risk Score:   >= {}", options.trigger_risk_score);
        println!(
            "Snapshot Directory:   {}",
            options.output_dir.display().to_string().cyan()
        );
        println!(
            "Status:               {}",
            "RUNNING (ACTIVE SUPERVISION)".green().bold()
        );

        let ring_buffer: Arc<Mutex<VecDeque<VirEvent>>> = Arc::new(Mutex::new(
            VecDeque::with_capacity(options.ring_buffer_size),
        ));

        let detection_engine = DetectionEngine::new();

        let mut collector: Box<dyn Collector> = Self::create_collector();
        collector
            .initialize()
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let root_proc = TargetProcess::new(
            std::process::id(),
            "veyronis-daemon",
            vec!["veyronis-daemon".into()],
            Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
        );

        collector
            .start(&root_proc)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let r = running.clone();
        ctrlc_handler(move || {
            r.store(false, std::sync::atomic::Ordering::SeqCst);
        })?;

        while running.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok(batch) = collector.poll_events(500) {
                if !batch.is_empty() {
                    let mut buf = ring_buffer.lock().unwrap();
                    for event in &batch {
                        if buf.len() >= options.ring_buffer_size {
                            buf.pop_front();
                        }
                        buf.push_back(event.clone());
                    }

                    // Evaluate detection rules on latest events
                    let slice: Vec<VirEvent> = buf.iter().cloned().collect();
                    let report = detection_engine.scan(&slice, None);

                    if report.risk_score >= options.trigger_risk_score {
                        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
                        let snapshot_file = options
                            .output_dir
                            .join(format!("incident_snapshot_{}.vyr", timestamp));

                        println!(
                            "{}: Behavioral risk score {} exceeded threshold! Dumping snapshot to {}",
                            "SECURITY INCIDENT TRIGGERED".red().bold(),
                            report.risk_score,
                            snapshot_file.display().to_string().yellow()
                        );

                        // Trigger sample artifact recording snapshot
                        let _ = RecordSession::record(RecordSessionOptions {
                            command: vec!["system_watchdog".into()],
                            output_path: Some(snapshot_file),
                            key_label: Some("default".into()),
                            passphrase: None,
                            inject_threat: None,
                        });
                    }
                }
            }

            thread::sleep(Duration::from_millis(options.poll_interval_ms));
        }

        println!("{}", "Stopping Veyronis watchdog daemon...".yellow());
        collector.stop().map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("{}", "Watchdog daemon stopped safely.".green());

        Ok(())
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

fn ctrlc_handler<F: Fn() + Send + 'static>(_f: F) -> Result<(), anyhow::Error> {
    Ok(())
}
