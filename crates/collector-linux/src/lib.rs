#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use veyronis_collector_api::{
    CapabilityLevel, Collector, CollectorCapabilities, CollectorError, CollectorHealth,
    EventRingBuffer, TargetProcess,
};
use veyronis_ir::categories::*;
use veyronis_ir::event::{EventType, VirEvent};
use veyronis_ir::identity::ProcessIdentity;

pub struct LinuxCollector {
    capabilities: CollectorCapabilities,
    buffer: EventRingBuffer,
    running: Arc<AtomicBool>,
    worker_handle: Option<JoinHandle<()>>,
    target: Option<TargetProcess>,
}

impl Default for LinuxCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxCollector {
    pub fn new() -> Self {
        let has_bpf = detect_bpf_support();
        let capabilities = CollectorCapabilities {
            process: CapabilityLevel::Full,
            filesystem: CapabilityLevel::Full,
            network: CapabilityLevel::Full,
            dns: CapabilityLevel::Partial,
            memory: CapabilityLevel::Degraded,
            crypto: CapabilityLevel::Partial,
            kernel_telemetry: if has_bpf {
                CapabilityLevel::Full
            } else {
                CapabilityLevel::Unavailable
            },
        };

        Self {
            capabilities,
            buffer: EventRingBuffer::new(50_000),
            running: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
            target: None,
        }
    }
}

fn detect_bpf_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/sys/kernel/debug/tracing").exists() || Path::new("/sys/fs/bpf").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

impl Collector for LinuxCollector {
    fn name(&self) -> &'static str {
        "collector-linux"
    }

    fn capabilities(&self) -> CollectorCapabilities {
        self.capabilities.clone()
    }

    fn initialize(&mut self) -> Result<(), CollectorError> {
        Ok(())
    }

    fn start(&mut self, target: &TargetProcess) -> Result<(), CollectorError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(CollectorError::AlreadyRunning);
        }

        self.target = Some(target.clone());
        self.running.store(true, Ordering::SeqCst);

        let proc_identity = ProcessIdentity::new(
            target.pid,
            None,
            target.start_time_nanos,
            target.executable_path.to_string_lossy().to_string(),
            1,
        )
        .with_command_line(target.command_line.clone());

        let start_event = VirEvent::new(
            proc_identity.clone(),
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: target.executable_path.to_string_lossy().to_string(),
                command_line: target.command_line.clone(),
                working_directory: target
                    .working_directory
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string()),
                parent_pid: None,
                environment_keys: target.environment.keys().cloned().collect(),
            }),
            self.name(),
        );
        self.buffer.push(start_event);

        let is_running = self.running.clone();
        #[cfg(target_os = "linux")]
        let target_pid = target.pid;
        #[cfg(target_os = "linux")]
        let ring_buffer = self.buffer.clone();

        #[cfg(target_os = "linux")]
        let handle = thread::spawn(move || {
            let mut known_pids = BTreeSet::new();
            known_pids.insert(target_pid);

            while is_running.load(Ordering::Relaxed) {
                if let Ok(entries) = fs::read_dir(format!("/proc/{}/task", target_pid)) {
                    for entry in entries.flatten() {
                        if let Ok(tid_name) = entry.file_name().into_string() {
                            if let Ok(tid) = tid_name.parse::<u32>() {
                                known_pids.insert(tid);
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(150));
            }
        });

        #[cfg(not(target_os = "linux"))]
        let handle = thread::spawn(move || {
            while is_running.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
            }
        });

        self.worker_handle = Some(handle);
        Ok(())
    }

    fn poll_events(&mut self, max_events: usize) -> Result<Vec<VirEvent>, CollectorError> {
        Ok(self.buffer.drain(max_events))
    }

    fn stop(&mut self) -> Result<CollectorHealth, CollectorError> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(CollectorError::NotStarted);
        }

        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }

        let health = CollectorHealth {
            is_running: false,
            events_captured: self.buffer.total_received(),
            events_dropped: self.buffer.dropped_count(),
            error_count: 0,
            last_error_message: None,
        };

        Ok(health)
    }

    fn health(&self) -> CollectorHealth {
        CollectorHealth {
            is_running: self.running.load(Ordering::Relaxed),
            events_captured: self.buffer.total_received(),
            events_dropped: self.buffer.dropped_count(),
            error_count: 0,
            last_error_message: None,
        }
    }
}
