#[cfg(windows)]
use std::collections::BTreeSet;
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

pub struct WindowsCollector {
    capabilities: CollectorCapabilities,
    buffer: EventRingBuffer,
    running: Arc<AtomicBool>,
    worker_handle: Option<JoinHandle<()>>,
    target: Option<TargetProcess>,
}

impl Default for WindowsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsCollector {
    pub fn new() -> Self {
        let capabilities = CollectorCapabilities {
            process: CapabilityLevel::Full,
            filesystem: CapabilityLevel::Partial,
            network: CapabilityLevel::Partial,
            dns: CapabilityLevel::Partial,
            memory: CapabilityLevel::Degraded,
            crypto: CapabilityLevel::Partial,
            kernel_telemetry: CapabilityLevel::Unavailable,
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

impl Collector for WindowsCollector {
    fn name(&self) -> &'static str {
        "collector-windows"
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

        // Record Initial Target Process Start Event
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
        #[cfg(windows)]
        let target_pid = target.pid;
        #[cfg(windows)]
        let ring_buffer = self.buffer.clone();

        #[cfg(windows)]
        let handle = thread::spawn(move || {
            let mut known_pids = BTreeSet::new();
            known_pids.insert(target_pid);

            while is_running.load(Ordering::Relaxed) {
                // Poll child processes using Toolhelp32 snapshots
                let new_children = enumerate_child_processes(&known_pids);
                for (child_pid, parent_pid, exe_name) in new_children {
                    known_pids.insert(child_pid);

                    let child_identity = ProcessIdentity::new(
                        child_pid,
                        Some(parent_pid),
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
                        &exe_name,
                        1,
                    );

                    let spawn_event = VirEvent::new(
                        ProcessIdentity::new(parent_pid, None, 0, "parent", 1),
                        EventType::ProcessSpawn,
                        EventData::ProcessSpawn(ProcessSpawnData {
                            child_pid,
                            child_executable_path: exe_name.clone(),
                            command_line: vec![exe_name.clone()],
                        }),
                        "collector-windows",
                    );
                    ring_buffer.push(spawn_event);

                    let child_start_event = VirEvent::new(
                        child_identity,
                        EventType::ProcessStart,
                        EventData::ProcessStart(ProcessStartData {
                            executable_path: exe_name.clone(),
                            command_line: vec![exe_name],
                            working_directory: None,
                            parent_pid: Some(parent_pid),
                            environment_keys: Vec::new(),
                        }),
                        "collector-windows",
                    );
                    ring_buffer.push(child_start_event);
                }

                thread::sleep(Duration::from_millis(150));
            }
        });

        #[cfg(not(windows))]
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

#[cfg(windows)]
fn enumerate_child_processes(known_pids: &BTreeSet<u32>) -> Vec<(u32, u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut discovered = Vec::new();

    // SAFETY: CreateToolhelp32Snapshot is called with TH32CS_SNAPPROCESS to capture all processes.
    // The handle is checked against INVALID_HANDLE_VALUE and closed via CloseHandle.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return discovered;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                let ppid = entry.th32ParentProcessID;

                if known_pids.contains(&ppid) && !known_pids.contains(&pid) && pid != 0 {
                    let exe_len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let exe_name = String::from_utf16_lossy(&entry.szExeFile[..exe_len]);
                    discovered.push((pid, ppid, exe_name));
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    discovered
}
