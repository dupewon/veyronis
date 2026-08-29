use colored::*;
use tabled::{Table, Tabled};
use veyronis_collector_api::{CapabilityLevel, Collector, CollectorCapabilities};
use veyronis_ir::event::Platform;

#[derive(Tabled)]
struct CapabilityRow {
    #[tabled(rename = "Subsystem")]
    subsystem: String,
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Provider / Implementation")]
    provider: String,
}

pub struct PlatformDoctor;

impl PlatformDoctor {
    pub fn diagnose() {
        println!("{}", "VEYRONIS DOCTOR".bold().white());
        let platform = Platform::current();
        let os_info = format!("{} ({})", platform, std::env::consts::ARCH);
        println!("Platform:\n  {}\n", os_info.cyan());

        let collector_caps = Self::get_primary_collector_capabilities();

        let rows = vec![
            CapabilityRow {
                subsystem: "Process tracing".into(),
                status: format_level(collector_caps.process),
                provider: match platform {
                    Platform::Windows => "Windows Toolhelp32 & Process APIs".into(),
                    Platform::Linux => "Linux procfs & task tracking".into(),
                    Platform::MacOs => "macOS libproc & PID info".into(),
                    _ => "Portable supervisor".into(),
                },
            },
            CapabilityRow {
                subsystem: "Filesystem".into(),
                status: format_level(collector_caps.filesystem),
                provider: "Filesystem observation & normalization".into(),
            },
            CapabilityRow {
                subsystem: "Network".into(),
                status: format_level(collector_caps.network),
                provider: match platform {
                    Platform::Windows => "IP Helper TCP/UDP table polling".into(),
                    Platform::Linux => "Netlink & /proc/net sockets".into(),
                    _ => "Socket telemetry".into(),
                },
            },
            CapabilityRow {
                subsystem: "DNS".into(),
                status: format_level(collector_caps.dns),
                provider: "DNS query/response correlation".into(),
            },
            CapabilityRow {
                subsystem: "Memory".into(),
                status: format_level(collector_caps.memory),
                provider: "Virtual memory allocation sampling".into(),
            },
            CapabilityRow {
                subsystem: "Crypto tracing".into(),
                status: format_level(collector_caps.crypto),
                provider: "User-space safe crypto telemetry".into(),
            },
            CapabilityRow {
                subsystem: "Kernel telemetry".into(),
                status: format_level(collector_caps.kernel_telemetry),
                provider: match platform {
                    Platform::Linux => "eBPF (CAP_BPF required)".into(),
                    Platform::MacOs => "EndpointSecurity (Entitlement required)".into(),
                    _ => "Kernel drivers (N/A for user-space MVP)".into(),
                },
            },
            CapabilityRow {
                subsystem: "Artifact Crypto".into(),
                status: format_level(CapabilityLevel::Full),
                provider: "XChaCha20-Poly1305 + Argon2id + X25519".into(),
            },
            CapabilityRow {
                subsystem: "Signing".into(),
                status: format_level(CapabilityLevel::Full),
                provider: "Ed25519 Dalek v2 + BLAKE3 Merkle Tree".into(),
            },
        ];

        let table = Table::new(rows).to_string();
        println!("{}\n", table);

        println!("Status:\n  {}", "READY".green().bold());
    }

    fn get_primary_collector_capabilities() -> CollectorCapabilities {
        #[cfg(target_os = "windows")]
        {
            collector_windows::WindowsCollector::new().capabilities()
        }
        #[cfg(target_os = "linux")]
        {
            collector_linux::LinuxCollector::new().capabilities()
        }
        #[cfg(target_os = "macos")]
        {
            collector_macos::MacOsCollector::new().capabilities()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            collector_portable::PortableCollector::new().capabilities()
        }
    }
}

fn format_level(level: CapabilityLevel) -> String {
    match level {
        CapabilityLevel::Full => "FULL".green().bold().to_string(),
        CapabilityLevel::Partial => "PARTIAL".yellow().bold().to_string(),
        CapabilityLevel::Unavailable => "UNAVAILABLE".red().to_string(),
        CapabilityLevel::RequiresPrivilege => "REQUIRES_PRIVILEGE".yellow().to_string(),
        CapabilityLevel::RequiresEntitlement => "REQUIRES_ENTITLEMENT".yellow().to_string(),
        CapabilityLevel::Degraded => "DEGRADED".dimmed().to_string(),
    }
}
