<div align="center">

# ◈ VEYRONIS TELEMETRY COLLECTORS SPECIFICATION ◈

```text
 ██████╗ ██████╗ ██╗     ██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗ ███████╗
██╔════╝██╔═══██╗██║     ██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
██║     ██║   ██║██║     ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝███████╗
██║     ██║   ██║██║     ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗╚════██║
╚██████╗╚██████╔╝███████╗███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║███████║
 ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
```

**Cross-Platform Instrumentation • Ring 3 to Ring 0 • Zero-Overhead Capture**

</div>

---

# 🌐 1. Platform Matrix & Native Instrumentation

| Platform | Native Telemetry Collector | Mechanisms Used | Privilege Mode |
| :--- | :--- | :--- | :--- |
| **Windows 10 / 11 / Server** | `collector-windows` | `Toolhelp32Snapshot`, `IP Helper API`, `ETW Providers` | User-Mode / Admin |
| **Linux (Ubuntu / Debian / RHEL)** | `collector-linux` | `/proc/[pid]/stat`, `/proc/[pid]/maps`, `netlink`, `eBPF` | User-Mode / Root |
| **macOS (Intel & Apple Silicon)** | `collector-macos` | `libproc`, `proc_pidinfo`, `EndpointSecurity` | User-Mode / Root |
| **Cross-Platform Portable** | `collector-portable` | Process standard I/O & child supervisor | Unprivileged User |

---

# 🔍 2. Telemetry Capture Categories

1. **Process & Thread Operations:** `ProcessStart`, `ProcessExit`, `ProcessSpawn`, `ThreadCreate`.
2. **Filesystem Activity:** `FileOpen`, `FileRead`, `FileWrite`, `FileDelete`, `FileRename`.
3. **Network Egress & Ingress:** `SocketCreate`, `NetworkConnect`, `NetworkAccept`, `NetworkClose`.
4. **DNS & Resolution:** `DnsQuery`, `DnsResponse` (A, AAAA, CNAME).
5. **Memory Subsystems:** `MemoryMap`, `MemoryProtect` (RWX stagers, unbacked allocations).
6. **Cryptography & TLS:** `CryptoOperation` (AES, RSA, ECC, Hash), `TlsObserved` (JA3/JA4).
7. **IPC Channels:** `IpcConnect`, `IpcSend`, `NamedPipeOpen`.
