<div align="center">

# ◈ VEYRONIS SYSTEM ARCHITECTURE SPECIFICATION ◈

```text
█████╗ ██████╗  ██████╗██╗  ██╗██╗████████╗███████╗ ██████╗████████╗██╗   ██╗██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝██║  ██║██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
███████║██████╔╝██║     ███████║██║   ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝█████╗  
██╔══██║██╔══██╗██║     ██╔══██║██║   ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗██╔══╝  
██║  ██║██║  ██║╚██████╗██║  ██║██║   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
```

**25-Crate Pure Rust Workspace • Universal Telemetry Normalization • Cryptographic Pipelines**

</div>

---

# 🏛️ 1. Global Workspace Layering

Veyronis is engineered as a layered, decoupled system where ingestion, normalization, storage, cryptography, emulation, detection, and user interfaces reside in isolated crates:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            USER INTERFACE & PROTOCOLS                       │
│      veyronis-cli  │  veyronis-serve (Web SPA)  │  veyronis-mcp (JSON-RPC)   │
├─────────────────────────────────────────────────────────────────────────────┤
│                          FORENSIC & INVESTIGATION LAYER                     │
│    veyronis-ai (Local LLM) │ veyronis-emu (CPU JIT) │ veyronis-cluster (Hub) │
│    veyronis-detect (Sigma) │ veyronis-diff (Vectors)│ veyronis-query (VQL)   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         ORCHESTRATION & SESSION ENGINE                      │
│                veyronis-core   │   veyronis-daemon (Supervisor)             │
├─────────────────────────────────────────────────────────────────────────────┤
│                          DATA FORMAT & CRYPTOGRAPHY                         │
│   veyronis-format (.vyr) │ veyronis-crypto (AEAD/Merkle) │ veyronis-keystore │
├─────────────────────────────────────────────────────────────────────────────┤
│                    INTERMEDIATE REPRESENTATION & GRAPH                      │
│         veyronis-ir (VIR Telemetry)   │   veyronis-graph (Process Trees)    │
├─────────────────────────────────────────────────────────────────────────────┤
│                      CROSS-PLATFORM TELEMETRY COLLECTORS                    │
│   collector-windows  │  collector-linux  │  collector-macos  │  portable    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 📦 2. Crate Registry & Technical Responsibilities

| Crate | Responsibility | Key Structs & Functions |
| :--- | :--- | :--- |
| **`veyronis-cli`** | Command dispatcher, TUI terminal viewer (`ratatui`). | `Cli`, `execute`, `TuiViewer` |
| **`veyronis-mcp`** | Model Context Protocol server exposing DFIR tools via stdio. | `McpServer::run_stdio`, `tools/list` |
| **`veyronis-ai`** | Autonomous incident investigation & YARA/Sigma rule generation. | `IncidentExplainer::explain` |
| **`veyronis-emu`** | Isolated x86/x64 virtual memory and register emulator. | `ShellcodeEmulator::emulate` |
| **`veyronis-cluster`** | Multi-node endpoint clustering and incident hub. | `ClusterHub`, `FleetNode` |
| **`veyronis-core`** | Session recorder, doctor diagnostics, multi-format exporters. | `RecordSession`, `VyrInspector` |
| **`veyronis-parser`** | PE/ELF/Mach-O section parsing, Shannon entropy & unpacker. | `BinaryInspector`, `MemoryUnpacker` |
| **`veyronis-shim`** | Anti-anti-debug spoofing & RDTSC time-dilation layer. | `IsDebuggerPresent`, `TimeDilation` |
| **`veyronis-serve`** | Embedded HTTP web server & interactive single-page dashboard. | `VeyronisServer::start` |
| **`veyronis-daemon`** | Continuous system-wide supervisor with incident ring buffers. | `VeyronisDaemon::run` |
| **`veyronis-detect`** | Sigma rule evaluation, JA3/DGA checks, Direct Syscall hunter. | `DetectionEngine`, `SyscallHunter` |
| **`veyronis-ffi`** | C-ABI dynamic library (`libveyronis`) for external language bindings. | `vyr_open_artifact`, `vyr_verify` |
| **`veyronis-ir`** | Universal Intermediate Representation schema & canonical hashing. | `VirEvent`, `ProcessIdentity` |
| **`veyronis-graph`** | Directed acyclic behavior graph & process tree hierarchies. | `BehaviorGraph`, `ProcessTree` |
| **`veyronis-crypto`** | AEAD cipher primitives, Merkle trees, Shamir $k$-of-$n$, RFC 3161. | `AeadEnvelope`, `ShamirEngine` |
| **`veyronis-format`** | `.vyr` proprietary container parser, chunk encoder & reader. | `VyrWriter`, `VyrReader` |
| **`veyronis-keystore`** | Local secure key store with Argon2id passphrase wrapping. | `KeyStore`, `KeyMetadata` |
| **`veyronis-policy`** | Privacy classification and sensitive credential redaction. | `PolicyEngine`, `Redactor` |
| **`veyronis-query`** | VQL AST lexer, parser, and boolean predicate evaluator. | `Parser::parse_str`, `QueryEngine` |
| **`veyronis-diff`** | 32-dimensional behavioral graph vector embedding & cosine diff. | `BehaviorEmbedding`, `DiffEngine` |
| **`collector-*`** | Native OS event capture (Toolhelp32, procfs, eBPF, libproc). | `CollectorSession`, `EventBuffer` |

---

# 🔄 3. Telemetry Normalization Pipeline (VIR)

1. **Native Acquisition:** OS collectors read kernel snapshots and event streams.
2. **Identity Synthesis:** Assigns deterministic, monotonic `ProcessIdentity` (PID, parent PID, executable path, start timestamp, security context).
3. **Canonical Normalization:** Paths are canonicalized, IP addresses parsed into standard `IpAddr`, timestamps aligned to monotonic and wall clock nanoseconds.
4. **Privacy Scrubbing:** Sensitive keys (`SENSITIVE`, `SECRET`) are dropped before block serialization.
5. **Graph Ingestion:** Events insert directed causal edges (Parent -> Child, Process -> Network, Process -> File).

---

# 🔒 4. Container Storage Flow (.vyr)

```text
VIR Events -> Chunk Buffer (4 KB) -> Compression (zstd/none) ->
AEAD XChaCha20-Poly1305 (with AAD: Artifact UUID + Block Index) ->
BLAKE3 Block Hash -> Merkle Tree Root Computation ->
Ed25519 Signature over Merkle Root -> Stream to Disk (.vyr)
```
