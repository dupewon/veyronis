<div align="center">

# ◈ VEYRONIS ◈

```text
██╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ███╗   ██╗██╗███████╗
██║   ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗████╗  ██║██║██╔════╝
██║   ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║██╔██╗ ██║██║███████╗
╚██╗ ██╔╝██╔══╝    ╚██╔╝  ██╔══██╗██║   ██║██║╚██╗██║██║╚════██║
 ╚████╔╝ ███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║██║███████║
  ╚═══╝  ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚══════╝
```

### Universal Verifiable Security Behavior Engine & Autonomous AI Analyst

**Record. Normalize. Preserve. Compare. Emulate. Verify.**

<br>

![Status](https://img.shields.io/badge/STATUS-PRODUCTION%20MVP-success?style=for-the-badge)
![Version](https://img.shields.io/badge/VERSION-0.1.0-blue?style=for-the-badge)
![Core](https://img.shields.io/badge/CORE-PURE%20RUST-black?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/LICENSE-AGPL--3.0-663399?style=for-the-badge)

<br>

![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-0078D6?style=flat-square&logo=windows)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%20%7C%20Debian%20%7C%20Arch%20%7C%20RHEL-FCC624?style=flat-square&logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/macOS-Intel%20%7C%20Apple%20Silicon-000000?style=flat-square&logo=apple)
![Local](https://img.shields.io/badge/LOCAL-FIRST%20%28AIR--GAPPED%29-success?style=flat-square)
![Format](https://img.shields.io/badge/FORMAT-.VYR%20CONTAINER-blueviolet?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-JSON--RPC%202.0-orange?style=flat-square)
![Interface](https://img.shields.io/badge/INTERFACE-CLI%20%7C%20TUI%20%7C%20WEB%20SPA-informational?style=flat-square)

<br>

[ **English** ] · [ **Türkçe** ]

<br>

> ### Observe what software actually does in real-time.
> ### Preserve telemetry as mathematically tamper-evident evidence.
> ### Investigate, query, diff, emulate, and verify locally without cloud dependency.

<br>

**CheatGlobal:** `whuq`  
**GitHub:** [`dupewon`](https://github.com/dupewon)  
**YouTube:** [`dupewon`](https://youtube.com/@dupewon)

</div>

---

# 📑 Table of Contents

- [📌 1. Overview & Core Philosophy](#-1-overview--core-philosophy)
- [❓ 2. The Fundamental Problem in Telemetry](#-2-the-fundamental-problem-in-telemetry)
- [🧠 3. The Unified Semantic Architecture](#-3-the-unified-semantic-architecture)
- [⚙️ 4. How It Works: The Execution Pipeline](#-4-how-it-works-the-execution-pipeline)
- [🏗️ 5. Workspace Architecture (25 Specialized Crates)](#-5-workspace-architecture-25-specialized-crates)
- [🤖 6. Model Context Protocol (MCP) Multi-Language Ecosystem](#-6-model-context-protocol-mcp-multi-language-ecosystem)
- [🖥️ 7. Full CLI Command & Subcommand Reference](#-7-full-cli-command--subcommand-reference)
- [📦 8. VYR Binary Container Specification (.vyr)](#-8-vyr-binary-container-specification-vyr)
- [🔐 9. Cryptographic Primitives & Key Management](#-9-cryptographic-primitives--key-management)
- [🔎 10. VQL — Veyronis Query Language](#-10-vql--veyronis-query-language)
- [🔬 11. Static PE/ELF Forensics, Shannon Entropy & In-Memory Unpacker](#-11-static-peelf-forensics-shannon-entropy--in-memory-unpacker)
- [🛡️ 12. Direct Syscall Hunter & Evasion Shim](#-12-direct-syscall-hunter--evasion-shim)
- [🧬 13. Isolated x86/x64 Virtual CPU Shellcode Emulator](#-13-isolated-x86x64-virtual-cpu-shellcode-emulator)
- [🌐 14. Interactive Local Web Dashboard & REST API Server](#-14-interactive-local-web-dashboard--rest-api-server)
- [🏢 15. Distributed Fleet Clustering Hub](#-15-distributed-fleet-clustering-hub)
- [🔌 16. Reverse Engineering Plugins (Ghidra & IDA Pro)](#-16-reverse-engineering-plugins-ghidra--ida-pro)
- [🐍 17. Python SDK Reference](#-17-python-sdk-reference)
- [🔨 18. Compilation & Installation Guide](#-18-compilation--installation-guide)
- [📜 19. License & Open Source Integrity](#-19-license--open-source-integrity)
- [👤 20. Credits & Authorship](#-20-credits--authorship)

---

# 📌 1. Overview & Core Philosophy

**Veyronis** is an enterprise-grade, local-first, verifiable runtime behavior analysis platform, static binary inspector, automated in-memory unpacker, virtual CPU shellcode emulator, and autonomous AI incident response engine written entirely in pure **Rust**.

Instead of leaving process trees, filesystem mutations, network egress, DNS resolutions, IPC calls, memory permission swaps, and cryptographic operations scattered across fragmented OS-specific event logs, Veyronis connects every observation into a deterministic, queryable **Behavior Graph** and packages it into an encrypted, tamper-evident `.vyr` binary container.

```text
             ONE EXECUTABLE / ARTIFACT
                        │
                        ▼
             REAL RUNTIME BEHAVIOR
                        │
                        ▼
            NORMALIZED VIR TELEMETRY
                        │
                        ▼
             DIRECTED BEHAVIOR GRAPH
                        │
                        ▼
             ENCRYPTED .VYR CONTAINER
                        │
        ┌───────────────┼───────────────┬───────────────┐
        │               │               │               │
        ▼               ▼               ▼               ▼
     INSPECT          QUERY           DIFF           EXPLAIN
   (TUI & Web)        (VQL)        (Vectors)        (Local AI)
        │               │               │               │
        └───────────────┼───────────────┴───────────────┘
                        │
                        ▼
             CRYPTOGRAPHIC VERIFY
         (Ed25519 + Merkle Root + AEAD)
```

---

# ❓ 2. The Fundamental Problem in Telemetry

Modern software—and modern malware—executes dynamically across disparate operating systems:

```text
Processes spawn children -> Read configuration -> Resolve external domains ->
Establish TLS handshakes -> Allocate executable RWX memory -> Execute direct syscalls ->
Encrypt user files -> Terminate processes
```

Traditionally, observing this lifecycle requires completely disparate tooling:
* On **Windows**: ETW, Sysmon, Event Log, Toolhelp32, Process Explorer.
* On **Linux**: `procfs`, `sysfs`, `netlink`, `perf_events`, `eBPF`.
* On **macOS**: `libproc`, `EndpointSecurity`, `DTrace`.

Even when the high-level semantic intent is identical, raw OS telemetry formats share zero commonality.

> **Veyronis Core Thesis:** Platform-specific telemetry collection and platform-independent behavioral analysis must be decoupled into independent engineering layers.

---

# 🧠 3. The Unified Semantic Architecture

Veyronis normalizes all platform-specific telemetry into **VIR (Veyronis Intermediate Representation)**:

```text
PROCESS.START
      │
      ├── FILE.READ (Config / Credential)
      │
      ├── DNS.QUERY (api.c2server.org)
      │       │
      │       └── DNS.RESPONSE (Resolved IP)
      │
      ├── NET.CONNECT (TCP 443 Outbound)
      │       │
      │       └── CRYPTO.TLS (JA3 Fingerprint)
      │
      ├── MEMORY.MAP (RWX Memory Stager)
      │       │
      │       └── DETECT.SYSCALL (Hell's Gate Bypass)
      │
      └── PROCESS.EXIT
```

---

# ⚙️ 4. How It Works: The Execution Pipeline

```text
┌─────────────────────────────────────────────────────────────────┐
│                 TARGET APPLICATION / MALWARE SAMPLE             │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      NATIVE OS COLLECTORS                       │
│    Windows (Toolhelp32/IPHelper) │ Linux (procfs/eBPF) │ macOS  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│            VIR NORMALIZATION & PRIVACY CLASSIFICATION           │
│       (Redacts secret keys, enforces categorical schemas)       │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   DIRECTED BEHAVIOR GRAPH                       │
│      (Nodes: Processes, Files, Sockets | Edges: Causality)      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  .VYR FORENSIC CONTAINER ENGINE                 │
│  AEAD XChaCha20-Poly1305 -> BLAKE3 Tree -> Ed25519 Signatures   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
                        evidence.vyr
```

---

# 🏗️ 5. Workspace Architecture (25 Specialized Crates)

The Veyronis workspace is strictly decoupled into **25 standalone pure-Rust crates**:

```text
veyronis/
├── crates/
│   ├── veyronis-cli/            # Main CLI binary, ratatui TUI, and subcommand dispatcher
│   ├── veyronis-mcp/            # Model Context Protocol (MCP) JSON-RPC 2.0 stdio server
│   ├── veyronis-ai/             # Autonomous local AI incident explainer & rule synthesizer
│   ├── veyronis-emu/            # Isolated x86/x64 virtual CPU shellcode & ROP emulator
│   ├── veyronis-cluster/        # Multi-node fleet clustering hub & telemetry ingestion
│   ├── veyronis-core/           # Orchestrator, session recorder, scan runner, multi-format exporter
│   ├── veyronis-parser/         # PE/ELF/Mach-O static forensics, Shannon entropy & unpacker
│   ├── veyronis-shim/           # Anti-Anti-Debug & time-dilation evasion layer
│   ├── veyronis-serve/          # Embedded local web visualizer server & REST API (`veyronis serve`)
│   ├── veyronis-daemon/         # Continuous background ring-buffer supervisor (`veyronis daemon`)
│   ├── veyronis-detect/         # Threat detection engine (Sigma rules, JA3, DGA, SyscallHunter)
│   ├── veyronis-ffi/            # C-ABI shared library (libveyronis.so / veyronis.dll)
│   ├── veyronis-ir/             # Universal Intermediate Representation (VIR) data models
│   ├── veyronis-graph/          # Deterministic directed behavior graph & process trees
│   ├── veyronis-crypto/         # XChaCha20, Argon2id, X25519, Ed25519, Merkle, Shamir, RFC3161
│   ├── veyronis-format/         # .vyr proprietary binary container parser & writer
│   ├── veyronis-keystore/       # Local secure encrypted key storage (~/.veyronis/keys/)
│   ├── veyronis-policy/         # Privacy classification and field redaction engine
│   ├── veyronis-query/          # VQL AST parser and execution engine
│   ├── veyronis-diff/           # Semantic behavioral comparison engine & vector embeddings
│   ├── veyronis-collector-api/  # Universal collector trait and bounded event ring buffer
│   ├── collector-windows/       # Windows native Toolhelp32 & IP Helper collector
│   ├── collector-linux/         # Linux native procfs & eBPF collector
│   ├── collector-macos/         # macOS native libproc collector
│   └── collector-portable/      # Baseline portable child supervisor
├── mcp/                         # Multi-language MCP bridges (Node.js, Python, Go, PHP)
├── rules/                       # Sigma detection rules (Ransomware, C2, Direct Syscall, etc.)
├── plugins/                     # Ghidra and IDA Pro runtime telemetry overlay scripts
├── sdk/python/                  # Python SDK package (`veyronis`)
└── examples/fixtures/           # 6 cross-platform test fixtures
```

---

# 🤖 6. Model Context Protocol (MCP) Multi-Language Ecosystem

Veyronis provides a native **JSON-RPC 2.0 stdio MCP server** (`veyronis mcp`). Any AI client (Claude Desktop, Cursor, Ollama, LangChain, OpenAI, AutoGen) can invoke Veyronis tools directly.

### 🌐 Ready-to-Use Multi-Language Bridges:

| Language | Path | Usage |
| :--- | :--- | :--- |
| 🟢 **Node.js / TS** | `mcp/nodejs/index.js` | `node mcp/nodejs/index.js` |
| 🐍 **Python** | `mcp/python/veyronis_mcp.py` | `python mcp/python/veyronis_mcp.py` |
| 🦀 **Rust (Native)** | `crates/veyronis-mcp` | `veyronis mcp` |
| 🐹 **Go** | `mcp/go/main.go` | `go run mcp/go/main.go` |
| 🐘 **PHP** | `mcp/php/veyronis_mcp.php` | `php mcp/php/veyronis_mcp.php` |

### 🛠️ Exposed MCP Forensic Tools:
1. `veyronis_inspect`: Returns container UUID, Merkle root, event counts, signing state.
2. `veyronis_query`: Executes VQL queries (e.g., `FIND event WHERE type = 'NetworkConnect'`).
3. `veyronis_scan`: Scans container against behavioral Sigma rules and maps MITRE ATT&CK.
4. `veyronis_analyze_binary`: Analyzes PE/ELF/Mach-O sections and Shannon entropy.
5. `veyronis_diff`: Performs semantic behavioral comparison between two artifacts.
6. `veyronis_generate_rules`: Synthesizes automated YARA and Sigma rules from live traces.
7. `veyronis_deobfuscate`: Eliminates opaque predicates, strips dead code, and recovers stack strings.
8. `veyronis_convert_dump_to_pe`: Reconstructs memory dumps (`.dmp`) into valid loadable PE `.exe` files.
9. `veyronis_vmp_unpack`: Analyzes VMProtect architecture, traces VIP/VSP bytecode, and unpacks stubs.

---

# 🖥️ 7. Full CLI Command & Subcommand Reference

### 1. Key Management
```bash
# Generate asymmetric Ed25519 and X25519 identity
veyronis keygen --name default

# List public keys in local keystore
veyronis key list

# Inspect public credentials
veyronis key inspect --name default
```

### 2. Runtime Telemetry Recording
```bash
# Record live execution into an encrypted .vyr container
veyronis record --output capture.vyr -- curl.exe https://api.github.com

# Record with threshold encryption and simulated threat injection for rule validation
veyronis record --output session.vyr --inject-threat ransomware -- ./target/release/crypto-test.exe
```

### 3. Inspection & Cryptographic Verification
```bash
# Inspect container headers, process tree, and summary
veyronis inspect capture.vyr

# Verify cryptographic AEAD tags, Merkle root hash, and Ed25519 signature
veyronis verify capture.vyr
```

### 4. Autonomous AI Incident Response & Rule Generation
```bash
# Generate executive summary, observations, mitigation plan, and YARA rule
veyronis explain capture.vyr
```

### 5. Isolated CPU Shellcode Emulation
```bash
# Step-execute shellcode in isolated virtual RAM & registers
veyronis emulate payload.bin --max-instructions 500
```

### 6. Behavioral Threat Scanning
```bash
# Scan container against Sigma rules & MITRE ATT&CK mappings
veyronis scan capture.vyr --rules rules/
```

### 7. Static Binary Analysis, Deobfuscation & Memory Dump Reconstructor
```bash
# Analyze PE/ELF/Mach-O sections and calculate Shannon entropy
veyronis analyze suspicious_binary.exe

# Deobfuscate code, eliminate opaque predicates, unflatten CFF dispatchers, recover stack strings
veyronis deobfuscate obfuscated_sample.bin --output deobfuscated_clean.bin

# Reconstruct raw memory dump (.dmp / minidump / process page) to loadable Windows PE executable (.exe)
veyronis dmp2pe memory.dmp --output reconstructed.exe --oep 0x1000

# Analyze VMProtect 2.x/3.x architecture, trace VIP/VSP bytecode, and unpack virtualization stubs
veyronis vmp protected_sample.exe --unpack --output vmp_unpacked.exe --devirtualize
```

### 8. RFC 3161 Cryptographic Timestamping
```bash
# Issue an RFC 3161 digital timestamp token for legal evidence
veyronis timestamp capture.vyr
```

### 9. Behavioral Vector Similarity Search
```bash
# Search corpus of .vyr archives for variants (Cosine Similarity >= 85%)
veyronis search capture.vyr --corpus /archive/vyr_corpus/ --threshold 0.85
```

### 10. Interactive Web Dashboard & TUI Viewer
```bash
# Launch local Web SPA dashboard on port 8080
veyronis serve capture.vyr --port 8080

# Launch interactive terminal UI (TUI)
veyronis view capture.vyr
```

### 11. Multi-Format Exporters
```bash
veyronis export capture.vyr --format html --output report.html
veyronis export capture.vyr --format stix --output stix_bundle.json
veyronis export capture.vyr --format sarif --output results.sarif
veyronis export capture.vyr --format ndjson --output events.ndjson
veyronis export capture.vyr --format csv --output events.csv
```

### 12. Threshold Cryptography (k-of-n Shamir Secret Sharing)
```bash
# Split master passphrase into 3-of-5 custodian shares
veyronis threshold split --secret "MasterPassphrase2026" -k 3 -n 5

# Reconstruct original secret from k shares
veyronis threshold combine VYR-SHARE-01... VYR-SHARE-02... VYR-SHARE-03...
```

---

# 📦 8. VYR Binary Container Specification (.vyr)

The `.vyr` container is designed to be versioned, streaming-compatible, encrypted, authenticated, and mathematically tamper-evident.

```text
┌────────────────────────────────────────────────────────┐
│                   VYR CONTAINER HEADER                 │
│      Magic Bytes (0x56 0x59 0x52 0x31 -> "VYR1")       │
│      Format Version (0x0100)                           │
│      Artifact UUID (128-bit RFC 4122 v4)               │
│      Created Timestamp (Unix Epoch Seconds)            │
│      Header Flags (ENCRYPTED | SIGNED | COMPRESSED)    │
├────────────────────────────────────────────────────────┤
│                      KEY ENVELOPE                      │
│      Recipient Public Keys (X25519 / Ephemeral)        │
│      Argon2id Salt & KDF Parameters                    │
│      Encrypted Content Master Key                      │
├────────────────────────────────────────────────────────┤
│                   ENCRYPTED MANIFEST                   │
│      Host Identity, OS Build, CPU Arch, Collectors     │
├────────────────────────────────────────────────────────┤
│                    ENCRYPTED INDEX                     │
│      Event Offsets, Types, Chunk Index Lookup Table    │
├────────────────────────────────────────────────────────┤
│               ENCRYPTED EVENT BLOCKS (1..N)            │
│      Block Header (Index, Type, Length)                │
│      AEAD Ciphertext (XChaCha20-Poly1305)              │
│      Poly1305 Authentication Tag (16 bytes)            │
├────────────────────────────────────────────────────────┤
│                  INTEGRITY STRUCTURE                   │
│      BLAKE3 Merkle Tree of All Block Hashes            │
│      Merkle Root Hash (32 bytes)                       │
├────────────────────────────────────────────────────────┤
│                   SIGNATURE TRAILER                    │
│      Ed25519 Public Key (32 bytes)                     │
│      Ed25519 Digital Signature (64 bytes)              │
└────────────────────────────────────────────────────────┘
```

---

# 🔐 9. Cryptographic Primitives & Key Management

Veyronis uses only established, audited cryptographic primitives:

| Purpose | Technology / Primitive | Security Strength |
| :--- | :--- | :--- |
| **Content Encryption** | XChaCha20-Poly1305 (AEAD) | 256-bit Key / 192-bit Nonce |
| **Alternative AEAD** | AES-256-GCM | 256-bit Key / 96-bit Nonce |
| **Password Hashing** | Argon2id | Memory-hard ($m=65536, t=3, p=4$) |
| **Key Agreement** | X25519 (ECDH) | 128-bit Security (Curve25519) |
| **Digital Signatures** | Ed25519 (EdDSA) | 128-bit Security |
| **Cryptographic Hashing** | BLAKE3 | 256-bit Tree Hash |
| **Threshold Secret Sharing** | Shamir's Scheme over $\text{GF}(256)$ | Information-Theoretic Security |
| **Timestamping** | RFC 3161 Cryptographic Token | Ed25519 / Merkle Root Binding |

---

# 🔎 10. VQL — Veyronis Query Language

VQL allows querying structured behavioral events rather than raw text logs.

```sql
-- Find all outbound network connections
FIND event WHERE type = "NetworkConnect"

-- Find events where a specific process wrote to files
FIND event WHERE process.name = "malware.exe" AND type = "FileWrite"

-- Find cryptographic hashing operations using SHA-256
FIND event WHERE type = "CryptoOperation" AND crypto.algorithm = "SHA256"

-- Find external IP connections
FIND process WHERE network.external = true
```

---

# 🔬 11. Static PE/ELF Forensics, Shannon Entropy & In-Memory Unpacker

### Shannon Entropy Calculation ($H$):
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* **$H < 6.0$:** Normal code / data sections.
* **$H \ge 7.2$:** High-entropy section indicating custom packing, obfuscation, or encryption.

```bash
veyronis analyze ./malware_sample.exe
# Flags packed sections (.upx, .themida, .vmp, custom packers)
```

### Automated In-Memory Unpacking (`veyronis unpack`):
1. Reads in-memory decrypted image.
2. Re-aligns virtual section headers to raw disk offsets.
3. Fixes Original Entry Point (OEP) and repairs ImageBase.
4. Dumps runnable, clean unpacked executable to disk.

---

# 🛡️ 12. Direct Syscall Hunter & Evasion Shim

### Direct Syscall Hunter (`crates/veyronis-detect`):
Detects EDR user-mode API hook bypasses (Hell's Gate, Halo's Gate, SysWhispers) by flagging:
* Unbacked memory execution outside of `ntdll.dll` / `kernel32.dll`.
* Transitions to `PAGE_EXECUTE_READWRITE` (RWX) permissions.

### Anti-Anti-Debug & Time-Dilation Shim (`crates/veyronis-shim`):
* Neutralizes `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and `NtQueryInformationProcess`.
* Virtualizes CPU clock cycles / RDTSC time to bypass sleep delays (10-minute delays bypassed in 0ms).

---

# 🧬 13. Isolated x86/x64 Virtual CPU Shellcode Emulator

Emulate raw binary shellcode without executing it on the host OS:
* Initializes a 64 KB isolated virtual RAM initialized with NOPs.
* Virtualizes CPU registers: `RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `RSP`, `RBP`, `RIP`.
* Identifies NOP sleds and XOR decoding loops.
* Extracts decrypted payload strings from virtual RAM.

```bash
veyronis emulate shellcode.bin --max-instructions 500
```

---

# 🌐 14. Interactive Local Web Dashboard & REST API Server

```bash
veyronis serve capture.vyr --port 8080
```

Open your browser at **`http://127.0.0.1:8080`**:
* **Overview & Security:** Executive metrics, Merkle root, risk gauge (0-100).
* **Process Lineage Tree:** Interactive parent-child execution graph.
* **Normalized VIR Events:** Searchable, filterable event table.
* **MITRE ATT&CK Matrix:** Color-coded adversary TTP mapping.
* **VQL Query Console:** Live in-browser behavioral query runner.

---

# 🏢 15. Distributed Fleet Clustering Hub

Manage thousands of enterprise endpoints running Veyronis daemons:
```bash
# Register an endpoint node
veyronis cluster register --hostname server-01 --ip 192.168.1.50 --os "Linux Ubuntu 24.04"

# Check cluster status
veyronis cluster status
```

---

# 🔌 16. Reverse Engineering Plugins (Ghidra & IDA Pro)

Overlay runtime VIR events, memory hits, and execution heatmaps directly onto decompiler listings:
* **Ghidra Plugin:** `plugins/ghidra/veyronis_ghidra.py`
* **IDA Pro Plugin:** `plugins/ida/veyronis_ida.py`

---

# 🐍 17. Python SDK Reference

```python
from veyronis import VyrReader

# Open and verify forensic artifact
reader = VyrReader.open_file("session.vyr")
decrypted = reader.decrypt_with_passphrase("")

print(f"Artifact UUID: {decrypted.header.artifact_uuid}")
print(f"Total Events: {len(decrypted.events)}")

for event in decrypted.events:
    print(f"[{event.event_type}] {event.process_identity.canonical_name()}")
```

---

# 🔨 18. Compilation & Installation Guide

### Prerequisites:
* Rust toolchain `1.75+` (`cargo`, `rustc`)

### Build Steps:
```bash
# 1. Clone repository
git clone https://github.com/dupewon/veyronis.git
cd veyronis

# 2. Run full workspace test suite (25 crates)
cargo test --workspace

# 3. Compile optimized release binaries
cargo build --release --workspace

# 4. Binary location
./target/release/veyronis --help
```

---

# 📜 19. License & Open Source Integrity

Veyronis is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

```text
SPDX-License-Identifier: AGPL-3.0-only
```

Improvements made to the open-source engine must remain open to the security community.

---

# 👤 20. Credits & Authorship

<div align="center">

## ◈ VEYRONIS ◈

### Universal Verifiable Security Behavior Engine

```text
RECORD ──► NORMALIZE ──► PRESERVE ──► ANALYZE ──► EMULATE ──► VERIFY
```

<br>

**Lead Architect & Developer**  
`whuq`

**CheatGlobal:** [`whuq`](https://cheatglobal.com)  
**GitHub:** [`dupewon`](https://github.com/dupewon)  
**YouTube:** [`dupewon`](https://youtube.com/@dupewon)

<br>

---

### Windows • Linux • macOS • Apple Silicon
### Pure Rust • VIR • VYR • VQL • MCP • AGPL-3.0
### Local-First • Cryptographically Verifiable

---

> **Something different has been built.**

### Built from Türkiye. Designed for everywhere.

</div>
