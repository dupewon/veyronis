pub mod tui;

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use tabled::{Table, Tabled};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use tui::TuiViewer;
use veyronis_ai::IncidentExplainer;
use veyronis_cluster::{render_cluster_status, ClusterHub};
use veyronis_core::{
    PlatformDoctor, RecordSession, RecordSessionOptions, VyrExporter, VyrInspector, VyrScanner,
    VyrVerifier,
};
use veyronis_crypto::{SecretShare, ShamirEngine, TimestampAuthority};
use veyronis_daemon::{DaemonOptions, VeyronisDaemon};
use veyronis_detect::DetectionEngine;
use veyronis_diff::{BehaviorEmbedding, DiffEngine};
use veyronis_emu::ShellcodeEmulator;
use veyronis_format::VyrReader;
use veyronis_keystore::KeyStore;
use veyronis_mcp::McpServer;
use veyronis_parser::{
    BinaryInspector, DeobfuscationEngine, DumpToPeConverter, DumpToPeOptions, MemoryUnpacker,
    VmProtectAnalyzer,
};
use veyronis_query::{Parser as VqlParser, QueryEngine};
use veyronis_serve::VeyronisServer;

#[derive(Parser)]
#[command(
    name = "veyronis",
    author = "dupewon <whuq@cheatglobal>",
    version = "0.1.0",
    about = "Universal Verifiable Security Behavior Engine",
    long_about = "Veyronis records runtime behavior, normalizes telemetry into VIR, stores tamper-evident .vyr artifacts, and provides behavioral threat intelligence."
)]
struct Cli {
    #[arg(short = 'v', action = clap::ArgAction::Count, global = true, help = "Increase logging verbosity (-v, -vv, -vvv)")]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Display version, build, and platform information")]
    Version,

    #[command(about = "Diagnose host system telemetry capabilities and cryptographic providers")]
    Doctor,

    #[command(
        about = "Start standard Model Context Protocol (MCP) JSON-RPC stdio server for AI agents"
    )]
    Mcp,

    #[command(about = "Generate an autonomous AI incident explanation and remediation plan")]
    Explain {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(short, long, help = "Optional passphrase to decrypt artifact")]
        passphrase: Option<String>,
    },

    #[command(about = "Emulate isolated x86/x64 shellcode in a virtual CPU environment")]
    Emulate {
        #[arg(help = "Path to raw binary shellcode file")]
        shellcode_file: PathBuf,

        #[arg(
            short,
            long,
            default_value = "500",
            help = "Maximum virtual CPU instructions to step"
        )]
        max_instructions: usize,
    },

    #[command(about = "Manage distributed fleet cluster hub and node telemetry")]
    Cluster {
        #[command(subcommand)]
        command: ClusterCommands,
    },

    #[command(
        about = "Execute a child process and record runtime behavioral telemetry into a .vyr artifact"
    )]
    Record {
        #[arg(short, long, help = "Custom output path for the .vyr artifact")]
        output: Option<PathBuf>,

        #[arg(
            short,
            long,
            help = "Keystore key label for artifact signing and encryption"
        )]
        key: Option<String>,

        #[arg(short, long, help = "Optional passphrase for envelope encryption")]
        passphrase: Option<String>,

        #[arg(
            long,
            help = "Inject simulated threat pattern for rule testing (ransomware, c2)"
        )]
        inject_threat: Option<String>,

        #[arg(
            trailing_var_arg = true,
            required = true,
            help = "Target command and arguments to record (e.g. -- curl https://example.com)"
        )]
        command: Vec<String>,
    },

    #[command(
        about = "Inspect container metadata, process tree, network flows, and cryptographic operations"
    )]
    Inspect {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(short, long, help = "Keystore key label to decrypt artifact")]
        key: Option<String>,

        #[arg(short, long, help = "Passphrase to decrypt artifact")]
        passphrase: Option<String>,
    },

    #[command(
        about = "Verify container structure, AEAD tags, Merkle tree root, and Ed25519 signature"
    )]
    Verify {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,
    },

    #[command(
        about = "Scan .vyr artifact against behavioral security detection rules and MITRE ATT&CK"
    )]
    Scan {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(short, long, help = "Directory of custom YAML/Sigma detection rules")]
        rules: Option<PathBuf>,

        #[arg(short, long, help = "Keystore key label to decrypt artifact")]
        key: Option<String>,

        #[arg(short, long, help = "Passphrase to decrypt artifact")]
        passphrase: Option<String>,
    },

    #[command(
        about = "Perform static binary inspection, PE/ELF/Mach-O parsing, and Shannon entropy analysis"
    )]
    Analyze {
        #[arg(help = "Path to target binary file")]
        binary: PathBuf,
    },

    #[command(about = "Automated in-memory unpacked PE dumper and header reconstructor")]
    Unpack {
        #[arg(help = "Path to packed binary file")]
        binary: PathBuf,

        #[arg(
            short,
            long,
            default_value = "unpacked_dump.exe",
            help = "Destination path for reconstructed unpacked binary"
        )]
        output: PathBuf,
    },

    #[command(
        name = "deobfuscate",
        about = "Deobfuscate code, strip opaque predicates, unflatten control flow, and recover stack strings"
    )]
    Deobfuscate {
        #[arg(help = "Path to binary or extracted code block to deobfuscate")]
        input: PathBuf,

        #[arg(
            short,
            long,
            default_value = "deobfuscated_clean.bin",
            help = "Output path for cleaned binary"
        )]
        output: PathBuf,
    },

    #[command(
        name = "dmp2pe",
        about = "Convert memory dump (.dmp / minidump / process page) to a reconstructed, loadable PE executable"
    )]
    Dmp2Pe {
        #[arg(help = "Path to .dmp memory dump file")]
        dump_file: PathBuf,

        #[arg(
            short,
            long,
            default_value = "reconstructed.exe",
            help = "Output path for reconstructed .exe"
        )]
        output: PathBuf,

        #[arg(long, help = "Custom Original Entry Point (OEP) RVA (e.g. 0x1000)")]
        oep: Option<String>,

        #[arg(long, help = "Skip Import Address Table (IAT) reconstruction")]
        no_iat_rebuild: bool,
    },

    #[command(
        about = "Analyze VMProtect architecture, trace VIP/VSP bytecode, and unpack virtualization stubs"
    )]
    Vmp {
        #[arg(help = "Path to VMProtected PE binary")]
        binary: PathBuf,

        #[arg(short, long, help = "Unpack and dump reconstructed PE to disk")]
        unpack: bool,

        #[arg(
            short,
            long,
            default_value = "vmp_unpacked.exe",
            help = "Destination path for unpacked binary"
        )]
        output: PathBuf,

        #[arg(long, help = "Devirtualize and disassemble virtual bytecode handlers")]
        devirtualize: bool,
    },

    #[command(about = "Issue or verify an RFC 3161 cryptographic timestamp token for an artifact")]
    Timestamp {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(short, long, help = "Keystore key label for TSA signing")]
        key: Option<String>,
    },

    #[command(
        about = "Perform offline behavioral vector embedding similarity search across an artifact corpus"
    )]
    Search {
        #[arg(help = "Path to query .vyr artifact")]
        query_artifact: PathBuf,

        #[arg(
            short,
            long,
            required = true,
            help = "Corpus directory containing .vyr archives"
        )]
        corpus: PathBuf,

        #[arg(
            short,
            long,
            default_value = "0.75",
            help = "Minimum cosine similarity threshold (0.0 - 1.0)"
        )]
        threshold: f32,

        #[arg(short, long, help = "Passphrase to decrypt artifacts")]
        passphrase: Option<String>,
    },

    #[command(about = "Launch local web visualizer server & interactive REST API dashboard")]
    Serve {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(
            short,
            long,
            default_value = "8080",
            help = "HTTP port to bind on localhost"
        )]
        port: u16,

        #[arg(short, long, help = "Keystore key label to decrypt artifact")]
        key: Option<String>,

        #[arg(short, long, help = "Passphrase to decrypt artifact")]
        passphrase: Option<String>,
    },

    #[command(
        about = "Run continuous system-wide telemetry supervisor and incident snapshot daemon"
    )]
    Daemon {
        #[arg(
            short,
            long,
            default_value = "snapshots",
            help = "Directory to store incident snapshots"
        )]
        output_dir: PathBuf,

        #[arg(
            short,
            long,
            default_value = "75",
            help = "Risk score threshold to trigger automatic snapshot"
        )]
        trigger_score: u32,
    },

    #[command(
        about = "Manage Shamir k-of-n threshold cryptographic secret shares for artifact decryption"
    )]
    Threshold {
        #[command(subcommand)]
        command: ThresholdCommands,
    },

    #[command(about = "Launch interactive terminal user interface (TUI) to inspect artifact")]
    View {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(short, long, help = "Keystore key label to decrypt artifact")]
        key: Option<String>,

        #[arg(short, long, help = "Passphrase to decrypt artifact")]
        passphrase: Option<String>,
    },

    #[command(about = "Semantically compare behavioral telemetry between two .vyr artifacts")]
    Diff {
        #[arg(help = "Path to baseline .vyr artifact")]
        old_artifact: PathBuf,

        #[arg(help = "Path to comparison .vyr artifact")]
        new_artifact: PathBuf,

        #[arg(short, long, help = "Keystore key label to decrypt artifacts")]
        key: Option<String>,

        #[arg(short, long, help = "Passphrase to decrypt artifacts")]
        passphrase: Option<String>,
    },

    #[command(about = "Execute a VQL query over an artifact's normalized behavioral telemetry")]
    Query {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(
            short,
            long,
            required = true,
            help = "VQL query string (e.g. --query 'FIND event WHERE type = \"NetworkConnect\"')"
        )]
        query: String,

        #[arg(
            short,
            long,
            default_value = "table",
            value_enum,
            help = "Output format"
        )]
        output: OutputFormat,

        #[arg(short, long, help = "Keystore key label to decrypt artifact")]
        key: Option<String>,

        #[arg(short, long, help = "Passphrase to decrypt artifact")]
        passphrase: Option<String>,
    },

    #[command(
        about = "Export artifact telemetry to JSON, HTML Dashboard, STIX 2.1, SARIF, NDJSON, or CSV"
    )]
    Export {
        #[arg(help = "Path to .vyr artifact")]
        artifact: PathBuf,

        #[arg(
            short,
            long,
            default_value = "json",
            help = "Export format (json, html, stix, sarif, ndjson, csv)"
        )]
        format: String,

        #[arg(short, long, required = true, help = "Destination report file path")]
        output: PathBuf,

        #[arg(short, long, help = "Keystore key label to decrypt artifact")]
        key: Option<String>,

        #[arg(short, long, help = "Passphrase to decrypt artifact")]
        passphrase: Option<String>,
    },

    #[command(about = "Generate an asymmetric Ed25519 and X25519 keypair in the local keystore")]
    Keygen {
        #[arg(short, long, default_value = "default", help = "Key label")]
        name: String,

        #[arg(short, long, help = "Optional passphrase to protect key")]
        passphrase: Option<String>,
    },

    #[command(about = "Manage local signing and recipient keys")]
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
}

#[derive(Subcommand)]
enum ClusterCommands {
    #[command(about = "List connected cluster fleet nodes and incident activity")]
    Status,

    #[command(about = "Register a local or remote node with the fleet cluster")]
    Register {
        #[arg(
            short = 'H',
            long,
            default_value = "endpoint-node-01",
            help = "Node hostname"
        )]
        hostname: String,

        #[arg(short, long, default_value = "127.0.0.1", help = "Node IP address")]
        ip: String,

        #[arg(
            short,
            long,
            default_value = "Windows 11 x86_64",
            help = "Operating system"
        )]
        os: String,
    },
}

#[derive(Subcommand)]
enum ThresholdCommands {
    #[command(about = "Split a master secret or passphrase into k-of-n Shamir shares")]
    Split {
        #[arg(
            short,
            long,
            required = true,
            help = "Secret passphrase or key to split"
        )]
        secret: String,

        #[arg(
            short = 'k',
            long,
            default_value = "3",
            help = "Threshold shares required to reconstruct"
        )]
        threshold: u8,

        #[arg(
            short = 'n',
            long,
            default_value = "5",
            help = "Total shares to generate"
        )]
        total: u8,
    },

    #[command(about = "Combine k Shamir secret share tokens to reconstruct the original secret")]
    Combine {
        #[arg(required = true, help = "List of VYR-SHARE-... token strings")]
        shares: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    #[command(about = "List stored public keys in local keystore")]
    List,

    #[command(about = "Inspect key metadata and public credentials")]
    Inspect {
        #[arg(short, long, default_value = "default", help = "Key label")]
        name: String,
    },
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Tabled)]
struct KeyListRow {
    #[tabled(rename = "Label")]
    label: String,
    #[tabled(rename = "Key ID")]
    key_id: String,
    #[tabled(rename = "Created At")]
    created_at: String,
}

#[derive(Tabled)]
struct SearchResultRow {
    #[tabled(rename = "Corpus Artifact")]
    artifact_name: String,
    #[tabled(rename = "Behavioral Similarity")]
    similarity: String,
    #[tabled(rename = "Status")]
    status: String,
}

fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => Level::ERROR,
        1 => Level::WARN,
        2 => Level::INFO,
        _ => Level::DEBUG,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match execute(cli.command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}: {}", "ERROR".red().bold(), err);
            ExitCode::FAILURE
        }
    }
}

fn execute(command: Commands) -> Result<ExitCode, anyhow::Error> {
    match command {
        Commands::Version => {
            println!("VEYRONIS v0.1.0");
            println!("Universal Verifiable Security Behavior Engine");
            println!(
                "Target: {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            println!("Authors: dupewon <whuq@cheatglobal>");
            Ok(ExitCode::SUCCESS)
        }

        Commands::Doctor => {
            PlatformDoctor::diagnose();
            Ok(ExitCode::SUCCESS)
        }

        Commands::Mcp => {
            McpServer::run_stdio()?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Explain {
            artifact,
            passphrase,
        } => {
            let keystore = KeyStore::open_default()?;
            let reader = VyrReader::open_file(&artifact)?;
            let decrypted = if let Some(pass) = &passphrase {
                reader.decrypt_with_passphrase(pass.as_bytes())?
            } else if let Ok(recipient_key) = keystore.load_recipient_key("default", None) {
                reader.decrypt_with_key(&recipient_key)?
            } else {
                reader.decrypt_with_passphrase(b"")?
            };
            let detection_engine = DetectionEngine::new();
            let report = detection_engine.scan(&decrypted.events, decrypted.graph.as_ref());
            let explanation = IncidentExplainer::explain(&decrypted, &report);
            print!("{}", IncidentExplainer::render_terminal(&explanation));
            Ok(ExitCode::SUCCESS)
        }

        Commands::Emulate {
            shellcode_file,
            max_instructions,
        } => {
            let bytes = fs::read(&shellcode_file)?;
            let report = ShellcodeEmulator::emulate(&bytes, max_instructions)?;
            print!("{}", ShellcodeEmulator::render_terminal(&report));
            Ok(ExitCode::SUCCESS)
        }

        Commands::Cluster { command } => match command {
            ClusterCommands::Status => {
                let hub = ClusterHub::new();
                let nodes = hub.list_nodes();
                print!("{}", render_cluster_status(&nodes));
                Ok(ExitCode::SUCCESS)
            }
            ClusterCommands::Register { hostname, ip, os } => {
                let hub = ClusterHub::new();
                let node = hub.register_node(&hostname, &ip, &os);
                println!("{}", "=== FLEET NODE REGISTERED ===".bold().white());
                println!("Node ID:  {}", node.node_id.to_string().cyan());
                println!("Hostname: {}", node.hostname.green());
                println!("Status:   {}", node.status.green().bold());
                Ok(ExitCode::SUCCESS)
            }
        },

        Commands::Analyze { binary } => {
            let report = BinaryInspector::inspect_file(&binary)?;
            print!("{}", report.render_terminal());
            Ok(ExitCode::SUCCESS)
        }

        Commands::Unpack { binary, output } => {
            let bytes = fs::read(&binary)?;
            MemoryUnpacker::dump_unpacked_pe(&bytes, 0x1000, &output)?;
            println!(
                "{}",
                "=== VEYRONIS AUTOMATED IN-MEMORY UNPACKER ==="
                    .bold()
                    .white()
            );
            println!(
                "Source Packed File:   {}",
                binary.display().to_string().cyan()
            );
            println!(
                "Reconstructed File:   {}",
                output.display().to_string().green().bold()
            );
            println!("Status:               {}", "UNPACKED SUCCESSFULLY".green());
            Ok(ExitCode::SUCCESS)
        }

        Commands::Deobfuscate { input, output } => {
            let bytes = fs::read(&input)?;
            let (cleaned, report) = DeobfuscationEngine::deobfuscate(&bytes)?;
            fs::write(&output, &cleaned)?;

            println!("{}", "=== VEYRONIS DEOBFUSCATION ENGINE ===".bold().white());
            println!(
                "Input File:                        {}",
                input.display().to_string().cyan()
            );
            println!(
                "Clean Output File:                 {}",
                output.display().to_string().green().bold()
            );
            println!(
                "Opaque Predicates Removed:         {}",
                report.opaque_predicates_removed
            );
            println!(
                "Dead Instructions Stripped:        {}",
                report.dead_instructions_removed
            );
            println!(
                "Control Flow Dispatchers Resolved: {}",
                report.control_flow_dispatchers_resolved
            );
            println!(
                "Clean Code Size:                   {} bytes",
                report.clean_code_size
            );

            if !report.extracted_strings.is_empty() {
                println!("\n{}", "Recovered Obfuscated Strings:".bold().yellow());
                for s in &report.extracted_strings {
                    println!(
                        "  [Offset 0x{:04X}] {} (Method: {})",
                        s.offset,
                        s.value.green(),
                        s.method.dimmed()
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Dmp2Pe {
            dump_file,
            output,
            oep,
            no_iat_rebuild,
        } => {
            let bytes = fs::read(&dump_file)?;
            let custom_oep = oep.and_then(|s| {
                if s.starts_with("0x") || s.starts_with("0X") {
                    u32::from_str_radix(&s[2..], 16).ok()
                } else {
                    s.parse::<u32>().ok()
                }
            });

            let options = DumpToPeOptions {
                custom_oep_rva: custom_oep,
                rebuild_iat: !no_iat_rebuild,
                fix_section_alignments: true,
                unmap_sections: true,
            };

            let info = DumpToPeConverter::convert_dump(&bytes, options, &output)?;

            println!(
                "{}",
                "=== VEYRONIS DMP TO PE RECONSTRUCTOR ===".bold().white()
            );
            println!(
                "Source Memory Dump:  {}",
                dump_file.display().to_string().cyan()
            );
            println!(
                "Reconstructed PE:    {}",
                output.display().to_string().green().bold()
            );
            println!(
                "Architecture:        {}",
                if info.is_64bit {
                    "x86_64 (PE32+)"
                } else {
                    "x86 (PE32)"
                }
                .cyan()
            );
            println!("ImageBase:           0x{:X}", info.original_image_base);
            println!("Entry Point (OEP):   0x{:X}", info.entry_point_rva);
            println!("Sections Restored:   {}", info.section_count);
            for sec in &info.sections {
                println!(
                    "  - {:<8} (VA: 0x{:06X}, Raw: 0x{:06X}, Size: {} bytes)",
                    sec.name, sec.virtual_address, sec.raw_data_pointer, sec.raw_data_size
                );
            }
            println!("Output File Size:    {} bytes", info.file_size_bytes);
            println!(
                "Status:              {}",
                "RECONSTRUCTED SUCCESSFULLY".green().bold()
            );
            Ok(ExitCode::SUCCESS)
        }

        Commands::Vmp {
            binary,
            unpack,
            output,
            devirtualize,
        } => {
            let bytes = fs::read(&binary)?;
            let report = VmProtectAnalyzer::analyze_vmp(&bytes)?;

            println!(
                "{}",
                "=== VEYRONIS VMPROTECT ANALYZER & UNPACKER ==="
                    .bold()
                    .white()
            );
            println!(
                "Target Binary:            {}",
                binary.display().to_string().cyan()
            );
            println!(
                "VMProtect Detected:       {}",
                if report.is_vmp_protected {
                    "YES (VMProtect Active)".red().bold()
                } else {
                    "NO".green()
                }
            );
            println!(
                "Protection Architecture:  {}",
                report.detected_version_hint.yellow()
            );
            println!("Highest Section Entropy:  {:.4}", report.highest_entropy);
            if !report.vmp_sections.is_empty() {
                println!(
                    "VMP Sections:             {}",
                    report.vmp_sections.join(", ").magenta()
                );
            }
            if let Some(disp) = report.virtual_dispatcher_rva {
                println!("VM Dispatcher Offset:     0x{:X}", disp);
            }
            if let Some(oep) = report.recovered_oep_rva {
                println!("Recovered OEP Transition: 0x{:X}", oep);
            }

            if devirtualize && !report.devirtualized_instructions.is_empty() {
                println!("\n{}", "Devirtualized Assembly Trace:".bold().yellow());
                for (idx, line) in report.devirtualized_instructions.iter().enumerate() {
                    println!("  [{:02}] {}", idx + 1, line.cyan());
                }
            }

            if unpack {
                VmProtectAnalyzer::unpack_vmp_to_file(&bytes, report.recovered_oep_rva, &output)?;
                println!("\n{}", "Unpacking Status:".bold().white());
                println!(
                    "Unpacked Output PE:       {}",
                    output.display().to_string().green().bold()
                );
                println!(
                    "Status:                   {}",
                    "UNPACKED SUCCESSFULLY".green().bold()
                );
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Timestamp { artifact, key } => {
            let key_label = key.as_deref().unwrap_or("default");
            let keystore = KeyStore::open_default()?;
            let signing_key = keystore.load_signing_key(key_label, None)?;
            let reader = VyrReader::open_file(&artifact)?;

            let token = TimestampAuthority::create_token(
                &reader.trailer.merkle_root,
                &signing_key,
                "1.3.6.1.4.1.61234.1.1 (Veyronis TSA Policy)",
            );

            let token_json = serde_json::to_string_pretty(&token)?;
            let token_path = artifact.with_extension("tsa.json");
            fs::write(&token_path, token_json)?;

            println!(
                "{}",
                "=== VEYRONIS RFC 3161 CRYPTOGRAPHIC TIMESTAMP ==="
                    .bold()
                    .white()
            );
            println!(
                "Artifact:             {}",
                artifact.display().to_string().cyan()
            );
            println!("Serial Number:        {}", token.serial_number);
            println!(
                "Timestamp Authority:  {}",
                "VERIFIED & ISSUED".green().bold()
            );
            println!(
                "Token Saved To:       {}",
                token_path.display().to_string().yellow()
            );

            Ok(ExitCode::SUCCESS)
        }

        Commands::Search {
            query_artifact,
            corpus,
            threshold,
            passphrase,
        } => {
            let keystore = KeyStore::open_default()?;
            let query_reader = VyrReader::open_file(&query_artifact)?;
            let query_decrypted = if let Some(pass) = &passphrase {
                query_reader.decrypt_with_passphrase(pass.as_bytes())?
            } else if let Ok(recipient_key) = keystore.load_recipient_key("default", None) {
                query_reader.decrypt_with_key(&recipient_key)?
            } else {
                return Err(anyhow::anyhow!("cannot decrypt query artifact"));
            };

            let query_emb = BehaviorEmbedding::from_events(&query_decrypted.events);

            let mut results: Vec<SearchResultRow> = Vec::new();

            if corpus.is_dir() {
                for entry in fs::read_dir(&corpus)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "vyr") && path != query_artifact {
                        if let Ok(reader) = VyrReader::open_file(&path) {
                            if let Ok(dec) = reader.decrypt_with_passphrase(b"") {
                                let emb = BehaviorEmbedding::from_events(&dec.events);
                                let sim = query_emb.cosine_similarity(&emb);
                                if sim >= threshold {
                                    results.push(SearchResultRow {
                                        artifact_name: path
                                            .file_name()
                                            .unwrap()
                                            .to_string_lossy()
                                            .into(),
                                        similarity: format!("{:.2}%", sim * 100.0),
                                        status: if sim >= 0.9 {
                                            "HIGHLY SIMILAR (VARIANT)".red().to_string()
                                        } else {
                                            "RELATED".yellow().to_string()
                                        },
                                    });
                                }
                            }
                        }
                    }
                }
            }

            println!(
                "{}",
                "=== VEYRONIS BEHAVIORAL VECTOR SEARCH ===".bold().white()
            );
            println!(
                "Query Artifact:       {}",
                query_artifact.display().to_string().cyan()
            );
            println!("Similarity Threshold: >= {:.0}%", threshold * 100.0);
            println!("Matches Found:        {}\n", results.len());

            if results.is_empty() {
                println!("No corpus artifacts met the similarity threshold.");
            } else {
                println!("{}", Table::new(results));
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Serve {
            artifact,
            port,
            key,
            passphrase,
        } => {
            VeyronisServer::start(&artifact, port, key.as_deref(), passphrase.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Daemon {
            output_dir,
            trigger_score,
        } => {
            let options = DaemonOptions {
                output_dir,
                ring_buffer_size: 50_000,
                trigger_risk_score: trigger_score,
                poll_interval_ms: 200,
            };
            VeyronisDaemon::run(options)?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Threshold { command } => match command {
            ThresholdCommands::Split {
                secret,
                threshold,
                total,
            } => {
                let shares = ShamirEngine::split_secret(secret.as_bytes(), threshold, total)?;
                println!(
                    "{}",
                    "=== VEYRONIS THRESHOLD SECRET SPLIT ===".bold().white()
                );
                println!("Threshold Required (k): {}", threshold.to_string().green());
                println!("Total Shares Generated (n): {}", total.to_string().cyan());
                println!("\nGenerated Secret Share Tokens:");
                for (i, share) in shares.iter().enumerate() {
                    println!("  Share #{}: {}", i + 1, share.to_token_string().yellow());
                }
                println!(
                    "\n{}",
                    "Preserve these tokens across designated multi-party custodian keyholders."
                        .bright_black()
                );
                Ok(ExitCode::SUCCESS)
            }

            ThresholdCommands::Combine { shares } => {
                let parsed_shares: Result<Vec<SecretShare>, _> = shares
                    .iter()
                    .map(|s| SecretShare::from_token_string(s))
                    .collect();
                let parsed = parsed_shares.map_err(|_| {
                    anyhow::anyhow!("failed to parse one or more VYR-SHARE token strings")
                })?;

                let recovered_bytes = ShamirEngine::combine_shares(&parsed)?;
                let recovered_str = String::from_utf8(recovered_bytes)?;

                println!(
                    "{}",
                    "=== VEYRONIS THRESHOLD RECONSTRUCTION ===".bold().white()
                );
                println!(
                    "Status:                 {}",
                    "RECONSTRUCTED SUCCESSFULLY".green().bold()
                );
                println!("Reconstructed Secret:   {}", recovered_str.cyan().bold());
                Ok(ExitCode::SUCCESS)
            }
        },

        Commands::Record {
            output,
            key,
            passphrase,
            inject_threat,
            command,
        } => {
            let options = RecordSessionOptions {
                command,
                output_path: output,
                key_label: key,
                passphrase,
                inject_threat,
            };

            RecordSession::record(options)?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Inspect {
            artifact,
            key,
            passphrase,
        } => {
            VyrInspector::inspect(&artifact, key.as_deref(), passphrase.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Verify { artifact } => {
            let valid = VyrVerifier::verify(&artifact)?;
            if valid {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        }

        Commands::Scan {
            artifact,
            rules,
            key,
            passphrase,
        } => {
            let report = VyrScanner::scan(
                &artifact,
                rules.as_deref(),
                key.as_deref(),
                passphrase.as_deref(),
            )?;
            print!("{}", report.render_terminal());
            Ok(ExitCode::SUCCESS)
        }

        Commands::View {
            artifact,
            key,
            passphrase,
        } => {
            TuiViewer::run(&artifact, key.as_deref(), passphrase.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Diff {
            old_artifact,
            new_artifact,
            key,
            passphrase,
        } => {
            let key_label = key.as_deref().unwrap_or("default");
            let keystore = KeyStore::open_default()?;

            let reader_old = VyrReader::open_file(&old_artifact)?;
            let reader_new = VyrReader::open_file(&new_artifact)?;

            let old_decrypted = if let Some(pass) = &passphrase {
                reader_old.decrypt_with_passphrase(pass.as_bytes())?
            } else if let Ok(recipient_key) = keystore.load_recipient_key(key_label, None) {
                reader_old.decrypt_with_key(&recipient_key)?
            } else {
                return Err(anyhow::anyhow!(
                    "cannot decrypt old artifact: recipient key '{}' not found",
                    key_label
                ));
            };

            let new_decrypted = if let Some(pass) = &passphrase {
                reader_new.decrypt_with_passphrase(pass.as_bytes())?
            } else if let Ok(recipient_key) = keystore.load_recipient_key(key_label, None) {
                reader_new.decrypt_with_key(&recipient_key)?
            } else {
                return Err(anyhow::anyhow!(
                    "cannot decrypt new artifact: recipient key '{}' not found",
                    key_label
                ));
            };

            let diff_report = DiffEngine::diff_events(&old_decrypted.events, &new_decrypted.events);
            print!("{}", diff_report.render_terminal());

            Ok(ExitCode::SUCCESS)
        }

        Commands::Query {
            artifact,
            query,
            output,
            key,
            passphrase,
        } => {
            let key_label = key.as_deref().unwrap_or("default");
            let keystore = KeyStore::open_default()?;
            let reader = VyrReader::open_file(&artifact)?;

            let decrypted = if let Some(pass) = &passphrase {
                reader.decrypt_with_passphrase(pass.as_bytes())?
            } else if let Ok(recipient_key) = keystore.load_recipient_key(key_label, None) {
                reader.decrypt_with_key(&recipient_key)?
            } else {
                return Err(anyhow::anyhow!(
                    "cannot decrypt artifact: recipient key '{}' not found",
                    key_label
                ));
            };

            let parsed_query = VqlParser::parse_str(&query)
                .map_err(|e| anyhow::anyhow!("VQL syntax error: {}", e))?;

            let engine = QueryEngine::new(&decrypted.events, decrypted.graph.as_ref());
            let results = engine.execute(&parsed_query);

            match output {
                OutputFormat::Table => {
                    let table = Table::new(results).to_string();
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                }
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Export {
            artifact,
            format,
            output,
            key,
            passphrase,
        } => {
            VyrExporter::export(
                &artifact,
                &output,
                &format,
                key.as_deref(),
                passphrase.as_deref(),
            )?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Keygen { name, passphrase } => {
            let mut keystore = KeyStore::open_default()?;
            let meta = keystore.generate_key(&name, passphrase.as_deref().map(|s| s.as_bytes()))?;

            println!("{}", "VEYRONIS KEY GENERATION".bold().white());
            println!("Label:                 {}", meta.label.green());
            println!("Key ID:                {}", meta.key_id.cyan());
            println!("Public Signing Key:    {}", meta.public_signing_key);
            println!("Public Encryption Key: {}", meta.public_encryption_key);
            println!(
                "Status:                {}",
                "STORED SECURELY".green().bold()
            );

            Ok(ExitCode::SUCCESS)
        }

        Commands::Key { command } => match command {
            KeyCommands::List => {
                let keystore = KeyStore::open_default()?;
                let keys = keystore.list_keys();

                if keys.is_empty() {
                    println!(
                        "No keys found in local keystore. Run 'veyronis keygen' to create one."
                    );
                } else {
                    let rows: Vec<KeyListRow> = keys
                        .into_iter()
                        .map(|k| KeyListRow {
                            label: k.label,
                            key_id: k.key_id[..16].to_string(),
                            created_at: k.created_at,
                        })
                        .collect();
                    println!("{}", Table::new(rows));
                }

                Ok(ExitCode::SUCCESS)
            }

            KeyCommands::Inspect { name } => {
                let keystore = KeyStore::open_default()?;
                let meta = keystore.get_metadata(&name)?;

                println!("{}", "VEYRONIS KEY INSPECTION".bold().white());
                println!("Label:                 {}", meta.label.green());
                println!("Key ID:                {}", meta.key_id.cyan());
                println!("Public Signing Key:    {}", meta.public_signing_key);
                println!("Public Encryption Key: {}", meta.public_encryption_key);
                println!("Created At:            {}", meta.created_at);

                Ok(ExitCode::SUCCESS)
            }
        },
    }
}
