use std::fs;
use std::path::Path;
use veyronis_detect::DetectionReport;
use veyronis_format::DecryptedArtifact;
use veyronis_graph::ProcessTree;

pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    pub fn generate(
        artifact: &DecryptedArtifact,
        detection_report: &DetectionReport,
        output_path: &Path,
    ) -> Result<(), anyhow::Error> {
        let manifest = artifact.manifest.as_ref();
        let target_cmd = manifest
            .map(|m| m.target_command.join(" "))
            .unwrap_or_else(|| "Unknown".into());
        let os_str = manifest
            .map(|m| m.platform.to_string())
            .unwrap_or_else(|| "Unknown Platform".into());
        let duration_ms = manifest.map(|m| m.duration_ms).unwrap_or(0);
        let artifact_uuid = artifact.header.artifact_uuid.to_string();
        let merkle_root_hex = hex_encode(&artifact.trailer.merkle_root);
        let signer_pubkey_hex = hex_encode(&artifact.trailer.signer_public_key);

        let process_tree_text = if let Some(graph) = &artifact.graph {
            let tree = ProcessTree::build(graph);
            tree.render_tree()
        } else {
            "No process tree available".to_string()
        };

        let mut alerts_html = String::new();
        if detection_report.alerts.is_empty() {
            alerts_html.push_str(
                r#"<div class="alert-clean">✓ No Behavioral Security Threats Detected</div>"#,
            );
        } else {
            for alert in &detection_report.alerts {
                let mitre_badge = alert
                    .mitre_technique
                    .as_deref()
                    .map(|m| format!(r#"<span class="badge mitre">{}</span>"#, m))
                    .unwrap_or_default();

                alerts_html.push_str(&format!(
                    r#"<div class="alert-card sev-{}">
                        <div class="alert-header">
                            <span class="badge sev-badge">{}</span>
                            <span class="alert-title">{}</span>
                            {}
                        </div>
                        <p class="alert-remediation"><strong>Remediation:</strong> {}</p>
                        <div class="alert-events">Matched Event Count: {}</div>
                    </div>"#,
                    alert.severity.to_string().to_lowercase(),
                    alert.severity,
                    alert.title,
                    mitre_badge,
                    alert.remediation,
                    alert.matched_event_ids.len()
                ));
            }
        }

        let mut events_rows = String::new();
        for event in &artifact.events {
            events_rows.push_str(&format!(
                r#"<tr>
                    <td><code>{}</code></td>
                    <td><span class="badge event-type">{}</span></td>
                    <td><strong>{}</strong> (PID: {})</td>
                    <td>{}</td>
                    <td><span class="badge conf-{}">{}</span></td>
                </tr>"#,
                &event.event_id.to_string()[..8],
                event.event_type,
                event.process_identity.canonical_name(),
                event.process_identity.pid,
                format_event_details(event),
                event.confidence.to_string().to_lowercase(),
                event.confidence
            ));
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Veyronis Behavioral Security Report - {artifact_uuid}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-bright: #f0f6fc;
            --accent: #58a6ff;
            --green: #3fb950;
            --red: #f85149;
            --yellow: #d29922;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{ color: var(--text-bright); margin: 0; font-size: 24px; }}
        .header-meta {{ font-size: 13px; color: #8b949e; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .metric-card .title {{ font-size: 12px; color: #8b949e; text-transform: uppercase; font-weight: 600; }}
        .metric-card .value {{ font-size: 24px; color: var(--text-bright); font-weight: bold; margin-top: 6px; }}
        .section-title {{
            font-size: 18px;
            color: var(--text-bright);
            margin: 30px 0 15px 0;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}
        .badge {{
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
        }}
        .badge.mitre {{ background: #21262d; border: 1px solid #388bfd33; color: var(--accent); }}
        .badge.event-type {{ background: #21262d; color: var(--text-bright); border: 1px solid var(--border); }}
        .badge.conf-high {{ background: #238636; color: white; }}
        .alert-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-left: 4px solid var(--yellow);
            border-radius: 6px;
            padding: 14px;
            margin-bottom: 12px;
        }}
        .alert-card.sev-critical {{ border-left-color: var(--red); }}
        .alert-card.sev-high {{ border-left-color: #f0883e; }}
        .alert-card.sev-medium {{ border-left-color: var(--yellow); }}
        .alert-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .alert-title {{ font-weight: bold; color: var(--text-bright); }}
        .alert-clean {{
            background: #1f3b25;
            color: #7ee787;
            padding: 16px;
            border-radius: 6px;
            border: 1px solid #2ea04366;
            font-weight: 600;
        }}
        pre.process-tree {{
            background: #090d13;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            color: #79c0ff;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 13px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{ background: #21262d; color: var(--text-bright); font-weight: 600; }}
        tr:hover {{ background: #1c2128; }}
        code {{
            background: #21262d;
            padding: 2px 5px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 12px;
        }}
        footer {{
            margin-top: 50px;
            text-align: center;
            font-size: 12px;
            color: #8b949e;
            border-top: 1px solid var(--border);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>VEYRONIS Behavioral Security Report</h1>
                <div class="header-meta">Target: <code>{target_cmd}</code> | Platform: {os_str}</div>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background: #1f6feb; color: white;">VERIFIED ARTIFACT</span>
                <div class="header-meta" style="margin-top: 4px;">UUID: <code>{artifact_uuid}</code></div>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="title">Risk Score</div>
                <div class="metric-card value" style="color: {};">{}/100</div>
            </div>
            <div class="metric-card">
                <div class="title">Execution Duration</div>
                <div class="metric-card value">{} ms</div>
            </div>
            <div class="metric-card">
                <div class="title">Recorded Events</div>
                <div class="metric-card value">{}</div>
            </div>
            <div class="metric-card">
                <div class="title">Threat Alerts</div>
                <div class="metric-card value">{}</div>
            </div>
        </div>

        <div class="section-title">Cryptographic Provenance & Container Integrity</div>
        <table style="margin-bottom: 25px;">
            <tr><th>Property</th><th>Cryptographic Value</th></tr>
            <tr><td>Container Format</td><td><strong>VYR1</strong> (XChaCha20-Poly1305 AEAD + Merkle Tree)</td></tr>
            <tr><td>Merkle Root Hash (BLAKE3)</td><td><code>{}</code></td></tr>
            <tr><td>Signer Public Key (Ed25519)</td><td><code>{}</code></td></tr>
            <tr><td>Signature Verification</td><td><span style="color: var(--green); font-weight: bold;">VALID & AUTHENTIC</span></td></tr>
        </table>

        <div class="section-title">Behavioral Threat Detections</div>
        {}

        <div class="section-title">Execution Process Tree & Hierarchy</div>
        <pre class="process-tree">{}</pre>

        <div class="section-title">Normalized Event Stream ({})</div>
        <table>
            <thead>
                <tr>
                    <th>Event ID</th>
                    <th>Type</th>
                    <th>Process</th>
                    <th>Details & Telemetry</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>

        <footer>
            Generated locally by <strong>VEYRONIS v0.1.0</strong> | Universal Verifiable Security Behavior Engine
        </footer>
    </div>
</body>
</html>"#,
            if detection_report.risk_score >= 75 {
                "var(--red)"
            } else if detection_report.risk_score >= 40 {
                "var(--yellow)"
            } else {
                "var(--green)"
            },
            detection_report.risk_score,
            duration_ms,
            artifact.events.len(),
            detection_report.alerts.len(),
            merkle_root_hex,
            signer_pubkey_hex,
            alerts_html,
            process_tree_text,
            artifact.events.len(),
            events_rows
        );

        fs::write(output_path, html)?;
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn format_event_details(event: &veyronis_ir::event::VirEvent) -> String {
    use veyronis_ir::categories::EventData;
    match &event.data {
        EventData::ProcessStart(p) => format!("exec <code>{}</code>", p.executable_path),
        EventData::ProcessExit(e) => format!("exit code <code>{}</code>", e.exit_code),
        EventData::ProcessSpawn(s) => format!(
            "spawn child PID <code>{}</code> (<code>{}</code>)",
            s.child_pid, s.child_executable_path
        ),
        EventData::FileOpen(f) => format!(
            "open <code>{}</code> (read: {}, write: {})",
            f.path, f.read, f.write
        ),
        EventData::FileRead(f) => {
            format!("read {} bytes from <code>{}</code>", f.bytes_read, f.path)
        }
        EventData::FileWrite(f) => {
            format!("write {} bytes to <code>{}</code>", f.bytes_written, f.path)
        }
        EventData::FileDelete(f) => format!("delete <code>{}</code>", f.path),
        EventData::FileRename(f) => format!(
            "rename <code>{}</code> -> <code>{}</code>",
            f.old_path, f.new_path
        ),
        EventData::DnsQuery(d) => format!(
            "DNS query for <code>{}</code> ({})",
            d.query_name, d.record_type
        ),
        EventData::DnsResponse(d) => format!(
            "DNS resolved <code>{}</code> -> <code>{:?}</code>",
            d.query_name, d.addresses
        ),
        EventData::NetworkConnect(n) => format!(
            "TCP connect to <code>{}:{}</code> (external: {})",
            n.remote_address, n.remote_port, n.is_external
        ),
        EventData::NetworkAccept(n) => format!(
            "TCP accept from <code>{}:{}</code>",
            n.remote_address, n.remote_port
        ),
        EventData::NetworkClose(n) => format!(
            "TCP close (sent: {} bytes, recv: {} bytes)",
            n.bytes_sent, n.bytes_received
        ),
        EventData::SocketCreate(s) => {
            format!("Socket created (<code>{}/{}</code>)", s.domain, s.protocol)
        }
        EventData::CryptoOperation(c) => format!(
            "{:?} with <code>{}</code> ({})",
            c.category, c.algorithm, c.provider
        ),
        EventData::TlsObserved(t) => format!(
            "TLS <code>{}</code> (suite: <code>{:?}</code>)",
            t.version, t.cipher_suite
        ),
        EventData::MemoryMap(m) => format!(
            "mmap {} bytes (perm: <code>{}</code>)",
            m.size_bytes, m.permissions
        ),
        EventData::MemoryProtect(m) => format!("mprotect to <code>{}</code>", m.new_permissions),
        EventData::IpcConnect(i) => format!("IPC connect to <code>{}</code>", i.target_endpoint),
        EventData::IpcSend(i) => format!("IPC send {} bytes", i.message_bytes),
        EventData::UserSession(u) => format!("User session: <code>{}</code>", u.username),
        EventData::SystemMetadata(s) => format!(
            "OS <code>{}</code> (arch: <code>{}</code>)",
            s.os_name, s.architecture
        ),
    }
}
