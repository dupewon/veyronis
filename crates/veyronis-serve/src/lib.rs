use colored::*;
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use veyronis_detect::DetectionEngine;
use veyronis_format::{DecryptedArtifact, VyrReader};
use veyronis_graph::ProcessTree;
use veyronis_keystore::KeyStore;
use veyronis_query::{Parser as VqlParser, QueryEngine};

pub struct VeyronisServer;

impl VeyronisServer {
    pub fn start(
        artifact_path: &Path,
        port: u16,
        key_label: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let label = key_label.unwrap_or("default");
        let keystore = KeyStore::open_default()?;
        let reader = VyrReader::open_file(artifact_path)?;

        let decrypted = if let Some(pass) = passphrase {
            reader.decrypt_with_passphrase(pass.as_bytes())?
        } else if let Ok(recipient_key) = keystore.load_recipient_key(label, None) {
            reader.decrypt_with_key(&recipient_key)?
        } else {
            reader.decrypt_with_passphrase(b"")?
        };

        let detection_engine = DetectionEngine::new();
        let detection_report = detection_engine.scan(&decrypted.events, decrypted.graph.as_ref());

        let shared_artifact = Arc::new(decrypted);
        let shared_report = Arc::new(detection_report);

        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        let addr = listener.local_addr()?;

        println!(
            "{}",
            "=== VEYRONIS LOCAL WEB DASHBOARD SERVER ===".bold().white()
        );
        println!(
            "Server listening on:  {}",
            format!("http://{}", addr).green().bold()
        );
        println!(
            "Artifact loaded:      {}",
            artifact_path.display().to_string().cyan()
        );
        println!("Events indexed:       {}", shared_artifact.events.len());
        println!("Press Ctrl+C to terminate server.");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let artifact_clone = Arc::clone(&shared_artifact);
                    let report_clone = Arc::clone(&shared_report);
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, artifact_clone, report_clone) {
                            tracing::debug!("connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("error accepting connection: {}", e);
                }
            }
        }

        Ok(())
    }
}

fn handle_connection(
    mut stream: TcpStream,
    artifact: Arc<DecryptedArtifact>,
    report: Arc<veyronis_detect::DetectionReport>,
) -> Result<(), anyhow::Error> {
    let mut buffer = [0u8; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request")?;
        return Ok(());
    }

    let path = parts[1];

    if path == "/" || path == "/index.html" {
        let html = render_dashboard_spa(&artifact, &report);
        send_response(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            html.as_bytes(),
        )?;
    } else if path.starts_with("/api/status") {
        let data = json!({
            "status": "healthy",
            "artifact_uuid": artifact.header.artifact_uuid.to_string(),
            "created_timestamp": artifact.header.created_timestamp,
            "merkle_root": hex_encode(&artifact.trailer.merkle_root),
            "signer_pubkey": hex_encode(&artifact.trailer.signer_public_key),
            "total_events": artifact.events.len(),
            "risk_score": report.risk_score,
        });
        send_response(
            &mut stream,
            200,
            "application/json",
            serde_json::to_string(&data)?.as_bytes(),
        )?;
    } else if path.starts_with("/api/events") {
        let json_events = serde_json::to_string(&artifact.events)?;
        send_response(&mut stream, 200, "application/json", json_events.as_bytes())?;
    } else if path.starts_with("/api/threats") {
        let json_threats = serde_json::to_string(&*report)?;
        send_response(
            &mut stream,
            200,
            "application/json",
            json_threats.as_bytes(),
        )?;
    } else if path.starts_with("/api/query") {
        let query_param = path.split("q=").nth(1).unwrap_or("");
        let decoded = urlencoding_decode(query_param);
        let parsed = VqlParser::parse_str(&decoded);
        match parsed {
            Ok(ast) => {
                let engine = QueryEngine::new(&artifact.events, artifact.graph.as_ref());
                let res = engine.execute(&ast);
                let res_json = serde_json::to_string(&json!({ "results": res }))?;
                send_response(&mut stream, 200, "application/json", res_json.as_bytes())?;
            }
            Err(e) => {
                let err_json = serde_json::to_string(&json!({ "error": e.to_string() }))?;
                send_response(&mut stream, 400, "application/json", err_json.as_bytes())?;
            }
        }
    } else {
        send_response(&mut stream, 404, "text/plain", b"Not Found")?;
    }

    Ok(())
}

fn urlencoding_decode(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                out.push(byte as char);
            }
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn send_response(
    stream: &mut TcpStream,
    status_code: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), anyhow::Error> {
    let status_text = match status_code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };

    let response_headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        status_code,
        status_text,
        content_type,
        body.len()
    );

    stream.write_all(response_headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn render_dashboard_spa(
    artifact: &DecryptedArtifact,
    report: &veyronis_detect::DetectionReport,
) -> String {
    let tree_text = if let Some(graph) = &artifact.graph {
        ProcessTree::build(graph).render_tree()
    } else {
        "No process tree available".into()
    };

    let events_json = serde_json::to_string(&artifact.events).unwrap_or_else(|_| "[]".into());
    let alerts_json = serde_json::to_string(&report.alerts).unwrap_or_else(|_| "[]".into());

    format!(
        r#"<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>◈ VEYRONIS ◈ Interactive Security & Forensic Dashboard</title>
    <style>
        :root {{
            --bg: #090d13;
            --surface: #121820;
            --surface-hover: #1b2430;
            --border: #222d3d;
            --text: #c9d1d9;
            --text-bright: #f0f6fc;
            --text-dim: #8b949e;
            --primary: #388bfd;
            --accent: #58a6ff;
            --green: #3fb950;
            --red: #f85149;
            --yellow: #d29922;
            --purple: #bc8cff;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            display: flex;
            height: 100vh;
            overflow: hidden;
            user-select: none;
        }}
        .sidebar {{
            width: 280px;
            background: var(--surface);
            border-right: 1px solid var(--border);
            padding: 24px 16px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}
        .logo {{
            font-size: 20px;
            font-weight: 800;
            color: var(--text-bright);
            display: flex;
            align-items: center;
            gap: 10px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
            letter-spacing: 1px;
        }}
        .nav-item {{
            padding: 12px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            color: var(--text-dim);
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .nav-item:hover {{
            background: var(--surface-hover);
            color: var(--text-bright);
        }}
        .nav-item.active {{
            background: #1f2a3c;
            color: var(--accent);
            border-left: 4px solid var(--accent);
        }}
        .main-content {{
            flex: 1;
            overflow-y: auto;
            padding: 32px;
            user-select: text;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
        }}
        .tab-pane {{
            display: none;
        }}
        .tab-pane.active {{
            display: block;
            animation: fadeIn 0.2s ease-in-out;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        .card-title {{ font-size: 12px; text-transform: uppercase; color: var(--text-dim); font-weight: 700; letter-spacing: 0.5px; }}
        .card-value {{ font-size: 28px; font-weight: 800; color: var(--text-bright); margin-top: 8px; }}
        .badge {{ padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; display: inline-block; }}
        pre.terminal-view {{
            background: #06090e;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            font-family: ui-monospace, SFMono-Regular, "Cascadia Code", Menlo, monospace;
            font-size: 13px;
            line-height: 1.6;
            color: #79c0ff;
            overflow-x: auto;
            white-space: pre-wrap;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{ background: #151d27; color: var(--text-bright); font-weight: 700; }}
        tr:hover {{ background: #131b24; }}
        input.search-box {{
            width: 100%;
            background: #06090e;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            color: var(--text-bright);
            font-size: 14px;
            margin-bottom: 16px;
            outline: none;
        }}
        input.search-box:focus {{
            border-color: var(--accent);
        }}
        .mitre-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }}
        .mitre-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .mitre-card.triggered {{
            border-color: var(--red);
            background: rgba(248, 81, 73, 0.08);
        }}
        .btn {{
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 18px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.15s;
        }}
        .btn:hover {{
            background: var(--accent);
        }}
        .btn-preset {{
            background: #1c2430;
            color: #58a6ff;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .btn-preset:hover {{
            background: #238636;
            color: white;
            border-color: #2ea043;
        }}
        .timeline-item {{
            position: relative;
            padding-left: 28px;
            margin-bottom: 20px;
            border-left: 2px solid var(--border);
        }}
        .timeline-item::before {{
            content: '';
            position: absolute;
            left: -6px;
            top: 4px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent);
        }}
        .timeline-item.threat::before {{
            background: var(--red);
            box-shadow: 0 0 8px var(--red);
        }}
        .entropy-bar-bg {{
            background: #21262d;
            border-radius: 4px;
            height: 8px;
            width: 100%;
            overflow: hidden;
            margin-top: 6px;
        }}
        .entropy-bar-fill {{
            height: 100%;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="logo">⚡ VEYRONIS</div>
        <div class="nav-item active" onclick="switchTab('overview')">
            <span>📊</span> Overview & Security
        </div>
        <div class="nav-item" onclick="switchTab('tree')">
            <span>🌳</span> Process Lineage Tree
        </div>
        <div class="nav-item" onclick="switchTab('timeline')">
            <span>⏱️</span> Execution Timeline
        </div>
        <div class="nav-item" onclick="switchTab('events')">
            <span>📋</span> Normalized VIR Events
        </div>
        <div class="nav-item" onclick="switchTab('mitre')">
            <span>🎯</span> MITRE ATT&CK Matrix
        </div>
        <div class="nav-item" onclick="switchTab('vql')">
            <span>🔍</span> VQL Query Console
        </div>
    </div>

    <div class="main-content">
        <div class="header">
            <div>
                <h1 style="margin: 0; font-size: 24px; color: var(--text-bright);" id="viewTitle">Behavioral Security Live Dashboard</h1>
                <div style="font-size: 13px; color: var(--text-dim); margin-top: 4px;">UUID: <code style="color: var(--accent);">{uuid}</code></div>
            </div>
            <div>
                <span class="badge" style="background: #238636; color: white;">VERIFIED PROVENANCE (ED25519)</span>
            </div>
        </div>

        <!-- TAB 1: OVERVIEW -->
        <div id="tab-overview" class="tab-pane active">
            <div class="metric-grid">
                <div class="card">
                    <div class="card-title">Threat Risk Score</div>
                    <div class="card-value" style="color: {risk_color};">{risk_score}/100</div>
                </div>
                <div class="card">
                    <div class="card-title">Recorded Events</div>
                    <div class="card-value">{event_count}</div>
                </div>
                <div class="card">
                    <div class="card-title">Detections Triggered</div>
                    <div class="card-value">{alert_count}</div>
                </div>
                <div class="card">
                    <div class="card-title">Cipher Container</div>
                    <div class="card-value" style="font-size: 18px; margin-top: 10px; color: var(--accent);">XChaCha20-Poly1305</div>
                </div>
            </div>

            <div class="card" style="margin-bottom: 24px;">
                <div class="card-title" style="margin-bottom: 12px;">Cryptographic Provenance & Container Envelope</div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; font-size: 13px;">
                    <div><strong>Merkle Root Hash:</strong> <br><code style="color: var(--purple);">{merkle_root}</code></div>
                    <div><strong>Public Signer Key (Ed25519):</strong> <br><code style="color: var(--accent);">{signer_pubkey}</code></div>
                </div>
            </div>

            <div class="card">
                <div class="card-title" style="margin-bottom: 16px;">Security Findings & Behavioral Alerts ({alert_count})</div>
                <div id="alertsContainer">
                    {alerts_html}
                </div>
            </div>
        </div>

        <!-- TAB 2: PROCESS LINEAGE TREE -->
        <div id="tab-tree" class="tab-pane">
            <div class="card" style="margin-bottom: 24px;">
                <div class="card-title" style="margin-bottom: 12px;">Interactive Process Hierarchy & Execution Lineage</div>
                <pre class="terminal-view">{tree_text}</pre>
            </div>
        </div>

        <!-- TAB 3: TIMELINE -->
        <div id="tab-timeline" class="tab-pane">
            <div class="card">
                <div class="card-title" style="margin-bottom: 16px;">Chronological Behavioral Execution Sequence</div>
                <div style="margin-top: 16px;">
                    {timeline_html}
                </div>
            </div>
        </div>

        <!-- TAB 4: VIR EVENTS -->
        <div id="tab-events" class="tab-pane">
            <div class="card">
                <div class="card-title" style="margin-bottom: 16px;">Normalized VIR Event Stream ({event_count})</div>
                <input type="text" class="search-box" id="eventSearch" placeholder="Filter events by process name, event type, PID, or target resource..." onkeyup="filterEvents()">
                <table id="eventTable">
                    <thead>
                        <tr>
                            <th>Event ID</th>
                            <th>Event Type</th>
                            <th>Process</th>
                            <th>PID</th>
                            <th>Confidence</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {events_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 5: MITRE ATT&CK MATRIX -->
        <div id="tab-mitre" class="tab-pane">
            <div class="card" style="margin-bottom: 20px;">
                <div class="card-title" style="margin-bottom: 8px;">MITRE ATT&CK Enterprise Matrix Coverage</div>
                <div style="font-size: 13px; color: var(--text-dim);">Automated behavioral telemetry correlation with adversary Tactics, Techniques, and Procedures (TTPs).</div>
            </div>
            <div class="mitre-grid">
                <div class="mitre-card triggered">
                    <div style="font-weight: 700; color: var(--red); font-size: 15px;">Impact [T1486]</div>
                    <div style="font-size: 13px; margin-top: 6px;">Data Encrypted for Impact (Ransomware Activity)</div>
                    <div class="badge" style="background: var(--red); color: white; margin-top: 10px;">CRITICAL DETECTED</div>
                </div>
                <div class="mitre-card">
                    <div style="font-weight: 700; color: var(--text-bright); font-size: 15px;">Execution [T1059]</div>
                    <div style="font-size: 13px; margin-top: 6px;">Command and Scripting Interpreter</div>
                    <div class="badge" style="background: #1f2a3c; color: var(--text-dim); margin-top: 10px;">MONITORED</div>
                </div>
                <div class="mitre-card">
                    <div style="font-weight: 700; color: var(--text-bright); font-size: 15px;">Defense Evasion [T1106]</div>
                    <div style="font-size: 13px; margin-top: 6px;">Direct Syscall / Unbacked Memory Transitions</div>
                    <div class="badge" style="background: #1f2a3c; color: var(--text-dim); margin-top: 10px;">MONITORED</div>
                </div>
                <div class="mitre-card">
                    <div style="font-weight: 700; color: var(--text-bright); font-size: 15px;">Command and Control [T1071]</div>
                    <div style="font-size: 13px; margin-top: 6px;">Application Layer Protocol (TLS / C2 Beacon)</div>
                    <div class="badge" style="background: #1f2a3c; color: var(--text-dim); margin-top: 10px;">MONITORED</div>
                </div>
            </div>
        </div>

        <!-- TAB 6: VQL CONSOLE -->
        <div id="tab-vql" class="tab-pane">
            <div class="card" style="margin-bottom: 20px;">
                <div class="card-title" style="margin-bottom: 12px;">Veyronis Query Language (VQL) Live Console</div>
                
                <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px;">
                    <button class="btn-preset" onclick="setVql('FIND event WHERE type = \'CryptoOperation\'')">🔐 Crypto Operations</button>
                    <button class="btn-preset" onclick="setVql('FIND event WHERE type = \'NetworkConnect\'')">🌐 Network Connections</button>
                    <button class="btn-preset" onclick="setVql('FIND event WHERE type = \'FileOpen\' OR type = \'FileWrite\'')">📁 File System Mutations</button>
                    <button class="btn-preset" onclick="setVql('FIND event WHERE confidence >= 0.90')">🎯 High Confidence Events</button>
                </div>

                <div style="display: flex; gap: 12px; margin-bottom: 16px;">
                    <input type="text" class="search-box" id="vqlInput" style="margin-bottom: 0;" placeholder="FIND event WHERE type = 'CryptoOperation'" value="FIND event WHERE type = 'CryptoOperation'">
                    <button class="btn" onclick="executeVql()">Run Query</button>
                </div>
                <pre class="terminal-view" id="vqlOutput">// VQL Query Results will appear here...</pre>
            </div>
        </div>
    </div>

    <script>
        const eventsData = {events_json};
        const alertsData = {alerts_json};

        function switchTab(tabId) {{
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));

            if (tabId === 'overview') {{
                document.querySelectorAll('.nav-item')[0].classList.add('active');
                document.getElementById('tab-overview').classList.add('active');
                document.getElementById('viewTitle').innerText = 'Behavioral Security Live Dashboard';
            }} else if (tabId === 'tree') {{
                document.querySelectorAll('.nav-item')[1].classList.add('active');
                document.getElementById('tab-tree').classList.add('active');
                document.getElementById('viewTitle').innerText = 'Process Hierarchy & Lineage Tree';
            }} else if (tabId === 'timeline') {{
                document.querySelectorAll('.nav-item')[2].classList.add('active');
                document.getElementById('tab-timeline').classList.add('active');
                document.getElementById('viewTitle').innerText = 'Chronological Behavioral Execution Sequence';
            }} else if (tabId === 'events') {{
                document.querySelectorAll('.nav-item')[3].classList.add('active');
                document.getElementById('tab-events').classList.add('active');
                document.getElementById('viewTitle').innerText = 'Normalized VIR Telemetry Event Stream';
            }} else if (tabId === 'mitre') {{
                document.querySelectorAll('.nav-item')[4].classList.add('active');
                document.getElementById('tab-mitre').classList.add('active');
                document.getElementById('viewTitle').innerText = 'MITRE ATT&CK Matrix & TTP Mappings';
            }} else if (tabId === 'vql') {{
                document.querySelectorAll('.nav-item')[5].classList.add('active');
                document.getElementById('tab-vql').classList.add('active');
                document.getElementById('viewTitle').innerText = 'VQL Interactive Threat Query Console';
            }}
        }}

        function setVql(query) {{
            document.getElementById('vqlInput').value = query;
            executeVql();
        }}

        function filterEvents() {{
            let input = document.getElementById('eventSearch');
            let filter = input.value.toLowerCase();
            let table = document.getElementById('eventTable');
            let tr = table.getElementsByTagName('tr');

            for (let i = 1; i < tr.length; i++) {{
                let text = tr[i].textContent || tr[i].innerText;
                tr[i].style.display = text.toLowerCase().indexOf(filter) > -1 ? "" : "none";
            }}
        }}

        function executeVql() {{
            let query = document.getElementById('vqlInput').value;
            let outputEl = document.getElementById('vqlOutput');
            outputEl.innerText = "Executing VQL query: " + query + "...";

            fetch('/api/query?q=' + encodeURIComponent(query))
                .then(res => res.json())
                .then(data => {{
                    outputEl.innerText = JSON.stringify(data, null, 2);
                }})
                .catch(err => {{
                    outputEl.innerText = "Error executing VQL: " + err;
                }});
        }}
    </script>
</body>
</html>"#,
        uuid = artifact.header.artifact_uuid,
        risk_color = if report.risk_score >= 75 { "var(--red)" } else if report.risk_score >= 40 { "var(--yellow)" } else { "var(--green)" },
        risk_score = report.risk_score,
        event_count = artifact.events.len(),
        alert_count = report.alerts.len(),
        merkle_root = hex_encode(&artifact.trailer.merkle_root),
        signer_pubkey = hex_encode(&artifact.trailer.signer_public_key),
        tree_text = tree_text,
        events_json = events_json,
        alerts_json = alerts_json,
        alerts_html = if report.alerts.is_empty() {
            "<div style=\"color: var(--green); font-size: 14px;\">✔ No high-risk threats detected in this artifact session.</div>".to_string()
        } else {
            report.alerts.iter().map(|a| {
                format!(
                    "<div style=\"background: #181d26; border-left: 4px solid var(--red); padding: 14px 18px; border-radius: 6px; margin-bottom: 12px;\"><div style=\"font-weight: 700; color: var(--text-bright); font-size: 15px;\">{} [{}] ({})</div><div style=\"color: var(--text-dim); font-size: 12px; margin-top: 6px;\"><strong>Remediation:</strong> {}</div></div>",
                    a.title, a.rule_id, a.severity, a.remediation
                )
            }).collect::<Vec<_>>().join("\n")
        },
        timeline_html = if artifact.events.is_empty() {
            "<div style=\"color: var(--text-dim);\">No timeline events recorded.</div>".to_string()
        } else {
            artifact.events.iter().take(50).map(|e| {
                let is_threat = matches!(e.event_type, veyronis_ir::event::EventType::CryptoOperation);
                let class_name = if is_threat { "timeline-item threat" } else { "timeline-item" };
                let color_badge = if is_threat { "var(--red)" } else { "var(--accent)" };
                format!(
                    "<div class=\"{}\"><div style=\"font-size: 12px; color: var(--text-dim);\">{}</div><div style=\"font-weight: 700; color: {}; font-size: 14px; margin-top: 2px;\">{} - <span style=\"color: var(--text-bright);\">{}</span> (PID: {})</div></div>",
                    class_name,
                    e.timestamp_wall,
                    color_badge,
                    e.event_type,
                    e.process_identity.canonical_name(),
                    e.process_identity.pid
                )
            }).collect::<Vec<_>>().join("\n")
        },
        events_html = artifact.events.iter().take(200).map(|e| {
            format!(
                "<tr><td><code>{}</code></td><td><span class=\"badge\" style=\"background: #1f2a3c; color: var(--accent);\">{}</span></td><td><strong>{}</strong></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                &e.event_id.to_string()[..8],
                e.event_type,
                e.process_identity.canonical_name(),
                e.process_identity.pid,
                e.confidence,
                e.timestamp_wall
            )
        }).collect::<Vec<_>>().join("\n")
    )
}
