use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, Tabs},
    Terminal,
};
use std::io;
use std::path::Path;
use veyronis_detect::DetectionEngine;
use veyronis_format::VyrReader;
use veyronis_graph::ProcessTree;
use veyronis_keystore::KeyStore;

pub struct TuiViewer;

impl TuiViewer {
    pub fn run(
        artifact_path: &Path,
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
            return Err(anyhow::anyhow!(
                "cannot decrypt artifact: recipient key '{}' not found in keystore and no passphrase provided",
                label
            ));
        };

        let detection_engine = DetectionEngine::new();
        let detection_report = detection_engine.scan(&decrypted.events, decrypted.graph.as_ref());

        let process_tree_text = if let Some(graph) = &decrypted.graph {
            let tree = ProcessTree::build(graph);
            tree.render_tree()
        } else {
            "No process tree available".to_string()
        };

        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut active_tab = 0;
        let tab_titles = [
            "Overview & Crypto",
            "Process Tree",
            "Event Stream",
            "Threat Scan",
        ];

        loop {
            terminal.draw(|f| {
                let size = f.area();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(0),
                        Constraint::Length(2),
                    ])
                    .split(size);

                // Top Tabs
                let titles: Vec<Line> = tab_titles
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        let style = if i == active_tab {
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        };
                        Line::from(vec![Span::raw(format!(" [{}] {} ", i + 1, t))]).style(style)
                    })
                    .collect();

                let tabs = Tabs::new(titles)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" VEYRONIS TUI EXPLORER v0.1.0 "),
                    )
                    .select(active_tab)
                    .style(Style::default().fg(Color::White))
                    .highlight_style(Style::default().fg(Color::Yellow));
                f.render_widget(tabs, chunks[0]);

                // Content Panel
                match active_tab {
                    0 => {
                        let manifest = decrypted.manifest.as_ref();
                        let target_cmd = manifest
                            .map(|m| m.target_command.join(" "))
                            .unwrap_or_else(|| "Unknown".into());
                        let platform_str = manifest
                            .map(|m| m.platform.to_string())
                            .unwrap_or_else(|| "Unknown".into());
                        let duration = manifest.map(|m| m.duration_ms).unwrap_or(0);

                        let info_text = vec![
                            Line::from(vec![
                                Span::styled(
                                    "Artifact UUID:      ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw(decrypted.header.artifact_uuid.to_string()),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Target Command:     ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw(target_cmd),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Host Platform:      ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw(platform_str),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Duration:           ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw(format!("{} ms", duration)),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Total VIR Events:   ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw(decrypted.events.len().to_string()),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Cipher / AEAD:      ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw("XChaCha20-Poly1305 (256-bit)"),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Merkle Root (BLAKE3):",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw(hex_encode(&decrypted.trailer.merkle_root)),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Signer PubKey:      ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::raw(hex_encode(&decrypted.trailer.signer_public_key)),
                            ]),
                            Line::from(vec![
                                Span::styled(
                                    "Signature Trust:    ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::styled(
                                    "VERIFIED (Ed25519)",
                                    Style::default()
                                        .fg(Color::Green)
                                        .add_modifier(Modifier::BOLD),
                                ),
                            ]),
                        ];

                        let p = Paragraph::new(info_text).block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(" Container Provenance & Metadata "),
                        );
                        f.render_widget(p, chunks[1]);
                    }
                    1 => {
                        let p = Paragraph::new(process_tree_text.clone()).block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(" Process Hierarchy & Lineage "),
                        );
                        f.render_widget(p, chunks[1]);
                    }
                    2 => {
                        let rows: Vec<Row> = decrypted
                            .events
                            .iter()
                            .take(50)
                            .map(|e| {
                                Row::new(vec![
                                    e.event_id.to_string()[..8].to_string(),
                                    e.event_type.to_string(),
                                    e.process_identity.canonical_name().to_string(),
                                    e.process_identity.pid.to_string(),
                                    e.confidence.to_string(),
                                ])
                            })
                            .collect();

                        let table = Table::new(
                            rows,
                            [
                                Constraint::Length(10),
                                Constraint::Length(18),
                                Constraint::Length(25),
                                Constraint::Length(8),
                                Constraint::Length(12),
                            ],
                        )
                        .header(
                            Row::new(vec!["ID", "Event Type", "Process", "PID", "Confidence"])
                                .style(
                                    Style::default()
                                        .fg(Color::Yellow)
                                        .add_modifier(Modifier::BOLD),
                                ),
                        )
                        .block(
                            Block::default().borders(Borders::ALL).title(format!(
                                " Recorded VIR Events ({}) ",
                                decrypted.events.len()
                            )),
                        );
                        f.render_widget(table, chunks[1]);
                    }
                    3 => {
                        let mut alert_lines = vec![
                            Line::from(vec![
                                Span::styled(
                                    "Overall Risk Score: ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::styled(
                                    format!("{}/100", detection_report.risk_score),
                                    if detection_report.risk_score >= 75 {
                                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                                    } else if detection_report.risk_score >= 40 {
                                        Style::default()
                                            .fg(Color::Yellow)
                                            .add_modifier(Modifier::BOLD)
                                    } else {
                                        Style::default()
                                            .fg(Color::Green)
                                            .add_modifier(Modifier::BOLD)
                                    },
                                ),
                            ]),
                            Line::from(""),
                        ];

                        if detection_report.alerts.is_empty() {
                            alert_lines.push(Line::from(Span::styled(
                                "  [+] No behavioral security threats detected.",
                                Style::default()
                                    .fg(Color::Green)
                                    .add_modifier(Modifier::BOLD),
                            )));
                        } else {
                            for a in &detection_report.alerts {
                                alert_lines.push(Line::from(vec![
                                    Span::styled(
                                        format!("[{}] ", a.severity),
                                        Style::default().fg(Color::Red),
                                    ),
                                    Span::styled(
                                        format!("{}: ", a.rule_id),
                                        Style::default().fg(Color::Yellow),
                                    ),
                                    Span::raw(a.title.clone()),
                                ]));
                                alert_lines.push(Line::from(vec![
                                    Span::styled(
                                        "   MITRE:       ",
                                        Style::default().fg(Color::Cyan),
                                    ),
                                    Span::raw(a.mitre_technique.as_deref().unwrap_or("N/A")),
                                ]));
                                alert_lines.push(Line::from(vec![
                                    Span::styled(
                                        "   Remediation: ",
                                        Style::default().fg(Color::Gray),
                                    ),
                                    Span::raw(a.remediation.clone()),
                                ]));
                                alert_lines.push(Line::from(""));
                            }
                        }

                        let p = Paragraph::new(alert_lines).block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(" Behavioral Threat Intelligence & Scan "),
                        );
                        f.render_widget(p, chunks[1]);
                    }
                    _ => {}
                }

                // Bottom Status Bar
                let status_bar =
                    Paragraph::new(" [1-4] Switch Tabs | [q/Esc] Exit | [↑/↓] Navigate")
                        .style(Style::default().fg(Color::DarkGray));
                f.render_widget(status_bar, chunks[2]);
            })?;

            // Handle Key Events
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('1') => active_tab = 0,
                        KeyCode::Char('2') => active_tab = 1,
                        KeyCode::Char('3') => active_tab = 2,
                        KeyCode::Char('4') => active_tab = 3,
                        KeyCode::Tab => active_tab = (active_tab + 1) % 4,
                        _ => {}
                    }
                }
            }
        }

        // Restore terminal
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
