use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;
use veyronis_detect::DetectionEngine;
use veyronis_diff::DiffEngine;
use veyronis_format::VyrReader;
use veyronis_parser::BinaryInspector;
use veyronis_query::{Parser as VqlParser, QueryEngine};

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

pub struct McpServer;

impl McpServer {
    /// Starts the Model Context Protocol (MCP) JSON-RPC loop over standard I/O.
    pub fn run_stdio() -> Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let handle = stdin.lock();

        for line in handle.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&line) {
                let response = Self::handle_request(req);
                let res_json = serde_json::to_string(&response)?;
                writeln!(stdout, "{}", res_json)?;
                stdout.flush()?;
            }
        }

        Ok(())
    }

    fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.clone();
        match req.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "veyronis-mcp",
                        "version": "0.1.0"
                    }
                });
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: Some(result),
                    error: None,
                }
            }

            "tools/list" => {
                let tools = json!({
                    "tools": [
                        {
                            "name": "veyronis_inspect",
                            "description": "Inspects a Veyronis .vyr forensic artifact header, Merkle root, and event count",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "artifact_path": { "type": "string", "description": "Path to .vyr artifact" },
                                    "passphrase": { "type": "string", "description": "Optional container passphrase" }
                                },
                                "required": ["artifact_path"]
                            }
                        },
                        {
                            "name": "veyronis_query",
                            "description": "Executes a VQL behavioral query over a .vyr artifact (e.g. FIND event WHERE type = 'NetworkConnect')",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "artifact_path": { "type": "string", "description": "Path to .vyr artifact" },
                                    "query": { "type": "string", "description": "VQL query string" },
                                    "passphrase": { "type": "string", "description": "Optional passphrase" }
                                },
                                "required": ["artifact_path", "query"]
                            }
                        },
                        {
                            "name": "veyronis_scan",
                            "description": "Scans a .vyr container against behavioral Sigma rules and maps MITRE ATT&CK techniques",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "artifact_path": { "type": "string", "description": "Path to .vyr artifact" },
                                    "passphrase": { "type": "string", "description": "Optional passphrase" }
                                },
                                "required": ["artifact_path"]
                            }
                        },
                        {
                            "name": "veyronis_analyze_binary",
                            "description": "Performs static binary inspection, PE/ELF/Mach-O section parsing, and Shannon entropy analysis",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "binary_path": { "type": "string", "description": "Path to target binary" }
                                },
                                "required": ["binary_path"]
                            }
                        },
                        {
                            "name": "veyronis_diff",
                            "description": "Calculates semantic behavioral diff and similarity between baseline and comparison artifacts",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "baseline_path": { "type": "string", "description": "Path to baseline .vyr" },
                                    "comparison_path": { "type": "string", "description": "Path to comparison .vyr" },
                                    "passphrase": { "type": "string", "description": "Optional passphrase" }
                                },
                                "required": ["baseline_path", "comparison_path"]
                            }
                        },
                        {
                            "name": "veyronis_generate_rules",
                            "description": "Synthesizes automated YARA strings and Sigma detection rules from recorded behavioral telemetry",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "artifact_path": { "type": "string", "description": "Path to .vyr artifact" },
                                    "passphrase": { "type": "string", "description": "Optional passphrase" }
                                },
                                "required": ["artifact_path"]
                            }
                        }
                    ]
                });

                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: Some(tools),
                    error: None,
                }
            }

            "tools/call" => {
                let tool_name = req
                    .params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let args = req.params.get("arguments").cloned().unwrap_or(json!({}));

                match Self::execute_tool(tool_name, &args) {
                    Ok(val) => JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: Some(
                            json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&val).unwrap_or_default() }] }),
                        ),
                        error: None,
                    },
                    Err(e) => JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: None,
                        error: Some(json!({ "code": -32603, "message": e.to_string() })),
                    },
                }
            }

            _ => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(json!({ "code": -32601, "message": "Method not found" })),
            },
        }
    }

    fn execute_tool(name: &str, args: &Value) -> Result<Value> {
        match name {
            "veyronis_inspect" => {
                let path = args
                    .get("artifact_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing artifact_path"))?;
                let pass = args
                    .get("passphrase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reader = VyrReader::open_file(Path::new(path))?;
                let decrypted = reader.decrypt_with_passphrase(pass.as_bytes())?;

                Ok(json!({
                    "artifact_uuid": decrypted.header.artifact_uuid.to_string(),
                    "created_timestamp": decrypted.header.created_timestamp,
                    "event_count": decrypted.events.len(),
                    "is_signed": decrypted.header.is_signed(),
                    "is_encrypted": decrypted.header.is_encrypted(),
                }))
            }

            "veyronis_query" => {
                let path = args
                    .get("artifact_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing artifact_path"))?;
                let query_str = args
                    .get("query")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing query"))?;
                let pass = args
                    .get("passphrase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reader = VyrReader::open_file(Path::new(path))?;
                let decrypted = reader.decrypt_with_passphrase(pass.as_bytes())?;

                let parsed = VqlParser::parse_str(query_str)
                    .map_err(|e| anyhow::anyhow!("VQL syntax error: {}", e))?;
                let engine = QueryEngine::new(&decrypted.events, decrypted.graph.as_ref());
                let results = engine.execute(&parsed);

                Ok(json!({ "matched_events": results }))
            }

            "veyronis_scan" => {
                let path = args
                    .get("artifact_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing artifact_path"))?;
                let pass = args
                    .get("passphrase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reader = VyrReader::open_file(Path::new(path))?;
                let decrypted = reader.decrypt_with_passphrase(pass.as_bytes())?;

                let engine = DetectionEngine::new();
                let report = engine.scan(&decrypted.events, decrypted.graph.as_ref());

                Ok(json!({
                    "risk_score": report.risk_score,
                    "total_rules": report.total_rules_evaluated,
                    "alerts": report.alerts
                }))
            }

            "veyronis_analyze_binary" => {
                let path = args
                    .get("binary_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing binary_path"))?;
                let report = BinaryInspector::inspect_file(Path::new(path))?;

                Ok(json!({
                    "file_path": report.file_path,
                    "size_bytes": report.size_bytes,
                    "overall_entropy": report.overall_entropy,
                    "is_packed": report.is_packed,
                }))
            }

            "veyronis_diff" => {
                let base_path = args
                    .get("baseline_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing baseline_path"))?;
                let comp_path = args
                    .get("comparison_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing comparison_path"))?;
                let pass = args
                    .get("passphrase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let reader_a = VyrReader::open_file(Path::new(base_path))?;
                let reader_b = VyrReader::open_file(Path::new(comp_path))?;
                let dec_a = reader_a.decrypt_with_passphrase(pass.as_bytes())?;
                let dec_b = reader_b.decrypt_with_passphrase(pass.as_bytes())?;

                let diff_report = DiffEngine::diff_events(&dec_a.events, &dec_b.events);

                Ok(json!({
                    "similarity_score": diff_report.similarity_score,
                    "added_behaviors": diff_report.added_behaviors,
                    "removed_behaviors": diff_report.removed_behaviors,
                    "changed_behaviors": diff_report.changed_behaviors,
                }))
            }

            "veyronis_generate_rules" => {
                let path = args
                    .get("artifact_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing artifact_path"))?;
                let pass = args
                    .get("passphrase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reader = VyrReader::open_file(Path::new(path))?;
                let decrypted = reader.decrypt_with_passphrase(pass.as_bytes())?;

                let proc_names: Vec<String> = decrypted
                    .events
                    .iter()
                    .map(|e| e.process_identity.canonical_name().to_string())
                    .collect();
                let yara_rule = format!(
                    "rule Veyronis_Generated_Rule {{\n  meta:\n    author = \"Veyronis Automated Rule Synthesizer\"\n    artifact_uuid = \"{}\"\n  strings:\n    $s1 = \"{}\"\n  condition:\n    any of them\n}}",
                    decrypted.header.artifact_uuid,
                    proc_names.first().cloned().unwrap_or_else(|| "malware".into())
                );

                let sigma_rule = format!(
                    "title: Auto-Generated Detection Rule\nid: {}\nstatus: experimental\ndescription: Automatically synthesized from .vyr execution trace\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '{}'\n  condition: selection\nlevel: high\n",
                    uuid::Uuid::new_v4(),
                    proc_names.first().cloned().unwrap_or_else(|| "target.exe".into())
                );

                Ok(json!({
                    "yara_rule": yara_rule,
                    "sigma_rule": sigma_rule
                }))
            }

            _ => Err(anyhow::anyhow!("unsupported tool: {}", name)),
        }
    }
}
