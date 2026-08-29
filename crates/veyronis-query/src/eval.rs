use crate::ast::*;
use serde::{Deserialize, Serialize};
use tabled::Tabled;
use veyronis_graph::BehaviorGraph;
use veyronis_ir::categories::EventData;
use veyronis_ir::event::VirEvent;

#[derive(Debug, Clone, Serialize, Deserialize, Tabled)]
pub struct QueryResultRow {
    #[tabled(rename = "Event ID")]
    pub event_id: String,
    #[tabled(rename = "Type")]
    pub event_type: String,
    #[tabled(rename = "Process")]
    pub process: String,
    #[tabled(rename = "PID")]
    pub pid: u32,
    #[tabled(rename = "Summary")]
    pub summary: String,
    #[tabled(rename = "Confidence")]
    pub confidence: String,
}

pub struct QueryEngine<'a> {
    events: &'a [VirEvent],
    _graph: Option<&'a BehaviorGraph>,
}

impl<'a> QueryEngine<'a> {
    pub fn new(events: &'a [VirEvent], graph: Option<&'a BehaviorGraph>) -> Self {
        Self {
            events,
            _graph: graph,
        }
    }

    pub fn execute(&self, query: &Query) -> Vec<QueryResultRow> {
        match query {
            Query::Find(find) => self.execute_find(find),
            Query::Match(m) => self.execute_match(m),
        }
    }

    fn execute_find(&self, find: &FindQuery) -> Vec<QueryResultRow> {
        let mut results = Vec::new();

        for event in self.events {
            if let Some(filter) = &find.filter {
                if !self.eval_expr(filter, event) {
                    continue;
                }
            }

            let summary = format_event_summary(event);
            results.push(QueryResultRow {
                event_id: event.event_id.to_string()[..8].to_string(),
                event_type: event.event_type.to_string(),
                process: event.process_identity.canonical_name().to_string(),
                pid: event.process_identity.pid,
                summary,
                confidence: event.confidence.to_string(),
            });

            if let Some(limit) = find.limit {
                if results.len() >= limit {
                    break;
                }
            }
        }

        results
    }

    fn execute_match(&self, m: &MatchQuery) -> Vec<QueryResultRow> {
        if m.sequence.len() < 2 {
            return Vec::new();
        }

        let mut results = Vec::new();
        let target_seq: Vec<String> = m.sequence.iter().map(|s| s.to_uppercase()).collect();

        // Check sliding window across event stream
        for window in self.events.windows(target_seq.len()) {
            let mut matches = true;
            for (i, target_type) in target_seq.iter().enumerate() {
                if window[i].event_type.to_string().to_uppercase() != *target_type {
                    matches = false;
                    break;
                }
            }

            if matches {
                for event in window {
                    results.push(QueryResultRow {
                        event_id: event.event_id.to_string()[..8].to_string(),
                        event_type: event.event_type.to_string(),
                        process: event.process_identity.canonical_name().to_string(),
                        pid: event.process_identity.pid,
                        summary: format_event_summary(event),
                        confidence: event.confidence.to_string(),
                    });
                }
            }
        }

        results
    }

    fn eval_expr(&self, expr: &Expr, event: &VirEvent) -> bool {
        match expr {
            Expr::Comparison { field, op, value } => self.eval_comparison(field, *op, value, event),
            Expr::And(left, right) => self.eval_expr(left, event) && self.eval_expr(right, event),
            Expr::Or(left, right) => self.eval_expr(left, event) || self.eval_expr(right, event),
            Expr::Not(inner) => !self.eval_expr(inner, event),
        }
    }

    fn eval_comparison(&self, field: &str, op: CmpOp, value: &Value, event: &VirEvent) -> bool {
        let field_lower = field.to_lowercase();

        match field_lower.as_str() {
            "type" | "event.type" | "event_type" => {
                let actual = event.event_type.to_string().to_lowercase();
                compare_strings(&actual, op, value)
            }
            "process.name" | "process" | "executable" => {
                let actual = event.process_identity.canonical_name().to_lowercase();
                compare_strings(&actual, op, value)
            }
            "process.pid" | "pid" => {
                let actual = event.process_identity.pid as f64;
                compare_numbers(actual, op, value)
            }
            "crypto.algorithm" | "algorithm" => match &event.data {
                EventData::CryptoOperation(c) => {
                    compare_strings(&c.algorithm.to_lowercase(), op, value)
                }
                _ => false,
            },
            "crypto.provider" | "provider" => match &event.data {
                EventData::CryptoOperation(c) => {
                    compare_strings(&c.provider.to_lowercase(), op, value)
                }
                _ => false,
            },
            "network.external" | "network.is_external" => match &event.data {
                EventData::NetworkConnect(n) => compare_bools(n.is_external, op, value),
                _ => false,
            },
            "network.remote_address" | "network.dst_ip" => match &event.data {
                EventData::NetworkConnect(n) => {
                    compare_strings(&n.remote_address.to_string(), op, value)
                }
                _ => false,
            },
            "network.remote_port" | "network.dst_port" => match &event.data {
                EventData::NetworkConnect(n) => compare_numbers(n.remote_port as f64, op, value),
                _ => false,
            },
            "file.path" | "path" => match &event.data {
                EventData::FileOpen(f) => compare_strings(&f.path.to_lowercase(), op, value),
                EventData::FileRead(f) => compare_strings(&f.path.to_lowercase(), op, value),
                EventData::FileWrite(f) => compare_strings(&f.path.to_lowercase(), op, value),
                EventData::FileDelete(f) => compare_strings(&f.path.to_lowercase(), op, value),
                _ => false,
            },
            "confidence" => {
                let actual = event.confidence.to_string().to_lowercase();
                compare_strings(&actual, op, value)
            }
            "privacy" => {
                let actual = event.privacy.to_string().to_lowercase();
                compare_strings(&actual, op, value)
            }
            _ => false,
        }
    }
}

fn compare_strings(actual: &str, op: CmpOp, expected: &Value) -> bool {
    let expected_str = match expected {
        Value::String(s) => s.to_lowercase(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
    };

    match op {
        CmpOp::Eq => actual == expected_str,
        CmpOp::Ne => actual != expected_str,
        CmpOp::Contains => actual.contains(&expected_str),
        CmpOp::StartsWith => actual.starts_with(&expected_str),
        _ => false,
    }
}

fn compare_numbers(actual: f64, op: CmpOp, expected: &Value) -> bool {
    let exp_num = match expected {
        Value::Number(n) => *n,
        Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
    };

    match op {
        CmpOp::Eq => (actual - exp_num).abs() < f64::EPSILON,
        CmpOp::Ne => (actual - exp_num).abs() >= f64::EPSILON,
        CmpOp::Lt => actual < exp_num,
        CmpOp::Lte => actual <= exp_num,
        CmpOp::Gt => actual > exp_num,
        CmpOp::Gte => actual >= exp_num,
        _ => false,
    }
}

fn compare_bools(actual: bool, op: CmpOp, expected: &Value) -> bool {
    let exp_bool = match expected {
        Value::Bool(b) => *b,
        Value::String(s) => s.to_lowercase() == "true",
        Value::Number(n) => *n != 0.0,
    };

    match op {
        CmpOp::Eq => actual == exp_bool,
        CmpOp::Ne => actual != exp_bool,
        _ => false,
    }
}

fn format_event_summary(event: &VirEvent) -> String {
    match &event.data {
        EventData::ProcessStart(p) => format!("exec {}", p.executable_path),
        EventData::ProcessExit(e) => format!("exit code {}", e.exit_code),
        EventData::ProcessSpawn(s) => {
            format!("spawn pid:{} ({})", s.child_pid, s.child_executable_path)
        }
        EventData::FileOpen(f) => format!("open {}", f.path),
        EventData::FileRead(f) => format!("read {} bytes from {}", f.bytes_read, f.path),
        EventData::FileWrite(f) => format!("write {} bytes to {}", f.bytes_written, f.path),
        EventData::FileDelete(f) => format!("delete {}", f.path),
        EventData::FileRename(f) => format!("rename {} -> {}", f.old_path, f.new_path),
        EventData::DnsQuery(d) => format!("query {}", d.query_name),
        EventData::DnsResponse(d) => format!("resolved {} -> {:?}", d.query_name, d.addresses),
        EventData::NetworkConnect(n) => format!("connect {}:{}", n.remote_address, n.remote_port),
        EventData::NetworkAccept(n) => {
            format!("accept from {}:{}", n.remote_address, n.remote_port)
        }
        EventData::NetworkClose(n) => {
            format!("close sent:{} recv:{}", n.bytes_sent, n.bytes_received)
        }
        EventData::SocketCreate(s) => format!("socket {}/{}", s.domain, s.protocol),
        EventData::CryptoOperation(c) => format!(
            "{:?} algo:{} provider:{}",
            c.category, c.algorithm, c.provider
        ),
        EventData::TlsObserved(t) => format!("TLS {} ciphersuite:{:?}", t.version, t.cipher_suite),
        EventData::MemoryMap(m) => format!("mmap size:{} perm:{}", m.size_bytes, m.permissions),
        EventData::MemoryProtect(m) => format!("mprotect perm:{}", m.new_permissions),
        EventData::IpcConnect(i) => format!("ipc connect {}", i.target_endpoint),
        EventData::IpcSend(i) => format!("ipc send {} bytes", i.message_bytes),
        EventData::UserSession(u) => format!("user {}", u.username),
        EventData::SystemMetadata(s) => format!("os {} arch {}", s.os_name, s.architecture),
    }
}
