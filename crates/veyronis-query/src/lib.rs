pub mod ast;
pub mod eval;
pub mod lexer;
pub mod parser;

pub use ast::{CmpOp, Expr, FindQuery, MatchQuery, Query, TargetEntity, Value};
pub use eval::{QueryEngine, QueryResultRow};
pub use lexer::{Lexer, Token};
pub use parser::{Parser, ParserError};

#[cfg(test)]
mod tests {
    use super::*;
    use veyronis_ir::categories::*;
    use veyronis_ir::event::{EventType, VirEvent};
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_vql_parser_and_evaluator() {
        let query_str =
            r#"FIND event WHERE type = "CryptoOperation" AND crypto.algorithm = "SHA256""#;
        let query = Parser::parse_str(query_str).expect("parse successful");

        let proc = ProcessIdentity::new(100, None, 0, "curl", 1);
        let event1 = VirEvent::new(
            proc.clone(),
            EventType::CryptoOperation,
            EventData::CryptoOperation(CryptoOperationData {
                category: CryptoCategory::Hash,
                algorithm: "SHA256".into(),
                provider: "OpenSSL".into(),
                key_size_bits: None,
                mode: None,
            }),
            "test",
        );

        let event2 = VirEvent::new(
            proc,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "/usr/bin/curl".into(),
                command_line: vec![],
                working_directory: None,
                parent_pid: None,
                environment_keys: vec![],
            }),
            "test",
        );

        let events = vec![event1, event2];
        let engine = QueryEngine::new(&events, None);
        let results = engine.execute(&query);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_type, "CryptoOperation");
    }

    #[test]
    fn test_vql_network_predicate() {
        let query_str = r#"FIND process WHERE network.external = true"#;
        let query = Parser::parse_str(query_str).expect("parse query");

        let proc = ProcessIdentity::new(200, None, 0, "app", 1);
        let event = VirEvent::new(
            proc,
            EventType::NetworkConnect,
            EventData::NetworkConnect(NetworkConnectData {
                protocol: NetworkProtocol::Tcp,
                local_address: None,
                local_port: None,
                remote_address: "1.1.1.1".parse().unwrap(),
                remote_port: 443,
                remote_hostname: None,
                is_external: true,
            }),
            "test",
        );

        let events = vec![event];
        let engine = QueryEngine::new(&events, None);
        let results = engine.execute(&query);
        assert_eq!(results.len(), 1);
    }
}
