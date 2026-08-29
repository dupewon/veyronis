pub mod embedding;
pub mod engine;
pub mod model;

pub use embedding::BehaviorEmbedding;
pub use engine::DiffEngine;
pub use model::{BehaviorDiffResult, CanonicalBehavior, ChangedBehavior};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use veyronis_ir::categories::{
        FileOpenData, NetworkConnectData, NetworkProtocol, ProcessStartData,
    };
    use veyronis_ir::event::{EventType, VirEvent};
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_diff_engine_detects_added_network_and_calculates_similarity() {
        let p = ProcessIdentity::new(100, None, 1000, "/usr/bin/test_proc", 1);

        let ev1 = VirEvent::new(
            p.clone(),
            EventType::ProcessStart,
            veyronis_ir::categories::EventData::ProcessStart(ProcessStartData {
                executable_path: "/usr/bin/test_proc".into(),
                command_line: vec!["test_proc".into()],
                working_directory: None,
                parent_pid: None,
                environment_keys: vec![],
            }),
            "system",
        );

        let ev2 = VirEvent::new(
            p.clone(),
            EventType::FileOpen,
            veyronis_ir::categories::EventData::FileOpen(FileOpenData {
                path: "/etc/config.json".into(),
                normalized_path: "/etc/config.json".into(),
                read: true,
                write: false,
                create: false,
                truncate: false,
                append: false,
            }),
            "procfs",
        );

        let ev3 = VirEvent::new(
            p.clone(),
            EventType::NetworkConnect,
            veyronis_ir::categories::EventData::NetworkConnect(NetworkConnectData {
                protocol: NetworkProtocol::Tcp,
                local_address: None,
                local_port: None,
                remote_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                remote_port: 443,
                remote_hostname: None,
                is_external: true,
            }),
            "socket",
        );

        let old_events = vec![ev1.clone(), ev2.clone()];
        let new_events = vec![ev1.clone(), ev2.clone(), ev3.clone()];

        let report = DiffEngine::diff_events(&old_events, &new_events);

        assert_eq!(report.added_behaviors.len(), 1);
        assert_eq!(report.removed_behaviors.len(), 0);
        assert!(report.similarity_score > 0.0 && report.similarity_score < 100.0);
    }
}
