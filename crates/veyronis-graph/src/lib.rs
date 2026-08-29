pub mod edge;
pub mod graph;
pub mod process_tree;

pub use edge::{EdgeKind, GraphEdge};
pub use graph::BehaviorGraph;
pub use process_tree::{ProcessNode, ProcessTree};

#[cfg(test)]
mod tests {
    use super::*;
    use veyronis_ir::categories::*;
    use veyronis_ir::event::{EventType, VirEvent};
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_behavior_graph_traversal() {
        let mut graph = BehaviorGraph::new();

        let proc = ProcessIdentity::new(100, None, 1000, "curl", 1);
        let event1 = VirEvent::new(
            proc.clone(),
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "/usr/bin/curl".into(),
                command_line: vec!["curl".into()],
                working_directory: None,
                parent_pid: None,
                environment_keys: Vec::new(),
            }),
            "test",
        );
        let id1 = event1.event_id;

        let event2 = VirEvent::new(
            proc.clone(),
            EventType::DnsResponse,
            EventData::DnsResponse(DnsResponseData {
                query_name: "example.com".into(),
                record_type: "A".into(),
                addresses: vec!["93.184.216.34".into()],
                rcode: 0,
            }),
            "test",
        )
        .with_parent(id1);
        let id2 = event2.event_id;

        let event3 = VirEvent::new(
            proc,
            EventType::NetworkConnect,
            EventData::NetworkConnect(NetworkConnectData {
                protocol: NetworkProtocol::Tcp,
                local_address: None,
                local_port: None,
                remote_address: "93.184.216.34".parse().unwrap(),
                remote_port: 443,
                remote_hostname: Some("example.com".into()),
                is_external: true,
            }),
            "test",
        )
        .with_causal_parent(id2);
        let id3 = event3.event_id;

        graph.add_event(event1);
        graph.add_event(event2);
        graph.add_event(event3);

        let ancestors = graph.ancestors(&id3);
        assert_eq!(ancestors.len(), 2);

        let descendants = graph.descendants(&id1);
        assert_eq!(descendants.len(), 2);
    }

    #[test]
    fn test_process_tree_rendering() {
        let mut graph = BehaviorGraph::new();
        let p_root = ProcessIdentity::new(10, None, 1000, "parent.exe", 1);
        let p_child = ProcessIdentity::new(20, Some(10), 2000, "child.exe", 1);

        graph.add_event(VirEvent::new(
            p_root,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "parent.exe".into(),
                command_line: vec![],
                working_directory: None,
                parent_pid: None,
                environment_keys: vec![],
            }),
            "test",
        ));

        graph.add_event(VirEvent::new(
            p_child,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "child.exe".into(),
                command_line: vec![],
                working_directory: None,
                parent_pid: Some(10),
                environment_keys: vec![],
            }),
            "test",
        ));

        let tree = ProcessTree::build(&graph);
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.roots[0].children.len(), 1);

        let rendered = tree.render_tree();
        assert!(rendered.contains("parent.exe"));
        assert!(rendered.contains("child.exe"));
    }
}
