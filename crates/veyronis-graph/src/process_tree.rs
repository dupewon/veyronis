use crate::graph::BehaviorGraph;
use std::collections::{BTreeMap, BTreeSet};
use veyronis_ir::event::EventType;
use veyronis_ir::identity::ProcessIdentity;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessNode {
    pub identity: ProcessIdentity,
    pub parent_pid: Option<u32>,
    pub event_count: usize,
    pub file_count: usize,
    pub network_count: usize,
    pub crypto_count: usize,
    pub exit_code: Option<i32>,
    pub children: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProcessTree {
    pub roots: Vec<ProcessNode>,
}

impl ProcessTree {
    pub fn build(graph: &BehaviorGraph) -> Self {
        let mut processes: BTreeMap<u32, ProcessIdentity> = BTreeMap::new();
        let mut parent_map: BTreeMap<u32, u32> = BTreeMap::new();
        let mut event_counts: BTreeMap<u32, (usize, usize, usize, usize, Option<i32>)> =
            BTreeMap::new();

        for event in graph.all_events() {
            let pid = event.process_identity.pid;
            processes
                .entry(pid)
                .or_insert_with(|| event.process_identity.clone());

            if let Some(ppid) = event.process_identity.ppid {
                parent_map.insert(pid, ppid);
            }

            let entry = event_counts.entry(pid).or_insert((0, 0, 0, 0, None));
            entry.0 += 1; // total events

            match event.event_type {
                EventType::FileOpen
                | EventType::FileRead
                | EventType::FileWrite
                | EventType::FileDelete
                | EventType::FileRename => {
                    entry.1 += 1;
                }
                EventType::NetworkConnect
                | EventType::NetworkAccept
                | EventType::NetworkClose
                | EventType::DnsQuery
                | EventType::DnsResponse => {
                    entry.2 += 1;
                }
                EventType::CryptoOperation | EventType::TlsObserved => {
                    entry.3 += 1;
                }
                EventType::ProcessExit => {
                    if let veyronis_ir::categories::EventData::ProcessExit(exit) = &event.data {
                        entry.4 = Some(exit.exit_code);
                    }
                }
                _ => {}
            }
        }

        // Build child map
        let mut children_map: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut child_pids: BTreeSet<u32> = BTreeSet::new();

        for (&pid, &ppid) in &parent_map {
            if processes.contains_key(&ppid) {
                children_map.entry(ppid).or_default().push(pid);
                child_pids.insert(pid);
            }
        }

        let mut roots = Vec::new();
        for &pid in processes.keys() {
            if !child_pids.contains(&pid) {
                roots.push(Self::build_node(
                    pid,
                    &processes,
                    &children_map,
                    &event_counts,
                ));
            }
        }

        Self { roots }
    }

    fn build_node(
        pid: u32,
        processes: &BTreeMap<u32, ProcessIdentity>,
        children_map: &BTreeMap<u32, Vec<u32>>,
        event_counts: &BTreeMap<u32, (usize, usize, usize, usize, Option<i32>)>,
    ) -> ProcessNode {
        let identity = processes
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| ProcessIdentity::new(pid, None, 0, "unknown", 0));
        let parent_pid = identity.ppid;
        let (event_count, file_count, network_count, crypto_count, exit_code) = event_counts
            .get(&pid)
            .cloned()
            .unwrap_or((0, 0, 0, 0, None));

        let mut children = Vec::new();
        if let Some(child_pids) = children_map.get(&pid) {
            for &c_pid in child_pids {
                children.push(Self::build_node(
                    c_pid,
                    processes,
                    children_map,
                    event_counts,
                ));
            }
        }

        ProcessNode {
            identity,
            parent_pid,
            event_count,
            file_count,
            network_count,
            crypto_count,
            exit_code,
            children,
        }
    }

    pub fn render_tree(&self) -> String {
        let mut output = String::new();
        for (i, root) in self.roots.iter().enumerate() {
            let is_last = i + 1 == self.roots.len();
            Self::render_node(root, "", is_last, &mut output);
        }
        output
    }

    fn render_node(node: &ProcessNode, prefix: &str, is_last: bool, out: &mut String) {
        let marker = if prefix.is_empty() {
            ""
        } else if is_last {
            "└── "
        } else {
            "├── "
        };

        let exit_str = match node.exit_code {
            Some(code) => format!(" (exit: {})", code),
            None => "".to_string(),
        };

        out.push_str(&format!(
            "{}{}{} [pid: {}, events: {}, files: {}, net: {}, crypto: {}]{}\n",
            prefix,
            marker,
            node.identity.canonical_name(),
            node.identity.pid,
            node.event_count,
            node.file_count,
            node.network_count,
            node.crypto_count,
            exit_str
        ));

        let new_prefix = if prefix.is_empty() {
            ""
        } else if is_last {
            "    "
        } else {
            "│   "
        };
        let combined_prefix = format!("{}{}", prefix, new_prefix);

        for (i, child) in node.children.iter().enumerate() {
            let child_is_last = i + 1 == node.children.len();
            Self::render_node(child, &combined_prefix, child_is_last, out);
        }
    }
}
