use crate::edge::{EdgeKind, GraphEdge};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use uuid::Uuid;
use veyronis_ir::categories::EventData;
use veyronis_ir::event::{EventType, VirEvent};

/// Deterministic directed behavior graph modeling execution telemetry and causal relationships.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BehaviorGraph {
    nodes: BTreeMap<Uuid, VirEvent>,
    outgoing: BTreeMap<Uuid, Vec<GraphEdge>>,
    incoming: BTreeMap<Uuid, Vec<GraphEdge>>,
}

impl BehaviorGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a graph from a collection of VIR events and infers relationships.
    pub fn from_events(events: Vec<VirEvent>) -> Self {
        let mut graph = Self::new();
        for event in events {
            graph.add_event(event);
        }
        graph.build_inferred_edges();
        graph
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.outgoing.values().map(|edges| edges.len()).sum()
    }

    pub fn add_event(&mut self, event: VirEvent) {
        let id = event.event_id;

        // Explicit structural parent
        if let Some(parent_id) = event.parent_event_id {
            self.add_edge_internal(GraphEdge::new(parent_id, id, EdgeKind::Parent));
        }

        // Explicit causal parents
        for causal_id in &event.causal_parent_ids {
            self.add_edge_internal(GraphEdge::new(*causal_id, id, EdgeKind::Causal));
        }

        self.nodes.insert(id, event);
    }

    pub fn add_edge(&mut self, edge: GraphEdge) {
        if self.nodes.contains_key(&edge.source_id) && self.nodes.contains_key(&edge.target_id) {
            self.add_edge_internal(edge);
        }
    }

    fn add_edge_internal(&mut self, edge: GraphEdge) {
        self.outgoing
            .entry(edge.source_id)
            .or_default()
            .push(edge.clone());
        self.incoming.entry(edge.target_id).or_default().push(edge);
    }

    pub fn get_event(&self, id: &Uuid) -> Option<&VirEvent> {
        self.nodes.get(id)
    }

    pub fn all_events(&self) -> impl Iterator<Item = &VirEvent> {
        self.nodes.values()
    }

    /// Infer semantic edges: temporal ordering within threads, process lineage, resource reuse, network flows.
    pub fn build_inferred_edges(&mut self) {
        // Group event IDs by PID and Thread ID
        let mut pid_events: BTreeMap<u32, Vec<Uuid>> = BTreeMap::new();
        let mut file_path_events: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
        let mut dns_to_net: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();

        // Sort events deterministically by wall timestamp then monotonic nanos
        let mut sorted_events: Vec<VirEvent> = self.nodes.values().cloned().collect();
        sorted_events.sort_by(|a, b| {
            a.timestamp_wall
                .cmp(&b.timestamp_wall)
                .then_with(|| a.timestamp_monotonic_ns.cmp(&b.timestamp_monotonic_ns))
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        for event in &sorted_events {
            pid_events
                .entry(event.process_identity.pid)
                .or_default()
                .push(event.event_id);

            match &event.data {
                EventData::FileOpen(f) => {
                    file_path_events
                        .entry(f.normalized_path.clone())
                        .or_default()
                        .push(event.event_id);
                }
                EventData::FileRead(f) => {
                    file_path_events
                        .entry(f.path.clone())
                        .or_default()
                        .push(event.event_id);
                }
                EventData::FileWrite(f) => {
                    file_path_events
                        .entry(f.path.clone())
                        .or_default()
                        .push(event.event_id);
                }
                EventData::DnsResponse(d) => {
                    for addr in &d.addresses {
                        dns_to_net
                            .entry(addr.clone())
                            .or_default()
                            .push(event.event_id);
                    }
                }
                EventData::NetworkConnect(n) => {
                    let remote_ip = n.remote_address.to_string();
                    if let Some(dns_ids) = dns_to_net.get(&remote_ip) {
                        for dns_id in dns_ids {
                            self.add_edge_internal(GraphEdge::new(
                                *dns_id,
                                event.event_id,
                                EdgeKind::Causal,
                            ));
                        }
                    }
                }
                EventData::ProcessSpawn(s) => {
                    // Link parent process spawn event to child's ProcessStart if present
                    for candidate in &sorted_events {
                        if candidate.process_identity.pid == s.child_pid
                            && candidate.event_type == EventType::ProcessStart
                        {
                            self.add_edge_internal(GraphEdge::new(
                                event.event_id,
                                candidate.event_id,
                                EdgeKind::ProcessLineage,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }

        // Build temporal edges within each process
        for (_pid, ids) in pid_events {
            for window in ids.windows(2) {
                self.add_edge_internal(GraphEdge::new(window[0], window[1], EdgeKind::Temporal));
            }
        }

        // Build resource relationship edges for files accessed multiple times
        for (_path, ids) in file_path_events {
            for window in ids.windows(2) {
                self.add_edge_internal(GraphEdge::new(
                    window[0],
                    window[1],
                    EdgeKind::ResourceRelationship,
                ));
            }
        }
    }

    /// Traverses directed edges backwards to return all ancestors of an event.
    pub fn ancestors(&self, event_id: &Uuid) -> Vec<&VirEvent> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back(*event_id);
        visited.insert(*event_id);

        while let Some(current) = queue.pop_front() {
            if let Some(incoming_edges) = self.incoming.get(&current) {
                for edge in incoming_edges {
                    if visited.insert(edge.source_id) {
                        if let Some(node) = self.nodes.get(&edge.source_id) {
                            result.push(node);
                            queue.push_back(edge.source_id);
                        }
                    }
                }
            }
        }
        result
    }

    /// Traverses directed edges forward to return all descendants of an event.
    pub fn descendants(&self, event_id: &Uuid) -> Vec<&VirEvent> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back(*event_id);
        visited.insert(*event_id);

        while let Some(current) = queue.pop_front() {
            if let Some(outgoing_edges) = self.outgoing.get(&current) {
                for edge in outgoing_edges {
                    if visited.insert(edge.target_id) {
                        if let Some(node) = self.nodes.get(&edge.target_id) {
                            result.push(node);
                            queue.push_back(edge.target_id);
                        }
                    }
                }
            }
        }
        result
    }

    /// Returns events in the causal neighborhood up to a given depth.
    pub fn causal_neighborhood(&self, event_id: &Uuid, depth: usize) -> Vec<&VirEvent> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back((*event_id, 0));
        visited.insert(*event_id);

        while let Some((current, d)) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&current) {
                if current != *event_id {
                    result.push(node);
                }
            }
            if d < depth {
                if let Some(out) = self.outgoing.get(&current) {
                    for edge in out {
                        if (edge.kind == EdgeKind::Causal || edge.kind == EdgeKind::Parent)
                            && visited.insert(edge.target_id)
                        {
                            queue.push_back((edge.target_id, d + 1));
                        }
                    }
                }
                if let Some(inc) = self.incoming.get(&current) {
                    for edge in inc {
                        if (edge.kind == EdgeKind::Causal || edge.kind == EdgeKind::Parent)
                            && visited.insert(edge.source_id)
                        {
                            queue.push_back((edge.source_id, d + 1));
                        }
                    }
                }
            }
        }
        result
    }

    /// Deterministically sorted vector of all events for serialization.
    pub fn events_deterministic(&self) -> Vec<&VirEvent> {
        let mut events: Vec<&VirEvent> = self.nodes.values().collect();
        events.sort_by(|a, b| {
            a.timestamp_wall
                .cmp(&b.timestamp_wall)
                .then_with(|| a.timestamp_monotonic_ns.cmp(&b.timestamp_monotonic_ns))
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        events
    }

    /// Computes canonical BLAKE3 hash over the deterministic graph topology.
    pub fn canonical_hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        for event in self.events_deterministic() {
            hasher.update(event.canonical_hash().as_bytes());
        }
        for (src, edges) in &self.outgoing {
            for edge in edges {
                hasher.update(src.as_bytes());
                hasher.update(edge.target_id.as_bytes());
                hasher.update(edge.kind.to_string().as_bytes());
            }
        }
        hasher.finalize()
    }
}
