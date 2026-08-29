use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetNode {
    pub node_id: Uuid,
    pub hostname: String,
    pub ip_address: String,
    pub os_name: String,
    pub total_artifacts_reported: usize,
    pub last_heartbeat: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Default)]
pub struct ClusterHub {
    nodes: Arc<Mutex<HashMap<Uuid, FleetNode>>>,
}

impl ClusterHub {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_node(&self, hostname: &str, ip_address: &str, os_name: &str) -> FleetNode {
        let mut nodes = self.nodes.lock().unwrap();
        let node_id = Uuid::new_v4();
        let node = FleetNode {
            node_id,
            hostname: hostname.to_string(),
            ip_address: ip_address.to_string(),
            os_name: os_name.to_string(),
            total_artifacts_reported: 0,
            last_heartbeat: Utc::now(),
            status: "ONLINE (HEALTHY)".into(),
        };
        nodes.insert(node_id, node.clone());
        node
    }

    pub fn report_incident(&self, node_id: Uuid) {
        let mut nodes = self.nodes.lock().unwrap();
        if let Some(node) = nodes.get_mut(&node_id) {
            node.total_artifacts_reported += 1;
            node.last_heartbeat = Utc::now();
        }
    }

    pub fn list_nodes(&self) -> Vec<FleetNode> {
        let nodes = self.nodes.lock().unwrap();
        nodes.values().cloned().collect()
    }
}

pub fn render_cluster_status(nodes: &[FleetNode]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        "=== VEYRONIS DISTRIBUTED FLEET CLUSTER HUB ==="
            .bold()
            .white()
    ));
    out.push_str(&format!("Active Connected Nodes: {}\n\n", nodes.len()));

    for n in nodes {
        out.push_str(&format!(
            "Node: {} ({}) | OS: {} | Incidents: {} | Status: {}\n",
            n.hostname.cyan().bold(),
            n.ip_address,
            n.os_name,
            n.total_artifacts_reported,
            n.status.green()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_hub_node_lifecycle() {
        let hub = ClusterHub::new();
        let node = hub.register_node("server-prod-01", "10.0.1.15", "Linux Ubuntu 24.04");
        assert_eq!(hub.list_nodes().len(), 1);

        hub.report_incident(node.node_id);
        let updated = hub.list_nodes();
        assert_eq!(updated[0].total_artifacts_reported, 1);
    }
}
