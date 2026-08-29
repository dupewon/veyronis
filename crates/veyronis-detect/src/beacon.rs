use serde::{Deserialize, Serialize};
use veyronis_ir::categories::EventData;
use veyronis_ir::event::{EventType, VirEvent};

/// Analysis of C2 network beaconing activity and jitter variance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconProfile {
    pub is_beaconing: bool,
    pub target_domain_or_ip: String,
    pub mean_interval_seconds: f64,
    pub jitter_percentage: f64,
    pub sample_count: usize,
    pub confidence: f32,
    pub synthesized_suricata_rule: String,
    pub synthesized_snort_rule: String,
}

/// Advanced C2 Network Traffic, Jitter & Beaconing Analyzer.
pub struct BeaconAnalyzer;

impl BeaconAnalyzer {
    /// Analyzes a stream of telemetry events to detect periodic C2 beaconing patterns.
    pub fn analyze_events(events: &[VirEvent]) -> Vec<BeaconProfile> {
        let mut network_events: Vec<&VirEvent> = events
            .iter()
            .filter(|e| matches!(e.event_type, EventType::NetworkConnect))
            .collect();

        if network_events.len() < 3 {
            return Vec::new();
        }

        // Sort by timestamp
        network_events.sort_by_key(|e| e.timestamp_wall);

        let mut intervals = Vec::new();
        for window in network_events.windows(2) {
            let t1 = window[0].timestamp_wall;
            let t2 = window[1].timestamp_wall;
            let diff = t2.signed_duration_since(t1).num_seconds().unsigned_abs() as f64;
            if diff > 0.0 {
                intervals.push(diff);
            }
        }

        if intervals.len() < 2 {
            return Vec::new();
        }

        let mean_interval: f64 = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance: f64 = intervals
            .iter()
            .map(|val| (val - mean_interval).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();
        let jitter = if mean_interval > 0.0 {
            (std_dev / mean_interval) * 100.0
        } else {
            0.0
        };

        // Extract destination IP from first event
        let dest = if let Some(first_ev) = network_events.first() {
            if let EventData::NetworkConnect(ref conn) = first_ev.data {
                format!("{}:{}", conn.remote_address, conn.remote_port)
            } else {
                "10.0.0.1".to_string()
            }
        } else {
            "10.0.0.1".to_string()
        };

        let is_beacon = mean_interval >= 1.0 && mean_interval <= 600.0 && jitter <= 35.0;
        let confidence = if is_beacon { 0.90 } else { 0.30 };

        let suricata = format!(
            "alert tcp any any -> {} any (msg:\"VEYRONIS - Suspicious Periodic C2 Beacon Traffic\"; flow:established,to_server; threshold:type both, track by_src, count 5, seconds {}; classtype:trojan-activity; sid:9001001; rev:1;)",
            dest.split(':').next().unwrap_or("any"),
            (mean_interval * 5.0) as u64
        );

        let snort = format!(
            "alert ip $HOME_NET any -> {} any (msg:\"VEYRONIS - Periodic C2 Outbound Activity (Jitter {:.1}%)\"; detection_filter:track by_src, count 5, seconds {}; sid:9001002; rev:1;)",
            dest.split(':').next().unwrap_or("any"),
            jitter,
            (mean_interval * 5.0) as u64
        );

        vec![BeaconProfile {
            is_beaconing: is_beacon,
            target_domain_or_ip: dest,
            mean_interval_seconds: mean_interval,
            jitter_percentage: jitter,
            sample_count: network_events.len(),
            confidence,
            synthesized_suricata_rule: suricata,
            synthesized_snort_rule: snort,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::net::IpAddr;
    use veyronis_ir::categories::{NetworkConnectData, NetworkProtocol};
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_beacon_jitter_analysis() {
        let base_time = Utc::now();
        let mut events = Vec::new();
        let p = ProcessIdentity::new(100, None, 1000, "implant.exe", 1);

        for i in 0..5 {
            let mut ev = VirEvent::new(
                p.clone(),
                EventType::NetworkConnect,
                EventData::NetworkConnect(NetworkConnectData {
                    protocol: NetworkProtocol::Tcp,
                    local_address: None,
                    local_port: None,
                    remote_address: "192.168.1.100".parse::<IpAddr>().unwrap(),
                    remote_port: 443,
                    remote_hostname: None,
                    is_external: true,
                }),
                "etw",
            );
            ev.timestamp_wall = base_time + Duration::seconds(i * 10);
            events.push(ev);
        }

        let profiles = BeaconAnalyzer::analyze_events(&events);
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].is_beaconing);
        assert!((profiles[0].mean_interval_seconds - 10.0).abs() < 0.1);
        assert!(profiles[0].jitter_percentage < 5.0);
    }
}
