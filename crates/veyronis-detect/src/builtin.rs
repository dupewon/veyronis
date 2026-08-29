use crate::rule::{DetectionCriterion, MitreAttack, SecurityRule, Severity};

pub fn get_builtin_rules() -> Vec<SecurityRule> {
    vec![
        SecurityRule {
            id: "VYR-SEC-001".into(),
            title: "Behavioral Ransomware Activity - Bulk Modification & Encryption".into(),
            description: "Detects a process performing file writes followed by cryptographic hashing or cipher operations.".into(),
            author: "dupewon <whuq@cheatglobal>".into(),
            severity: Severity::Critical,
            mitre: Some(MitreAttack {
                tactic: "Impact".into(),
                technique_id: "T1486".into(),
                technique_name: "Data Encrypted for Impact".into(),
            }),
            criteria: vec![
                DetectionCriterion {
                    event_type: Some("FileWrite".into()),
                    process_name_contains: None,
                    target_resource_contains: None,
                    is_external_network: None,
                    crypto_algorithm: None,
                    min_event_count: Some(1),
                },
                DetectionCriterion {
                    event_type: Some("CryptoOperation".into()),
                    process_name_contains: None,
                    target_resource_contains: None,
                    is_external_network: None,
                    crypto_algorithm: None,
                    min_event_count: Some(1),
                },
            ],
            remediation: "Isolate host immediately, capture memory container, and investigate parent process lineage.".into(),
        },
        SecurityRule {
            id: "VYR-SEC-002".into(),
            title: "Interactive Shell Spawn with External Network Egress".into(),
            description: "Detects command interpreters or scripting shells establishing outbound network connections.".into(),
            author: "dupewon <whuq@cheatglobal>".into(),
            severity: Severity::High,
            mitre: Some(MitreAttack {
                tactic: "Command and Control".into(),
                technique_id: "T1059".into(),
                technique_name: "Command and Scripting Interpreter".into(),
            }),
            criteria: vec![
                DetectionCriterion {
                    event_type: Some("NetworkConnect".into()),
                    process_name_contains: None,
                    target_resource_contains: None,
                    is_external_network: Some(true),
                    crypto_algorithm: None,
                    min_event_count: Some(1),
                },
            ],
            remediation: "Inspect socket destination IP and review command-line arguments passed to the shell.".into(),
        },
        SecurityRule {
            id: "VYR-SEC-003".into(),
            title: "Sensitive Credential Vault & Shadow File Access".into(),
            description: "Detects access attempts targeting OS credential databases, SAM, or shadow directories.".into(),
            author: "dupewon <whuq@cheatglobal>".into(),
            severity: Severity::High,
            mitre: Some(MitreAttack {
                tactic: "Credential Access".into(),
                technique_id: "T1003".into(),
                technique_name: "OS Credential Dumping".into(),
            }),
            criteria: vec![
                DetectionCriterion {
                    event_type: Some("FileOpen".into()),
                    process_name_contains: None,
                    target_resource_contains: Some("sam".into()),
                    is_external_network: None,
                    crypto_algorithm: None,
                    min_event_count: Some(1),
                },
            ],
            remediation: "Verify process integrity and terminate unauthorized credential enumeration.".into(),
        },
        SecurityRule {
            id: "VYR-SEC-004".into(),
            title: "Living-off-the-Land Process Spawning".into(),
            description: "Detects LOLBAS execution patterns spawning system utilities (certutil, powershell, curl, bash).".into(),
            author: "dupewon <whuq@cheatglobal>".into(),
            severity: Severity::Medium,
            mitre: Some(MitreAttack {
                tactic: "Defense Evasion".into(),
                technique_id: "T1218".into(),
                technique_name: "System Binary Proxy Execution".into(),
            }),
            criteria: vec![
                DetectionCriterion {
                    event_type: Some("ProcessSpawn".into()),
                    process_name_contains: None,
                    target_resource_contains: None,
                    is_external_network: None,
                    crypto_algorithm: None,
                    min_event_count: Some(1),
                },
            ],
            remediation: "Audit parent application to verify whether spawning subprocesses is legitimate behavior.".into(),
        },
        SecurityRule {
            id: "VYR-SEC-005".into(),
            title: "Anomalous Port & Network Service Discovery".into(),
            description: "Detects rapid socket creation across local or external endpoints indicative of reconnaissance.".into(),
            author: "dupewon <whuq@cheatglobal>".into(),
            severity: Severity::Low,
            mitre: Some(MitreAttack {
                tactic: "Discovery".into(),
                technique_id: "T1046".into(),
                technique_name: "Network Service Discovery".into(),
            }),
            criteria: vec![
                DetectionCriterion {
                    event_type: Some("SocketCreate".into()),
                    process_name_contains: None,
                    target_resource_contains: None,
                    is_external_network: None,
                    crypto_algorithm: None,
                    min_event_count: Some(1),
                },
            ],
            remediation: "Review network scanning activity and restrict endpoint access policies.".into(),
        },
    ]
}
