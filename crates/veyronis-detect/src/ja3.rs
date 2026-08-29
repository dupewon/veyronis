/// Calculates a deterministic JA3 string and hash from TLS Client Hello attributes.
pub struct Ja3Fingerprint {
    pub raw_ja3_string: String,
    pub ja3_hash: String,
}

impl Ja3Fingerprint {
    /// Computes a standard JA3 fingerprint representation.
    pub fn compute(
        tls_version: u16,
        cipher_suites: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        elliptic_curve_point_formats: &[u8],
    ) -> Self {
        let ciphers_str = cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let extensions_str = extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let curves_str = elliptic_curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let formats_str = elliptic_curve_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let raw_ja3_string = format!(
            "{},{},{},{},{}",
            tls_version, ciphers_str, extensions_str, curves_str, formats_str
        );

        let hash_bytes = blake3::hash(raw_ja3_string.as_bytes());
        let ja3_hash = hash_bytes.to_hex().to_string()[..32].to_string();

        Self {
            raw_ja3_string,
            ja3_hash,
        }
    }
}

/// Known malicious C2 framework JA3 signatures (Cobalt Strike, Metasploit, Emotet, Sliver, Trickbot).
pub const KNOWN_MALICIOUS_JA3: &[(&str, &str)] = &[
    (
        "a0e9f5d64349fb13191bc781f81f42e1",
        "Cobalt Strike Default Malleable C2",
    ),
    (
        "72a589da586844d7f0818ce684948eea",
        "Metasploit Meterpreter Reverse HTTPS",
    ),
    (
        "4d7a28d6f22da2d8e907d722d427d14d",
        "Emotet Banking Trojan TLS Payload",
    ),
    (
        "e7d705a3286e19ea42f587b344ee6865",
        "Sliver C2 Implant Framework",
    ),
];

pub fn check_known_malicious_ja3(hash: &str) -> Option<&'static str> {
    for &(known_hash, threat_name) in KNOWN_MALICIOUS_JA3 {
        if known_hash.eq_ignore_ascii_case(hash) {
            return Some(threat_name);
        }
    }
    None
}
