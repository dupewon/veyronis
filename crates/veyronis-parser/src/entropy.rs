pub const ENTROPY_PACKED_THRESHOLD: f64 = 7.20;

/// Calculates the Shannon entropy of a byte buffer in bits per byte (0.0 to 8.0).
/// Higher values (> 7.2) strongly indicate compression, obfuscation, or encryption.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Evaluates whether an entropy score suggests packed/encrypted content.
pub fn is_likely_packed(entropy: f64) -> bool {
    entropy >= ENTROPY_PACKED_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zero_for_uniform_bytes() {
        let zeroes = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&zeroes), 0.0);
    }

    #[test]
    fn test_entropy_high_for_random_bytes() {
        let mut pseudo_random = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                pseudo_random.push(b);
            }
        }
        let entropy = calculate_entropy(&pseudo_random);
        assert!((entropy - 8.0).abs() < 0.001);
        assert!(is_likely_packed(entropy));
    }
}
