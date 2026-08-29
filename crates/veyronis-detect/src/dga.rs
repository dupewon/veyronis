/// Analyzes a domain name to assess likelihood of algorithmic generation (DGA).
pub struct DgaDetector;

impl DgaDetector {
    /// Calculates Shannon entropy of the domain prefix.
    pub fn calculate_domain_entropy(domain: &str) -> f64 {
        let prefix = domain.split('.').next().unwrap_or(domain);
        if prefix.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &b in prefix.as_bytes() {
            counts[b as usize] += 1;
        }

        let len = prefix.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Evaluates vowel-to-consonant and digit ratios in the second-level domain.
    pub fn is_likely_dga(domain: &str) -> bool {
        let prefix = domain.split('.').next().unwrap_or(domain).to_lowercase();
        if prefix.len() < 8 {
            return false;
        }

        let entropy = Self::calculate_domain_entropy(&prefix);
        let digits = prefix.chars().filter(|c| c.is_ascii_digit()).count();
        let vowels = prefix
            .chars()
            .filter(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
            .count();
        let consonants = prefix
            .chars()
            .filter(|c| c.is_alphabetic() && !matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
            .count();

        let vowel_ratio = if !prefix.is_empty() {
            vowels as f64 / prefix.len() as f64
        } else {
            0.0
        };

        // DGA domains typically have high entropy (> 3.5), very low vowel ratio (< 0.15), or many consecutive consonants
        (entropy > 3.65 && vowel_ratio < 0.18)
            || (digits > 5 && entropy > 3.2)
            || (consonants > 9 && vowels <= 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dga_detection() {
        assert!(DgaDetector::is_likely_dga("xkzjqpwbvrtyqpl.com"));
        assert!(DgaDetector::is_likely_dga("q9v8w7x6z5k4j3.net"));
        assert!(!DgaDetector::is_likely_dga("google.com"));
        assert!(!DgaDetector::is_likely_dga("microsoft.com"));
        assert!(!DgaDetector::is_likely_dga("github.com"));
    }
}
