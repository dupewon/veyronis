use crate::error::CryptoError;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Russian Peasant multiplication in GF(256) with Rijndael reduction polynomial 0x11B.
#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while a != 0 && b != 0 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// Computes multiplicative inverse in GF(256) using Fermat's Little Theorem: b^(254) = b^(-1).
#[inline]
fn gf_inv(b: u8) -> u8 {
    if b == 0 {
        panic!("GF(256) division by zero");
    }
    let mut res = 1u8;
    let mut base = b;
    let mut exp = 254;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf_mul(res, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    res
}

#[inline]
fn gf_div(a: u8, b: u8) -> u8 {
    if a == 0 {
        0
    } else {
        gf_mul(a, gf_inv(b))
    }
}

/// Represents an individual Shamir secret share for threshold reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretShare {
    pub x: u8,
    pub data: Vec<u8>,
    pub threshold: u8,
    pub total_shares: u8,
}

impl SecretShare {
    /// Formats the share as a human-readable, portable token string (e.g. `VYR-SHARE-3-1-...`).
    pub fn to_token_string(&self) -> String {
        format!(
            "VYR-SHARE-{}-{}-{}",
            self.threshold,
            self.x,
            hex::encode(&self.data)
        )
    }

    /// Parses a token string back into a `SecretShare`.
    pub fn from_token_string(token: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() < 5 || parts[0] != "VYR" || parts[1] != "SHARE" {
            return Err(CryptoError::EnvelopeUnwrapFailed);
        }
        let threshold = parts[2]
            .parse::<u8>()
            .map_err(|_| CryptoError::EnvelopeUnwrapFailed)?;
        let x = parts[3]
            .parse::<u8>()
            .map_err(|_| CryptoError::EnvelopeUnwrapFailed)?;
        let data = hex::decode(parts[4]).map_err(|_| CryptoError::EnvelopeUnwrapFailed)?;

        Ok(Self {
            x,
            data,
            threshold,
            total_shares: 0,
        })
    }
}

pub struct ShamirEngine;

impl ShamirEngine {
    /// Splits a secret slice into `n` shares requiring `k` shares to reconstruct.
    pub fn split_secret(
        secret: &[u8],
        threshold: u8,
        total_shares: u8,
    ) -> Result<Vec<SecretShare>, CryptoError> {
        if threshold < 2 || threshold > total_shares || total_shares > 254 {
            return Err(CryptoError::InvalidKeyLength {
                expected: threshold as usize,
                got: total_shares as usize,
            });
        }

        let mut rng = rand::thread_rng();
        let mut shares_data: Vec<Vec<u8>> =
            vec![Vec::with_capacity(secret.len()); total_shares as usize];

        for &byte in secret {
            // Polynomial: f(x) = secret + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1}
            let mut coeffs = vec![byte];
            for _ in 1..threshold {
                let mut coeff = [0u8; 1];
                rng.fill_bytes(&mut coeff);
                coeffs.push(coeff[0]);
            }

            // Evaluate polynomial for each x in 1..=total_shares
            for x_idx in 1..=total_shares {
                let mut val = 0u8;
                let mut x_pow = 1u8;
                for &coeff in &coeffs {
                    val = gf_add(val, gf_mul(coeff, x_pow));
                    x_pow = gf_mul(x_pow, x_idx);
                }
                shares_data[(x_idx - 1) as usize].push(val);
            }
        }

        let result = (1..=total_shares)
            .map(|x| SecretShare {
                x,
                data: shares_data[(x - 1) as usize].clone(),
                threshold,
                total_shares,
            })
            .collect();

        Ok(result)
    }

    /// Reconstructs the secret from `k` valid shares using Lagrange polynomial interpolation.
    pub fn combine_shares(shares: &[SecretShare]) -> Result<Vec<u8>, CryptoError> {
        if shares.is_empty() {
            return Err(CryptoError::EnvelopeUnwrapFailed);
        }
        let threshold = shares[0].threshold as usize;
        if shares.len() < threshold {
            return Err(CryptoError::EnvelopeUnwrapFailed);
        }

        let secret_len = shares[0].data.len();
        let mut secret = Vec::with_capacity(secret_len);

        // Verify distinct x coordinates
        let mut seen_x = std::collections::HashSet::new();
        for s in shares {
            if !seen_x.insert(s.x) || s.x == 0 {
                return Err(CryptoError::EnvelopeUnwrapFailed);
            }
        }

        let k_shares = &shares[..threshold];

        for byte_idx in 0..secret_len {
            let mut secret_byte = 0u8;

            for (i, share_i) in k_shares.iter().enumerate() {
                let x_i = share_i.x;
                let y_i = share_i.data[byte_idx];

                // Lagrange basis L_i(0) = \prod_{j != i} (x_j) / (x_i ^ x_j)
                let mut num = 1u8;
                let mut den = 1u8;

                for (j, share_j) in k_shares.iter().enumerate() {
                    if i != j {
                        let x_j = share_j.x;
                        num = gf_mul(num, x_j);
                        den = gf_mul(den, gf_add(x_i, x_j));
                    }
                }

                let basis = gf_div(num, den);
                secret_byte = gf_add(secret_byte, gf_mul(y_i, basis));
            }

            secret.push(secret_byte);
        }

        Ok(secret)
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_split_and_recombine() {
        let master_secret = b"MasterEncryptionSecretKeyForVeyronisContainers#2026";
        let threshold = 3;
        let total_shares = 5;

        let shares = ShamirEngine::split_secret(master_secret, threshold, total_shares)
            .expect("splitting succeeds");

        assert_eq!(shares.len(), 5);

        // Combine any 3 shares: (0, 2, 4)
        let subset_3 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = ShamirEngine::combine_shares(&subset_3).expect("combine succeeds");
        assert_eq!(master_secret.as_slice(), recovered.as_slice());

        // Combine another 3 shares: (1, 3, 4)
        let subset_alt = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let recovered_alt = ShamirEngine::combine_shares(&subset_alt).expect("combine succeeds");
        assert_eq!(master_secret.as_slice(), recovered_alt.as_slice());

        // Token serialization & parsing roundtrip
        let token = shares[0].to_token_string();
        let parsed_share = SecretShare::from_token_string(&token).expect("parse token");
        assert_eq!(shares[0].x, parsed_share.x);
        assert_eq!(shares[0].data, parsed_share.data);
    }
}
