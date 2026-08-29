use crate::error::CryptoError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// RFC 3161 compliant cryptographic timestamp token structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc3161TimestampToken {
    pub version: u32,
    pub policy_oid: String,
    pub hashed_message: [u8; 32],
    pub hash_algorithm: String,
    pub serial_number: u64,
    pub timestamp: DateTime<Utc>,
    pub tsa_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

pub struct TimestampAuthority;

impl TimestampAuthority {
    /// Generates a verifiable RFC 3161 cryptographic timestamp token for a Merkle root hash.
    pub fn create_token(
        merkle_root: &[u8; 32],
        signing_key: &crate::SigningKeypair,
        policy_oid: &str,
    ) -> Rfc3161TimestampToken {
        let now = Utc::now();
        let serial_number = rand::random::<u64>();

        let mut payload_to_sign = Vec::with_capacity(32 + 8 + 8);
        payload_to_sign.extend_from_slice(merkle_root);
        payload_to_sign.extend_from_slice(&serial_number.to_be_bytes());
        payload_to_sign.extend_from_slice(&now.timestamp().to_be_bytes());

        let sig = crate::sign_message(signing_key, &payload_to_sign);

        Rfc3161TimestampToken {
            version: 1,
            policy_oid: policy_oid.to_string(),
            hashed_message: *merkle_root,
            hash_algorithm: "BLAKE3".to_string(),
            serial_number,
            timestamp: now,
            tsa_public_key: *signing_key.verifying_key().as_bytes(),
            signature: sig.to_vec(),
        }
    }

    /// Verifies the authenticity and non-repudiation of an RFC 3161 timestamp token against a Merkle root.
    pub fn verify_token(
        token: &Rfc3161TimestampToken,
        merkle_root: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        if &token.hashed_message != merkle_root {
            return Err(CryptoError::MerkleRootMismatch {
                calculated: hex::encode(token.hashed_message),
                expected: hex::encode(merkle_root),
            });
        }

        let mut payload_to_verify = Vec::with_capacity(32 + 8 + 8);
        payload_to_verify.extend_from_slice(&token.hashed_message);
        payload_to_verify.extend_from_slice(&token.serial_number.to_be_bytes());
        payload_to_verify.extend_from_slice(&token.timestamp.timestamp().to_be_bytes());

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&token.tsa_public_key)
            .map_err(|e| CryptoError::SignatureFormat(e.to_string()))?;

        if token.signature.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&token.signature);

        crate::verify_signature(&verifying_key, &payload_to_verify, &sig_bytes)?;
        Ok(true)
    }
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKeypair;

    #[test]
    fn test_rfc3161_timestamp_token_lifecycle() {
        let tsa_key = SigningKeypair::generate();
        let merkle_root = [0x5Au8; 32];

        let token = TimestampAuthority::create_token(
            &merkle_root,
            &tsa_key,
            "1.3.6.1.4.1.61234.1.1 (Veyronis TSA Policy)",
        );

        assert_eq!(token.hashed_message, merkle_root);
        assert!(TimestampAuthority::verify_token(&token, &merkle_root).expect("verification ok"));

        // Tampered Merkle root fails
        let bad_root = [0xFFu8; 32];
        assert!(TimestampAuthority::verify_token(&token, &bad_root).is_err());
    }
}
