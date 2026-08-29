use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use veyronis_crypto::{NONCE_SIZE, SALT_SIZE};

/// Stored encrypted key pair containing both signing (Ed25519) and envelope (X25519) credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeyEntry {
    pub label: String,
    pub key_id: [u8; 32],
    pub public_signing_key: [u8; 32],
    pub public_encryption_key: [u8; 32],
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub encrypted_signing_key: Vec<u8>,
    pub encrypted_encryption_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub use_dpapi: bool,
}

/// Metadata view of a stored key without private key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntryMetadata {
    pub label: String,
    pub key_id: String,
    pub public_signing_key: String,
    pub public_encryption_key: String,
    pub created_at: String,
    pub dpapi_protected: bool,
}

impl From<&EncryptedKeyEntry> for KeyEntryMetadata {
    fn from(entry: &EncryptedKeyEntry) -> Self {
        Self {
            label: entry.label.clone(),
            key_id: hex::encode(&entry.key_id),
            public_signing_key: hex::encode(&entry.public_signing_key),
            public_encryption_key: hex::encode(&entry.public_encryption_key),
            created_at: entry.created_at.to_rfc3339(),
            dpapi_protected: entry.use_dpapi,
        }
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
