use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    #[error("AEAD authentication/decryption failed (corrupt ciphertext or wrong key)")]
    DecryptionFailed,

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("invalid signature: cryptographic signature verification failed")]
    InvalidSignature,

    #[error("signature format error: {0}")]
    SignatureFormat(String),

    #[error("key envelope unwrapping failed: no matching recipient key or invalid passphrase")]
    EnvelopeUnwrapFailed,

    #[error("KDF error: {0}")]
    KdfError(String),

    #[error("Merkle tree root mismatch: calculated {calculated}, expected {expected}")]
    MerkleRootMismatch {
        calculated: String,
        expected: String,
    },

    #[error("empty data provided for Merkle tree generation")]
    EmptyMerkleData,

    #[error("IO/Serialization error: {0}")]
    Serialization(String),
}
