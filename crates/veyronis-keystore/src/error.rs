use thiserror::Error;
use veyronis_crypto::CryptoError;

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("key '{0}' not found in keystore")]
    KeyNotFound(String),

    #[error("key '{0}' already exists in keystore")]
    KeyAlreadyExists(String),

    #[error("keystore decryption failed: incorrect passphrase or corrupted keystore entry")]
    DecryptionFailed,

    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("platform protection error: {0}")]
    PlatformProtection(String),
}
