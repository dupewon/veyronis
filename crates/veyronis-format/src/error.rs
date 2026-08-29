use thiserror::Error;
use veyronis_crypto::CryptoError;

#[derive(Error, Debug)]
pub enum FormatError {
    #[error("invalid magic bytes: expected VYR1, got {0:?}")]
    InvalidMagic([u8; 4]),

    #[error("unsupported major format version: {version} (maximum supported is {max_supported})")]
    UnsupportedVersion { version: u16, max_supported: u16 },

    #[error("corrupted header: header checksum mismatch")]
    CorruptedHeader,

    #[error("corrupted block table: entry {index} failed hash integrity check")]
    CorruptedBlock { index: u32 },

    #[error("corrupted container structure: unexpected EOF or invalid length field")]
    UnexpectedEof,

    #[error("allocation limit exceeded: size {size} exceeds safe limit {limit}")]
    AllocationLimitExceeded { size: usize, limit: usize },

    #[error("tamper evidence failed: Merkle root mismatch")]
    MerkleRootMismatch,

    #[error("signature verification failed: invalid artifact signature")]
    InvalidSignature,

    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("decompression error: {0}")]
    Decompression(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("decryption required: artifact is encrypted but no key was provided")]
    KeyRequired,
}
