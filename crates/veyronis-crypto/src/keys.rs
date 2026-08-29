use crate::error::CryptoError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit symmetric content encryption key.
/// Zeroized automatically on drop to prevent key material lingering in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ContentEncryptionKey([u8; 32]);

impl ContentEncryptionKey {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: slice.len(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Asymmetric Ed25519 keypair for artifact signing and integrity verification.
pub struct SigningKeypair {
    pub signing_key: SigningKey,
}

impl SigningKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn key_id(&self) -> [u8; 32] {
        *blake3::hash(self.verifying_key().as_bytes()).as_bytes()
    }
}

/// Asymmetric X25519 keypair for key envelope recipient encryption.
pub struct RecipientKeypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl RecipientKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn key_id(&self) -> [u8; 32] {
        *blake3::hash(self.public.as_bytes()).as_bytes()
    }
}

/// Public key representation for key storage and recipient lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientPublicKey {
    pub key_id: [u8; 32],
    pub public_bytes: [u8; 32],
    pub label: String,
}

impl RecipientPublicKey {
    pub fn from_x25519(public_key: &X25519PublicKey, label: impl Into<String>) -> Self {
        let public_bytes = *public_key.as_bytes();
        let key_id = *blake3::hash(&public_bytes).as_bytes();
        Self {
            key_id,
            public_bytes,
            label: label.into(),
        }
    }
}
