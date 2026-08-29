use crate::aead::{decrypt_aead, encrypt_aead, generate_nonce, NONCE_SIZE};
use crate::error::CryptoError;
use crate::kdf::{derive_key_argon2id, generate_salt, SALT_SIZE};
use crate::keys::{ContentEncryptionKey, RecipientKeypair, RecipientPublicKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

const ENVELOPE_HKDF_INFO: &[u8] = b"VEYRONIS-ENVELOPE-V1";

/// Recipient key envelope entry for asymmetric public key wrapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyRecipientEntry {
    pub recipient_key_id: [u8; 32],
    pub ephemeral_public_key: [u8; 32],
    pub nonce: [u8; NONCE_SIZE],
    pub encrypted_cek: Vec<u8>, // 32 bytes CEK + 16 bytes auth tag = 48 bytes
}

/// Password-based key envelope entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordRecipientEntry {
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub encrypted_cek: Vec<u8>, // 32 bytes CEK + 16 bytes auth tag = 48 bytes
}

/// Container key envelope holding recipient access grants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub public_key_recipients: Vec<PublicKeyRecipientEntry>,
    pub password_recipients: Vec<PasswordRecipientEntry>,
}

impl KeyEnvelope {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wraps the CEK for an asymmetric X25519 public key recipient.
    pub fn add_public_key_recipient(
        &mut self,
        recipient: &RecipientPublicKey,
        cek: &ContentEncryptionKey,
    ) -> Result<(), CryptoError> {
        let recipient_x25519 = X25519PublicKey::from(recipient.public_bytes);
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        // Ephemeral-Static Diffie-Hellman
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

        // Salt = recipient_public || ephemeral_public
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(recipient_x25519.as_bytes());
        salt.extend_from_slice(ephemeral_public.as_bytes());

        // Derive wrapping key using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
        let mut wrapping_key_bytes = [0u8; 32];
        hk.expand(ENVELOPE_HKDF_INFO, &mut wrapping_key_bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let wrapping_key = ContentEncryptionKey::from_slice(&wrapping_key_bytes)?;

        let nonce = generate_nonce();
        let aad = recipient.key_id;
        let encrypted_cek = encrypt_aead(&wrapping_key, &nonce, cek.as_bytes(), &aad)?;

        self.public_key_recipients.push(PublicKeyRecipientEntry {
            recipient_key_id: recipient.key_id,
            ephemeral_public_key: *ephemeral_public.as_bytes(),
            nonce,
            encrypted_cek,
        });

        Ok(())
    }

    /// Wraps the CEK with a passphrase using Argon2id.
    pub fn add_password_recipient(
        &mut self,
        passphrase: &[u8],
        cek: &ContentEncryptionKey,
    ) -> Result<(), CryptoError> {
        let salt = generate_salt();
        let wrapping_key = derive_key_argon2id(passphrase, &salt)?;

        let nonce = generate_nonce();
        let aad = b"VEYRONIS-PASSWD-RECIPIENT";
        let encrypted_cek = encrypt_aead(&wrapping_key, &nonce, cek.as_bytes(), aad)?;

        self.password_recipients.push(PasswordRecipientEntry {
            salt,
            nonce,
            encrypted_cek,
        });

        Ok(())
    }

    /// Unwraps the CEK using a private recipient keypair.
    pub fn unwrap_with_private_key(
        &self,
        keypair: &RecipientKeypair,
    ) -> Result<ContentEncryptionKey, CryptoError> {
        let my_key_id = keypair.key_id();

        for entry in &self.public_key_recipients {
            if entry.recipient_key_id == my_key_id {
                let ephemeral_public = X25519PublicKey::from(entry.ephemeral_public_key);
                let shared_secret = keypair.secret().diffie_hellman(&ephemeral_public);

                let mut salt = Vec::with_capacity(64);
                salt.extend_from_slice(keypair.public_key().as_bytes());
                salt.extend_from_slice(ephemeral_public.as_bytes());

                let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
                let mut wrapping_key_bytes = [0u8; 32];
                hk.expand(ENVELOPE_HKDF_INFO, &mut wrapping_key_bytes)
                    .map_err(|e| CryptoError::Serialization(e.to_string()))?;
                let wrapping_key = ContentEncryptionKey::from_slice(&wrapping_key_bytes)?;

                let decrypted_cek_bytes = decrypt_aead(
                    &wrapping_key,
                    &entry.nonce,
                    &entry.encrypted_cek,
                    &entry.recipient_key_id,
                )?;

                return ContentEncryptionKey::from_slice(&decrypted_cek_bytes);
            }
        }

        Err(CryptoError::EnvelopeUnwrapFailed)
    }

    /// Unwraps the CEK using a passphrase.
    pub fn unwrap_with_passphrase(
        &self,
        passphrase: &[u8],
    ) -> Result<ContentEncryptionKey, CryptoError> {
        for entry in &self.password_recipients {
            if let Ok(wrapping_key) = derive_key_argon2id(passphrase, &entry.salt) {
                let aad = b"VEYRONIS-PASSWD-RECIPIENT";
                if let Ok(decrypted_cek_bytes) =
                    decrypt_aead(&wrapping_key, &entry.nonce, &entry.encrypted_cek, aad)
                {
                    return ContentEncryptionKey::from_slice(&decrypted_cek_bytes);
                }
            }
        }

        Err(CryptoError::EnvelopeUnwrapFailed)
    }
}
