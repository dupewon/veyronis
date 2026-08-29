use crate::error::CryptoError;
use crate::keys::ContentEncryptionKey;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

/// Generates a cryptographically secure 24-byte random nonce.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext with XChaCha20-Poly1305 using the provided 256-bit key, 24-byte nonce, and authenticated associated data.
pub fn encrypt_aead(
    key: &ContentEncryptionKey,
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(xnonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts and authenticates ciphertext with XChaCha20-Poly1305.
pub fn decrypt_aead(
    key: &ContentEncryptionKey,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}
