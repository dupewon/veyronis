use crate::error::CryptoError;
use crate::keys::ContentEncryptionKey;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;

pub const SALT_SIZE: usize = 32;

/// Derives a 256-bit symmetric key from a passphrase and salt using Argon2id.
pub fn derive_key_argon2id(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<ContentEncryptionKey, CryptoError> {
    if salt.len() < 16 {
        return Err(CryptoError::KdfError(
            "salt too short (minimum 16 bytes)".into(),
        ));
    }

    let is_fast = cfg!(test) || std::env::var("VEYRONIS_FAST_KDF").is_ok();
    let params = if is_fast {
        Params::new(4096, 1, 1, Some(32)).map_err(|e| CryptoError::KdfError(e.to_string()))?
    } else {
        Params::new(65536, 3, 2, Some(32)).map_err(|e| CryptoError::KdfError(e.to_string()))?
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output_key)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    ContentEncryptionKey::from_slice(&output_key)
}

/// Generates a cryptographically secure 32-byte salt for password KDF.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}
