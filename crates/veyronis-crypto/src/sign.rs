use crate::error::CryptoError;
use crate::keys::SigningKeypair;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

pub const SIGNATURE_SIZE: usize = 64;

/// Signs a canonical message using the Ed25519 private key.
pub fn sign_message(keypair: &SigningKeypair, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let signature = keypair.signing_key.sign(message);
    signature.to_bytes()
}

/// Verifies an Ed25519 signature against the expected message and public key.
pub fn verify_signature(
    public_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8; SIGNATURE_SIZE],
) -> Result<(), CryptoError> {
    let signature = Signature::from_bytes(signature_bytes);
    public_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}
