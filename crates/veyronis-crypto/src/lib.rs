pub mod aead;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod merkle;
pub mod shamir;
pub mod sign;
pub mod timestamp;

pub use aead::{decrypt_aead, encrypt_aead, generate_nonce, NONCE_SIZE, TAG_SIZE};
pub use envelope::{KeyEnvelope, PasswordRecipientEntry, PublicKeyRecipientEntry};
pub use error::CryptoError;
pub use kdf::{derive_key_argon2id, generate_salt, SALT_SIZE};
pub use keys::{ContentEncryptionKey, RecipientKeypair, RecipientPublicKey, SigningKeypair};
pub use merkle::MerkleTree;
pub use shamir::{SecretShare, ShamirEngine};
pub use sign::{sign_message, verify_signature, SIGNATURE_SIZE};
pub use timestamp::{Rfc3161TimestampToken, TimestampAuthority};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_encrypt_decrypt_roundtrip() {
        let cek = ContentEncryptionKey::generate();
        let nonce = generate_nonce();
        let plaintext = b"Security runtime telemetry payload 12345";
        let aad = b"AAD_BINDING_UUID_VERSION";

        let ciphertext = encrypt_aead(&cek, &nonce, plaintext, aad).expect("encryption succeeds");
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decrypted = decrypt_aead(&cek, &nonce, &ciphertext, aad).expect("decryption succeeds");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aead_wrong_key_rejection() {
        let cek1 = ContentEncryptionKey::generate();
        let cek2 = ContentEncryptionKey::generate();
        let nonce = generate_nonce();
        let plaintext = b"Sensitive behavioral record";
        let aad = b"AAD_BINDING";

        let ciphertext = encrypt_aead(&cek1, &nonce, plaintext, aad).unwrap();
        let result = decrypt_aead(&cek2, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_tampered_ciphertext_rejection() {
        let cek = ContentEncryptionKey::generate();
        let nonce = generate_nonce();
        let plaintext = b"Sensitive behavioral record";
        let aad = b"AAD_BINDING";

        let mut ciphertext = encrypt_aead(&cek, &nonce, plaintext, aad).unwrap();
        // Flip one byte
        ciphertext[5] ^= 0xFF;

        let result = decrypt_aead(&cek, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_tampered_aad_rejection() {
        let cek = ContentEncryptionKey::generate();
        let nonce = generate_nonce();
        let plaintext = b"Sensitive behavioral record";

        let ciphertext = encrypt_aead(&cek, &nonce, plaintext, b"VALID_AAD").unwrap();
        let result = decrypt_aead(&cek, &nonce, &ciphertext, b"FORGED_AAD");
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_and_verification() {
        let keypair = SigningKeypair::generate();
        let message = b"Artifact Merkle Root 378492348";

        let signature = sign_message(&keypair, message);
        let verify_result = verify_signature(&keypair.verifying_key(), message, &signature);
        assert!(verify_result.is_ok());

        let bad_message = b"Tampered Merkle Root 00000000";
        let bad_verify = verify_signature(&keypair.verifying_key(), bad_message, &signature);
        assert!(bad_verify.is_err());
    }

    #[test]
    fn test_merkle_tree_integrity() {
        let block1_hash = *blake3::hash(b"block 1 ciphertext").as_bytes();
        let block2_hash = *blake3::hash(b"block 2 ciphertext").as_bytes();
        let block3_hash = *blake3::hash(b"block 3 ciphertext").as_bytes();

        let leaves = vec![block1_hash, block2_hash, block3_hash];
        let tree = MerkleTree::from_leaf_hashes(leaves.clone()).expect("tree created");

        assert!(MerkleTree::verify_root(&leaves, tree.root_hash()).is_ok());

        // Tamper with one block hash
        let mut tampered_leaves = leaves.clone();
        tampered_leaves[1][0] ^= 0x01;
        assert!(MerkleTree::verify_root(&tampered_leaves, tree.root_hash()).is_err());
    }

    #[test]
    fn test_envelope_public_key_wrapping() {
        let cek = ContentEncryptionKey::generate();
        let recipient_keypair = RecipientKeypair::generate();
        let recipient_pub =
            RecipientPublicKey::from_x25519(recipient_keypair.public_key(), "operator-key");

        let mut envelope = KeyEnvelope::new();
        envelope
            .add_public_key_recipient(&recipient_pub, &cek)
            .expect("recipient added");

        let unwrapped_cek = envelope
            .unwrap_with_private_key(&recipient_keypair)
            .expect("unwrapping succeeds");
        assert_eq!(cek.as_bytes(), unwrapped_cek.as_bytes());

        // Wrong keypair fails
        let wrong_keypair = RecipientKeypair::generate();
        assert!(envelope.unwrap_with_private_key(&wrong_keypair).is_err());
    }

    #[test]
    fn test_envelope_password_wrapping() {
        let cek = ContentEncryptionKey::generate();
        let passphrase = b"SuperStrongPassphrase#2026";

        let mut envelope = KeyEnvelope::new();
        envelope
            .add_password_recipient(passphrase, &cek)
            .expect("password recipient added");

        let unwrapped_cek = envelope
            .unwrap_with_passphrase(passphrase)
            .expect("unwrapping succeeds");
        assert_eq!(cek.as_bytes(), unwrapped_cek.as_bytes());

        assert!(envelope.unwrap_with_passphrase(b"WrongPassphrase").is_err());
    }
}
