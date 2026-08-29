pub mod entry;
pub mod error;
pub mod store;

pub use entry::{EncryptedKeyEntry, KeyEntryMetadata};
pub use error::KeystoreError;
pub use store::KeyStore;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_keystore_generate_and_load_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("vyr_test_keystore_{}", uuid::Uuid::new_v4()));
        let mut store = KeyStore::open_path(temp_dir.clone()).expect("open test store");

        let metadata = store
            .generate_key("operator-1", Some(b"TestPassword123!"))
            .expect("key generated");
        assert_eq!(metadata.label, "operator-1");

        let keys = store.list_keys();
        assert_eq!(keys.len(), 1);

        let signing_key = store
            .load_signing_key("operator-1", Some(b"TestPassword123!"))
            .expect("signing key loaded");
        assert_eq!(
            signing_key.verifying_key().as_bytes(),
            &hex_decode(&metadata.public_signing_key)[..]
        );

        let recipient_key = store
            .load_recipient_key("operator-1", Some(b"TestPassword123!"))
            .expect("recipient key loaded");
        assert_eq!(
            recipient_key.public_key().as_bytes(),
            &store
                .get_recipient_public_key("operator-1")
                .unwrap()
                .public_bytes
        );

        // Wrong password fails
        assert!(store
            .load_signing_key("operator-1", Some(b"WrongPassword"))
            .is_err());

        let _ = fs::remove_dir_all(temp_dir);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
