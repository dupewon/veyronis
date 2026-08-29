use crate::entry::{EncryptedKeyEntry, KeyEntryMetadata};
use crate::error::KeystoreError;
use chrono::Utc;
use directories::ProjectDirs;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use veyronis_crypto::{
    decrypt_aead, derive_key_argon2id, encrypt_aead, generate_nonce, generate_salt,
    RecipientKeypair, RecipientPublicKey, SigningKeypair,
};
use x25519_dalek::PublicKey as X25519PublicKey;

pub struct KeyStore {
    store_dir: PathBuf,
    entries: BTreeMap<String, EncryptedKeyEntry>,
}

impl KeyStore {
    pub fn open_default() -> Result<Self, KeystoreError> {
        let store_dir = if let Some(proj_dirs) = ProjectDirs::from("com", "veyronis", "veyronis") {
            proj_dirs.data_local_dir().join("keys")
        } else {
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".veyronis").join("keys")
        };

        Self::open_path(store_dir)
    }

    pub fn open_path(store_dir: PathBuf) -> Result<Self, KeystoreError> {
        fs::create_dir_all(&store_dir)?;
        let mut store = Self {
            store_dir,
            entries: BTreeMap::new(),
        };
        store.reload()?;
        Ok(store)
    }

    pub fn reload(&mut self) -> Result<(), KeystoreError> {
        self.entries.clear();
        if !self.store_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.store_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(file) = File::open(&path) {
                    let reader = BufReader::new(file);
                    if let Ok(key_entry) = serde_json::from_reader::<_, EncryptedKeyEntry>(reader) {
                        self.entries.insert(key_entry.label.clone(), key_entry);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn generate_key(
        &mut self,
        label: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<KeyEntryMetadata, KeystoreError> {
        if self.entries.contains_key(label) {
            return Err(KeystoreError::KeyAlreadyExists(label.to_string()));
        }

        let signing_keypair = SigningKeypair::generate();
        let recipient_keypair = RecipientKeypair::generate();

        let salt = generate_salt();
        let nonce = generate_nonce();

        let default_pass = b"VEYRONIS-LOCAL-DEFAULT-KEY-WRAP";
        let pass_slice = passphrase.unwrap_or(default_pass);
        let wrapping_key = derive_key_argon2id(pass_slice, &salt)?;

        let aad = label.as_bytes();
        let encrypted_signing_key =
            encrypt_aead(&wrapping_key, &nonce, &signing_keypair.to_bytes(), aad)?;

        let encrypted_encryption_key = encrypt_aead(
            &wrapping_key,
            &nonce,
            &recipient_keypair.secret_bytes(),
            aad,
        )?;

        let entry = EncryptedKeyEntry {
            label: label.to_string(),
            key_id: signing_keypair.key_id(),
            public_signing_key: *signing_keypair.verifying_key().as_bytes(),
            public_encryption_key: *recipient_keypair.public_key().as_bytes(),
            salt,
            nonce,
            encrypted_signing_key,
            encrypted_encryption_key,
            created_at: Utc::now(),
            use_dpapi: false,
        };

        let file_path = self.store_dir.join(format!("{}.json", label));
        let file = File::create(&file_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &entry)
            .map_err(|e| KeystoreError::Serialization(e.to_string()))?;

        let metadata = KeyEntryMetadata::from(&entry);
        self.entries.insert(label.to_string(), entry);

        Ok(metadata)
    }

    pub fn list_keys(&self) -> Vec<KeyEntryMetadata> {
        self.entries.values().map(KeyEntryMetadata::from).collect()
    }

    pub fn get_metadata(&self, label: &str) -> Result<KeyEntryMetadata, KeystoreError> {
        self.entries
            .get(label)
            .map(KeyEntryMetadata::from)
            .ok_or_else(|| KeystoreError::KeyNotFound(label.to_string()))
    }

    pub fn load_signing_key(
        &self,
        label: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<SigningKeypair, KeystoreError> {
        let entry = self
            .entries
            .get(label)
            .ok_or_else(|| KeystoreError::KeyNotFound(label.to_string()))?;

        let default_pass = b"VEYRONIS-LOCAL-DEFAULT-KEY-WRAP";
        let pass_slice = passphrase.unwrap_or(default_pass);
        let wrapping_key = derive_key_argon2id(pass_slice, &entry.salt)?;

        let decrypted_bytes = decrypt_aead(
            &wrapping_key,
            &entry.nonce,
            &entry.encrypted_signing_key,
            entry.label.as_bytes(),
        )
        .map_err(|_| KeystoreError::DecryptionFailed)?;

        if decrypted_bytes.len() != 32 {
            return Err(KeystoreError::DecryptionFailed);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decrypted_bytes);
        Ok(SigningKeypair::from_bytes(&key_bytes))
    }

    pub fn load_recipient_key(
        &self,
        label: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<RecipientKeypair, KeystoreError> {
        let entry = self
            .entries
            .get(label)
            .ok_or_else(|| KeystoreError::KeyNotFound(label.to_string()))?;

        let default_pass = b"VEYRONIS-LOCAL-DEFAULT-KEY-WRAP";
        let pass_slice = passphrase.unwrap_or(default_pass);
        let wrapping_key = derive_key_argon2id(pass_slice, &entry.salt)?;

        let decrypted_bytes = decrypt_aead(
            &wrapping_key,
            &entry.nonce,
            &entry.encrypted_encryption_key,
            entry.label.as_bytes(),
        )
        .map_err(|_| KeystoreError::DecryptionFailed)?;

        if decrypted_bytes.len() != 32 {
            return Err(KeystoreError::DecryptionFailed);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decrypted_bytes);
        Ok(RecipientKeypair::from_bytes(key_bytes))
    }

    pub fn get_recipient_public_key(
        &self,
        label: &str,
    ) -> Result<RecipientPublicKey, KeystoreError> {
        let entry = self
            .entries
            .get(label)
            .ok_or_else(|| KeystoreError::KeyNotFound(label.to_string()))?;
        let pub_key = X25519PublicKey::from(entry.public_encryption_key);
        Ok(RecipientPublicKey::from_x25519(&pub_key, label))
    }
}
