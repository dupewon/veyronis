use crate::block::{BlockEntry, BLOCK_TYPE_EVENTS, BLOCK_TYPE_GRAPH, BLOCK_TYPE_MANIFEST};
use crate::error::FormatError;
use crate::header::{VyrHeader, CURRENT_MAJOR_VERSION, CURRENT_MINOR_VERSION};
use crate::manifest::ArtifactManifest;
use crate::trailer::VyrTrailer;
use byteorder::{BigEndian, ReadBytesExt};
use flate2::read::DeflateDecoder;
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use veyronis_crypto::{
    decrypt_aead, ContentEncryptionKey, KeyEnvelope, MerkleTree, RecipientKeypair,
};
use veyronis_graph::BehaviorGraph;
use veyronis_ir::event::VirEvent;

pub const MAX_KEY_ENVELOPE_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_BLOCK_COUNT: usize = 100_000;
pub const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024;

/// Result payload containing fully decrypted artifact components.
#[derive(Debug, Clone)]
pub struct DecryptedArtifact {
    pub header: VyrHeader,
    pub manifest: Option<ArtifactManifest>,
    pub events: Vec<VirEvent>,
    pub graph: Option<BehaviorGraph>,
    pub trailer: VyrTrailer,
}

/// Strict, bounds-checked container parser and verifier for .vyr artifacts.
#[derive(Debug, Clone)]
pub struct VyrReader {
    pub header: VyrHeader,
    pub key_envelope: KeyEnvelope,
    pub block_entries: Vec<BlockEntry>,
    pub block_ciphertexts: Vec<Vec<u8>>,
    pub trailer: VyrTrailer,
}

impl VyrReader {
    pub fn open_file(path: &Path) -> Result<Self, FormatError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        Self::read_from(&mut reader)
    }

    pub fn read_from<R: Read + Seek>(reader: &mut R) -> Result<Self, FormatError> {
        let header = VyrHeader::read_from(reader)?;

        // Read Key Envelope
        let envelope_len = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)? as usize;
        if envelope_len > MAX_KEY_ENVELOPE_SIZE {
            return Err(FormatError::AllocationLimitExceeded {
                size: envelope_len,
                limit: MAX_KEY_ENVELOPE_SIZE,
            });
        }

        let mut envelope_bytes = vec![0u8; envelope_len];
        reader
            .read_exact(&mut envelope_bytes)
            .map_err(|_| FormatError::UnexpectedEof)?;
        let key_envelope: KeyEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| FormatError::Serialization(e.to_string()))?;

        // Read Block Table
        let block_count = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)? as usize;
        if block_count > MAX_BLOCK_COUNT {
            return Err(FormatError::AllocationLimitExceeded {
                size: block_count,
                limit: MAX_BLOCK_COUNT,
            });
        }

        let mut block_entries = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            let entry = BlockEntry::read_from(reader)?;
            block_entries.push(entry);
        }

        // Read Block Ciphertexts
        let mut block_ciphertexts = Vec::with_capacity(block_count);
        for entry in &block_entries {
            let len = entry.ciphertext_len as usize;
            if len > MAX_BLOCK_SIZE {
                return Err(FormatError::AllocationLimitExceeded {
                    size: len,
                    limit: MAX_BLOCK_SIZE,
                });
            }
            let mut ciphertext = vec![0u8; len];
            reader
                .read_exact(&mut ciphertext)
                .map_err(|_| FormatError::UnexpectedEof)?;
            block_ciphertexts.push(ciphertext);
        }

        // Read Signature Trailer
        let trailer = VyrTrailer::read_from(reader)?;

        Ok(Self {
            header,
            key_envelope,
            block_entries,
            block_ciphertexts,
            trailer,
        })
    }

    /// Verifies container structure, block hashes, Merkle root, and Ed25519 signature.
    /// Does NOT require decryption keys.
    pub fn verify_integrity_and_signature(&self) -> Result<(), FormatError> {
        // 1. Verify header checksum
        if self.header.compute_checksum() != self.header.header_checksum {
            return Err(FormatError::CorruptedHeader);
        }

        // 2. Verify all block ciphertext hashes
        let mut leaf_hashes = Vec::with_capacity(self.block_entries.len());
        for (i, entry) in self.block_entries.iter().enumerate() {
            let ciphertext = &self.block_ciphertexts[i];
            let calculated_hash = *blake3::hash(ciphertext).as_bytes();
            if calculated_hash != entry.block_hash {
                return Err(FormatError::CorruptedBlock {
                    index: entry.block_index,
                });
            }
            leaf_hashes.push(entry.block_hash);
        }

        // 3. Verify Merkle root
        let merkle_tree = MerkleTree::from_leaf_hashes(leaf_hashes).map_err(FormatError::Crypto)?;
        if merkle_tree.root_hash() != &self.trailer.merkle_root {
            return Err(FormatError::MerkleRootMismatch);
        }

        // 4. Verify Ed25519 Signature Trailer
        self.trailer
            .verify(&self.header.artifact_uuid, &self.header.header_checksum)?;

        Ok(())
    }

    pub fn decrypt_with_key(
        &self,
        recipient_key: &RecipientKeypair,
    ) -> Result<DecryptedArtifact, FormatError> {
        let cek = self
            .key_envelope
            .unwrap_with_private_key(recipient_key)
            .map_err(FormatError::Crypto)?;
        self.decrypt_with_cek(&cek)
    }

    pub fn decrypt_with_passphrase(
        &self,
        passphrase: &[u8],
    ) -> Result<DecryptedArtifact, FormatError> {
        let cek = self
            .key_envelope
            .unwrap_with_passphrase(passphrase)
            .map_err(FormatError::Crypto)?;
        self.decrypt_with_cek(&cek)
    }

    pub fn decrypt_with_cek(
        &self,
        cek: &ContentEncryptionKey,
    ) -> Result<DecryptedArtifact, FormatError> {
        self.verify_integrity_and_signature()?;

        let mut manifest: Option<ArtifactManifest> = None;
        let mut events: Vec<VirEvent> = Vec::new();
        let mut graph: Option<BehaviorGraph> = None;

        for (i, entry) in self.block_entries.iter().enumerate() {
            let ciphertext = &self.block_ciphertexts[i];
            let aad = BlockEntry::derive_aad(
                &self.header.artifact_uuid,
                CURRENT_MAJOR_VERSION,
                CURRENT_MINOR_VERSION,
                entry.block_index,
                entry.block_type,
            );

            let compressed_bytes =
                decrypt_aead(cek, &entry.nonce, ciphertext, &aad).map_err(FormatError::Crypto)?;

            // Decompress
            let mut decoder = DeflateDecoder::new(&compressed_bytes[..]);
            let mut uncompressed_bytes = Vec::new();
            decoder
                .read_to_end(&mut uncompressed_bytes)
                .map_err(|e| FormatError::Decompression(e.to_string()))?;

            match entry.block_type {
                BLOCK_TYPE_MANIFEST => {
                    let m: ArtifactManifest = serde_json::from_slice(&uncompressed_bytes)
                        .map_err(|e| FormatError::Serialization(e.to_string()))?;
                    manifest = Some(m);
                }
                BLOCK_TYPE_EVENTS => {
                    let mut evts: Vec<VirEvent> = serde_json::from_slice(&uncompressed_bytes)
                        .map_err(|e| FormatError::Serialization(e.to_string()))?;
                    events.append(&mut evts);
                }
                BLOCK_TYPE_GRAPH => {
                    let g: BehaviorGraph = serde_json::from_slice(&uncompressed_bytes)
                        .map_err(|e| FormatError::Serialization(e.to_string()))?;
                    graph = Some(g);
                }
                _ => {}
            }
        }

        Ok(DecryptedArtifact {
            header: self.header.clone(),
            manifest,
            events,
            graph,
            trailer: self.trailer.clone(),
        })
    }
}
