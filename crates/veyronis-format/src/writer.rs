use crate::block::{BlockEntry, BLOCK_TYPE_EVENTS, BLOCK_TYPE_GRAPH, BLOCK_TYPE_MANIFEST};
use crate::error::FormatError;
use crate::header::{
    VyrHeader, CURRENT_MAJOR_VERSION, CURRENT_MINOR_VERSION, FLAG_COMPRESSED, FLAG_ENCRYPTED,
    FLAG_SIGNED,
};
use crate::manifest::ArtifactManifest;
use crate::trailer::VyrTrailer;
use byteorder::{BigEndian, WriteBytesExt};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use uuid::Uuid;
use veyronis_crypto::{
    encrypt_aead, generate_nonce, ContentEncryptionKey, KeyEnvelope, MerkleTree,
    RecipientPublicKey, SigningKeypair,
};
use veyronis_graph::BehaviorGraph;
use veyronis_ir::event::VirEvent;

/// Chunked builder and serializer for producing tamper-evident .vyr artifacts.
pub struct VyrWriter {
    artifact_uuid: Uuid,
    cek: ContentEncryptionKey,
    key_envelope: KeyEnvelope,
    signing_key: SigningKeypair,
    block_entries: Vec<BlockEntry>,
    block_ciphertexts: Vec<Vec<u8>>,
    current_block_index: u32,
}

impl VyrWriter {
    pub fn new(signing_key: SigningKeypair) -> Self {
        let artifact_uuid = Uuid::new_v4();
        let cek = ContentEncryptionKey::generate();

        Self {
            artifact_uuid,
            cek,
            key_envelope: KeyEnvelope::new(),
            signing_key,
            block_entries: Vec::new(),
            block_ciphertexts: Vec::new(),
            current_block_index: 0,
        }
    }

    pub fn artifact_uuid(&self) -> &Uuid {
        &self.artifact_uuid
    }

    pub fn cek(&self) -> &ContentEncryptionKey {
        &self.cek
    }

    pub fn add_recipient_public_key(
        &mut self,
        recipient: &RecipientPublicKey,
    ) -> Result<(), FormatError> {
        self.key_envelope
            .add_public_key_recipient(recipient, &self.cek)
            .map_err(FormatError::Crypto)
    }

    pub fn add_passphrase_recipient(&mut self, passphrase: &[u8]) -> Result<(), FormatError> {
        self.key_envelope
            .add_password_recipient(passphrase, &self.cek)
            .map_err(FormatError::Crypto)
    }

    /// Appends a structured data payload as a compressed, AEAD-encrypted block.
    fn append_block(&mut self, block_type: u16, raw_bytes: &[u8]) -> Result<(), FormatError> {
        let uncompressed_len = raw_bytes.len() as u32;

        // Compress block with Deflate
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw_bytes)?;
        let compressed_bytes = encoder.finish()?;
        let compressed_len = compressed_bytes.len() as u32;

        // Generate independent nonce per block
        let nonce = generate_nonce();
        let aad = BlockEntry::derive_aad(
            &self.artifact_uuid,
            CURRENT_MAJOR_VERSION,
            CURRENT_MINOR_VERSION,
            self.current_block_index,
            block_type,
        );

        let ciphertext = encrypt_aead(&self.cek, &nonce, &compressed_bytes, &aad)
            .map_err(FormatError::Crypto)?;
        let ciphertext_len = ciphertext.len() as u32;

        // Compute BLAKE3 block hash over the ciphertext
        let block_hash = *blake3::hash(&ciphertext).as_bytes();

        let entry = BlockEntry {
            block_index: self.current_block_index,
            block_type,
            uncompressed_len,
            compressed_len,
            ciphertext_len,
            nonce,
            block_hash,
        };

        self.block_entries.push(entry);
        self.block_ciphertexts.push(ciphertext);
        self.current_block_index += 1;

        Ok(())
    }

    pub fn write_manifest(&mut self, manifest: &ArtifactManifest) -> Result<(), FormatError> {
        let serialized =
            serde_json::to_vec(manifest).map_err(|e| FormatError::Serialization(e.to_string()))?;
        self.append_block(BLOCK_TYPE_MANIFEST, &serialized)
    }

    pub fn write_events(&mut self, events: &[VirEvent]) -> Result<(), FormatError> {
        let serialized =
            serde_json::to_vec(events).map_err(|e| FormatError::Serialization(e.to_string()))?;
        self.append_block(BLOCK_TYPE_EVENTS, &serialized)
    }

    pub fn write_graph(&mut self, graph: &BehaviorGraph) -> Result<(), FormatError> {
        let serialized =
            serde_json::to_vec(graph).map_err(|e| FormatError::Serialization(e.to_string()))?;
        self.append_block(BLOCK_TYPE_GRAPH, &serialized)
    }

    /// Finalizes the artifact stream: derives Merkle tree, signs container, and writes all sections.
    pub fn write_to<W: Write>(self, writer: &mut W) -> Result<VyrTrailer, FormatError> {
        let flags = FLAG_ENCRYPTED | FLAG_COMPRESSED | FLAG_SIGNED;
        let header = VyrHeader::new(self.artifact_uuid, flags);
        header.write_to(writer)?;

        // Serialize and write Key Envelope
        let envelope_json = serde_json::to_vec(&self.key_envelope)
            .map_err(|e| FormatError::Serialization(e.to_string()))?;
        writer.write_u32::<BigEndian>(envelope_json.len() as u32)?;
        writer.write_all(&envelope_json)?;

        // Write Block Table
        writer.write_u32::<BigEndian>(self.block_entries.len() as u32)?;
        for entry in &self.block_entries {
            entry.write_to(writer)?;
        }

        // Write Data Blocks (ciphertexts)
        for ciphertext in &self.block_ciphertexts {
            writer.write_all(ciphertext)?;
        }

        // Compute Merkle Tree over block hashes
        let leaf_hashes: Vec<[u8; 32]> = self.block_entries.iter().map(|e| e.block_hash).collect();
        let merkle_tree = MerkleTree::from_leaf_hashes(leaf_hashes).map_err(FormatError::Crypto)?;

        // Sign container trailer
        let trailer = VyrTrailer::sign(
            &self.signing_key,
            &self.artifact_uuid,
            merkle_tree.root_hash(),
            &header.header_checksum,
        );
        trailer.write_to(writer)?;

        Ok(trailer)
    }

    /// Writes the artifact to a file atomically via a temporary sibling file.
    pub fn write_to_file(self, target_path: &Path) -> Result<VyrTrailer, FormatError> {
        let temp_path = target_path.with_extension(format!("tmp.{}", Uuid::new_v4()));

        let trailer = {
            let file = File::create(&temp_path)?;
            let mut buf_writer = BufWriter::new(file);
            let trailer = self.write_to(&mut buf_writer)?;
            buf_writer.flush()?;
            trailer
        };

        // Atomic rename
        if let Err(e) = std::fs::rename(&temp_path, target_path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(FormatError::Io(e));
        }

        Ok(trailer)
    }
}
