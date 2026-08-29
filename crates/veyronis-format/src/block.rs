use crate::error::FormatError;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use uuid::Uuid;
use veyronis_crypto::NONCE_SIZE;

pub const BLOCK_TYPE_MANIFEST: u16 = 1;
pub const BLOCK_TYPE_EVENTS: u16 = 2;
pub const BLOCK_TYPE_GRAPH: u16 = 3;
pub const BLOCK_TYPE_RAW_EVIDENCE: u16 = 4;

/// Metadata entry in the container's block table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    pub block_index: u32,
    pub block_type: u16,
    pub uncompressed_len: u32,
    pub compressed_len: u32,
    pub ciphertext_len: u32,
    pub nonce: [u8; NONCE_SIZE],
    pub block_hash: [u8; 32],
}

impl BlockEntry {
    pub fn derive_aad(
        artifact_uuid: &Uuid,
        major_version: u16,
        minor_version: u16,
        block_index: u32,
        block_type: u16,
    ) -> [u8; 26] {
        let mut aad = [0u8; 26];
        aad[0..16].copy_from_slice(artifact_uuid.as_bytes());
        aad[16..18].copy_from_slice(&major_version.to_be_bytes());
        aad[18..20].copy_from_slice(&minor_version.to_be_bytes());
        aad[20..24].copy_from_slice(&block_index.to_be_bytes());
        aad[24..26].copy_from_slice(&block_type.to_be_bytes());
        aad
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), FormatError> {
        writer.write_u32::<BigEndian>(self.block_index)?;
        writer.write_u16::<BigEndian>(self.block_type)?;
        writer.write_u32::<BigEndian>(self.uncompressed_len)?;
        writer.write_u32::<BigEndian>(self.compressed_len)?;
        writer.write_u32::<BigEndian>(self.ciphertext_len)?;
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.block_hash)?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, FormatError> {
        let block_index = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;
        let block_type = reader
            .read_u16::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;
        let uncompressed_len = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;
        let compressed_len = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;
        let ciphertext_len = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;

        let mut nonce = [0u8; NONCE_SIZE];
        reader
            .read_exact(&mut nonce)
            .map_err(|_| FormatError::UnexpectedEof)?;

        let mut block_hash = [0u8; 32];
        reader
            .read_exact(&mut block_hash)
            .map_err(|_| FormatError::UnexpectedEof)?;

        Ok(Self {
            block_index,
            block_type,
            uncompressed_len,
            compressed_len,
            ciphertext_len,
            nonce,
            block_hash,
        })
    }
}
