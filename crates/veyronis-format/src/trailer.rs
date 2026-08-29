use crate::error::FormatError;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::VerifyingKey;
use std::io::{Read, Write};
use uuid::Uuid;
use veyronis_crypto::{sign_message, verify_signature, SigningKeypair, SIGNATURE_SIZE};

pub const TRAILER_MAGIC: [u8; 4] = [0x56, 0x59, 0x52, 0x54]; // "VYRT"
pub const SIG_ALGO_ED25519: u16 = 1;
pub const SIGNATURE_DOMAIN: &[u8] = b"VEYRONIS-SIG-V1";

/// Cryptographic signature trailer at the end of the VYR container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VyrTrailer {
    pub merkle_root: [u8; 32],
    pub signer_public_key: [u8; 32],
    pub signature_algorithm: u16,
    pub signature: [u8; SIGNATURE_SIZE],
}

impl VyrTrailer {
    pub fn compute_signature_payload(
        artifact_uuid: &Uuid,
        merkle_root: &[u8; 32],
        header_checksum: &[u8; 8],
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(SIGNATURE_DOMAIN);
        payload.extend_from_slice(artifact_uuid.as_bytes());
        payload.extend_from_slice(merkle_root);
        payload.extend_from_slice(header_checksum);
        payload
    }

    pub fn sign(
        signing_key: &SigningKeypair,
        artifact_uuid: &Uuid,
        merkle_root: &[u8; 32],
        header_checksum: &[u8; 8],
    ) -> Self {
        let payload = Self::compute_signature_payload(artifact_uuid, merkle_root, header_checksum);
        let signature = sign_message(signing_key, &payload);
        let signer_public_key = *signing_key.verifying_key().as_bytes();

        Self {
            merkle_root: *merkle_root,
            signer_public_key,
            signature_algorithm: SIG_ALGO_ED25519,
            signature,
        }
    }

    pub fn verify(
        &self,
        artifact_uuid: &Uuid,
        header_checksum: &[u8; 8],
    ) -> Result<(), FormatError> {
        let payload =
            Self::compute_signature_payload(artifact_uuid, &self.merkle_root, header_checksum);
        let verifying_key = VerifyingKey::from_bytes(&self.signer_public_key)
            .map_err(|_| FormatError::InvalidSignature)?;

        verify_signature(&verifying_key, &payload, &self.signature)
            .map_err(|_| FormatError::InvalidSignature)?;

        Ok(())
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), FormatError> {
        writer.write_all(&self.merkle_root)?;
        writer.write_all(&self.signer_public_key)?;
        writer.write_u16::<BigEndian>(self.signature_algorithm)?;
        writer.write_all(&self.signature)?;
        writer.write_all(&TRAILER_MAGIC)?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, FormatError> {
        let mut merkle_root = [0u8; 32];
        reader
            .read_exact(&mut merkle_root)
            .map_err(|_| FormatError::UnexpectedEof)?;

        let mut signer_public_key = [0u8; 32];
        reader
            .read_exact(&mut signer_public_key)
            .map_err(|_| FormatError::UnexpectedEof)?;

        let signature_algorithm = reader
            .read_u16::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;

        let mut signature = [0u8; SIGNATURE_SIZE];
        reader
            .read_exact(&mut signature)
            .map_err(|_| FormatError::UnexpectedEof)?;

        let mut trailer_magic = [0u8; 4];
        reader
            .read_exact(&mut trailer_magic)
            .map_err(|_| FormatError::UnexpectedEof)?;
        if trailer_magic != TRAILER_MAGIC {
            return Err(FormatError::CorruptedBlock { index: 0 });
        }

        Ok(Self {
            merkle_root,
            signer_public_key,
            signature_algorithm,
            signature,
        })
    }
}
