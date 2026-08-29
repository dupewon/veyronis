use crate::error::FormatError;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use uuid::Uuid;

pub const MAGIC_BYTES: [u8; 4] = [0x56, 0x59, 0x52, 0x31]; // "VYR1"
pub const CURRENT_MAJOR_VERSION: u16 = 1;
pub const CURRENT_MINOR_VERSION: u16 = 0;
pub const HEADER_FIXED_SIZE: usize = 48;

pub const FLAG_ENCRYPTED: u32 = 1 << 0;
pub const FLAG_COMPRESSED: u32 = 1 << 1;
pub const FLAG_SIGNED: u32 = 1 << 2;

/// Fixed-size authenticated public header for .vyr binary containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VyrHeader {
    pub magic: [u8; 4],
    pub major_version: u16,
    pub minor_version: u16,
    pub flags: u32,
    pub header_length: u32,
    pub artifact_uuid: Uuid,
    pub created_timestamp: i64,
    pub header_checksum: [u8; 8],
}

impl VyrHeader {
    pub fn new(artifact_uuid: Uuid, flags: u32) -> Self {
        let mut header = Self {
            magic: MAGIC_BYTES,
            major_version: CURRENT_MAJOR_VERSION,
            minor_version: CURRENT_MINOR_VERSION,
            flags,
            header_length: HEADER_FIXED_SIZE as u32,
            artifact_uuid,
            created_timestamp: chrono::Utc::now().timestamp(),
            header_checksum: [0u8; 8],
        };
        header.header_checksum = header.compute_checksum();
        header
    }

    pub fn is_encrypted(&self) -> bool {
        (self.flags & FLAG_ENCRYPTED) != 0
    }

    pub fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }

    pub fn is_signed(&self) -> bool {
        (self.flags & FLAG_SIGNED) != 0
    }

    pub fn compute_checksum(&self) -> [u8; 8] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.magic);
        hasher.update(&self.major_version.to_be_bytes());
        hasher.update(&self.minor_version.to_be_bytes());
        hasher.update(&self.flags.to_be_bytes());
        hasher.update(&self.header_length.to_be_bytes());
        hasher.update(self.artifact_uuid.as_bytes());
        hasher.update(&self.created_timestamp.to_be_bytes());
        let hash = hasher.finalize();
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&hash.as_bytes()[0..8]);
        checksum
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), FormatError> {
        writer.write_all(&self.magic)?;
        writer.write_u16::<BigEndian>(self.major_version)?;
        writer.write_u16::<BigEndian>(self.minor_version)?;
        writer.write_u32::<BigEndian>(self.flags)?;
        writer.write_u32::<BigEndian>(self.header_length)?;
        writer.write_all(self.artifact_uuid.as_bytes())?;
        writer.write_i64::<BigEndian>(self.created_timestamp)?;
        writer.write_all(&self.header_checksum)?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, FormatError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| FormatError::UnexpectedEof)?;
        if magic != MAGIC_BYTES {
            return Err(FormatError::InvalidMagic(magic));
        }

        let major_version = reader
            .read_u16::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;
        if major_version > CURRENT_MAJOR_VERSION {
            return Err(FormatError::UnsupportedVersion {
                version: major_version,
                max_supported: CURRENT_MAJOR_VERSION,
            });
        }

        let minor_version = reader
            .read_u16::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;
        let flags = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;
        let header_length = reader
            .read_u32::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;

        let mut uuid_bytes = [0u8; 16];
        reader
            .read_exact(&mut uuid_bytes)
            .map_err(|_| FormatError::UnexpectedEof)?;
        let artifact_uuid = Uuid::from_bytes(uuid_bytes);

        let created_timestamp = reader
            .read_i64::<BigEndian>()
            .map_err(|_| FormatError::UnexpectedEof)?;

        let mut checksum = [0u8; 8];
        reader
            .read_exact(&mut checksum)
            .map_err(|_| FormatError::UnexpectedEof)?;

        let header = Self {
            magic,
            major_version,
            minor_version,
            flags,
            header_length,
            artifact_uuid,
            created_timestamp,
            header_checksum: checksum,
        };

        if header.compute_checksum() != checksum {
            return Err(FormatError::CorruptedHeader);
        }

        Ok(header)
    }
}
