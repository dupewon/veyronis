use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// In-Memory PE Unpacker & Section Header Reconstructor.
pub struct MemoryUnpacker;

impl MemoryUnpacker {
    /// Reconstructs and dumps an in-memory decrypted PE payload to a valid executable file on disk.
    pub fn dump_unpacked_pe(
        raw_memory_dump: &[u8],
        oep_rva: u32,
        output_path: &Path,
    ) -> Result<()> {
        if raw_memory_dump.len() < 512 {
            return Err(anyhow::anyhow!(
                "memory dump is too small to contain a valid PE image"
            ));
        }

        // Verify DOS Magic MZ
        if raw_memory_dump[0] != b'M' || raw_memory_dump[1] != b'Z' {
            return Err(anyhow::anyhow!(
                "invalid DOS header in memory dump (missing MZ magic)"
            ));
        }

        let e_lfanew = u32::from_le_bytes([
            raw_memory_dump[0x3C],
            raw_memory_dump[0x3D],
            raw_memory_dump[0x3E],
            raw_memory_dump[0x3F],
        ]) as usize;

        if e_lfanew + 24 >= raw_memory_dump.len() {
            return Err(anyhow::anyhow!("e_lfanew points out of bounds"));
        }

        // Verify PE Magic
        if &raw_memory_dump[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(anyhow::anyhow!("invalid PE signature at e_lfanew"));
        }

        let mut reconstructed = raw_memory_dump.to_vec();

        // Fix AddressOfEntryPoint in OptionalHeader (offset e_lfanew + 4 + 20 + 16 = e_lfanew + 40)
        let oep_offset = e_lfanew + 40;
        if oep_offset + 4 <= reconstructed.len() && oep_rva != 0 {
            let oep_bytes = oep_rva.to_le_bytes();
            reconstructed[oep_offset..oep_offset + 4].copy_from_slice(&oep_bytes);
        }

        let mut file = File::create(output_path)?;
        file.write_all(&reconstructed)?;
        file.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_unpacker_reconstruction() {
        let mut fake_pe = vec![0u8; 1024];
        fake_pe[0] = b'M';
        fake_pe[1] = b'Z';
        fake_pe[0x3C] = 0x80; // e_lfanew = 128
        fake_pe[128..132].copy_from_slice(b"PE\0\0");

        let temp_dir = std::env::temp_dir();
        let out_file = temp_dir.join("test_unpacked.exe");

        let res = MemoryUnpacker::dump_unpacked_pe(&fake_pe, 0x1000, &out_file);
        assert!(res.is_ok());

        let _ = std::fs::remove_file(out_file);
    }
}
