use colored::*;
use std::path::Path;
use veyronis_crypto::MerkleTree;
use veyronis_format::VyrReader;

pub struct VyrVerifier;

impl VyrVerifier {
    pub fn verify(artifact_path: &Path) -> Result<bool, anyhow::Error> {
        println!("{}", "VEYRONIS VERIFY".bold().white());

        let reader_result = VyrReader::open_file(artifact_path);
        let reader = match reader_result {
            Ok(r) => {
                println!("Container       {}", "VALID".green());
                r
            }
            Err(e) => {
                println!("Container       {}", "FAILED".red().bold());
                println!("Error:          {}", e);
                println!("Result:\n  {}", "REJECTED".red().bold());
                return Ok(false);
            }
        };

        if reader.header.is_encrypted() {
            println!("Encryption      {}", "VALID".green());
        } else {
            println!("Encryption      {}", "DISABLED (PLAINTEXT)".yellow());
        }

        // Check block integrity
        let mut failed_blocks = Vec::new();
        let mut leaf_hashes = Vec::with_capacity(reader.block_entries.len());

        for (i, entry) in reader.block_entries.iter().enumerate() {
            let ciphertext = &reader.block_ciphertexts[i];
            let calculated_hash = *blake3::hash(ciphertext).as_bytes();
            if calculated_hash != entry.block_hash {
                failed_blocks.push(entry.block_index);
            }
            leaf_hashes.push(entry.block_hash);
        }

        if !failed_blocks.is_empty() {
            println!("Block Integrity {}", "FAILED".red().bold());
            println!(
                "Invalid Blocks  {}",
                failed_blocks
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
                    .red()
            );
            println!("Result:\n  {}", "REJECTED".red().bold());
            return Ok(false);
        } else {
            println!("Block Integrity {}", "VALID".green());
        }

        // Check Merkle Root
        let merkle_tree = match MerkleTree::from_leaf_hashes(leaf_hashes) {
            Ok(tree) => tree,
            Err(_) => {
                println!("Merkle Root     {}", "FAILED".red().bold());
                println!("Result:\n  {}", "REJECTED".red().bold());
                return Ok(false);
            }
        };

        if merkle_tree.root_hash() != &reader.trailer.merkle_root {
            println!("Merkle Root     {}", "FAILED".red().bold());
            println!("Result:\n  {}", "REJECTED".red().bold());
            return Ok(false);
        } else {
            println!("Merkle Root     {}", "VALID".green());
        }

        // Check Signature
        match reader
            .trailer
            .verify(&reader.header.artifact_uuid, &reader.header.header_checksum)
        {
            Ok(()) => {
                println!("Signature       {}", "VALID".green());
            }
            Err(_) => {
                println!("Signature       {}", "INVALID".red().bold());
                println!("Result:\n  {}", "REJECTED".red().bold());
                return Ok(false);
            }
        }

        println!("Artifact Trust:\n  {}", "VERIFIED".green().bold());
        Ok(true)
    }
}
