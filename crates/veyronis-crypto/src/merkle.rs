use crate::error::CryptoError;

const LEAF_PREFIX: &[u8] = b"VYR-MERKLE-LEAF\x00";
const NODE_PREFIX: &[u8] = b"VYR-MERKLE-NODE\x00";

/// Merkle Tree for tamper-evident data block verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    leaf_hashes: Vec<[u8; 32]>,
    root_hash: [u8; 32],
}

impl MerkleTree {
    /// Computes a balanced Merkle tree over a slice of canonical 32-byte block hashes.
    pub fn from_leaf_hashes(leaf_hashes: Vec<[u8; 32]>) -> Result<Self, CryptoError> {
        if leaf_hashes.is_empty() {
            return Err(CryptoError::EmptyMerkleData);
        }

        // Hash leaves with domain separation prefix
        let mut current_level: Vec<[u8; 32]> = leaf_hashes
            .iter()
            .map(|leaf| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(LEAF_PREFIX);
                hasher.update(leaf);
                *hasher.finalize().as_bytes()
            })
            .collect();

        // Build tree levels upwards
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(NODE_PREFIX);
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                    next_level.push(*hasher.finalize().as_bytes());
                } else {
                    // Duplicate last odd node to balance tree
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(NODE_PREFIX);
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[0]);
                    next_level.push(*hasher.finalize().as_bytes());
                }
            }
            current_level = next_level;
        }

        let root_hash = current_level[0];
        Ok(Self {
            leaf_hashes,
            root_hash,
        })
    }

    pub fn root_hash(&self) -> &[u8; 32] {
        &self.root_hash
    }

    pub fn leaf_hashes(&self) -> &[[u8; 32]] {
        &self.leaf_hashes
    }

    /// Verifies that a given set of leaf hashes matches an expected Merkle root.
    pub fn verify_root(
        leaf_hashes: &[[u8; 32]],
        expected_root: &[u8; 32],
    ) -> Result<(), CryptoError> {
        let tree = Self::from_leaf_hashes(leaf_hashes.to_vec())?;
        if tree.root_hash() != expected_root {
            return Err(CryptoError::MerkleRootMismatch {
                calculated: hex::encode(tree.root_hash()),
                expected: hex::encode(expected_root),
            });
        }
        Ok(())
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
