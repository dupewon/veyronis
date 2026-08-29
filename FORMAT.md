<div align="center">

# ◈ VEYRONIS BINARY CONTAINER SPECIFICATION (.VYR) ◈

```text
███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗
██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝
█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   
██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   
██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   
```

**Binary Container Layout • Authenticated Encryption • Merkle Proofs • Signature Trailers**

</div>

---

# 📦 1. Binary Container Layout

A `.vyr` file is a deterministic, little-endian binary stream composed of 6 mandatory sections:

```text
+-------------------------------------------------------------+
| Header (32 bytes)                                           |
| - Magic: "VYR1" (0x56 0x59 0x52 0x31)                       |
| - Version: 0x0100 (v1.0)                                    |
| - Artifact UUID: 16 bytes (RFC 4122 v4)                     |
| - Created Timestamp: 8 bytes (Unix Seconds)                 |
| - Flags: 2 bytes (Bit 0: Encrypted, Bit 1: Signed)          |
| - Reserved: 2 bytes                                         |
+-------------------------------------------------------------+
| Key Envelope Section                                        |
| - Ephemeral Public Key / Salt (X25519 / Argon2id)           |
| - Encrypted Master Content Key                              |
+-------------------------------------------------------------+
| Encrypted Manifest Chunk                                    |
| - Host Metadata, OS Build, CPU Architecture                 |
+-------------------------------------------------------------+
| Encrypted Index Chunk                                       |
| - Event Offset Table & Chunk Lookup Dictionary              |
+-------------------------------------------------------------+
| Encrypted Event Blocks (1 .. N)                             |
| - Block Header (Index, Payload Length)                      |
| - AEAD Ciphertext (XChaCha20-Poly1305)                      |
| - Poly1305 Authentication Tag (16 bytes)                    |
+-------------------------------------------------------------+
| Integrity Structure & Signature Trailer                     |
| - BLAKE3 Merkle Tree Root Hash (32 bytes)                   |
| - Ed25519 Public Signer Key (32 bytes)                      |
| - Ed25519 Digital Signature (64 bytes)                      |
+-------------------------------------------------------------+
```

---

# 🔐 2. Authenticated Associated Data (AAD) Binding

To prevent ciphertext substitution or chunk-reordering attacks, every encrypted event chunk binds contextual AAD before computing the Poly1305 tag:

$$\text{AAD} = \text{Artifact UUID} \,\|\, \text{Format Version} \,\|\, \text{Block Index} \,\|\, \text{Block Type}$$

If an adversary swaps Chunk #2 with Chunk #5, AEAD decryption immediately fails and the container is rejected.

---

# 🌲 3. Merkle Tree Root Calculation

Each block is hashed using **BLAKE3**:
$$H_i = \text{BLAKE3}(\text{Ciphertext}_i \,\|\, \text{Tag}_i)$$

The resulting hashes form the leaves of a binary Merkle tree. The top Merkle root hash is signed using **Ed25519**:

$$\text{Signature} = \text{Ed25519\_Sign}(\text{PrivateKey}_{\text{author}}, \text{MerkleRoot})$$
