<div align="center">

# ◈ VEYRONIS CRYPTOGRAPHIC ARCHITECTURE SPECIFICATION ◈

```text
 ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ 
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ 
```

**State-of-the-Art Primitives • Threshold Cryptography • RFC 3161 Timestamping**

</div>

---

# 🛡️ 1. Selected Cryptographic Primitives

Veyronis exclusively uses industry-standard, rigorously audited cryptographic primitives:

```text
┌─────────────────────────┬───────────────────────────────┬───────────────────────────┐
│ Function                │ Selected Primitive            │ Security Parameter        │
├─────────────────────────┼───────────────────────────────┼───────────────────────────┤
│ Content Confidentiality │ XChaCha20-Poly1305 (AEAD)     │ 256-bit Key / 192-bit IV  │
│ Alternative AEAD Cipher │ AES-256-GCM                   │ 256-bit Key / 96-bit IV   │
│ Password Key Derivation │ Argon2id                      │ m=64MB, t=3, p=4          │
│ Asymmetric Key Exchange │ X25519 (ECDH Curve25519)      │ 128-bit Security          │
│ Digital Signatures      │ Ed25519 (EdDSA)               │ 128-bit Security          │
│ Cryptographic Hashing   │ BLAKE3 / SHA-256              │ 256-bit Tree Hash         │
│ Threshold Shares        │ Shamir Secret Sharing         │ GF(256) Field Arithmetic  │
│ Evidence Timestamping   │ RFC 3161 Digital Token        │ Merkle Root Binding       │
└─────────────────────────┴───────────────────────────────┴───────────────────────────┘
```

---

# 🔑 2. Shamir $k$-of-$n$ Threshold Secret Sharing

For high-security multi-custodian operations, Veyronis provides native Shamir Secret Sharing over the Galois Field $\text{GF}(256)$ using Russian Peasant multiplication and Fermat's Little Theorem inversion:

$$P(x) = S + \sum_{j=1}^{k-1} a_j x^j \pmod{256}$$

* Any $k$ distinct shares reconstruct the secret:
  $$S = \sum_{i=1}^k y_i \prod_{j \ne i} \frac{x_j}{x_j \oplus x_i}$$
* Fewer than $k$ shares mathematically yield zero entropy regarding $S$.

---

# 📜 3. RFC 3161 Cryptographic Timestamping

To provide non-repudiable legal evidence admissible in judicial and regulatory audits, `veyronis timestamp` binds the Merkle root hash into a signed token:

```json
{
  "serial_number": 1900275338438251265,
  "artifact_merkle_root": "77bdfb31f0d5ad9c549f27f3ff380fb129b6e6c8b5df826db2154f1471b08430",
  "policy_oid": "1.3.6.1.4.1.61234.1.1 (Veyronis TSA Policy)",
  "timestamp": "2026-08-29T10:22:18.498Z",
  "signature_hex": "..."
}
```
