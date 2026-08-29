use std::time::Instant;
use veyronis_crypto::{
    decrypt_aead, derive_key_argon2id, encrypt_aead, generate_salt, sign_message, verify_signature,
    ContentEncryptionKey, MerkleTree, SigningKeypair,
};

fn main() {
    println!("=== VEYRONIS CRYPTOGRAPHIC PERFORMANCE BENCHMARK ===");

    // 1. AEAD Benchmark
    let key = ContentEncryptionKey::generate();
    let nonce = [0x42u8; 24];
    let aad = b"VEYRONIS-BENCHMARK-AAD";
    let data_1mb = vec![0xABu8; 1024 * 1024];

    let start = Instant::now();
    let iterations = 50;
    for _ in 0..iterations {
        let ciphertext = encrypt_aead(&key, &nonce, &data_1mb, aad).unwrap();
        let _decrypted = decrypt_aead(&key, &nonce, &ciphertext, aad).unwrap();
    }
    let elapsed = start.elapsed();
    let throughput_mb = (iterations as f64 * 2.0) / elapsed.as_secs_f64();
    println!(
        "AEAD XChaCha20-Poly1305 Throughput: {:.2} MB/s",
        throughput_mb
    );

    // 2. Merkle Tree Benchmark
    let leaf_hashes: Vec<[u8; 32]> = (0..10_000u32)
        .map(|i| *blake3::hash(&i.to_le_bytes()).as_bytes())
        .collect();
    let start = Instant::now();
    for _ in 0..10 {
        let _tree = MerkleTree::from_leaf_hashes(leaf_hashes.clone()).unwrap();
    }
    let elapsed = start.elapsed();
    println!(
        "Merkle Tree Generation (10,000 leaves): {:.2} ms/tree",
        elapsed.as_millis() as f64 / 10.0
    );

    // 3. Ed25519 Signing & Verification
    let signing_key = SigningKeypair::generate();
    let message = b"BENCHMARK-VERIFIABLE-PAYLOAD-HASH";
    let start = Instant::now();
    let sig_iterations = 1000;
    for _ in 0..sig_iterations {
        let sig = sign_message(&signing_key, message);
        verify_signature(&signing_key.verifying_key(), message, &sig).unwrap();
    }
    let elapsed = start.elapsed();
    println!(
        "Ed25519 Sign + Verify Rate: {:.2} ops/sec",
        sig_iterations as f64 / elapsed.as_secs_f64()
    );

    // 4. Argon2id KDF Benchmark
    let salt = generate_salt();
    let start = Instant::now();
    let _derived = derive_key_argon2id(b"MasterSecretPassphrase123!", &salt).unwrap();
    let elapsed = start.elapsed();
    println!(
        "Argon2id KDF (64MB memory, 3 iterations): {:.2} ms",
        elapsed.as_millis()
    );
    println!("=== BENCHMARK COMPLETE ===");
}
