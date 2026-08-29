use rand::RngCore;
use sha2::{Digest, Sha256};

fn main() {
    let mut rng = rand::rngs::OsRng;
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);

    let mut hasher = Sha256::new();
    hasher.update(random_bytes);
    let hash = hasher.finalize();

    println!(
        "Crypto test completed: SHA256({:02x?}...) = {:02x?}",
        &random_bytes[0..4],
        &hash[0..8]
    );
}
