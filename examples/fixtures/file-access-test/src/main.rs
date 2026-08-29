use std::fs::{self, File};
use std::io::{Read, Write};

fn main() {
    let temp_file = std::env::temp_dir().join("veyronis_fixture_sample.tmp");

    // Write file
    let mut file = File::create(&temp_file).expect("create file");
    file.write_all(b"Veyronis runtime behavior fixture payload")
        .expect("write file");
    drop(file);

    // Read file
    let mut file = File::open(&temp_file).expect("open file");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("read file");
    drop(file);

    // Delete file
    let _ = fs::remove_file(&temp_file);

    println!(
        "File access test completed successfully: {} bytes processed",
        buf.len()
    );
}
