use std::fs::{self, File};
use std::io::Write;
use std::net::TcpListener;

fn main() {
    // Modified behavior: performs a new TCP bind + different file write
    let temp_file = std::env::temp_dir().join("veyronis_modified_fixture.tmp");
    let mut file = File::create(&temp_file).expect("create file");
    file.write_all(b"Modified behavior divergence test data")
        .expect("write");
    drop(file);
    let _ = fs::remove_file(&temp_file);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    println!("Modified fixture completed: bound TCP port {}", port);
}
