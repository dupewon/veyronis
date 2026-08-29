use std::net::{TcpListener, TcpStream};
use std::thread;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    let server_handle = thread::spawn(move || {
        if let Ok((mut socket, _)) = listener.accept() {
            use std::io::Write;
            let _ = socket.write_all(b"OK");
        }
    });

    if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", port)) {
        use std::io::Read;
        let mut buf = [0u8; 2];
        let _ = stream.read_exact(&mut buf);
        println!("TCP socket test completed: connected to 127.0.0.1:{}", port);
    }

    let _ = server_handle.join();
}
