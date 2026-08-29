use std::net::ToSocketAddrs;

fn main() {
    let hostname = "localhost:80";
    if let Ok(addrs) = hostname.to_socket_addrs() {
        let count = addrs.count();
        println!("DNS test resolved localhost to {} socket addresses", count);
    } else {
        println!("DNS lookup completed");
    }
}
