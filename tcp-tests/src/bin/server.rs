use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.2:7878")?;
    for stream in listener.incoming() {
        handle_client(stream?);
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream) {
    let mut buff = [0; 1024];
    loop {
        let bytes = stream.read(&mut buff).unwrap();
        println!("recv: {:?} bytes", bytes);
    }
}
