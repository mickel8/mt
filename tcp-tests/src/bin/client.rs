use std::io::prelude::*;
use std::net::TcpStream;

const PACKET_NUM: u32 = 1000;

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.2:7878")?;

    let data = generate_data();
    for _ in 0..PACKET_NUM {
        let bytes = stream.write(&data)?;
        println!("wrote: {} bytes", bytes);
    }
    Ok(())
}

fn generate_data() -> Vec<u8> {
    // (0..800).map(|_| rand::random::<u8>()).collect()
    (0..800).map(|_| 1).collect()
}

