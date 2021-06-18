// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use std::net::ToSocketAddrs;

use ring::rand::*;
use std::fs::File;
use std::pin::Pin;

use quiche::Connection;

const MAX_DATAGRAM_SIZE: usize = 1350;

const SEND_STREAM: bool = false;
const SEND_DGRAM: bool = true;
const STREAMS: [u64; 1] = [0];
const STREAM_MSG_NUM: u32 = 1;
const STREAM_MSG_SIZE: u32 = 800;
const DGRAM_MSG_NUM: u32 = 1;
const DGRAM_MSG_SIZE: u32 = 800;
const MSG_ITERATIONS: u32 = 20;

fn main() {
    env_logger::init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut msg_cnt = 0;
    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 1 {
        println!("Usage: {} URL", cmd);
        println!("\nSee tools/apps/ for more complete implementations.");
        return;
    }

    let url = url::Url::parse(&args.next().unwrap()).unwrap();

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let socket = std::net::UdpSocket::bind(bind_addr).unwrap();
    socket.connect(peer_addr).unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.log_keys();

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config
        .set_application_protos(b"\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 1000, 1000);

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(url.domain(), &scid, peer_addr, &mut config).unwrap();
    // Only bother with qlog if the user specified it.
    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("{:?}", scid);
            let writer = make_qlog_writer(&dir, "client", &id);

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            );
        }
    }
    conn.set_keylog(Box::new(File::create("log.log").unwrap()));
    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let (write, _send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send(&out[..write]) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    debug!("written {}", write);

    let req_start = std::time::Instant::now();

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();
                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                }
            };

            debug!("got {} bytes", len);

            let recv_info = quiche::RecvInfo { from };
            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                }
            };

            debug!("processed {} bytes", read);
        }

        debug!("done reading");

        if conn.is_closed() {
            let stats = conn.stats();
            info!("connection closed, {:?}, {}", stats, stats.retrans);
            break;
        }

        if conn.is_established() && msg_cnt < MSG_ITERATIONS {
            info!("sending msg");
            if SEND_STREAM {
                let msg = generate_msg(STREAM_MSG_SIZE);
                for stream in STREAMS.iter() {
                    for _ in 0..STREAM_MSG_NUM {
                        send_msg(&mut conn, *stream, &msg);
                    }
                }
            }
            if SEND_DGRAM {
                let msg = generate_msg(DGRAM_MSG_SIZE);
                for _ in 0..DGRAM_MSG_NUM {
                    send_dgram(&mut conn, &msg)
                }
            }
            msg_cnt += 1;
        }

        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                debug!("received {} bytes", read);

                let stream_buf = &buf[..read];

                debug!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

                // The server reported that it has no more data to send, which
                // we got the full response. Close the connection.
                if s == 0 && fin {
                    info!("response received in {:?}, closing...", req_start.elapsed());

                    conn.close(true, 0x00, b"kthxbye").unwrap();
                }
            }
        }

        let mut dgram_buf = [0; 1000];
        while let Ok(len) = conn.dgram_recv(&mut dgram_buf) {
            info!("{} got {} bytes of DATAGRAM", conn.trace_id(), len);
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, _send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                }

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };

            if let Err(e) = socket.send(&out[..write]) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }

            debug!("written {}", write);
        }

        if conn.is_closed() {
            let stats = conn.stats();
            info!("connection closed, {:?}, retrans: {}", stats, stats.retrans);
            break;
        }
    }
}

fn send_msg(conn: &mut Pin<Box<Connection>>, stream_id: u64, msg: &[u8]) {
    let written_to_stream = conn.stream_send(stream_id, msg, false).unwrap();
    info!("written to stream: {}", written_to_stream);
    let stream_capacity = conn.stream_capacity(stream_id).unwrap();
    info!("stream capacity: {}", stream_capacity);
}

fn send_dgram(conn: &mut Pin<Box<Connection>>, msg: &[u8]) {
    conn.dgram_send(msg).unwrap();
}

fn generate_msg(size: u32) -> Vec<u8> {
    (0..size).map(|_| rand::random::<u8>()).collect()
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

pub fn make_qlog_writer(
    dir: &std::ffi::OsStr,
    role: &str,
    _id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{}.qlog", role);
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}
