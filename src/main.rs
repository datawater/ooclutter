#![feature(slice_as_array, addr_parse_ascii, ip_from)]
#![allow(dead_code)]

mod args;
mod client;
mod crypto;
mod packet;
mod server;
mod utils;

use args::*;
use packet::*;
use server::*;
use utils::*;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use std::net::Ipv4Addr;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> GResult<()> {
    let args = Args::from_env().unwrap_or_else(|err| panic!("{err}"));
    match args.is_server {
        true => run_server(&args).await.unwrap(),
        false => run_client(&args).await.unwrap(),
    }

    Ok(())
}

async fn run_server(args: &Args) -> GResult<()> {
    let mut server = Server::new(args.port, None, Some(message_callback));

    let s = tokio::spawn(async move {
        server.run().await
    });

    let local_ip = utils::get_local_addr()?;
    println!("[INFO] Local ip: {:?}", local_ip);

    if !local_ip.is_ipv4() {
        println!("girl how am i supposed to loop over ipv6");
        return Ok(());
    }

    let local_ip = Ipv4Addr::parse_ascii(local_ip.to_string().as_bytes())?;
    for i in 2..=255 {
        let itp = &mut local_ip.octets();
        let itp = format!("{}.{}.{}.{}:{}", itp[0], itp[1], itp[2], i, args.port);
        
        let stream = TcpStream::connect(&itp).await;
        if stream.is_err() {continue;}

        let stream = stream.unwrap();
        let mut framed = Framed::new(stream, packet::JsonPacketCodec);

        framed.send(packet::Packet::Ping).await.unwrap();
        let packet = framed.next().await.unwrap().unwrap();

        if packet == packet::Packet::Ack {
            println!("[INFO] YAY ALIVE ON {itp}");
        }
    }

    s.await??;

    Ok(())
}

async fn run_client(args: &Args) -> GResult<()> {
    client::test_client(args.port).await;

    Ok(())
}

fn message_callback(server: &mut Server, packet: &mut Packet) {
    eprintln!("[DEBUG] Recieved message packet: {packet:?}");

    let Packet::Message {
        to: _,
        from,
        payload,
        nonce,
    } = packet
    else {
        unreachable!()
    };

    let session = server.get_session_for_uuid(*from).unwrap();
    let unbound_key = UnboundKey::new(&AES_256_GCM, &session.session_key).unwrap();
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce);

    let aad = Aad::empty();

    let plaintext = key.open_in_place(nonce, aad, payload).unwrap();

    println!("[DEBUG] Recieved message content: {:?}", unsafe {
        str::from_utf8_unchecked(plaintext)
    });
}
