#![feature(slice_as_array)]
#![allow(dead_code)]

mod args;
mod client;
mod crypto;
mod packet;
mod server;
mod utils;

use args::*;
use packet::*;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use server::*;
use utils::*;

fn main() -> GResult<()> {
    let args = Args::from_env().unwrap_or_else(|err| panic!("{err}"));

    if args.is_server {
        run_server(&args)?;
    } else {
        run_client(&args)?;
    }

    Ok(())
}

fn run_server(args: &Args) -> GResult<()> {    
    let mut server = Server::new(args.port, None, Some(message_callback));

    server.run().unwrap();

    Ok(())
}

fn run_client(args: &Args) -> GResult<()> {
    client::test_client(args.port);

    Ok(())
}

fn message_callback(server: &mut Server, packet: &mut Packet) {
    eprintln!("[DEBUG] Recieved message packet: {packet:?}");

    let Packet::Message {
        to: _,
        from,
        payload,
        nonce
    } = packet else {
        unreachable!()
    };

    let session = server.get_session_for_uuid(*from).unwrap();
    let unbound_key = UnboundKey::new(&AES_256_GCM, &session.session_key).unwrap();
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce);

    let aad = Aad::empty();

    key.open_in_place(nonce, aad, payload).unwrap();

    println!("[DEBUG] Recieved message content: {:?}", unsafe { str::from_utf8_unchecked(payload) });
}