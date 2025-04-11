#![allow(dead_code)]

mod args;
mod client;
mod crypto;
mod packet;
mod server;
mod utils;

use args::*;
use server::*;
use utils::*;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> GResult<()> {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    let args = Args::from_env().unwrap_or_else(|err| panic!("{err}"));
    match args.is_server {
        true => run_server(&args).await.unwrap(),
        false => run_client(&args).await.unwrap(),
    }

    Ok(())
}

async fn run_server(args: &Args) -> GResult<()> {
    let mut server = Server::new(args.port, None, message_callback);

    let s = tokio::spawn(async move { server.run().await });

    let local_ip = utils::get_local_addr()?;
    log::info!("Local ip: {:?}", local_ip);

    if !local_ip.is_ipv4() {
        log::error!("girl how am i supposed to loop over ipv6");
        return Ok(());
    }

    let local_ip_as_string = format!("{:?}", local_ip);

    for i in 2..255 {
        let i = i.to_string();
        let port = args.port;

        let mut remote_address_as_vec = local_ip_as_string
            .split(".")
            .map(|x| x.to_string())
            .collect::<Vec<_>>();

        if remote_address_as_vec[3] == i {
            continue;
        }

        remote_address_as_vec[3] = i;

        let remote_address = remote_address_as_vec.join(".");
        let remote_address_with_port = format!("{remote_address}:{}", port);

        tokio::spawn(async move {
            let stream = TcpStream::connect(&remote_address_with_port).await;
            if stream.is_err() {
                return;
            }

            let stream = stream.unwrap();
            let mut framed = Framed::new(stream, packet::JsonPacketCodec);

            framed.send(packet::Packet::Ping).await.unwrap();
            let packet = framed.next().await.unwrap().unwrap();

            if packet == packet::Packet::Ack {
                log::info!("YAY ALIVE ON {remote_address}");
            }

            client::test_client(port, Some(&remote_address)).await;
        });
    }

    s.await??;

    Ok(())
}

async fn run_client(args: &Args) -> GResult<()> {
    client::test_client(args.port, None).await;

    Ok(())
}

fn message_callback(plaintext: &[u8]) {
    log::debug!("Recieved message content: {:?}", unsafe {
        std::str::from_utf8_unchecked(plaintext)
    });
}
