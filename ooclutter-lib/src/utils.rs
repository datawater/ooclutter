use std::error::Error;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::pin::Pin;

use futures_util::SinkExt;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::packet::{JsonPacketCodec, Packet};

pub type GResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
pub type BoxedFuture<'a, T = ()> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub fn get_local_addr() -> GResult<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let local_addr = socket.local_addr()?;

    Ok(local_addr.ip())
}

pub async fn send_packet_to_ip(ip: SocketAddr, packet: Packet) -> GResult<()> {
    let connection = TcpStream::connect(ip).await?;
    let mut framed = Framed::new(connection, JsonPacketCodec);

    let r = framed.send(packet).await;
    if r.is_err() {
        return Err(format!("Could not send packet: {:?}", unsafe {
            r.err().unwrap_unchecked()
        })
        .into());
    }

    Ok(())
}
