use std::error::Error;
use std::net::{IpAddr, UdpSocket};

pub type GResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub fn get_local_addr() -> GResult<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let local_addr = socket.local_addr()?;

    Ok(local_addr.ip())
}