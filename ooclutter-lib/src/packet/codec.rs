use std::error::Error;

use tokio_util::{
    bytes::{Buf, BufMut, BytesMut},
    codec::{Decoder, Encoder},
};

use super::Packet;
pub struct JsonPacketCodec;

impl Decoder for JsonPacketCodec {
    type Item = Packet;
    type Error = Box<dyn Error>;

    fn decode(
        &mut self,
        src: &mut tokio_util::bytes::BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let len = src[..4].as_ref().get_u32() as usize;

        if src.len() < 4 + len {
            return Ok(None);
        }

        src.advance(4);
        let data = src.split_to(len);

        match serde_json::from_slice(&data) {
            Ok(p) => Ok(Some(p)),
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl Encoder<Packet> for JsonPacketCodec {
    type Error = Box<dyn Error>;

    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = serde_json::to_vec(&item)?;
        let len = bytes.len() as u32;

        dst.put_u32(len);
        dst.extend_from_slice(&bytes);

        Ok(())
    }
}
