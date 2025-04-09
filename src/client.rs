use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519},
    rand::{SecureRandom, SystemRandom},
};

use crate::packet;
use crate::{crypto, packet::Packet};
use uuid::Uuid;

pub async fn test_client(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&addr).await.unwrap();
    let mut framed = Framed::new(stream, packet::JsonPacketCodec);

    let rng = SystemRandom::new();
    let my_priv_key = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let my_pub_key = my_priv_key.compute_public_key().unwrap();
    let my_id = Uuid::new_v4();

    let handshake = Packet::Handshake {
        ephemeral_key: my_pub_key.as_ref().into(),
        from: my_id,
    };

    framed.send(handshake).await.unwrap();

    let packet = framed.next().await.unwrap().unwrap();

    let Packet::Handshake {
        ephemeral_key,
        from,
    }: Packet = packet
    else {
        panic!("Invalid handshake response from server");
    };

    let session_key = ring::agreement::agree_ephemeral(
        my_priv_key,
        &UnparsedPublicKey::new(&X25519, ephemeral_key),
        crypto::hkdf_sha256,
    )
    .unwrap();

    let unbound_key = UnboundKey::new(&AES_256_GCM, &session_key).unwrap();
    let key = LessSafeKey::new(unbound_key);

    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let aad = Aad::empty();
    let mut message = b"HELLO".to_vec();

    key.seal_in_place_append_tag(nonce, aad, &mut message)
        .unwrap();

    let packet = Packet::Message {
        to: from,
        from: my_id,
        payload: message.into(),
        nonce: nonce_bytes,
    };

    framed.send(packet).await.unwrap();
}
