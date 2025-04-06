use std::{io::{BufReader, Read, Write}, net::TcpStream};

use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM}, agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519}, rand::{SecureRandom, SystemRandom}
};

use crate::{crypto, packet::Packet};

pub fn test_client(port: u16) {
    let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();

    let rng = SystemRandom::new();

    let my_priv_key = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let my_pub_key = my_priv_key.compute_public_key().unwrap();

    let my_id = uuid::Uuid::new_v4();

    let handshake = Packet::Handshake {
        ephemeral_key: my_pub_key.as_ref().into(),
        session_id: uuid::Uuid::new_v4(),
        from: my_id,
    };

    let s = serde_json::to_string(&handshake).unwrap();

    tcp_stream.write_all(s.as_bytes()).unwrap();
    tcp_stream.flush().unwrap();

    tcp_stream.shutdown(std::net::Shutdown::Write).unwrap();
    
    let mut reader = BufReader::new(&tcp_stream);
    let mut read = vec![];
    reader.read_to_end(&mut read).unwrap();

    let packet: Packet = serde_json::from_slice(read.as_slice()).unwrap();
    let Packet::Handshake { ephemeral_key, session_id: _, from } = packet else {unreachable!()};

    let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    
    let rng = ring::rand::SystemRandom::new();

    let session_key = agreement::agree_ephemeral(
        my_priv_key,
        &UnparsedPublicKey::new(&X25519, ephemeral_key),
        crypto::hkdf_sha256,
    ).unwrap();

    let unbound_key = UnboundKey::new(&AES_256_GCM, &session_key).unwrap();

    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let key = LessSafeKey::new(unbound_key);

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

    tcp_stream.write_all(
        serde_json::to_vec(&packet).unwrap().as_slice()
    ).unwrap();
}
