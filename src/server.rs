use crate::crypto::{self, EphemeralPair};
use crate::packet::Packet;
use crate::utils::GResult;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, UnparsedPublicKey, X25519};
use ring::rand::{self, SecureRandom, SystemRandom};
use uuid::Uuid;

type KDFFn = fn(&[u8]) -> [u8; 32];
type MessageCallbackFn = fn(&mut Server, &mut Packet);

#[derive(Debug, Clone)]
pub struct Session {
    device_ip: SocketAddr,
    device_id: Uuid,
    session_id: Uuid,
    pub session_key: [u8; 32],
}

#[derive(Debug)]
pub struct Server {
    port_to_run_on: u16,

    session_keys: HashMap<Uuid, Session>,
    kdf: KDFFn,

    uuid: Uuid,
    message_callback: MessageCallbackFn
}

impl Server {
    pub fn new(port_to_run_on: u16, kdf: Option<KDFFn>, message_callback: Option<MessageCallbackFn>) -> Self {
        Self {
            port_to_run_on,
            session_keys: HashMap::new(),
            kdf: kdf.unwrap_or(crypto::hkdf_sha256),
            uuid: uuid::Uuid::new_v4(),
            message_callback: message_callback.unwrap_or(Self::default_msg_callback)
        }
    }

    fn default_msg_callback(&mut self, _pack: &mut Packet) {}

    pub fn run(&mut self) -> GResult<()> {
        let addr = format!("127.0.0.1:{}", self.port_to_run_on);
        
        eprintln!("[INFO] Running server on addr: {addr}");

        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;

        for stream in listener.incoming() {
            if stream.is_err() {
                break;
            }

            let mut stream = stream?;
            let mut content = vec![];

            stream.read_to_end(&mut content)?;

            let mut packet = serde_json::from_slice::<Packet>(content.as_slice()).unwrap_or_default();

            match packet {
                Packet::Handshake { .. } => {
                    self.handle_handshake(packet, &mut stream, addr).unwrap()
                }
                Packet::Message { .. } => {
                    (self.message_callback)(self, &mut packet);
                },
                Packet::Invalid => {
                    stream.shutdown(Shutdown::Both)?;
                    continue;
                }
            }
        }

        Ok(())
    }

    fn handle_handshake(
        &mut self,
        packet: Packet,
        stream: &mut TcpStream,
        addr: SocketAddr,
    ) -> GResult<()> {
        let Packet::Handshake {
            ref ephemeral_key,
            session_id,
            from,
        } = packet
        else {
            return Err("Not a handshake packet".into());
        };

        eprintln!("[DEBUG] Recieved handshake packet: {packet:?}");

        let rng = rand::SystemRandom::new();
        let pair = EphemeralPair::generate(&rng)?;

        let session_key = agreement::agree_ephemeral(
            pair.private_key,
            &UnparsedPublicKey::new(&X25519, ephemeral_key),
            self.kdf,
        )?;

        self.session_keys.insert(
            from,
            Session {
                session_id,
                device_id: from,
                device_ip: addr,
                session_key: *session_key.as_array().unwrap(),
            },
        );

        let p = Packet::Handshake {
            ephemeral_key: pair.public_key.as_ref().into(),
            session_id: session_id,
            from: self.uuid,
        };

        let ps = serde_json::to_string(&p)?;

        stream.write(ps.as_bytes())?;
        stream.shutdown(Shutdown::Both)?;

        Ok(())
    }

    pub fn get_session_for_uuid(&mut self, id: Uuid) -> Option<Session> {
        self.session_keys.get(&id).cloned()
    }
}

impl Session {
    pub fn generate_message_packet(&self, message: Box<[u8]>, self_uuid: Uuid) -> GResult<Packet> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes).unwrap();

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.session_key).unwrap();

        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::empty();

        let mut message = message.to_vec();

        key.seal_in_place_append_tag(nonce, aad, &mut message)
            .unwrap();

        Ok(Packet::Message {
            to: self.device_id,
            from: self_uuid,
            payload: message.into_boxed_slice(),
            nonce: nonce_bytes,
        })
    }
}
