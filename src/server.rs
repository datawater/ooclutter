use crate::crypto::{self, EphemeralPair};
use crate::packet::{JsonPacketCodec, Packet};
use crate::utils::GResult;

use futures_util::SinkExt;
use tokio_stream::StreamExt;

use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, UnparsedPublicKey, X25519};
use ring::rand::{self, SecureRandom, SystemRandom};
use uuid::Uuid;

use dashmap::DashMap;

use std::sync::Arc;

type KDFFn = fn(&[u8]) -> [u8; 32];
type MessageCallbackFn = fn(&mut Server, &mut Packet);

#[derive(Debug, Clone)]
pub struct Session {
    device_ip: SocketAddr,
    device_id: Uuid,
    pub session_key: [u8; 32],
}

#[derive(Debug)]
pub struct ServerConfig {
    port_to_run_on: u16,
    kdf: KDFFn,
    uuid: Uuid,
    message_callback: MessageCallbackFn,
}

#[derive(Debug, Clone)]
pub struct Server {
    config: Arc<ServerConfig>,
    pub session_keys: Arc<DashMap<Uuid, Session>>,
}

unsafe impl Send for Session {}
unsafe impl Sync for Session {}
unsafe impl Send for Server {}
unsafe impl Sync for Server {}

impl Server {
    pub fn new(
        port_to_run_on: u16,
        kdf: Option<KDFFn>,
        message_callback: Option<MessageCallbackFn>,
    ) -> Self {
        let config = ServerConfig {
            port_to_run_on,
            kdf: kdf.unwrap_or(crypto::hkdf_sha256),
            uuid: uuid::Uuid::new_v4(),
            message_callback: message_callback.unwrap_or(Self::default_msg_callback),
        };

        Self {
            config: Arc::new(config),
            session_keys: Arc::new(DashMap::new()),
        }
    }

    fn default_msg_callback(&mut self, _pack: &mut Packet) {}

    pub async fn run(self) -> GResult<()> {
        let addr = format!("127.0.0.1:{}", self.config.port_to_run_on);
        let listener = TcpListener::bind(&addr).await?;

        loop {
            let (stream, addr) = listener.accept().await?;

            let mut framed = Framed::new(stream, super::packet::JsonPacketCodec);
            let mut server = self.clone();

            tokio::spawn(async move {
                while let Some(mut packet) = framed.next().await.unwrap_or(Err("".into())).ok() {
                    match &packet {
                        Packet::Handshake { .. } => {
                            server
                                .handle_handshake(packet, &mut framed, addr)
                                .await
                                .unwrap();
                        }
                        Packet::Message { .. } => {
                            (server.config.message_callback)(&mut server, &mut packet);
                        }
                        Packet::Invalid => {}
                    }
                }
            });
        }
    }

    async fn handle_handshake(
        &mut self,
        packet: Packet,
        stream: &mut Framed<TcpStream, JsonPacketCodec>,
        addr: SocketAddr,
    ) -> GResult<()> {
        let Packet::Handshake {
            ephemeral_key,
            from,
        } = packet
        else {
            return Err("Not a handshake packet".into());
        };

        let rng = rand::SystemRandom::new();
        let pair = EphemeralPair::generate(&rng)?;

        let kdf = self.config.kdf;

        let session_key: [u8; 32] = tokio::task::spawn_blocking(move || {
            agreement::agree_ephemeral(
                pair.private_key,
                &UnparsedPublicKey::new(&X25519, &ephemeral_key),
                kdf,
            )
            .map(|k| *k.as_array().unwrap())
        })
        .await??;

        self.session_keys.insert(
            from,
            Session {
                device_id: from,
                device_ip: addr,
                session_key: *session_key.as_array().unwrap(),
            },
        );

        let p = Packet::Handshake {
            ephemeral_key: pair.public_key.as_ref().into(),
            from: self.config.uuid,
        };

        stream.send(p).await?;

        Ok(())
    }

    pub fn get_session_for_uuid(
        &self,
        id: Uuid,
    ) -> Option<dashmap::mapref::one::Ref<Uuid, Session>> {
        self.session_keys.get(&id)
    }
}

impl Session {
    pub fn generate_message_packet(&self, message: &[u8], self_uuid: Uuid) -> GResult<Packet> {
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
