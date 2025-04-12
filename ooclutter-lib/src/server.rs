use crate::crypto::{self, EphemeralPair};
use crate::packet::{ErrorType, JsonPacketCodec, Packet};
use crate::utils::{self, GResult};

use futures_util::SinkExt;
use tokio_stream::StreamExt;

use std::net::SocketAddr;
use tokio::net::{TcpSocket, TcpStream};
use tokio_util::codec::Framed;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, UnparsedPublicKey, X25519};
use ring::rand::{self, SecureRandom, SystemRandom};
use uuid::Uuid;

use dashmap::DashMap;

use std::sync::Arc;

type KDFFn = fn(&[u8]) -> [u8; 32];
type ActualMessageCallbackFn = fn(&[u8]);

#[derive(Debug, Clone)]
pub struct Session {
    pub device_ip: SocketAddr,
    pub device_id: Uuid,
    pub session_key: [u8; 32],
}

pub struct ServerConfig {
    pub port_to_run_on: u16,
    kdf: KDFFn,
    pub uuid: Uuid,
    message_callback: ActualMessageCallbackFn,
}

#[derive(Clone)]
pub struct Server {
    pub config: Arc<ServerConfig>,
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
        message_callback: ActualMessageCallbackFn,
    ) -> Self {
        let config = ServerConfig {
            port_to_run_on,
            kdf: kdf.unwrap_or(crypto::hkdf_sha256),
            uuid: uuid::Uuid::new_v4(),
            message_callback,
        };

        Self {
            config: Arc::new(config),
            session_keys: Arc::new(DashMap::new()),
        }
    }

    pub async fn run(&mut self) -> GResult<()> {
        log::info!("Running on port {}", self.config.port_to_run_on);

        let addr = format!("0.0.0.0:{}", self.config.port_to_run_on).parse()?;

        let socket = TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.set_reuseport(true)?;
        socket.set_nodelay(true)?;
        socket.bind(addr)?;
        let listener = socket.listen(4096)?;

        loop {
            let (stream, addr) = listener.accept().await?;

            let mut framed = Framed::new(stream, super::packet::JsonPacketCodec);
            let mut server = self.clone();

            tokio::spawn(async move {
                // hacky fix because dyn StdErr can not be shared through threads safely
                #[allow(clippy::match_result_ok)]
                while let Some(packet) = framed.next().await.unwrap_or(Err("".into())).ok() {
                    match &packet {
                        Packet::Handshake { .. } => {
                            let e = server.handle_handshake(packet, &mut framed, addr).await;

                            if e.is_err() {
                                log::error!("Error handling handshake {}", unsafe {
                                    e.err().unwrap_unchecked()
                                });
                            }
                        }

                        Packet::Message { .. } => {
                            let err = server.handle_message(&mut framed, &packet).await;
                            if err.is_err() {
                                log::error!("Error sending back error {}", unsafe {
                                    err.err().unwrap_unchecked()
                                });
                                continue;
                            }
                            let err = unsafe { err.unwrap_unchecked() };

                            if err.is_some() {
                                let err = framed.send(unsafe { err.unwrap_unchecked() }).await;

                                if err.is_err() {
                                    log::error!("Error sending back error {}", unsafe {
                                        err.err().unwrap_unchecked()
                                    });
                                }
                            }
                        }

                        Packet::Ping => {
                            if let Err(e) = framed.send(Packet::Ack).await {
                                log::error!("Error sending ACK: {e}");
                                break;
                            }
                        }

                        Packet::Ack | Packet::Error { type_: _ } => {}

                        Packet::Invalid => {
                            log::warn!("[ERROR/WARN] Invalid packet recieved from: {addr:?}");
                            break;
                        }
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
        })
        .await??;

        self.session_keys.insert(
            from,
            Session {
                device_id: from,
                device_ip: addr,
                session_key,
            },
        );

        let p = Packet::Handshake {
            ephemeral_key: pair.public_key.as_ref().into(),
            from: self.config.uuid,
        };

        // I need to find a way to handle this error
        let _ = stream.send(p).await;
        Ok(())
    }

    async fn handle_message(
        &self,
        stream: &mut Framed<TcpStream, JsonPacketCodec>,
        packet: &Packet,
    ) -> GResult<Option<Packet>> {
        log::debug!("Recieved message packet: {packet:?}");

        let Packet::Message {
            to,
            from,
            payload,
            nonce,
        } = packet
        else {
            unreachable!()
        };

        if *to != self.config.uuid {
            let to_session = self.session_keys.get(to);
            match to_session {
                Some(s) => {
                    // TODO: Proper routing
                    let _ = utils::send_packet_to_ip(s.device_ip, packet.clone()).await;

                    return Ok(None);
                }

                None => {
                    let x = stream
                        .send(Packet::Error {
                            type_: ErrorType::CannotDeliverMessage,
                        })
                        .await;

                    if x.is_err() {
                        log::error!("{}", unsafe { x.err().unwrap_unchecked() });
                        return Ok(None);
                    }
                }
            }
        }

        let from_session = self.session_keys.get(from);

        if from_session.is_none() {
            return Ok(Some(Packet::Error {
                type_: ErrorType::WhoRU,
            }));
        }
        let session = unsafe { from_session.unwrap_unchecked() };

        let unbound_key = UnboundKey::new(&AES_256_GCM, &session.session_key)?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);

        let aad = Aad::empty();

        let mut payload = payload.clone();
        let plaintext = key.open_in_place(nonce, aad, &mut payload)?;

        (self.config.message_callback)(plaintext);

        Ok(None)
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
        rng.fill(&mut nonce_bytes)?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.session_key)?;

        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::empty();

        let mut message = message.to_vec();

        key.seal_in_place_append_tag(nonce, aad, &mut message)?;

        Ok(Packet::Message {
            to: self.device_id,
            from: self_uuid,
            payload: message.into_boxed_slice(),
            nonce: nonce_bytes,
        })
    }

    pub async fn send_packet(&self, packet: Packet) -> GResult<()> {
        utils::send_packet_to_ip(self.device_ip, packet).await
    }
}
