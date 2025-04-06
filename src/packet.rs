use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Packet {
    Handshake {
        ephemeral_key: Box<[u8]>,
        from: Uuid,
    },

    Message {
        to: Uuid,
        from: Uuid,

        payload: Box<[u8]>,
        nonce: [u8; 12],
    },

    #[default]
    Invalid,
}
