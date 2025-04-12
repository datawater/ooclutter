use ring::agreement::{self, Algorithm, EphemeralPrivateKey, PublicKey};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand;

use crate::utils::GResult;

#[derive(Debug)]
pub struct EphemeralPair {
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey,
    pub algorithm: &'static Algorithm,
}

pub fn hkdf_sha256(shared_secret: &[u8]) -> [u8; 32] {
    let salt = Salt::new(HKDF_SHA256, b"OOCLUTTER-SALT-123456789");
    let prk = salt.extract(shared_secret);

    let context = &["".as_bytes()];
    let okm = prk.expand(context, HKDF_SHA256).unwrap();

    let mut result = [0u8; SHA256_OUTPUT_LEN];
    okm.fill(&mut result).unwrap();

    result
}

impl EphemeralPair {
    pub fn generate(rng: &dyn rand::SecureRandom) -> GResult<Self> {
        let private_key = EphemeralPrivateKey::generate(&agreement::X25519, rng).unwrap();
        let public_key = private_key.compute_public_key().unwrap();

        Ok(Self {
            private_key,
            public_key,
            algorithm: &agreement::X25519,
        })
    }
}
