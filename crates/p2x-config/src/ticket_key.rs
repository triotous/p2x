use crate::secret_file::{SecretFileError, read_secret_file, write_secret_file};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TicketKeyError {
    #[error("ticket key file failed")]
    File(#[from] SecretFileError),
    #[error("ticket key must contain exactly 32 bytes")]
    Invalid,
}
pub struct TicketKey {
    pub signing: SigningKey,
    pub key_id: [u8; 16],
}
impl std::fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketKey(REDACTED)")
    }
}
impl TicketKey {
    pub fn load(path: &Path) -> Result<Self, TicketKeyError> {
        let b = read_secret_file(path)?;
        if b.first() != Some(&1) || b.len() != 33 {
            return Err(TicketKeyError::Invalid);
        }
        let seed: [u8; 32] = b[1..].try_into().map_err(|_| TicketKeyError::Invalid)?;
        Ok(Self::from_seed(seed))
    }
    pub fn create(path: &Path) -> Result<Self, TicketKeyError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| TicketKeyError::Invalid)?;
        let key = Self::from_seed(seed);
        let mut file = Vec::with_capacity(33);
        file.push(1);
        file.extend_from_slice(&seed);
        write_secret_file(path, &file)?;
        Ok(key)
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let digest = Sha256::digest(signing.verifying_key().as_bytes());
        let mut key_id = [0; 16];
        key_id.copy_from_slice(&digest[..16]);
        Self { signing, key_id }
    }
    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}
#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub key_id: [u8; 16],
    pub public: VerifyingKey,
    pub activates_at: i64,
    pub retires_at: Option<i64>,
}
#[derive(Default, Debug)]
pub struct VerificationKeyRing {
    keys: Vec<VerificationKey>,
}
impl VerificationKeyRing {
    pub fn add(&mut self, key: VerificationKey) {
        assert!(
            key.retires_at
                .is_none_or(|retire| retire > key.activates_at)
        );
        assert!(!self.keys.iter().any(|old| old.key_id == key.key_id));
        self.keys.push(key)
    }
    pub fn get(&self, key_id: [u8; 16], now: i64) -> Option<&VerificationKey> {
        self.keys.iter().find(|k| {
            k.key_id == key_id && now >= k.activates_at && k.retires_at.is_none_or(|t| now < t)
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_observes_activation_and_retirement() {
        let key = TicketKey::from_seed([9; 32]);
        let mut ring = VerificationKeyRing::default();
        ring.add(VerificationKey {
            key_id: key.key_id,
            public: key.public(),
            activates_at: 10,
            retires_at: Some(20),
        });
        assert!(ring.get(key.key_id, 9).is_none());
        assert!(ring.get(key.key_id, 10).is_some());
        assert!(ring.get(key.key_id, 20).is_none());
    }
    #[test]
    fn key_id_is_stable_and_debug_redacts() {
        let k = TicketKey::from_seed([9; 32]);
        assert_eq!(
            k.key_id,
            [
                0xdb, 0xc2, 0x98, 0x25, 0x1c, 0x51, 0x32, 0x1b, 0x72, 0x66, 0xe7, 0x8d, 0x1c, 0x15,
                0x1c, 0x2b
            ]
        );
        assert!(format!("{k:?}").contains("REDACTED"));
    }
}
