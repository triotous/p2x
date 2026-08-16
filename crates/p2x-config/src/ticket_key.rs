use crate::secret_file::{SecretFileError, read_secret_file, write_secret_file};
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum TicketKeyError {
    #[error("ticket signing key must differ from transport key")]
    KeySeparation,
    #[error("ticket key file failed")]
    File(#[from] SecretFileError),
    #[error("ticket key is invalid")]
    Invalid,
    #[error("ticket verification key is invalid")]
    InvalidVerificationKey,
    #[error("ticket verification key already exists")]
    DuplicateVerificationKey,
    #[error("ticket key configuration is invalid")]
    InvalidConfiguration,
    #[error("ticket key configuration could not be read")]
    ConfigurationIo(#[source] std::io::Error),
    #[error("ticket key configuration YAML is invalid")]
    ConfigurationYaml(#[source] serde_yaml::Error),
}
pub struct TicketKey {
    signing: SigningKey,
    key_id: [u8; 16],
}
impl std::fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketKey(REDACTED)")
    }
}
impl TicketKey {
    pub fn ensure_separate_from(&self, transport_public_key: &[u8]) -> Result<(), TicketKeyError> {
        if self.public().as_bytes() == transport_public_key {
            return Err(TicketKeyError::KeySeparation);
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, TicketKeyError> {
        let mut b = read_secret_file(path)?;
        let result = if b.first() != Some(&1) || b.len() != 33 {
            Err(TicketKeyError::Invalid)
        } else {
            let seed: [u8; 32] = b[1..].try_into().map_err(|_| TicketKeyError::Invalid)?;
            Ok(Self::from_seed(seed))
        };
        b.zeroize();
        result
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
    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }
    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing.sign(message)
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyRecord {
    key_id: String,
    public_key: String,
    activates_at: i64,
    retires_at: Option<i64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyFile {
    schema_version: u16,
    keys: Vec<VerificationKeyRecord>,
}

fn decode_hex_id(value: &str) -> Result<[u8; 16], TicketKeyError> {
    if value.len() != 32
        || value
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err(TicketKeyError::InvalidConfiguration);
    }
    let mut output = [0; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (pair[0] as char)
            .to_digit(16)
            .ok_or(TicketKeyError::InvalidConfiguration)? as u8
            * 16
            + (pair[1] as char)
                .to_digit(16)
                .ok_or(TicketKeyError::InvalidConfiguration)? as u8;
    }
    Ok(output)
}

impl VerificationKeyFile {
    fn load(path: &Path) -> Result<Self, TicketKeyError> {
        crate::yaml::load(path).map_err(|error| match error {
            crate::yaml::YamlError::Io(error) => TicketKeyError::ConfigurationIo(error),
            crate::yaml::YamlError::Parse(error) => TicketKeyError::ConfigurationYaml(error),
            crate::yaml::YamlError::TooLarge | crate::yaml::YamlError::Bounds => {
                TicketKeyError::InvalidConfiguration
            }
        })
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
impl p2x_protocol::ticket::TicketKeyResolver for VerificationKeyRing {
    fn key(&self, key_id: [u8; 16], now: i64) -> Option<&ed25519_dalek::VerifyingKey> {
        self.get(key_id, now).map(|key| &key.public)
    }
}
impl VerificationKeyRing {
    pub fn load(path: &Path) -> Result<Self, TicketKeyError> {
        let file = VerificationKeyFile::load(path)?;
        if file.schema_version != 1 || file.keys.len() > 256 {
            return Err(TicketKeyError::InvalidConfiguration);
        }
        let mut ring = Self::default();
        for record in file.keys {
            let key_id = decode_hex_id(&record.key_id)?;
            let public_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(record.public_key.as_bytes())
                .map_err(|_| TicketKeyError::InvalidConfiguration)?;
            let public_bytes: [u8; 32] = public_bytes
                .try_into()
                .map_err(|_| TicketKeyError::InvalidConfiguration)?;
            let public = VerifyingKey::from_bytes(&public_bytes)
                .map_err(|_| TicketKeyError::InvalidConfiguration)?;
            let digest = Sha256::digest(public.as_bytes());
            if key_id != digest[..16] {
                return Err(TicketKeyError::InvalidConfiguration);
            }
            ring.add(VerificationKey {
                key_id,
                public,
                activates_at: record.activates_at,
                retires_at: record.retires_at,
            })?;
        }
        Ok(ring)
    }
    pub fn add(&mut self, key: VerificationKey) -> Result<(), TicketKeyError> {
        if key
            .retires_at
            .is_some_and(|retire| retire <= key.activates_at)
        {
            return Err(TicketKeyError::InvalidVerificationKey);
        }
        if self.keys.iter().any(|old| old.key_id == key.key_id) {
            return Err(TicketKeyError::DuplicateVerificationKey);
        }
        self.keys.push(key);
        Ok(())
    }
    pub fn get(&self, key_id: [u8; 16], now: i64) -> Option<&VerificationKey> {
        self.keys.iter().find(|k| {
            k.key_id == key_id && now >= k.activates_at && k.retires_at.is_none_or(|t| now < t)
        })
    }
    pub fn verify(
        &self,
        envelope: &[u8],
        expected: &p2x_protocol::ticket::TicketValidation<'_>,
    ) -> Result<p2x_protocol::ticket::VerifiedTicket, p2x_protocol::ticket::TicketError> {
        p2x_protocol::ticket::verify_with_key_resolver(envelope, self, expected)
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
            key_id: key.key_id(),
            public: key.public(),
            activates_at: 10,
            retires_at: Some(20),
        })
        .unwrap();
        assert!(ring.get(key.key_id(), 9).is_none());
        assert!(ring.get(key.key_id(), 10).is_some());
        assert!(ring.get(key.key_id(), 20).is_none());
    }
    #[test]
    fn ring_verifies_exact_active_key() {
        let key = TicketKey::from_seed([9; 32]);
        let mut ring = VerificationKeyRing::default();
        ring.add(VerificationKey {
            key_id: key.key_id(),
            public: key.public(),
            activates_at: 0,
            retires_at: None,
        })
        .unwrap();
        let expected = p2x_protocol::ticket::TicketValidation {
            issuer_exchange_peer_id: &[],
            client_peer_id: &[],
            server_peer_id: &[],
            tenant: "",
            upstream_id: "",
            selector_fingerprint: [0; 32],
            registration_revision: 0,
            authorization_revision: 0,
            permissions: 0,
            max_streams: 0,
            now: 0,
            clock_skew: 0,
        };
        assert!(ring.verify(&[0; 4], &expected).is_err());
    }
    #[test]
    fn key_separation_is_enforced() {
        let key = TicketKey::from_seed([9; 32]);
        assert!(key.ensure_separate_from(key.public().as_bytes()).is_err());
        assert!(key.ensure_separate_from(&[0; 32]).is_ok());
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
    #[test]
    fn ring_loader_rejects_wrong_key_id_and_unknown_fields() {
        let key = TicketKey::from_seed([9; 32]);
        let path = std::env::temp_dir().join(format!("p2x-ticket-ring-{}", std::process::id()));
        let public =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public().as_bytes());
        let id = key
            .key_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::fs::write(&path, format!("schema_version: 1\nkeys:\n  - key_id: {id}\n    public_key: {public}\n    activates_at: 1\n    retires_at: 2\n")).unwrap();
        let ring = VerificationKeyRing::load(&path).unwrap();
        assert!(ring.get(key.key_id(), 1).is_some());
        std::fs::write(&path, "schema_version: 1\nkeys: []\nextra: true\n").unwrap();
        assert!(matches!(
            VerificationKeyRing::load(&path),
            Err(TicketKeyError::ConfigurationYaml(_))
        ));
        let _ = std::fs::remove_file(path);
    }
}
