use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_TICKET_CLAIMS: usize = 1024;
pub const MAX_TICKET_ENVELOPE: usize = 2048;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionTicketClaimsV1 {
    pub issuer_exchange_peer_id: Vec<u8>,
    pub tenant: String,
    pub client_peer_id: Vec<u8>,
    pub server_peer_id: Vec<u8>,
    pub upstream_id: String,
    pub selector_fingerprint: [u8; 32],
    pub registration_revision: u64,
    pub authorization_revision: u64,
    pub permissions: u32,
    pub not_before: i64,
    pub expires_at: i64,
    pub ticket_id: [u8; 16],
    pub max_streams: u16,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TicketError {
    #[error("invalid ticket")]
    Invalid,
    #[error("ticket exceeds bound")]
    TooLarge,
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TicketError> {
    if bytes.len() > u8::MAX as usize {
        return Err(TicketError::Invalid);
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    Ok(())
}
fn put_text(out: &mut Vec<u8>, text: &str) -> Result<(), TicketError> {
    if text.len() > u16::MAX as usize {
        return Err(TicketError::Invalid);
    }
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}
impl ConnectionTicketClaimsV1 {
    pub fn encode(&self) -> Result<Vec<u8>, TicketError> {
        if self.issuer_exchange_peer_id.is_empty()
            || self.client_peer_id.is_empty()
            || self.server_peer_id.is_empty()
            || self.not_before > self.expires_at
            || self.expires_at - self.not_before > 60
            || self.permissions != 4
            || self.max_streams != 1
        {
            return Err(TicketError::Invalid);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&1u16.to_be_bytes());
        put_bytes(&mut out, &self.issuer_exchange_peer_id)?;
        put_text(&mut out, &self.tenant)?;
        put_bytes(&mut out, &self.client_peer_id)?;
        put_bytes(&mut out, &self.server_peer_id)?;
        put_text(&mut out, &self.upstream_id)?;
        out.extend_from_slice(&self.selector_fingerprint);
        out.extend_from_slice(&self.registration_revision.to_be_bytes());
        out.extend_from_slice(&self.authorization_revision.to_be_bytes());
        out.extend_from_slice(&self.permissions.to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.ticket_id);
        out.extend_from_slice(&self.max_streams.to_be_bytes());
        if out.len() > MAX_TICKET_CLAIMS {
            return Err(TicketError::TooLarge);
        }
        Ok(out)
    }
}
pub struct TicketSigner {
    key: SigningKey,
    pub key_id: [u8; 16],
}
impl TicketSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let digest = Sha256::digest(key.verifying_key().as_bytes());
        let mut key_id = [0; 16];
        key_id.copy_from_slice(&digest[..16]);
        Self { key, key_id }
    }
    pub fn sign(&self, claims: &ConnectionTicketClaimsV1) -> Result<Vec<u8>, TicketError> {
        let claims = claims.encode()?;
        let mut message = b"p2x-ticket-v1\0".to_vec();
        message.extend_from_slice(&(claims.len() as u16).to_be_bytes());
        message.extend_from_slice(&claims);
        let signature = self.key.sign(&message);
        let mut out = b"P2XT".to_vec();
        out.push(1);
        out.push(16);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&(claims.len() as u16).to_be_bytes());
        out.extend_from_slice(&claims);
        out.extend_from_slice(&signature.to_bytes());
        if out.len() > MAX_TICKET_ENVELOPE {
            return Err(TicketError::TooLarge);
        }
        Ok(out)
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}
pub fn verify_envelope(
    envelope: &[u8],
    key_id: [u8; 16],
    key: &VerifyingKey,
) -> Result<(), TicketError> {
    if envelope.len() > MAX_TICKET_ENVELOPE
        || envelope.len() < 4 + 1 + 1 + 16 + 2 + 64
        || &envelope[..4] != b"P2XT"
        || envelope[4] != 1
        || envelope[5] != 16
        || envelope[6..22] != key_id
    {
        return Err(TicketError::Invalid);
    }
    let len = u16::from_be_bytes([envelope[22], envelope[23]]) as usize;
    if len > MAX_TICKET_CLAIMS || envelope.len() != 24 + len + 64 {
        return Err(TicketError::Invalid);
    }
    let mut message = b"p2x-ticket-v1\0".to_vec();
    message.extend_from_slice(&(len as u16).to_be_bytes());
    message.extend_from_slice(&envelope[24..24 + len]);
    let signature =
        Signature::from_slice(&envelope[24 + len..]).map_err(|_| TicketError::Invalid)?;
    key.verify(&message, &signature)
        .map_err(|_| TicketError::Invalid)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn claims() -> ConnectionTicketClaimsV1 {
        ConnectionTicketClaimsV1 {
            issuer_exchange_peer_id: vec![1],
            tenant: "t".into(),
            client_peer_id: vec![2],
            server_peer_id: vec![3],
            upstream_id: "u".into(),
            selector_fingerprint: [4; 32],
            registration_revision: 1,
            authorization_revision: 2,
            permissions: 4,
            not_before: 10,
            expires_at: 20,
            ticket_id: [5; 16],
            max_streams: 1,
        }
    }
    #[test]
    fn committed_vector_reproduces_exact_bytes() {
        let c = claims();
        let signer = TicketSigner::from_seed([9; 32]);
        let encoded = c.encode().unwrap();
        let ticket = signer.sign(&c).unwrap();
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/ticket-v1.json")).unwrap();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(hex(&encoded), vector["claims_hex"]);
        assert_eq!(hex(&ticket), vector["envelope_hex"]);
        assert_eq!(hex(&signer.key_id), vector["key_id_hex"]);
    }

    #[test]
    fn signs_and_rejects_mutation() {
        let signer = TicketSigner::from_seed([9; 32]);
        let ticket = signer.sign(&claims()).unwrap();
        verify_envelope(&ticket, signer.key_id, &signer.public_key()).unwrap();
        let mut changed = ticket;
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify_envelope(&changed, signer.key_id, &signer.public_key()).is_err());
    }
}
