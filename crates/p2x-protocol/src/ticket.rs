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
fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], TicketError> {
    let end = p.checked_add(n).ok_or(TicketError::Invalid)?;
    let v = b.get(*p..end).ok_or(TicketError::Invalid)?;
    *p = end;
    Ok(v)
}
fn u16v(b: &[u8], p: &mut usize) -> Result<u16, TicketError> {
    Ok(u16::from_be_bytes(
        take(b, p, 2)?
            .try_into()
            .map_err(|_| TicketError::Invalid)?,
    ))
}
fn u64v(b: &[u8], p: &mut usize) -> Result<u64, TicketError> {
    Ok(u64::from_be_bytes(
        take(b, p, 8)?
            .try_into()
            .map_err(|_| TicketError::Invalid)?,
    ))
}
fn i64v(b: &[u8], p: &mut usize) -> Result<i64, TicketError> {
    Ok(i64::from_be_bytes(
        take(b, p, 8)?
            .try_into()
            .map_err(|_| TicketError::Invalid)?,
    ))
}
fn bytes(b: &[u8], p: &mut usize) -> Result<Vec<u8>, TicketError> {
    let n = take(b, p, 1)?[0] as usize;
    Ok(take(b, p, n)?.to_vec())
}
fn text(b: &[u8], p: &mut usize) -> Result<String, TicketError> {
    let n = u16v(b, p)? as usize;
    String::from_utf8(take(b, p, n)?.to_vec()).map_err(|_| TicketError::Invalid)
}
fn put_bytes(o: &mut Vec<u8>, v: &[u8]) -> Result<(), TicketError> {
    if v.len() > u8::MAX as usize {
        return Err(TicketError::Invalid);
    }
    o.push(v.len() as u8);
    o.extend_from_slice(v);
    Ok(())
}
fn put_text(o: &mut Vec<u8>, v: &str) -> Result<(), TicketError> {
    if v.len() > u16::MAX as usize {
        return Err(TicketError::Invalid);
    }
    o.extend_from_slice(&(v.len() as u16).to_be_bytes());
    o.extend_from_slice(v.as_bytes());
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
        let mut o = Vec::new();
        o.extend_from_slice(&1u16.to_be_bytes());
        put_bytes(&mut o, &self.issuer_exchange_peer_id)?;
        put_text(&mut o, &self.tenant)?;
        put_bytes(&mut o, &self.client_peer_id)?;
        put_bytes(&mut o, &self.server_peer_id)?;
        put_text(&mut o, &self.upstream_id)?;
        o.extend_from_slice(&self.selector_fingerprint);
        o.extend_from_slice(&self.registration_revision.to_be_bytes());
        o.extend_from_slice(&self.authorization_revision.to_be_bytes());
        o.extend_from_slice(&self.permissions.to_be_bytes());
        o.extend_from_slice(&self.not_before.to_be_bytes());
        o.extend_from_slice(&self.expires_at.to_be_bytes());
        o.extend_from_slice(&self.ticket_id);
        o.extend_from_slice(&self.max_streams.to_be_bytes());
        if o.len() > MAX_TICKET_CLAIMS {
            Err(TicketError::TooLarge)
        } else {
            Ok(o)
        }
    }
    pub fn decode(b: &[u8]) -> Result<Self, TicketError> {
        if b.len() > MAX_TICKET_CLAIMS {
            return Err(TicketError::TooLarge);
        }
        let mut p = 0;
        if u16v(b, &mut p)? != 1 {
            return Err(TicketError::Invalid);
        }
        let issuer = bytes(b, &mut p)?;
        let tenant = text(b, &mut p)?;
        let client = bytes(b, &mut p)?;
        let server = bytes(b, &mut p)?;
        let upstream = text(b, &mut p)?;
        let selector = take(b, &mut p, 32)?
            .try_into()
            .map_err(|_| TicketError::Invalid)?;
        let registration_revision = u64v(b, &mut p)?;
        let authorization_revision = u64v(b, &mut p)?;
        let permissions = u32::from_be_bytes(
            take(b, &mut p, 4)?
                .try_into()
                .map_err(|_| TicketError::Invalid)?,
        );
        let not_before = i64v(b, &mut p)?;
        let expires_at = i64v(b, &mut p)?;
        let ticket_id = take(b, &mut p, 16)?
            .try_into()
            .map_err(|_| TicketError::Invalid)?;
        let max_streams = u16v(b, &mut p)?;
        if p != b.len() {
            return Err(TicketError::Invalid);
        }
        let c = Self {
            issuer_exchange_peer_id: issuer,
            tenant,
            client_peer_id: client,
            server_peer_id: server,
            upstream_id: upstream,
            selector_fingerprint: selector,
            registration_revision,
            authorization_revision,
            permissions,
            not_before,
            expires_at,
            ticket_id,
            max_streams,
        };
        if c.encode()? != b {
            return Err(TicketError::Invalid);
        }
        Ok(c)
    }
}
pub struct TicketSigner {
    key: SigningKey,
    pub key_id: [u8; 16],
}
impl TicketSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let d = Sha256::digest(key.verifying_key().as_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&d[..16]);
        Self { key, key_id: id }
    }
    pub fn sign(&self, c: &ConnectionTicketClaimsV1) -> Result<Vec<u8>, TicketError> {
        let c = c.encode()?;
        let mut m = b"p2x-ticket-v1\0".to_vec();
        m.extend_from_slice(&(c.len() as u16).to_be_bytes());
        m.extend_from_slice(&c);
        let sig = self.key.sign(&m);
        let mut o = b"P2XT".to_vec();
        o.extend_from_slice(&[1, 16]);
        o.extend_from_slice(&self.key_id);
        o.extend_from_slice(&(c.len() as u16).to_be_bytes());
        o.extend_from_slice(&c);
        o.extend_from_slice(&sig.to_bytes());
        if o.len() > MAX_TICKET_ENVELOPE {
            Err(TicketError::TooLarge)
        } else {
            Ok(o)
        }
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}
pub fn decode_envelope(
    e: &[u8],
) -> Result<([u8; 16], ConnectionTicketClaimsV1, Signature), TicketError> {
    if e.len() > MAX_TICKET_ENVELOPE
        || e.len() < 88
        || &e[..4] != b"P2XT"
        || e[4] != 1
        || e[5] != 16
    {
        return Err(TicketError::Invalid);
    }
    let id = e[6..22].try_into().map_err(|_| TicketError::Invalid)?;
    let n = u16::from_be_bytes([e[22], e[23]]) as usize;
    if e.len() != 24 + n + 64 {
        return Err(TicketError::Invalid);
    }
    let c = ConnectionTicketClaimsV1::decode(&e[24..24 + n])?;
    let sig = Signature::from_slice(&e[24 + n..]).map_err(|_| TicketError::Invalid)?;
    Ok((id, c, sig))
}
pub fn verify_envelope(e: &[u8], key_id: [u8; 16], key: &VerifyingKey) -> Result<(), TicketError> {
    let (id, c, sig) = decode_envelope(e)?;
    if id != key_id {
        return Err(TicketError::Invalid);
    }
    let bytes = c.encode()?;
    let mut m = b"p2x-ticket-v1\0".to_vec();
    m.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    m.extend_from_slice(&bytes);
    key.verify(&m, &sig).map_err(|_| TicketError::Invalid)
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
    fn decode_is_canonical() {
        let c = claims();
        assert_eq!(
            ConnectionTicketClaimsV1::decode(&c.encode().unwrap()).unwrap(),
            c
        )
    }
    #[test]
    fn vector_and_mutation() {
        let s = TicketSigner::from_seed([9; 32]);
        let t = s.sign(&claims()).unwrap();
        verify_envelope(&t, s.key_id, &s.public_key()).unwrap();
        let mut x = t.clone();
        *x.last_mut().unwrap() ^= 1;
        assert!(verify_envelope(&x, s.key_id, &s.public_key()).is_err());
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/ticket-v1.json")).unwrap();
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(h(&t), v["envelope_hex"]);
        assert_eq!(h(&s.key_id), v["key_id_hex"]);
    }
}
