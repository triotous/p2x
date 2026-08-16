use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_TICKET_CLAIMS: usize = 1024;
pub const MAX_TICKET_ENVELOPE: usize = 2048;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionTicketClaimsV1 {
    issuer_exchange_peer_id: Vec<u8>,
    tenant: String,
    client_peer_id: Vec<u8>,
    server_peer_id: Vec<u8>,
    upstream_id: String,
    selector_fingerprint: [u8; 32],
    registration_revision: u64,
    authorization_revision: u64,
    permissions: u32,
    not_before: i64,
    expires_at: i64,
    ticket_id: [u8; 16],
    max_streams: u16,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TicketError {
    #[error("invalid ticket")]
    Invalid,
    #[error("ticket expired")]
    Expired,
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
fn validate_peer(bytes: &[u8]) -> Result<(), TicketError> {
    libp2p_identity::PeerId::from_bytes(bytes)
        .map(|_| ())
        .map_err(|_| TicketError::Invalid)
}
fn validate_identifier(value: &str) -> Result<(), TicketError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(TicketError::Invalid);
    }
    Ok(())
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_exchange_peer_id: Vec<u8>,
        tenant: String,
        client_peer_id: Vec<u8>,
        server_peer_id: Vec<u8>,
        upstream_id: String,
        selector_fingerprint: [u8; 32],
        registration_revision: u64,
        authorization_revision: u64,
        permissions: u32,
        not_before: i64,
        expires_at: i64,
        ticket_id: [u8; 16],
        max_streams: u16,
    ) -> Result<Self, TicketError> {
        let claims = Self {
            issuer_exchange_peer_id,
            tenant,
            client_peer_id,
            server_peer_id,
            upstream_id,
            selector_fingerprint,
            registration_revision,
            authorization_revision,
            permissions,
            not_before,
            expires_at,
            ticket_id,
            max_streams,
        };
        claims.encode().map(|_| claims)
    }
    pub fn issuer_exchange_peer_id(&self) -> &[u8] {
        &self.issuer_exchange_peer_id
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn client_peer_id(&self) -> &[u8] {
        &self.client_peer_id
    }
    pub fn server_peer_id(&self) -> &[u8] {
        &self.server_peer_id
    }
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }
    pub fn selector_fingerprint(&self) -> [u8; 32] {
        self.selector_fingerprint
    }
    pub fn registration_revision(&self) -> u64 {
        self.registration_revision
    }
    pub fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }
    pub fn permissions(&self) -> u32 {
        self.permissions
    }
    pub fn not_before(&self) -> i64 {
        self.not_before
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn ticket_id(&self) -> [u8; 16] {
        self.ticket_id
    }
    pub fn max_streams(&self) -> u16 {
        self.max_streams
    }
    pub fn encode(&self) -> Result<Vec<u8>, TicketError> {
        validate_peer(&self.issuer_exchange_peer_id)?;
        validate_peer(&self.client_peer_id)?;
        validate_peer(&self.server_peer_id)?;
        if self.issuer_exchange_peer_id.is_empty()
            || self.client_peer_id.is_empty()
            || self.server_peer_id.is_empty()
            || validate_identifier(&self.tenant).is_err()
            || validate_identifier(&self.upstream_id).is_err()
            || self.not_before > self.expires_at
            || self.expires_at.saturating_sub(self.not_before) > 60
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
pub struct RawTicket(Vec<u8>);
impl RawTicket {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for RawTicket {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl Clone for RawTicket {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl std::fmt::Debug for RawTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawTicket(REDACTED)")
    }
}

pub struct TicketSigner {
    key: SigningKey,
    key_id: [u8; 16],
}
impl TicketSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let d = Sha256::digest(key.verifying_key().as_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&d[..16]);
        Self { key, key_id: id }
    }
    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }
    pub fn sign(&self, c: &ConnectionTicketClaimsV1) -> Result<RawTicket, TicketError> {
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
            Ok(RawTicket(o))
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTicket {
    ticket_id: [u8; 16],
    claims: ConnectionTicketClaimsV1,
}
impl VerifiedTicket {
    pub fn ticket_id(&self) -> [u8; 16] {
        self.ticket_id
    }
    pub fn claims(&self) -> &ConnectionTicketClaimsV1 {
        &self.claims
    }
}

pub trait TicketKeyResolver {
    fn key(&self, key_id: [u8; 16], now: i64) -> Option<&VerifyingKey>;
}

pub struct TicketValidation<'a> {
    pub issuer_exchange_peer_id: &'a [u8],
    pub client_peer_id: &'a [u8],
    pub server_peer_id: &'a [u8],
    pub tenant: &'a str,
    pub upstream_id: &'a str,
    pub selector_fingerprint: [u8; 32],
    pub registration_revision: u64,
    pub authorization_revision: u64,
    pub permissions: u32,
    pub max_streams: u16,
    pub now: i64,
    pub clock_skew: i64,
}

#[cfg(test)]
fn verify_envelope(e: &[u8], key_id: [u8; 16], key: &VerifyingKey) -> Result<(), TicketError> {
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

pub fn verify_with_key_resolver<R: TicketKeyResolver>(
    envelope: &[u8],
    resolver: &R,
    expected: &TicketValidation<'_>,
) -> Result<VerifiedTicket, TicketError> {
    let (key_id, claims, signature) = decode_envelope(envelope)?;
    let key = resolver
        .key(key_id, expected.now)
        .ok_or(TicketError::Invalid)?;
    verify_decoded(key_id, claims, signature, key, expected)
}
#[cfg(test)]
fn verify_and_validate(
    e: &[u8],
    _key_id: [u8; 16],
    key: &VerifyingKey,
    expected: &TicketValidation<'_>,
) -> Result<VerifiedTicket, TicketError> {
    let (envelope_key_id, c, sig) = decode_envelope(e)?;
    verify_decoded(envelope_key_id, c, sig, key, expected)
}
fn verify_decoded(
    key_id: [u8; 16],
    c: ConnectionTicketClaimsV1,
    sig: Signature,
    key: &VerifyingKey,
    expected: &TicketValidation<'_>,
) -> Result<VerifiedTicket, TicketError> {
    let _ = key_id;
    let bytes = c.encode()?;
    let mut message = b"p2x-ticket-v1\0".to_vec();
    message.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    message.extend_from_slice(&bytes);
    key.verify(&message, &sig)
        .map_err(|_| TicketError::Invalid)?;
    if expected.clock_skew < 0 || expected.clock_skew > 30 {
        return Err(TicketError::Invalid);
    }
    if c.expires_at <= expected.now.saturating_sub(expected.clock_skew) {
        return Err(TicketError::Expired);
    }
    if c.not_before > expected.now.saturating_add(expected.clock_skew) {
        return Err(TicketError::Invalid);
    }
    if c.issuer_exchange_peer_id != expected.issuer_exchange_peer_id
        || c.client_peer_id != expected.client_peer_id
        || c.server_peer_id != expected.server_peer_id
        || c.tenant != expected.tenant
        || c.upstream_id != expected.upstream_id
        || c.selector_fingerprint != expected.selector_fingerprint
        || c.registration_revision != expected.registration_revision
        || c.authorization_revision != expected.authorization_revision
        || c.permissions != expected.permissions
        || c.max_streams != expected.max_streams
    {
        return Err(TicketError::Invalid);
    }
    Ok(VerifiedTicket {
        ticket_id: c.ticket_id,
        claims: c,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const PEER: &[u8] = &[
        0, 36, 8, 1, 18, 32, 107, 117, 237, 81, 229, 13, 170, 0, 121, 162, 207, 180, 128, 192, 5,
        180, 135, 200, 156, 15, 161, 190, 109, 221, 66, 55, 60, 198, 198, 8, 78, 161,
    ];
    fn validation() -> TicketValidation<'static> {
        TicketValidation {
            issuer_exchange_peer_id: PEER,
            client_peer_id: PEER,
            server_peer_id: PEER,
            tenant: "t",
            upstream_id: "u",
            selector_fingerprint: [4; 32],
            registration_revision: 1,
            authorization_revision: 2,
            permissions: 4,
            max_streams: 1,
            now: 15,
            clock_skew: 0,
        }
    }
    fn claims() -> ConnectionTicketClaimsV1 {
        ConnectionTicketClaimsV1::new(
            PEER.to_vec(),
            "t".into(),
            PEER.to_vec(),
            PEER.to_vec(),
            "u".into(),
            [4; 32],
            1,
            2,
            4,
            10,
            20,
            [5; 16],
            1,
        )
        .unwrap()
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
    fn rejects_overflowed_lifetime() {
        let mut c = claims();
        c.not_before = i64::MIN;
        c.expires_at = i64::MAX;
        assert_eq!(c.encode(), Err(TicketError::Invalid));
    }
    #[test]
    fn raw_ticket_and_verified_ticket_redact_bytes() {
        let signer = TicketSigner::from_seed([9; 32]);
        let raw = signer.sign(&claims()).unwrap();
        assert!(format!("{raw:?}").contains("REDACTED"));
        let verified = verify_and_validate(
            raw.as_bytes(),
            signer.key_id(),
            &signer.public_key(),
            &validation(),
        )
        .unwrap();
        assert_eq!(verified.ticket_id(), [5; 16]);
        assert_eq!(verified.claims().tenant(), "t");
    }
    #[test]
    fn expiry_boundary_is_exclusive() {
        let signer = TicketSigner::from_seed([9; 32]);
        let mut expected = validation();
        expected.now = 20;
        assert_eq!(
            verify_and_validate(
                signer.sign(&claims()).unwrap().as_bytes(),
                signer.key_id(),
                &signer.public_key(),
                &expected
            ),
            Err(TicketError::Expired)
        );
    }
    #[test]
    fn vector_and_mutation() {
        let s = TicketSigner::from_seed([9; 32]);
        let t = s.sign(&claims()).unwrap();
        verify_and_validate(t.as_bytes(), s.key_id(), &s.public_key(), &validation()).unwrap();
        let mut x = t.as_bytes().to_vec();
        *x.last_mut().unwrap() ^= 1;
        assert!(verify_envelope(&x, s.key_id(), &s.public_key()).is_err());
        for index in 24..t.as_bytes().len() - 64 {
            let mut mutated = t.as_bytes().to_vec();
            mutated[index] ^= 1;
            assert!(verify_envelope(&mutated, s.key_id(), &s.public_key()).is_err());
        }
        let wrong_key = TicketSigner::from_seed([8; 32]);
        assert!(
            verify_envelope(t.as_bytes(), wrong_key.key_id(), &wrong_key.public_key()).is_err()
        );
        assert!(verify_envelope(t.as_bytes(), s.key_id(), &wrong_key.public_key()).is_err());
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/ticket-v1.json")).unwrap();
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(h(t.as_bytes()), v["envelope_hex"]);
        assert_eq!(h(&s.key_id()), v["key_id_hex"]);
    }
}
