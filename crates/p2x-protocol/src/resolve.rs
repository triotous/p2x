use crate::{
    Capabilities, PublicError, RegistrationRevision, UpstreamId,
    selector::{MetadataKey, MetadataValue, ProtocolClass, UnscopedSelector},
    ticket::RawTicket,
};
use libp2p_identity::PeerId;
use std::collections::BTreeMap;
use thiserror::Error;

pub const MAX_RESOLVE_FRAME: usize = 16_384;
const MAX_RELAY_ADDRESSES: usize = 4;
const MAX_MULTIADDR_BYTES: usize = 512;
const VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveRequestV1 {
    Resolve {
        request_id: [u8; 16],
        session_id: [u8; 16],
        selector: UnscopedSelector,
        client_capabilities: Capabilities,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveResponseV1 {
    Resolved {
        request_id: [u8; 16],
        server_peer_id: Vec<u8>,
        upstream_id: UpstreamId,
        selector_fingerprint: [u8; 32],
        registration_revision: RegistrationRevision,
        relay_addresses: Vec<Vec<u8>>,
        compatible_capabilities: Capabilities,
        registration_expires_at: i64,
        ticket_expires_at: i64,
        ticket: RawTicket,
    },
    Rejected {
        request_id: Option<[u8; 16]>,
        error: PublicError,
    },
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ResolveProtocolError {
    #[error("resolve frame is too large")]
    FrameTooLarge,
    #[error("resolve message is malformed")]
    Malformed,
    #[error("resolve version is unsupported")]
    UnsupportedVersion,
    #[error("resolve capabilities are unsupported")]
    CapabilityMismatch,
}
impl ResolveProtocolError {
    pub const fn public_code(self) -> crate::PublicErrorCode {
        match self {
            Self::FrameTooLarge => crate::PublicErrorCode::ProtocolFrameTooLarge,
            Self::Malformed => crate::PublicErrorCode::ProtocolMalformed,
            Self::UnsupportedVersion => crate::PublicErrorCode::ProtocolUnsupportedVersion,
            Self::CapabilityMismatch => crate::PublicErrorCode::ProtocolCapabilityMismatch,
        }
    }
}

fn malformed() -> ResolveProtocolError {
    ResolveProtocolError::Malformed
}
fn take<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    length: usize,
) -> Result<&'a [u8], ResolveProtocolError> {
    let end = position.checked_add(length).ok_or_else(malformed)?;
    let value = bytes.get(*position..end).ok_or_else(malformed)?;
    *position = end;
    Ok(value)
}
fn u16v(bytes: &[u8], position: &mut usize) -> Result<u16, ResolveProtocolError> {
    Ok(u16::from_be_bytes(
        take(bytes, position, 2)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn u32v(bytes: &[u8], position: &mut usize) -> Result<u32, ResolveProtocolError> {
    Ok(u32::from_be_bytes(
        take(bytes, position, 4)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn u64v(bytes: &[u8], position: &mut usize) -> Result<u64, ResolveProtocolError> {
    Ok(u64::from_be_bytes(
        take(bytes, position, 8)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn i64v(bytes: &[u8], position: &mut usize) -> Result<i64, ResolveProtocolError> {
    Ok(i64::from_be_bytes(
        take(bytes, position, 8)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn id(bytes: &[u8], position: &mut usize) -> Result<[u8; 16], ResolveProtocolError> {
    take(bytes, position, 16)?
        .try_into()
        .map_err(|_| malformed())
}
fn text(bytes: &[u8], position: &mut usize) -> Result<String, ResolveProtocolError> {
    let length = u16v(bytes, position)? as usize;
    String::from_utf8(take(bytes, position, length)?.to_vec()).map_err(|_| malformed())
}
fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), ResolveProtocolError> {
    if value.len() > u16::MAX as usize {
        return Err(malformed());
    }
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}
fn peer(bytes: &[u8], position: &mut usize) -> Result<Vec<u8>, ResolveProtocolError> {
    let length = take(bytes, position, 1)?[0] as usize;
    let value = take(bytes, position, length)?.to_vec();
    PeerId::from_bytes(&value).map_err(|_| malformed())?;
    Ok(value)
}
fn selector(bytes: &[u8], position: &mut usize) -> Result<UnscopedSelector, ResolveProtocolError> {
    let protocol = match take(bytes, position, 1)?[0] {
        0 => ProtocolClass::Http,
        1 => ProtocolClass::TlsPassthrough,
        2 => ProtocolClass::Tcp,
        _ => return Err(malformed()),
    };
    let count = take(bytes, position, 1)?[0] as usize;
    let mut metadata = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let key = MetadataKey::new(&text(bytes, position)?).map_err(|_| malformed())?;
        if previous
            .as_ref()
            .is_some_and(|old: &String| old.as_str() >= key.as_str())
        {
            return Err(malformed());
        }
        previous = Some(key.as_str().to_owned());
        let value = MetadataValue::new(&text(bytes, position)?).map_err(|_| malformed())?;
        if metadata.insert(key, value).is_some() {
            return Err(malformed());
        }
    }
    UnscopedSelector::new(protocol, metadata).map_err(|_| malformed())
}
fn put_selector(
    output: &mut Vec<u8>,
    selector: &UnscopedSelector,
) -> Result<(), ResolveProtocolError> {
    output.push(selector.protocol().wire());
    output.push(selector.metadata().len() as u8);
    for (key, value) in selector.metadata() {
        put_text(output, key.as_str())?;
        put_text(output, value.as_str())?;
    }
    Ok(())
}
fn capabilities(bits: u32) -> Result<Capabilities, ResolveProtocolError> {
    Capabilities::from_bits(bits).ok_or(ResolveProtocolError::CapabilityMismatch)
}
fn put_error(output: &mut Vec<u8>, error: PublicError) -> Result<(), ResolveProtocolError> {
    put_text(output, error.code.as_str())?;
    output.push(u8::from(error.retryable));
    Ok(())
}
fn error(bytes: &[u8], position: &mut usize) -> Result<PublicError, ResolveProtocolError> {
    let code =
        crate::PublicErrorCode::try_from_wire(&text(bytes, position)?).map_err(|_| malformed())?;
    let retryable = take(bytes, position, 1)?[0];
    if retryable > 1 {
        return Err(malformed());
    }
    Ok(PublicError::new(code, retryable == 1))
}

impl ResolveRequestV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResolveProtocolError> {
        let mut output = vec![VERSION, 0];
        match self {
            Self::Resolve {
                request_id,
                session_id,
                selector,
                client_capabilities,
            } => {
                output.extend_from_slice(request_id);
                output.extend_from_slice(session_id);
                put_selector(&mut output, selector)?;
                output.extend_from_slice(&client_capabilities.bits().to_be_bytes());
            }
        }
        if output.len() > MAX_RESOLVE_FRAME {
            return Err(ResolveProtocolError::FrameTooLarge);
        }
        Ok(output)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ResolveProtocolError> {
        if bytes.len() > MAX_RESOLVE_FRAME {
            return Err(ResolveProtocolError::FrameTooLarge);
        }
        let mut position = 0;
        if take(bytes, &mut position, 1)?[0] != VERSION {
            return Err(ResolveProtocolError::UnsupportedVersion);
        }
        if take(bytes, &mut position, 1)?[0] != 0 {
            return Err(malformed());
        }
        let request = Self::Resolve {
            request_id: id(bytes, &mut position)?,
            session_id: id(bytes, &mut position)?,
            selector: selector(bytes, &mut position)?,
            client_capabilities: capabilities(u32v(bytes, &mut position)?)?,
        };
        if position != bytes.len() {
            return Err(malformed());
        }
        Ok(request)
    }
}
impl ResolveResponseV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResolveProtocolError> {
        let mut output = vec![VERSION];
        match self {
            Self::Resolved {
                request_id,
                server_peer_id,
                upstream_id,
                selector_fingerprint,
                registration_revision,
                relay_addresses,
                compatible_capabilities,
                registration_expires_at,
                ticket_expires_at,
                ticket,
            } => {
                if !valid_addresses(relay_addresses)
                    || PeerId::from_bytes(server_peer_id).is_err()
                    || ticket.as_bytes().len() > crate::ticket::MAX_TICKET_ENVELOPE
                    || *ticket_expires_at > *registration_expires_at
                {
                    return Err(malformed());
                }
                output.push(0);
                output.extend_from_slice(request_id);
                if server_peer_id.len() > u8::MAX as usize {
                    return Err(malformed());
                }
                output.push(server_peer_id.len() as u8);
                output.extend_from_slice(server_peer_id);
                put_text(&mut output, upstream_id.as_str())?;
                output.extend_from_slice(selector_fingerprint);
                output.extend_from_slice(&registration_revision.get().to_be_bytes());
                output.push(relay_addresses.len() as u8);
                for address in relay_addresses {
                    output.extend_from_slice(&(address.len() as u16).to_be_bytes());
                    output.extend_from_slice(address);
                }
                output.extend_from_slice(&compatible_capabilities.bits().to_be_bytes());
                output.extend_from_slice(&registration_expires_at.to_be_bytes());
                output.extend_from_slice(&ticket_expires_at.to_be_bytes());
                output.extend_from_slice(&(ticket.as_bytes().len() as u16).to_be_bytes());
                output.extend_from_slice(ticket.as_bytes());
            }
            Self::Rejected { request_id, error } => {
                output.push(1);
                match request_id {
                    Some(id) => {
                        output.push(1);
                        output.extend_from_slice(id);
                    }
                    None => output.push(0),
                }
                put_error(&mut output, *error)?;
            }
        }
        if output.len() > MAX_RESOLVE_FRAME {
            return Err(ResolveProtocolError::FrameTooLarge);
        }
        Ok(output)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ResolveProtocolError> {
        if bytes.len() > MAX_RESOLVE_FRAME {
            return Err(ResolveProtocolError::FrameTooLarge);
        }
        let mut position = 0;
        if take(bytes, &mut position, 1)?[0] != VERSION {
            return Err(ResolveProtocolError::UnsupportedVersion);
        }
        let response = match take(bytes, &mut position, 1)?[0] {
            0 => {
                let request_id = id(bytes, &mut position)?;
                let server_peer_id = peer(bytes, &mut position)?;
                let upstream_id =
                    UpstreamId::new(&text(bytes, &mut position)?).map_err(|_| malformed())?;
                let selector_fingerprint = take(bytes, &mut position, 32)?
                    .try_into()
                    .map_err(|_| malformed())?;
                let registration_revision =
                    RegistrationRevision::new(u64v(bytes, &mut position)?).ok_or_else(malformed)?;
                let count = take(bytes, &mut position, 1)?[0] as usize;
                if !(1..=MAX_RELAY_ADDRESSES).contains(&count) {
                    return Err(malformed());
                }
                let mut relay_addresses = Vec::with_capacity(count);
                for _ in 0..count {
                    let length = u16v(bytes, &mut position)? as usize;
                    if length == 0 || length > MAX_MULTIADDR_BYTES {
                        return Err(malformed());
                    }
                    relay_addresses.push(take(bytes, &mut position, length)?.to_vec());
                }
                if !valid_addresses(&relay_addresses) {
                    return Err(malformed());
                }
                let compatible_capabilities = capabilities(u32v(bytes, &mut position)?)?;
                let registration_expires_at = i64v(bytes, &mut position)?;
                let ticket_expires_at = i64v(bytes, &mut position)?;
                let ticket_length = u16v(bytes, &mut position)? as usize;
                if ticket_length > crate::ticket::MAX_TICKET_ENVELOPE {
                    return Err(malformed());
                }
                let ticket = RawTicket::new(take(bytes, &mut position, ticket_length)?.to_vec())
                    .map_err(|_| malformed())?;
                Self::Resolved {
                    request_id,
                    server_peer_id,
                    upstream_id,
                    selector_fingerprint,
                    registration_revision,
                    relay_addresses,
                    compatible_capabilities,
                    registration_expires_at,
                    ticket_expires_at,
                    ticket,
                }
            }
            1 => {
                let has_id = take(bytes, &mut position, 1)?[0];
                let request_id = match has_id {
                    0 => None,
                    1 => Some(id(bytes, &mut position)?),
                    _ => return Err(malformed()),
                };
                Self::Rejected {
                    request_id,
                    error: error(bytes, &mut position)?,
                }
            }
            _ => return Err(malformed()),
        };
        if position != bytes.len() {
            return Err(malformed());
        }
        Ok(response)
    }
    pub fn resolved_at(&self, now: i64) -> bool {
        matches!(self, Self::Resolved { registration_expires_at, ticket_expires_at, .. } if *registration_expires_at > now && *ticket_expires_at > now && *ticket_expires_at <= *registration_expires_at)
    }
}
fn valid_addresses(addresses: &[Vec<u8>]) -> bool {
    (1..=MAX_RELAY_ADDRESSES).contains(&addresses.len())
        && addresses.iter().all(|address| {
            if address.is_empty() || address.len() > MAX_MULTIADDR_BYTES {
                return false;
            }
            let Ok(address) = multiaddr::Multiaddr::try_from(address.clone()) else {
                return false;
            };
            let parts = address.iter().collect::<Vec<_>>();
            let Some(circuit) = parts
                .iter()
                .position(|part| matches!(part, multiaddr::Protocol::P2pCircuit))
            else {
                return false;
            };
            let peer_positions = parts
                .iter()
                .enumerate()
                .filter_map(|(index, part)| match part {
                    multiaddr::Protocol::P2p(peer) => Some((index, *peer)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            circuit > 0
                && peer_positions.len() == 2
                && peer_positions[0].0 + 1 == circuit
                && peer_positions[1].0 + 1 == parts.len()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Health, ServiceAdvertisementV1, ServiceSet, Tenant};
    use std::collections::BTreeMap;

    fn selector() -> UnscopedSelector {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            MetadataKey::new("service").unwrap(),
            MetadataValue::new("orders").unwrap(),
        );
        UnscopedSelector::new(ProtocolClass::Http, metadata).unwrap()
    }
    fn ticket() -> RawTicket {
        RawTicket::new(vec![7; 16]).unwrap()
    }
    #[test]
    fn request_and_rejection_are_canonical() {
        let request = ResolveRequestV1::Resolve {
            request_id: [1; 16],
            session_id: [2; 16],
            selector: selector(),
            client_capabilities: Capabilities::from_bits(9).unwrap(),
        };
        assert_eq!(
            ResolveRequestV1::decode(&request.canonical_bytes().unwrap()).unwrap(),
            request
        );
        let response = ResolveResponseV1::Rejected {
            request_id: Some([1; 16]),
            error: PublicError::new(crate::PublicErrorCode::RegistryNotFound, true),
        };
        assert_eq!(
            ResolveResponseV1::decode(&response.canonical_bytes().unwrap()).unwrap(),
            response
        );
    }
    #[test]
    fn binary_multiaddr_bytes_are_accepted() {
        let peer = PeerId::random().to_bytes();
        let exchange = PeerId::random();
        let relay = format!(
            "/ip4/127.0.0.1/tcp/1/p2p/{exchange}/p2p-circuit/p2p/{}",
            PeerId::from_bytes(&peer).unwrap()
        )
        .parse::<multiaddr::Multiaddr>()
        .unwrap()
        .to_vec();
        assert!(valid_addresses(&[relay]));
    }

    #[test]
    fn oversized_frames_are_rejected_before_parsing() {
        assert_eq!(
            ResolveRequestV1::decode(&vec![0; MAX_RESOLVE_FRAME + 1]),
            Err(ResolveProtocolError::FrameTooLarge)
        );
        assert_eq!(
            ResolveResponseV1::decode(&vec![0; MAX_RESOLVE_FRAME + 1]),
            Err(ResolveProtocolError::FrameTooLarge)
        );
    }

    #[test]
    fn response_bounds_and_expiry_are_checked() {
        let peer = PeerId::random().to_bytes();
        let exchange = PeerId::random();
        let relay = format!(
            "/ip4/127.0.0.1/tcp/1/p2p/{exchange}/p2p-circuit/p2p/{}",
            PeerId::from_bytes(&peer).unwrap()
        );
        let relay = relay.parse::<multiaddr::Multiaddr>().unwrap().to_vec();
        let response = ResolveResponseV1::Resolved {
            request_id: [1; 16],
            server_peer_id: peer,
            upstream_id: UpstreamId::new("orders").unwrap(),
            selector_fingerprint: [3; 32],
            registration_revision: RegistrationRevision::new(1).unwrap(),
            relay_addresses: vec![relay],
            compatible_capabilities: Capabilities::RELAY_V2,
            registration_expires_at: 20,
            ticket_expires_at: 19,
            ticket: ticket(),
        };
        assert!(response.resolved_at(10));
        assert!(!response.resolved_at(19));
        assert!(ResolveResponseV1::decode(&response.canonical_bytes().unwrap()).is_ok());
        let mut bytes = response.canonical_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            ResolveResponseV1::decode(&bytes),
            Err(ResolveProtocolError::Malformed)
        );
    }
    #[test]
    fn selector_order_is_required() {
        let request = ResolveRequestV1::Resolve {
            request_id: [1; 16],
            session_id: [2; 16],
            selector: selector(),
            client_capabilities: Capabilities::RELAY_V2,
        };
        let mut bytes = request.canonical_bytes().unwrap();
        bytes[35] = b'z';
        assert!(ResolveRequestV1::decode(&bytes).is_err());
        let _ = (
            Tenant::new("tenant").unwrap(),
            ServiceSet::new(vec![ServiceAdvertisementV1::new(
                UpstreamId::new("orders").unwrap(),
                selector(),
                Health::Ready,
            )])
            .unwrap(),
        );
    }
}
