use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use p2x_protocol::selector::{MetadataKey, MetadataValue, ProtocolClass, UnscopedSelector};
use p2x_protocol::{
    Capabilities, Health, InstanceId, PublicError, PublicErrorCode, RegistrationRevision,
    RegistryRequestV1, RegistryResponseV1, ServiceAdvertisementV1, ServiceSet, UpstreamId,
};
use std::{io, num::NonZeroU64};
use thiserror::Error;

pub const REGISTRY_PROTOCOL: &str = "/p2x/registry/1";
pub const MAX_REGISTRY_FRAME: usize = 262_144;
const VERSION: u8 = 1;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistryProtocolError {
    #[error("registry frame is too large")]
    FrameTooLarge,
    #[error("registry message is malformed")]
    Malformed,
    #[error("registry version is unsupported")]
    UnsupportedVersion,
    #[error("registry capabilities are unsupported")]
    CapabilityMismatch,
}
impl RegistryProtocolError {
    pub fn public_code(&self) -> PublicErrorCode {
        match self {
            Self::FrameTooLarge => PublicErrorCode::ProtocolFrameTooLarge,
            Self::Malformed => PublicErrorCode::ProtocolMalformed,
            Self::UnsupportedVersion => PublicErrorCode::ProtocolUnsupportedVersion,
            Self::CapabilityMismatch => PublicErrorCode::ProtocolCapabilityMismatch,
        }
    }
}
fn malformed() -> RegistryProtocolError {
    RegistryProtocolError::Malformed
}
fn io_error(error: RegistryProtocolError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
fn take<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    length: usize,
) -> Result<&'a [u8], RegistryProtocolError> {
    let end = position.checked_add(length).ok_or_else(malformed)?;
    let value = bytes.get(*position..end).ok_or_else(malformed)?;
    *position = end;
    Ok(value)
}
fn u16v(bytes: &[u8], position: &mut usize) -> Result<u16, RegistryProtocolError> {
    Ok(u16::from_be_bytes(
        take(bytes, position, 2)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn u32v(bytes: &[u8], position: &mut usize) -> Result<u32, RegistryProtocolError> {
    Ok(u32::from_be_bytes(
        take(bytes, position, 4)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn u64v(bytes: &[u8], position: &mut usize) -> Result<u64, RegistryProtocolError> {
    Ok(u64::from_be_bytes(
        take(bytes, position, 8)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn i64v(bytes: &[u8], position: &mut usize) -> Result<i64, RegistryProtocolError> {
    Ok(i64::from_be_bytes(
        take(bytes, position, 8)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn text(bytes: &[u8], position: &mut usize) -> Result<String, RegistryProtocolError> {
    let length = u16v(bytes, position)? as usize;
    String::from_utf8(take(bytes, position, length)?.to_vec()).map_err(|_| malformed())
}
fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), RegistryProtocolError> {
    if value.len() > u16::MAX as usize {
        return Err(malformed());
    }
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}
fn protocol(value: u8) -> Result<ProtocolClass, RegistryProtocolError> {
    match value {
        0 => Ok(ProtocolClass::Http),
        1 => Ok(ProtocolClass::TlsPassthrough),
        2 => Ok(ProtocolClass::Tcp),
        _ => Err(malformed()),
    }
}
fn health(value: u8) -> Result<Health, RegistryProtocolError> {
    match value {
        0 => Ok(Health::Ready),
        1 => Ok(Health::Unavailable),
        _ => Err(malformed()),
    }
}
fn request_id(bytes: &[u8], position: &mut usize) -> Result<[u8; 16], RegistryProtocolError> {
    take(bytes, position, 16)?
        .try_into()
        .map_err(|_| malformed())
}
fn instance_id(bytes: &[u8], position: &mut usize) -> Result<InstanceId, RegistryProtocolError> {
    Ok(InstanceId::new(request_id(bytes, position)?))
}
fn selector(bytes: &[u8], position: &mut usize) -> Result<UnscopedSelector, RegistryProtocolError> {
    let protocol = protocol(take(bytes, position, 1)?[0])?;
    let count = take(bytes, position, 1)?[0] as usize;
    let mut metadata = std::collections::BTreeMap::new();
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let key = MetadataKey::new(&text(bytes, position)?).map_err(|_| malformed())?;
        if previous
            .as_ref()
            .is_some_and(|old| old.as_str() >= key.as_str())
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
fn service(
    bytes: &[u8],
    position: &mut usize,
) -> Result<ServiceAdvertisementV1, RegistryProtocolError> {
    let upstream_id = UpstreamId::new(&text(bytes, position)?).map_err(|_| malformed())?;
    let selector = selector(bytes, position)?;
    let health = health(take(bytes, position, 1)?[0])?;
    Ok(ServiceAdvertisementV1::new(upstream_id, selector, health))
}
fn services(bytes: &[u8], position: &mut usize) -> Result<ServiceSet, RegistryProtocolError> {
    let count = u16v(bytes, position)? as usize;
    if count > 128 {
        return Err(malformed());
    }
    let mut values = Vec::with_capacity(count);
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let value = service(bytes, position)?;
        if previous
            .as_ref()
            .is_some_and(|old| old.as_str() >= value.upstream_id().as_str())
        {
            return Err(malformed());
        }
        previous = Some(value.upstream_id().as_str().to_owned());
        values.push(value);
    }
    ServiceSet::new(values).map_err(|_| malformed())
}
fn encode_selector(
    output: &mut Vec<u8>,
    selector: &UnscopedSelector,
) -> Result<(), RegistryProtocolError> {
    output.push(selector.protocol().wire());
    output.push(selector.metadata().len() as u8);
    for (key, value) in selector.metadata() {
        put_text(output, key.as_str())?;
        put_text(output, value.as_str())?;
    }
    Ok(())
}
fn encode_services(
    output: &mut Vec<u8>,
    services: &ServiceSet,
) -> Result<(), RegistryProtocolError> {
    output.extend_from_slice(&(services.as_slice().len() as u16).to_be_bytes());
    for service in services.as_slice() {
        put_text(output, service.upstream_id().as_str())?;
        encode_selector(output, service.selector())?;
        output.push(match service.health() {
            Health::Ready => 0,
            Health::Unavailable => 1,
        });
    }
    Ok(())
}
fn encode_request(request: &RegistryRequestV1) -> Result<Vec<u8>, RegistryProtocolError> {
    let mut output = vec![VERSION];
    match request {
        RegistryRequestV1::Register {
            request_id,
            session_id,
            instance_id,
            requested_lease_seconds,
            capabilities,
            services,
        } => {
            output.push(0);
            output.extend_from_slice(request_id);
            output.extend_from_slice(session_id);
            output.extend_from_slice(instance_id.as_bytes());
            output.extend_from_slice(&requested_lease_seconds.to_be_bytes());
            output.extend_from_slice(&capabilities.bits().to_be_bytes());
            encode_services(&mut output, services)?;
        }
        RegistryRequestV1::Refresh {
            request_id,
            session_id,
            instance_id,
            expected_registration_revision,
            requested_lease_seconds,
        } => {
            output.push(1);
            output.extend_from_slice(request_id);
            output.extend_from_slice(session_id);
            output.extend_from_slice(instance_id.as_bytes());
            output.extend_from_slice(&expected_registration_revision.get().to_be_bytes());
            output.extend_from_slice(&requested_lease_seconds.to_be_bytes());
        }
        RegistryRequestV1::Withdraw {
            request_id,
            session_id,
            instance_id,
            expected_registration_revision,
        } => {
            output.push(2);
            output.extend_from_slice(request_id);
            output.extend_from_slice(session_id);
            output.extend_from_slice(instance_id.as_bytes());
            output.extend_from_slice(&expected_registration_revision.get().to_be_bytes());
        }
    }
    if output.len() > MAX_REGISTRY_FRAME {
        return Err(RegistryProtocolError::FrameTooLarge);
    }
    Ok(output)
}
fn encode_response(response: &RegistryResponseV1) -> Result<Vec<u8>, RegistryProtocolError> {
    let mut output = vec![VERSION];
    match response {
        RegistryResponseV1::Registered {
            request_id,
            instance_id,
            registration_revision,
            service_set_hash,
            expires_at,
            effective_lease_seconds,
        } => {
            output.push(0);
            output.extend_from_slice(request_id);
            output.extend_from_slice(instance_id.as_bytes());
            output.extend_from_slice(&registration_revision.get().to_be_bytes());
            output.extend_from_slice(service_set_hash);
            output.extend_from_slice(&expires_at.to_be_bytes());
            output.extend_from_slice(&effective_lease_seconds.to_be_bytes());
        }
        RegistryResponseV1::Refreshed {
            request_id,
            instance_id,
            registration_revision,
            expires_at,
        } => {
            output.push(1);
            output.extend_from_slice(request_id);
            output.extend_from_slice(instance_id.as_bytes());
            output.extend_from_slice(&registration_revision.get().to_be_bytes());
            output.extend_from_slice(&expires_at.to_be_bytes());
        }
        RegistryResponseV1::Withdrawn {
            request_id,
            instance_id,
            registration_revision,
        } => {
            output.push(2);
            output.extend_from_slice(request_id);
            output.extend_from_slice(instance_id.as_bytes());
            output.extend_from_slice(&registration_revision.get().to_be_bytes());
        }
        RegistryResponseV1::Rejected { request_id, error } => {
            output.push(3);
            match request_id {
                Some(id) => {
                    output.push(1);
                    output.extend_from_slice(id);
                }
                None => output.push(0),
            }
            put_text(&mut output, error.code.as_str())?;
            output.push(u8::from(error.retryable));
        }
    }
    if output.len() > MAX_REGISTRY_FRAME {
        return Err(RegistryProtocolError::FrameTooLarge);
    }
    Ok(output)
}
fn decode_request(bytes: &[u8]) -> Result<RegistryRequestV1, RegistryProtocolError> {
    let mut position = 0;
    if take(bytes, &mut position, 1)?[0] != VERSION {
        return Err(RegistryProtocolError::UnsupportedVersion);
    }
    let kind = take(bytes, &mut position, 1)?[0];
    let request = match kind {
        0 => RegistryRequestV1::Register {
            request_id: request_id(bytes, &mut position)?,
            session_id: request_id(bytes, &mut position)?,
            instance_id: instance_id(bytes, &mut position)?,
            requested_lease_seconds: u16v(bytes, &mut position)?,
            capabilities: Capabilities::from_bits(u32v(bytes, &mut position)?)
                .ok_or(RegistryProtocolError::CapabilityMismatch)?,
            services: services(bytes, &mut position)?,
        },
        1 => RegistryRequestV1::Refresh {
            request_id: request_id(bytes, &mut position)?,
            session_id: request_id(bytes, &mut position)?,
            instance_id: instance_id(bytes, &mut position)?,
            expected_registration_revision: NonZeroU64::new(u64v(bytes, &mut position)?)
                .ok_or_else(malformed)?,
            requested_lease_seconds: u16v(bytes, &mut position)?,
        },
        2 => RegistryRequestV1::Withdraw {
            request_id: request_id(bytes, &mut position)?,
            session_id: request_id(bytes, &mut position)?,
            instance_id: instance_id(bytes, &mut position)?,
            expected_registration_revision: NonZeroU64::new(u64v(bytes, &mut position)?)
                .ok_or_else(malformed)?,
        },
        _ => return Err(malformed()),
    };
    if position != bytes.len() {
        return Err(malformed());
    }
    Ok(request)
}
fn decode_response(bytes: &[u8]) -> Result<RegistryResponseV1, RegistryProtocolError> {
    let mut position = 0;
    if take(bytes, &mut position, 1)?[0] != VERSION {
        return Err(RegistryProtocolError::UnsupportedVersion);
    }
    let kind = take(bytes, &mut position, 1)?[0];
    let response = match kind {
        0 => RegistryResponseV1::Registered {
            request_id: request_id(bytes, &mut position)?,
            instance_id: instance_id(bytes, &mut position)?,
            registration_revision: RegistrationRevision::new(u64v(bytes, &mut position)?)
                .ok_or_else(malformed)?,
            service_set_hash: take(bytes, &mut position, 32)?
                .try_into()
                .map_err(|_| malformed())?,
            expires_at: i64v(bytes, &mut position)?,
            effective_lease_seconds: u16v(bytes, &mut position)?,
        },
        1 => RegistryResponseV1::Refreshed {
            request_id: request_id(bytes, &mut position)?,
            instance_id: instance_id(bytes, &mut position)?,
            registration_revision: RegistrationRevision::new(u64v(bytes, &mut position)?)
                .ok_or_else(malformed)?,
            expires_at: i64v(bytes, &mut position)?,
        },
        2 => RegistryResponseV1::Withdrawn {
            request_id: request_id(bytes, &mut position)?,
            instance_id: instance_id(bytes, &mut position)?,
            registration_revision: RegistrationRevision::new(u64v(bytes, &mut position)?)
                .ok_or_else(malformed)?,
        },
        3 => {
            let has_id = take(bytes, &mut position, 1)?[0];
            let request_id = match has_id {
                0 => None,
                1 => Some(request_id(bytes, &mut position)?),
                _ => return Err(malformed()),
            };
            let code = PublicErrorCode::try_from_wire(&text(bytes, &mut position)?)
                .map_err(|_| malformed())?;
            let retryable = take(bytes, &mut position, 1)?[0];
            if retryable > 1 {
                return Err(malformed());
            }
            RegistryResponseV1::Rejected {
                request_id,
                error: PublicError::new(code, retryable == 1),
            }
        }
        _ => return Err(malformed()),
    };
    if position != bytes.len() {
        return Err(malformed());
    }
    Ok(response)
}
async fn read_frame<T: AsyncRead + Unpin + Send>(
    io: &mut T,
) -> Result<Vec<u8>, RegistryProtocolError> {
    let mut header = [0; 4];
    io.read_exact(&mut header).await.map_err(|_| malformed())?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_REGISTRY_FRAME {
        return Err(RegistryProtocolError::FrameTooLarge);
    }
    let mut body = vec![0; length];
    io.read_exact(&mut body).await.map_err(|_| malformed())?;
    Ok(body)
}
async fn write_frame<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    body: &[u8],
) -> Result<(), RegistryProtocolError> {
    if body.is_empty() || body.len() > MAX_REGISTRY_FRAME {
        return Err(RegistryProtocolError::FrameTooLarge);
    }
    io.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|_| malformed())?;
    io.write_all(body).await.map_err(|_| malformed())?;
    io.flush().await.map_err(|_| malformed())?;
    io.close().await.map_err(|_| malformed())
}
#[derive(Clone, Default)]
pub struct RegistryCodec;
#[async_trait]
impl Codec for RegistryCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = RegistryRequestV1;
    type Response = RegistryResponseV1;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request> {
        read_frame(io)
            .await
            .and_then(|frame| decode_request(&frame))
            .map_err(io_error)
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        read_frame(io)
            .await
            .and_then(|frame| decode_response(&frame))
            .map_err(io_error)
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()> {
        write_frame(io, &encode_request(&request).map_err(io_error)?)
            .await
            .map_err(io_error)
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()> {
        write_frame(io, &encode_response(&response).map_err(io_error)?)
            .await
            .map_err(io_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::{AllowStdIo, Cursor};
    use std::collections::BTreeMap;
    fn request() -> RegistryRequestV1 {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            MetadataKey::new("service").unwrap(),
            MetadataValue::new("orders").unwrap(),
        );
        let selector = UnscopedSelector::new(ProtocolClass::Http, metadata).unwrap();
        let service = ServiceAdvertisementV1::new(
            UpstreamId::new("orders").unwrap(),
            selector,
            Health::Ready,
        );
        RegistryRequestV1::Register {
            request_id: [1; 16],
            session_id: [2; 16],
            instance_id: InstanceId::new([3; 16]),
            requested_lease_seconds: 30,
            capabilities: Capabilities::from_bits(7).unwrap(),
            services: ServiceSet::new(vec![service]).unwrap(),
        }
    }
    #[test]
    fn binary_round_trip_and_bounds() {
        let mut bytes = Vec::new();
        let mut codec = RegistryCodec;
        block_on(codec.write_request(
            &libp2p::StreamProtocol::new(REGISTRY_PROTOCOL),
            &mut AllowStdIo::new(&mut bytes),
            request(),
        ))
        .unwrap();
        assert!(matches!(
            block_on(codec.read_request(
                &libp2p::StreamProtocol::new(REGISTRY_PROTOCOL),
                &mut Cursor::new(bytes)
            )),
            Ok(RegistryRequestV1::Register { .. })
        ));
        assert_eq!(
            read_frame_error(&[0, 0, 0, 0]),
            RegistryProtocolError::FrameTooLarge
        );
        assert_eq!(
            read_frame_error(&[0, 0, 0]),
            RegistryProtocolError::Malformed
        );
    }
    fn read_frame_error(bytes: &[u8]) -> RegistryProtocolError {
        block_on(read_frame(&mut Cursor::new(bytes))).unwrap_err()
    }
    #[test]
    fn rejects_noncanonical_and_capability() {
        let mut encoded = encode_request(&request()).unwrap();
        encoded.push(0);
        assert_eq!(
            decode_request(&encoded),
            Err(RegistryProtocolError::Malformed)
        );
        let mut capability = encode_request(&request()).unwrap();
        capability[1] = 0;
        capability[2 + 16 + 16 + 16 + 2] = 0xff; // high byte of capabilities
        assert_eq!(
            decode_request(&capability),
            Err(RegistryProtocolError::CapabilityMismatch)
        );
    }
}
