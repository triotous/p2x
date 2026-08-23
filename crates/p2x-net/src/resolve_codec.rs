use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use p2x_protocol::{MAX_RESOLVE_FRAME, ResolveProtocolError, ResolveRequestV1, ResolveResponseV1};
use std::io;

pub const RESOLVE_PROTOCOL: &str = "/p2x/resolve/1";

async fn read_frame<T: AsyncRead + Unpin + Send>(
    io: &mut T,
) -> Result<Vec<u8>, ResolveProtocolError> {
    let mut header = [0; 4];
    io.read_exact(&mut header)
        .await
        .map_err(|_| ResolveProtocolError::Malformed)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(ResolveProtocolError::Malformed);
    }
    if length > MAX_RESOLVE_FRAME {
        return Err(ResolveProtocolError::FrameTooLarge);
    }
    let mut body = vec![0; length];
    io.read_exact(&mut body)
        .await
        .map_err(|_| ResolveProtocolError::Malformed)?;
    Ok(body)
}

async fn write_frame<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    body: &[u8],
) -> Result<(), ResolveProtocolError> {
    if body.is_empty() || body.len() > MAX_RESOLVE_FRAME {
        return Err(ResolveProtocolError::FrameTooLarge);
    }
    io.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|_| ResolveProtocolError::Malformed)?;
    io.write_all(body)
        .await
        .map_err(|_| ResolveProtocolError::Malformed)?;
    io.flush()
        .await
        .map_err(|_| ResolveProtocolError::Malformed)?;
    io.close()
        .await
        .map_err(|_| ResolveProtocolError::Malformed)
}

#[derive(Clone, Default)]
pub struct ResolveCodec;
#[async_trait]
impl Codec for ResolveCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = ResolveRequestV1;
    type Response = ResolveResponseV1;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request> {
        read_frame(io)
            .await
            .and_then(|frame| ResolveRequestV1::decode(&frame))
            .map_err(protocol_io)
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        read_frame(io)
            .await
            .and_then(|frame| ResolveResponseV1::decode(&frame))
            .map_err(protocol_io)
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()> {
        let frame = request.canonical_bytes().map_err(protocol_io)?;
        write_frame(io, &frame).await.map_err(protocol_io)
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()> {
        let frame = response.canonical_bytes().map_err(protocol_io)?;
        write_frame(io, &frame).await.map_err(protocol_io)
    }
}

fn protocol_io(error: ResolveProtocolError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::{AllowStdIo, Cursor};
    use p2x_protocol::{Capabilities, MetadataKey, MetadataValue, ProtocolClass, UpstreamId};
    use std::collections::BTreeMap;

    fn request() -> ResolveRequestV1 {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            MetadataKey::new("service").unwrap(),
            MetadataValue::new("orders").unwrap(),
        );
        ResolveRequestV1::Resolve {
            request_id: [1; 16],
            session_id: [2; 16],
            selector: p2x_protocol::UnscopedSelector::new(ProtocolClass::Http, metadata).unwrap(),
            client_capabilities: Capabilities::RELAY_V2,
        }
    }

    #[test]
    fn request_response_codec_round_trips_and_rejects_bad_length() {
        let mut bytes = Vec::new();
        block_on(ResolveCodec.write_request(
            &libp2p::StreamProtocol::new(RESOLVE_PROTOCOL),
            &mut AllowStdIo::new(&mut bytes),
            request(),
        ))
        .unwrap();
        assert!(matches!(
            block_on(ResolveCodec.read_request(
                &libp2p::StreamProtocol::new(RESOLVE_PROTOCOL),
                &mut Cursor::new(bytes)
            )),
            Ok(ResolveRequestV1::Resolve { .. })
        ));
        assert!(block_on(read_frame(&mut Cursor::new(vec![0, 0, 0, 0]))).is_err());
        let _ = UpstreamId::new("orders").unwrap();
    }
}
