use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use p2x_protocol::{
    MAX_PROXY_HANDSHAKE_FRAME, OpenProxyStreamV1, ProxyOpenResponseV1, ProxyProtocolError,
};
use std::io;

pub async fn read_open<T: AsyncRead + Unpin>(
    io: &mut T,
) -> Result<OpenProxyStreamV1, ProxyProtocolError> {
    read_frame(io)
        .await
        .and_then(|frame| OpenProxyStreamV1::decode(&frame))
}
pub async fn read_response<T: AsyncRead + Unpin>(
    io: &mut T,
) -> Result<ProxyOpenResponseV1, ProxyProtocolError> {
    read_frame(io)
        .await
        .and_then(|frame| ProxyOpenResponseV1::decode(&frame))
}
pub async fn write_open<T: AsyncWrite + Unpin>(
    io: &mut T,
    open: &OpenProxyStreamV1,
) -> Result<(), ProxyProtocolError> {
    let frame = open.canonical_bytes()?;
    write_frame(io, &frame).await
}
pub async fn write_response<T: AsyncWrite + Unpin>(
    io: &mut T,
    response: &ProxyOpenResponseV1,
) -> Result<(), ProxyProtocolError> {
    let frame = response.canonical_bytes()?;
    write_frame(io, &frame).await
}
async fn read_frame<T: AsyncRead + Unpin>(io: &mut T) -> Result<Vec<u8>, ProxyProtocolError> {
    let mut header = [0; 4];
    io.read_exact(&mut header)
        .await
        .map_err(|_| ProxyProtocolError::Malformed)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(ProxyProtocolError::Malformed);
    }
    if length > MAX_PROXY_HANDSHAKE_FRAME {
        return Err(ProxyProtocolError::FrameTooLarge);
    }
    let mut body = vec![0; length];
    io.read_exact(&mut body)
        .await
        .map_err(|_| ProxyProtocolError::Malformed)?;
    Ok(body)
}
async fn write_frame<T: AsyncWrite + Unpin>(
    io: &mut T,
    body: &[u8],
) -> Result<(), ProxyProtocolError> {
    if body.is_empty() || body.len() > MAX_PROXY_HANDSHAKE_FRAME {
        return Err(ProxyProtocolError::FrameTooLarge);
    }
    io.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|_| ProxyProtocolError::Malformed)?;
    io.write_all(body)
        .await
        .map_err(|_| ProxyProtocolError::Malformed)?;
    io.flush()
        .await
        .map_err(|_| ProxyProtocolError::Malformed)?;
    io.close().await.map_err(|_| ProxyProtocolError::Malformed)
}
pub fn io_error(error: ProxyProtocolError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::{AllowStdIo, Cursor};
    use p2x_protocol::{IngressKind, RawTicket, RegistrationRevision, UpstreamId};

    fn open() -> OpenProxyStreamV1 {
        OpenProxyStreamV1 {
            request_id: [1; 16],
            ticket: RawTicket::new(vec![7; 16]).unwrap(),
            upstream_id: UpstreamId::new("orders").unwrap(),
            registration_revision: RegistrationRevision::new(1).unwrap(),
            ingress_kind: IngressKind::FixedTcp,
        }
    }
    #[test]
    fn opened_stream_codec_round_trips() {
        let mut bytes = Vec::new();
        block_on(write_open(&mut AllowStdIo::new(&mut bytes), &open())).unwrap();
        assert_eq!(
            block_on(read_open(&mut Cursor::new(bytes))).unwrap(),
            open()
        );
    }
}
