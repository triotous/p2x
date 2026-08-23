use futures::io::{AsyncRead, AsyncWrite};
use p2x_net::proxy_codec;
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicErrorCode};
use std::time::Duration;

pub async fn authorize_empty_stream<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    open: &OpenProxyStreamV1,
    timeout: Duration,
) -> Result<([u8; 16], [u8; 16]), PublicErrorCode> {
    tokio::time::timeout(timeout, async {
        proxy_codec::write_open(&mut stream, open)
            .await
            .map_err(|_| PublicErrorCode::ProtocolMalformed)?;
        match proxy_codec::read_response(&mut stream)
            .await
            .map_err(|_| PublicErrorCode::ProtocolMalformed)?
        {
            ProxyOpenResponseV1::Authorized {
                request_id,
                stream_id,
            } if request_id == open.request_id => Ok((request_id, stream_id)),
            ProxyOpenResponseV1::Rejected { error, .. } => Err(error.code),
            _ => Err(PublicErrorCode::ProtocolMalformed),
        }
    })
    .await
    .map_err(|_| PublicErrorCode::PeerSetupTimeout)?
}
