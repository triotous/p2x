use futures::io::{AsyncRead, AsyncWrite};
use p2x_net::proxy_codec;
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicErrorCode};
use std::time::Duration;

pub async fn open_accepted_stream<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    open: &OpenProxyStreamV1,
    timeout: Duration,
) -> Result<([u8; 16], [u8; 16], T), PublicErrorCode> {
    let deadline = tokio::time::Instant::now() + timeout;
    let result = tokio::time::timeout_at(deadline, async {
        proxy_codec::write_open(&mut stream, open)
            .await
            .map_err(|_| PublicErrorCode::ProtocolMalformed)?;
        match proxy_codec::read_response(&mut stream)
            .await
            .map_err(|_| PublicErrorCode::ProtocolMalformed)?
        {
            ProxyOpenResponseV1::Accepted {
                request_id,
                stream_id,
                selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp,
            } if request_id == open.request_id => Ok((request_id, stream_id, stream)),
            ProxyOpenResponseV1::Rejected { request_id, error }
                if request_id == Some(open.request_id) || request_id.is_none() =>
            {
                Err(error.code)
            }
            ProxyOpenResponseV1::Rejected { .. } => Err(PublicErrorCode::ProtocolMalformed),
            ProxyOpenResponseV1::Authorized { .. } => {
                Err(PublicErrorCode::ProtocolCapabilityMismatch)
            }
            _ => Err(PublicErrorCode::ProtocolMalformed),
        }
    })
    .await
    .map_err(|_| PublicErrorCode::PeerSetupTimeout)?;
    if tokio::time::Instant::now() >= deadline {
        Err(PublicErrorCode::PeerSetupTimeout)
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
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

    #[tokio::test]
    async fn deadline_wins_when_response_failure_is_already_ready() {
        assert!(matches!(
            open_accepted_stream(Cursor::new(Vec::new()), &open(), Duration::ZERO).await,
            Err(PublicErrorCode::PeerSetupTimeout)
        ));
    }

    #[tokio::test]
    async fn malformed_response_before_deadline_stays_malformed() {
        assert!(matches!(
            open_accepted_stream(Cursor::new(Vec::new()), &open(), Duration::from_secs(1),).await,
            Err(PublicErrorCode::ProtocolMalformed)
        ));
    }
}
