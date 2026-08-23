use futures::io::{AsyncRead, AsyncReadExt};
use libp2p::{PeerId, swarm::ConnectionId};
use p2x_config::ticket_key::VerificationKeyRing;
use p2x_net::proxy_codec;
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicError, PublicErrorCode};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug)]
pub struct Release {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
}

pub struct Candidate {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub open: Result<OpenProxyStreamV1, PublicErrorCode>,
    pub validation: Result<super::ticket_admission::ValidationCandidate, PublicErrorCode>,
    pub decision: oneshot::Sender<ProxyOpenResponseV1>,
}

async fn read_open_and_require_half_close<T: AsyncRead + Unpin>(
    stream: &mut T,
) -> Result<OpenProxyStreamV1, PublicErrorCode> {
    let open = proxy_codec::read_open(stream)
        .await
        .map_err(|_| PublicErrorCode::ProtocolMalformed)?;
    let mut early_application_byte = [0; 1];
    if stream
        .read(&mut early_application_byte)
        .await
        .map_err(|_| PublicErrorCode::ProtocolMalformed)?
        != 0
    {
        return Err(PublicErrorCode::ProtocolMalformed);
    }
    Ok(open)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_worker(
    peer_id: PeerId,
    connection_id: ConnectionId,
    mut stream: libp2p::swarm::Stream,
    verification_ring: Option<VerificationKeyRing>,
    now: i64,
    clock_skew: i64,
    hold_handshake_ms: Option<u64>,
    candidates: mpsc::Sender<Candidate>,
    releases: mpsc::Sender<Release>,
) {
    let (decision, response) = oneshot::channel();
    let open = tokio::time::timeout(
        Duration::from_secs(5),
        read_open_and_require_half_close(&mut stream),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .ok_or(PublicErrorCode::ProtocolMalformed);
    let request_id = open.as_ref().ok().map(|open| open.request_id);
    if let Some(delay) = hold_handshake_ms {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let validation = match (&verification_ring, open.as_ref()) {
        (Some(ring), Ok(open)) => super::ticket_admission::TicketAdmissionLedger::new(
            super::ticket_admission::MAX_REPLAY_ENTRIES,
            clock_skew,
        )
        .expect("worker verification limits are valid")
        .verify_candidate(ring, open.ticket.as_bytes(), now),
        (None, Ok(_)) => Err(PublicErrorCode::AuthSessionRequired),
        (_, Err(code)) => Err(*code),
    };
    if candidates
        .send(Candidate {
            peer_id,
            connection_id,
            open,
            validation,
            decision,
        })
        .await
        .is_err()
    {
        let _ = releases
            .send(Release {
                peer_id,
                connection_id,
            })
            .await;
        return;
    }
    let response = response
        .await
        .unwrap_or_else(|_| ProxyOpenResponseV1::Rejected {
            request_id,
            error: PublicError::new(PublicErrorCode::ExchangeOverloaded, true),
        });
    let _ = proxy_codec::write_response(&mut stream, &response).await;
    let _ = releases
        .send(Release {
            peer_id,
            connection_id,
        })
        .await;
}

pub fn random_stream_id() -> Result<[u8; 16], PublicErrorCode> {
    let mut stream_id = [0; 16];
    getrandom::fill(&mut stream_id).map_err(|_| PublicErrorCode::ExchangeOverloaded)?;
    Ok(stream_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, io::Cursor};
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

    fn framed_open() -> Vec<u8> {
        let body = open().canonical_bytes().unwrap();
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn open_requires_write_half_close_before_authorization() {
        let mut valid = Cursor::new(framed_open());
        assert_eq!(
            block_on(read_open_and_require_half_close(&mut valid)).unwrap(),
            open()
        );

        let mut early_data = framed_open();
        early_data.push(0x42);
        assert_eq!(
            block_on(read_open_and_require_half_close(&mut Cursor::new(
                early_data
            ))),
            Err(PublicErrorCode::ProtocolMalformed)
        );
    }
}
