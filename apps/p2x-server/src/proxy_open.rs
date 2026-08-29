use crate::{config::LocalUpstream, stream_admission::AdmissionToken};
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::{PeerId, swarm::ConnectionId};
use p2x_config::ticket_key::VerificationKeyRing;
use p2x_net::proxy_codec;
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicError, PublicErrorCode};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

pub struct Promotion {
    pub admission: AdmissionToken,
    pub acknowledged: oneshot::Sender<bool>,
}

pub struct Release {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub admission: AdmissionToken,
    pub request_id_hash: u64,
    pub stream_id_hash: Option<u64>,
    pub accepted: bool,
    pub code: Option<PublicErrorCode>,
    pub pump: Option<p2x_proxy::PumpResult>,
}

pub enum ServerDecision {
    Admit {
        stream_id: [u8; 16],
        admission: AdmissionToken,
        upstream: Arc<LocalUpstream>,
        copy_buffer_bytes: usize,
    },
    Reject(ProxyOpenResponseV1),
}

pub struct Candidate {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub deadline: std::time::Instant,
    pub open: Result<OpenProxyStreamV1, PublicErrorCode>,
    pub validation: Result<super::ticket_admission::ValidationCandidate, PublicErrorCode>,
    pub decision: oneshot::Sender<ServerDecision>,
}

async fn read_open<T: AsyncRead + Unpin>(
    stream: &mut T,
) -> Result<OpenProxyStreamV1, PublicErrorCode> {
    proxy_codec::read_open(stream)
        .await
        .map_err(|_| PublicErrorCode::ProtocolMalformed)
}

async fn write_response_bounded<T: AsyncWrite + Unpin>(
    stream: &mut T,
    response: &ProxyOpenResponseV1,
    deadline: std::time::Instant,
    cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        result = tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            proxy_codec::write_response(stream, response),
        ) => result.is_ok_and(|result| result.is_ok()),
    }
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
    hold_dial_ms: Option<u64>,
    candidates: mpsc::Sender<Candidate>,
    releases: mpsc::Sender<Release>,
    promotions: mpsc::Sender<Promotion>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let (decision, response) = oneshot::channel();
    let started = std::time::Instant::now();
    let worker_deadline = started + Duration::from_secs(5);
    let started_unix = now;
    let cancel = shutdown.child_token();
    let open = tokio::select! {
        _ = cancel.cancelled() => Err(PublicErrorCode::ExchangeDraining),
        result = tokio::time::timeout(
            worker_deadline.saturating_duration_since(std::time::Instant::now()),
            read_open(&mut stream),
        ) => result
            .ok()
            .and_then(Result::ok)
            .ok_or(PublicErrorCode::ProtocolMalformed),
    };
    let request_id = open.as_ref().ok().map(|open| open.request_id);
    if let Some(delay) = hold_handshake_ms {
        let remaining = worker_deadline.saturating_duration_since(std::time::Instant::now());
        if super::upstream::hold(Duration::from_millis(delay), remaining, cancel.clone())
            .await
            .is_err()
        {
            let request_id_hash = request_id
                .map(p2x_net::lifecycle::stable_hash)
                .unwrap_or_default();
            release(
                &releases,
                peer_id,
                connection_id,
                AdmissionToken::empty(),
                request_id_hash,
                None,
                false,
                Some(PublicErrorCode::PeerSetupTimeout),
                None,
            )
            .await;
            return;
        }
    }
    let validation = match (&verification_ring, open.as_ref()) {
        (Some(ring), Ok(open)) => super::ticket_admission::TicketAdmissionLedger::new(
            super::ticket_admission::MAX_REPLAY_ENTRIES,
            clock_skew,
        )
        .expect("worker verification limits are valid")
        .verify_candidate(
            ring,
            open.ticket.as_bytes(),
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64)
                .max(started_unix),
        ),
        (None, Ok(_)) => Err(PublicErrorCode::AuthSessionRequired),
        (_, Err(_)) => Err(PublicErrorCode::ProtocolMalformed),
    };
    let candidate = Candidate {
        peer_id,
        connection_id,
        deadline: worker_deadline,
        open: open.clone(),
        validation,
        decision,
    };
    let candidate_sent = tokio::select! {
        _ = cancel.cancelled() => false,
        result = tokio::time::timeout(
            worker_deadline.saturating_duration_since(std::time::Instant::now()),
            candidates.send(candidate),
        ) => result.is_ok_and(|result| result.is_ok()),
    };
    if !candidate_sent {
        release(
            &releases,
            peer_id,
            connection_id,
            AdmissionToken::empty(),
            request_id
                .map(p2x_net::lifecycle::stable_hash)
                .unwrap_or_default(),
            None,
            false,
            Some(PublicErrorCode::PeerSetupTimeout),
            None,
        )
        .await;
        return;
    }
    let decision = tokio::select! {
        _ = cancel.cancelled() => ServerDecision::Reject(ProxyOpenResponseV1::Rejected {
            request_id,
            error: PublicError::new(PublicErrorCode::ExchangeDraining, true),
        }),
        decision = tokio::time::timeout(
            worker_deadline.saturating_duration_since(std::time::Instant::now()),
            response,
        ) => decision.ok().and_then(Result::ok).unwrap_or_else(|| ServerDecision::Reject(
            ProxyOpenResponseV1::Rejected {
                request_id,
                error: PublicError::new(PublicErrorCode::PeerSetupTimeout, true),
            },
        )),
    };
    let request_id_hash = request_id
        .map(p2x_net::lifecycle::stable_hash)
        .unwrap_or_default();
    let mut stream_id_hash = None;
    let mut accepted = false;
    let mut code = None;
    let mut pump = None;
    let admission = match decision {
        ServerDecision::Reject(response) => {
            if let ProxyOpenResponseV1::Rejected { error, .. } = &response {
                code = Some(error.code);
            }
            let _ = write_response_bounded(&mut stream, &response, worker_deadline, &cancel).await;
            AdmissionToken::empty()
        }
        ServerDecision::Admit {
            stream_id,
            admission,
            upstream,
            copy_buffer_bytes,
        } => {
            stream_id_hash = Some(p2x_net::lifecycle::stable_hash(stream_id));
            let Ok(open) = open.as_ref() else {
                release(
                    &releases,
                    peer_id,
                    connection_id,
                    admission,
                    request_id_hash,
                    stream_id_hash,
                    false,
                    None,
                    None,
                )
                .await;
                return;
            };
            let remaining = worker_deadline.saturating_duration_since(std::time::Instant::now());
            let dial = match hold_dial_ms {
                Some(delay) => match super::upstream::hold(
                    Duration::from_millis(delay),
                    remaining,
                    cancel.clone(),
                )
                .await
                {
                    Ok(()) => {
                        super::upstream::connect(
                            &upstream,
                            worker_deadline.saturating_duration_since(std::time::Instant::now()),
                            cancel.clone(),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                },
                None => super::upstream::connect(&upstream, remaining, cancel.clone()).await,
            };
            match dial {
                Ok(socket) => {
                    let (acknowledged, ack) = oneshot::channel();
                    if promotions
                        .send(Promotion {
                            admission,
                            acknowledged,
                        })
                        .await
                        .is_err()
                        || !tokio::select! {
                            _ = cancel.cancelled() => false,
                            acknowledged = ack => acknowledged.unwrap_or(false),
                        }
                    {
                        drop(socket);
                        release(
                            &releases,
                            peer_id,
                            connection_id,
                            admission,
                            request_id_hash,
                            stream_id_hash,
                            false,
                            Some(PublicErrorCode::ExchangeDraining),
                            None,
                        )
                        .await;
                        return;
                    }
                    let response = ProxyOpenResponseV1::Accepted {
                        request_id: open.request_id,
                        stream_id,
                        selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp,
                    };
                    if write_response_bounded(&mut stream, &response, worker_deadline, &cancel)
                        .await
                    {
                        accepted = true;
                        pump = p2x_proxy::pump(
                            stream,
                            tokio_util::compat::TokioAsyncReadCompatExt::compat(socket),
                            copy_buffer_bytes,
                            upstream.idle_timeout,
                            shutdown.cancelled(),
                        )
                        .await
                        .ok();
                        if pump.as_ref().is_some_and(|result| {
                            result.terminal == p2x_proxy::Terminal::IdleTimeout
                        }) {
                            code = Some(PublicErrorCode::UpstreamIdleTimeout);
                        }
                    } else {
                        code = Some(PublicErrorCode::ProtocolMalformed);
                    }
                }
                Err(error) => {
                    code = Some(error.code());
                    let response = ProxyOpenResponseV1::Rejected {
                        request_id: Some(open.request_id),
                        error: PublicError::new(error.code(), true),
                    };
                    let _ =
                        write_response_bounded(&mut stream, &response, worker_deadline, &cancel)
                            .await;
                }
            }
            admission
        }
    };
    release(
        &releases,
        peer_id,
        connection_id,
        admission,
        request_id_hash,
        stream_id_hash,
        accepted,
        code,
        pump,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn release(
    releases: &mpsc::Sender<Release>,
    peer_id: PeerId,
    connection_id: ConnectionId,
    admission: AdmissionToken,
    request_id_hash: u64,
    stream_id_hash: Option<u64>,
    accepted: bool,
    code: Option<PublicErrorCode>,
    pump: Option<p2x_proxy::PumpResult>,
) {
    let _ = releases
        .send(Release {
            peer_id,
            connection_id,
            admission,
            request_id_hash,
            stream_id_hash,
            accepted,
            code,
            pump,
        })
        .await;
}

pub async fn reject_stream<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    code: PublicErrorCode,
) {
    let request_id = proxy_codec::read_open(&mut stream)
        .await
        .ok()
        .map(|open| open.request_id);
    let response = ProxyOpenResponseV1::Rejected {
        request_id,
        error: PublicError::new(code, true),
    };
    let _ = proxy_codec::write_response(&mut stream, &response).await;
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
    fn open_reads_one_frame_without_waiting_for_write_half_close() {
        let mut valid = Cursor::new(framed_open());
        assert_eq!(block_on(read_open(&mut valid)).unwrap(), open());

        let mut early_data = framed_open();
        early_data.push(0x42);
        assert_eq!(
            block_on(read_open(&mut Cursor::new(early_data))).unwrap(),
            open()
        );
    }
}
