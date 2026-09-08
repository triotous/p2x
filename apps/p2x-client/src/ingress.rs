use crate::{
    config::{AdapterListenerConfig, RawTcpListener},
    router::{AdapterKind, DomainRouter},
};
use p2x_protocol::IngressKind;
use p2x_proxy::{PrefixedIo, PumpResult, http_io::HttpGuardedIo, tls::ClientHelloInspector};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IngressId(pub u64);

pub trait TunnelIo: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin + Send {}
impl<T> TunnelIo for T where T: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin + Send {}

pub enum IngressCommand {
    StartTunnel { stream: Box<dyn TunnelIo> },
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreAcceptCause {
    Eof,
    LocalIo,
    Deadline,
    Shutdown,
}

#[derive(Debug, Error)]
pub enum PumpFailure {
    #[error("pump setup failed: {0}")]
    Setup(#[from] io::Error),
}

pub enum IngressEvent {
    Accepted {
        id: IngressId,
        route_id: String,
        kind: IngressKind,
        started_at: Instant,
        deadline: Instant,
        command: mpsc::Sender<IngressCommand>,
        cancel: CancellationToken,
    },
    Rejected {
        id: IngressId,
        route_id: String,
        code: &'static str,
    },
    PreAcceptClosed {
        id: IngressId,
        cause: PreAcceptCause,
    },
    TunnelFinished {
        id: IngressId,
        result: Result<PumpResult, PumpFailure>,
    },
}

enum ListenerConfig {
    Raw(RawTcpListener),
    Adapter(AdapterListenerConfig),
}

pub struct BoundListener {
    listener: TcpListener,
    config: ListenerConfig,
}

pub async fn bind_all(
    raw: &[RawTcpListener],
    adapters: &[AdapterListenerConfig],
) -> io::Result<Vec<BoundListener>> {
    let configs = raw
        .iter()
        .cloned()
        .map(ListenerConfig::Raw)
        .chain(adapters.iter().cloned().map(ListenerConfig::Adapter));
    let configs = configs.collect::<Vec<_>>();
    let mut bound = Vec::with_capacity(configs.len());
    for config in configs {
        let bind = match &config {
            ListenerConfig::Raw(config) => config.bind,
            ListenerConfig::Adapter(config) => config.bind,
        };
        bound.push(BoundListener {
            listener: TcpListener::bind(bind).await?,
            config,
        });
    }
    Ok(bound)
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_all(
    listeners: Vec<BoundListener>,
    max_connections: usize,
    copy_buffer_bytes: usize,
    setup_timeout: Duration,
    parse_timeout: Duration,
    max_http_header_bytes: usize,
    max_tls_client_hello_bytes: usize,
    router: DomainRouter,
    events: mpsc::Sender<IngressEvent>,
    shutdown: CancellationToken,
) -> Vec<JoinHandle<()>> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let next_id = Arc::new(AtomicU64::new(0));
    let router = std::sync::Arc::new(router);
    listeners
        .into_iter()
        .map(|bound| {
            let permits = permits.clone();
            let next_id = next_id.clone();
            let events = events.clone();
            let shutdown = shutdown.clone();
            let router = router.clone();
            tokio::spawn(async move {
                accept_loop(
                    bound,
                    permits,
                    next_id,
                    copy_buffer_bytes,
                    setup_timeout,
                    parse_timeout,
                    max_http_header_bytes,
                    max_tls_client_hello_bytes,
                    (*router).clone(),
                    events,
                    shutdown,
                )
                .await;
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    bound: BoundListener,
    permits: Arc<Semaphore>,
    next_id: Arc<AtomicU64>,
    copy_buffer_bytes: usize,
    setup_timeout: Duration,
    parse_timeout: Duration,
    max_http_header_bytes: usize,
    max_tls_client_hello_bytes: usize,
    router: DomainRouter,
    events: mpsc::Sender<IngressEvent>,
    shutdown: CancellationToken,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = bound.listener.accept() => accepted,
        };
        let (socket, _) = match accepted {
            Ok(accepted) => accepted,
            Err(_) if shutdown.is_cancelled() => break,
            Err(_) => continue,
        };
        let id = IngressId(next_id.fetch_add(1, Ordering::Relaxed).saturating_add(1));
        let (route_id, adapter) = match &bound.config {
            ListenerConfig::Raw(config) => (config.route_id.clone(), None),
            ListenerConfig::Adapter(config) => (String::new(), Some(config.clone())),
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(socket);
            if events
                .send(IngressEvent::Rejected {
                    id,
                    route_id,
                    code: p2x_protocol::PublicErrorCode::LimitProxyStreams.as_str(),
                })
                .await
                .is_err()
            {
                return;
            }
            continue;
        };
        let started_at = Instant::now();
        let deadline = started_at + setup_timeout;
        if let Some(adapter) = adapter {
            connections.spawn(run_adapter_connection(
                id,
                adapter,
                router.clone(),
                socket,
                permit,
                copy_buffer_bytes,
                parse_timeout,
                max_http_header_bytes,
                max_tls_client_hello_bytes,
                started_at,
                deadline,
                events.clone(),
                shutdown.clone(),
            ));
            continue;
        }
        let (command, commands) = mpsc::channel(1);
        let cancel = shutdown.child_token();
        if events
            .send(IngressEvent::Accepted {
                id,
                route_id: route_id.clone(),
                kind: IngressKind::FixedTcp,
                started_at,
                deadline,
                command,
                cancel: cancel.clone(),
            })
            .await
            .is_err()
        {
            drop(permit);
            return;
        }
        let events = events.clone();
        let shutdown = shutdown.clone();
        connections.spawn(run_connection(
            id,
            route_id,
            socket,
            commands,
            permit,
            copy_buffer_bytes,
            deadline,
            events,
            cancel,
            shutdown.clone(),
            IngressKind::FixedTcp,
            None,
            None,
            Vec::new(),
        ));
    }
    while connections.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn run_adapter_connection(
    id: IngressId,
    adapter: AdapterListenerConfig,
    router: DomainRouter,
    socket: TcpStream,
    permit: tokio::sync::OwnedSemaphorePermit,
    copy_buffer_bytes: usize,
    parse_timeout: Duration,
    max_http_header_bytes: usize,
    max_tls_client_hello_bytes: usize,
    started_at: Instant,
    deadline: Instant,
    events: mpsc::Sender<IngressEvent>,
    shutdown: CancellationToken,
) {
    let failure_events = events.clone();
    let parse_deadline = (started_at + parse_timeout).min(deadline);
    let parse_budget = parse_deadline.saturating_duration_since(Instant::now());
    let parse_expired_as_setup = parse_deadline == deadline;
    let parsed = tokio::time::timeout(
        parse_budget,
        parse_adapter_preface(
            adapter,
            router,
            socket,
            max_http_header_bytes,
            max_tls_client_hello_bytes,
            permit,
        ),
    )
    .await;
    let (socket, permit, route_id, kind, http_state, prefix) = match parsed {
        Err(_) => {
            let code = if parse_expired_as_setup {
                "peer.setup_timeout"
            } else {
                "route.parse_timeout"
            };
            let _ = failure_events
                .send(IngressEvent::Rejected {
                    id,
                    route_id: String::new(),
                    code,
                })
                .await;
            return;
        }
        Ok(Ok(parsed)) => parsed,
        Ok(Err(error)) => {
            let _ = failure_events
                .send(IngressEvent::Rejected {
                    id,
                    route_id: String::new(),
                    code: adapter_error_code(&error),
                })
                .await;
            return;
        }
    };
    if Instant::now() >= deadline {
        let _ = failure_events
            .send(IngressEvent::Rejected {
                id,
                route_id,
                code: "peer.setup_timeout",
            })
            .await;
        drop((socket, permit));
        return;
    }
    let (command, commands) = mpsc::channel(1);
    let cancel = shutdown.child_token();
    if events
        .send(IngressEvent::Accepted {
            id,
            route_id: route_id.clone(),
            kind,
            started_at,
            deadline,
            command,
            cancel: cancel.clone(),
        })
        .await
        .is_err()
    {
        drop((socket, permit));
        return;
    }
    run_connection(
        id,
        route_id,
        socket,
        commands,
        permit,
        copy_buffer_bytes,
        deadline,
        events,
        cancel,
        shutdown,
        kind,
        (kind == IngressKind::HttpHost).then_some(max_http_header_bytes),
        http_state,
        prefix,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn parse_adapter_preface(
    adapter: AdapterListenerConfig,
    router: DomainRouter,
    mut socket: TcpStream,
    max_http_header_bytes: usize,
    max_tls_client_hello_bytes: usize,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> io::Result<(
    TcpStream,
    tokio::sync::OwnedSemaphorePermit,
    String,
    IngressKind,
    Option<(p2x_proxy::http::HttpRequestGate, Vec<u8>)>,
    Vec<u8>,
)> {
    let max_prefix = match adapter.kind {
        AdapterKind::Http => max_http_header_bytes,
        AdapterKind::TlsSni => max_tls_client_hello_bytes,
    };
    let mut prefix = Vec::with_capacity(max_prefix);
    let mut http_gate = (adapter.kind == AdapterKind::Http)
        .then(|| p2x_proxy::http::HttpRequestGate::new(max_http_header_bytes))
        .transpose()
        .map_err(io::Error::other)?;
    let mut http_ready = Vec::new();
    let mut tls = (adapter.kind == AdapterKind::TlsSni)
        .then(|| ClientHelloInspector::new(max_tls_client_hello_bytes))
        .transpose()
        .map_err(io::Error::other)?;
    loop {
        let mut chunk = vec![0; 4096.min(max_prefix.saturating_sub(prefix.len()).max(1))];
        let count = socket.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "adapter EOF"));
        }
        if adapter.kind == AdapterKind::Http {
            prefix.extend_from_slice(&chunk[..count]);
        }
        let domain = match adapter.kind {
            AdapterKind::Http => {
                let gate = http_gate.as_mut().expect("HTTP gate");
                http_ready.extend(gate.feed(&chunk[..count]).map_err(io::Error::other)?);
                gate.locked_authority()
                    .map(|authority| authority.domain.clone())
            }
            AdapterKind::TlsSni => match tls
                .as_mut()
                .expect("TLS inspector")
                .feed(&chunk[..count])
                .map_err(io::Error::other)?
            {
                p2x_proxy::tls::ClientHelloResult::NeedMore => None,
                p2x_proxy::tls::ClientHelloResult::Selected { domain, .. } => Some(domain),
            },
        };
        if let Some(domain) = domain {
            let target = router
                .lookup(adapter.id, &domain)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "domain route not found"))?;
            let kind = match adapter.kind {
                AdapterKind::Http => IngressKind::HttpHost,
                AdapterKind::TlsSni => IngressKind::TlsSni,
            };
            if adapter.kind == AdapterKind::TlsSni {
                prefix = tls.take().expect("TLS inspector").into_prefix();
            }
            return Ok((
                socket,
                permit,
                target.route_id.clone(),
                kind,
                http_gate.take().map(|gate| (gate, http_ready)),
                if adapter.kind == AdapterKind::Http {
                    Vec::new()
                } else {
                    prefix
                },
            ));
        }
        if adapter.kind == AdapterKind::Http && prefix.len() == max_prefix {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "adapter prefix limit",
            ));
        }
    }
}

fn adapter_error_code(error: &io::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("domain route not found") {
        "route.not_found"
    } else if message.contains("Host is required") {
        "route.host_required"
    } else if message.contains("Missing SNI") || message.contains("SNI is required") {
        "route.sni_required"
    } else if message.contains("unsupported") {
        "route.unsupported_protocol"
    } else if message.contains("limit") || message.contains("prefix") {
        "limit.ingress_preface"
    } else {
        "route.malformed"
    }
}

async fn send_pre_accept(
    events: &mpsc::Sender<IngressEvent>,
    id: IngressId,
    cause: PreAcceptCause,
    delivered: &mut bool,
) {
    if *delivered {
        return;
    }
    *delivered = true;
    let _ = events
        .send(IngressEvent::PreAcceptClosed { id, cause })
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    id: IngressId,
    _route_id: String,
    mut socket: TcpStream,
    mut commands: mpsc::Receiver<IngressCommand>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    copy_buffer_bytes: usize,
    deadline_at: Instant,
    events: mpsc::Sender<IngressEvent>,
    cancel: CancellationToken,
    shutdown: CancellationToken,
    initial_kind: IngressKind,
    http_limit: Option<usize>,
    http_state: Option<(p2x_proxy::http::HttpRequestGate, Vec<u8>)>,
    initial_prefix: Vec<u8>,
) {
    let mut prebuffer = vec![0; copy_buffer_bytes.max(initial_prefix.len())];
    prebuffer[..initial_prefix.len()].copy_from_slice(&initial_prefix);
    let mut filled = initial_prefix.len();
    let mut terminal_delivered = false;
    let deadline = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline_at));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                send_pre_accept(&events, id, PreAcceptCause::Deadline, &mut terminal_delivered).await;
                return;
            },
            _ = shutdown.cancelled() => {
                send_pre_accept(&events, id, PreAcceptCause::Shutdown, &mut terminal_delivered).await;
                return;
            },
            command = commands.recv() => match command {
                Some(IngressCommand::StartTunnel { stream }) => {
                    prebuffer.truncate(filled);
                    let result = match (initial_kind, http_limit, http_state) {
                        (IngressKind::HttpHost, Some(_limit), Some((gate, ready))) => {
                            let local = PrefixedIo::new(prebuffer, socket.compat());
                            let guarded = HttpGuardedIo::with_state(
                                local, gate, ready, copy_buffer_bytes,
                            );
                            p2x_proxy::pump_no_idle(
                                guarded,
                                stream,
                                copy_buffer_bytes,
                                cancel.cancelled(),
                            )
                            .await
                        }
                        _ => {
                            let local = PrefixedIo::new(prebuffer, socket.compat());
                            p2x_proxy::pump_no_idle(
                                local,
                                stream,
                                copy_buffer_bytes,
                                cancel.cancelled(),
                            )
                            .await
                        }
                    };
                    let _ = events
                        .send(IngressEvent::TunnelFinished {
                            id,
                            result: result.map_err(PumpFailure::Setup),
                        })
                        .await;
                    return;
                }
                Some(IngressCommand::Reject) | None => return,
            },
            read = socket.read(&mut prebuffer[filled..]), if filled < prebuffer.len() => match read {
                Ok(0) => {
                    send_pre_accept(&events, id, PreAcceptCause::Eof, &mut terminal_delivered).await;
                    return;
                }
                Ok(count) => filled += count,
                Err(_) => {
                    send_pre_accept(&events, id, PreAcceptCause::LocalIo, &mut terminal_delivered).await;
                    return;
                }
            },
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn adapter_selects_exact_route_before_accepting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address);
        let (client, accepted) = tokio::join!(client, listener.accept());
        let mut client = client.unwrap();
        let (socket, _) = accepted.unwrap();
        let router = DomainRouter::build(
            &[(
                crate::router::ListenerId(1),
                "http".into(),
                AdapterKind::Http,
            )],
            &[crate::router::DomainRouteSpec {
                listener: "http".into(),
                domain: "orders.example".into(),
                route_id: "orders".into(),
            }],
            &[("orders".into(), p2x_protocol::ProtocolClass::Http)],
        )
        .unwrap();
        let (events, mut received) = mpsc::channel(2);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: orders.example\r\n\r\n")
            .await
            .unwrap();
        let task = tokio::spawn(run_adapter_connection(
            IngressId(1),
            AdapterListenerConfig {
                id: crate::router::ListenerId(1),
                name: "http".into(),
                bind: address,
                kind: AdapterKind::Http,
            },
            router,
            socket,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            p2x_proxy::MIN_COPY_BUFFER,
            Duration::from_secs(1),
            16 * 1024,
            64 * 1024,
            Instant::now(),
            Instant::now() + Duration::from_secs(1),
            events,
            CancellationToken::new(),
        ));
        let command = match received.recv().await.unwrap() {
            IngressEvent::Accepted {
                command,
                kind,
                route_id,
                ..
            } => {
                assert_eq!(kind, IngressKind::HttpHost);
                assert_eq!(route_id, "orders");
                command
            }
            _ => panic!("adapter did not accept the selected route"),
        };
        let (mut remote_peer, remote) = tokio::io::duplex(256);
        command
            .send(IngressCommand::StartTunnel {
                stream: Box::new(remote.compat()),
            })
            .await
            .unwrap();
        let mut forwarded = vec![0; b"GET / HTTP/1.1\r\nHost: orders.example\r\n\r\n".len()];
        remote_peer.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, b"GET / HTTP/1.1\r\nHost: orders.example\r\n\r\n");
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn pre_accept_terminal_is_delivered_once() {
        let (events, mut received) = mpsc::channel(2);
        let mut delivered = false;
        send_pre_accept(&events, IngressId(1), PreAcceptCause::Eof, &mut delivered).await;
        send_pre_accept(
            &events,
            IngressId(1),
            PreAcceptCause::Deadline,
            &mut delivered,
        )
        .await;
        assert!(matches!(
            received.recv().await,
            Some(IngressEvent::PreAcceptClosed {
                id: IngressId(1),
                cause: PreAcceptCause::Eof,
            })
        ));
        assert!(received.try_recv().is_err());
    }

    #[tokio::test]
    async fn bound_listener_forwards_prefixed_bytes_after_start() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (events, mut received) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let permits = Arc::new(Semaphore::new(1));
        let (command, commands) = mpsc::channel(1);
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let id = IngressId(1);
        let mut client = client;
        client.write_all(b"prefix").await.unwrap();
        let task = tokio::spawn(run_connection(
            id,
            "orders".into(),
            server,
            commands,
            permits.try_acquire_owned().unwrap(),
            p2x_proxy::MIN_COPY_BUFFER,
            Instant::now() + Duration::from_secs(1),
            events,
            shutdown.child_token(),
            shutdown.clone(),
            IngressKind::FixedTcp,
            None,
            None,
            Vec::new(),
        ));
        let (mut remote_peer, remote) = tokio::io::duplex(64);
        command
            .send(IngressCommand::StartTunnel {
                stream: Box::new(remote.compat()),
            })
            .await
            .unwrap();
        let mut bytes = [0; 6];
        tokio::io::AsyncReadExt::read_exact(&mut remote_peer, &mut bytes)
            .await
            .unwrap();
        assert_eq!(&bytes, b"prefix");
        shutdown.cancel();
        task.abort();
        let _ = received.try_recv();
    }
}
