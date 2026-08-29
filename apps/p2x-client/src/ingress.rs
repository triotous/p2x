use crate::config::RawTcpListener;
use p2x_proxy::{PrefixedIo, PumpResult};
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

pub struct BoundListener {
    listener: TcpListener,
    config: RawTcpListener,
}

pub async fn bind_all(configs: &[RawTcpListener]) -> io::Result<Vec<BoundListener>> {
    let mut bound = Vec::with_capacity(configs.len());
    for config in configs {
        bound.push(BoundListener {
            listener: TcpListener::bind(config.bind).await?,
            config: config.clone(),
        });
    }
    Ok(bound)
}

pub fn spawn_all(
    listeners: Vec<BoundListener>,
    max_connections: usize,
    copy_buffer_bytes: usize,
    setup_timeout: Duration,
    events: mpsc::Sender<IngressEvent>,
    shutdown: CancellationToken,
) -> Vec<JoinHandle<()>> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let next_id = Arc::new(AtomicU64::new(0));
    listeners
        .into_iter()
        .map(|bound| {
            let permits = permits.clone();
            let next_id = next_id.clone();
            let events = events.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                accept_loop(
                    bound,
                    permits,
                    next_id,
                    copy_buffer_bytes,
                    setup_timeout,
                    events,
                    shutdown,
                )
                .await;
            })
        })
        .collect()
}

async fn accept_loop(
    bound: BoundListener,
    permits: Arc<Semaphore>,
    next_id: Arc<AtomicU64>,
    copy_buffer_bytes: usize,
    setup_timeout: Duration,
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
        let route_id = bound.config.route_id.clone();
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
        let (command, commands) = mpsc::channel(1);
        let cancel = shutdown.child_token();
        if events
            .send(IngressEvent::Accepted {
                id,
                route_id: route_id.clone(),
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
        ));
    }
    while connections.join_next().await.is_some() {}
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
) {
    let mut prebuffer = vec![0; copy_buffer_bytes];
    let mut filled = 0;
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
                    let local = PrefixedIo::new(prebuffer, socket.compat());
                    let result = p2x_proxy::pump_no_idle(local, stream, copy_buffer_bytes, cancel.cancelled()).await;
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
