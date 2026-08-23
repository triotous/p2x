use super::handler::{OpenProxy, ProxyEvent, ProxyHandler, ProxyRequestId};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
};
use p2x_protocol::OpenProxyStreamV1;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::{Context, Poll},
    time::{Duration, Instant},
};

const MAX_PENDING: usize = 128;
const MAX_PER_PEER: usize = 64;
const MAX_QUEUE: usize = 128;
const OPEN_DEADLINE: Duration = Duration::from_secs(5);
pub const MAX_INBOUND_WORKERS: usize = 256;
pub const MAX_INBOUND_WORKERS_PER_PEER: usize = 32;
#[derive(Debug)]
pub enum ProxyOutput {
    OutboundOpened {
        request_id: ProxyRequestId,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream: libp2p::swarm::Stream,
    },
    OutboundFailed {
        request_id: ProxyRequestId,
        peer_id: PeerId,
        connection_id: ConnectionId,
        code: &'static str,
    },
    InboundOpened {
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream: libp2p::swarm::Stream,
    },
    InboundRejected {
        peer_id: PeerId,
        connection_id: ConnectionId,
        code: &'static str,
    },
}
#[derive(Default)]
pub struct ProxyStreamBehaviour {
    inbound_enabled: bool,
    outbound_enabled: bool,
    next: u64,
    known: HashSet<(PeerId, ConnectionId)>,
    pending: HashMap<ProxyRequestId, PendingOpen>,
    commands: VecDeque<ProxyRequestId>,
    terminals: VecDeque<ProxyRequestId>,
    inbound_events: VecDeque<ProxyOutput>,
    inbound_workers: HashMap<PeerId, usize>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Queued,
    Notified,
    TerminalQueued,
}
struct PendingOpen {
    request: OpenProxy,
    deadline: Instant,
    phase: Phase,
    terminal: Option<ProxyOutput>,
}
impl ProxyStreamBehaviour {
    pub fn product() -> Self {
        Self {
            inbound_enabled: false,
            outbound_enabled: true,
            ..Self::default()
        }
    }
    pub fn server() -> Self {
        Self {
            inbound_enabled: true,
            outbound_enabled: false,
            ..Self::default()
        }
    }
    pub fn open_on(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        open: OpenProxyStreamV1,
    ) -> Result<ProxyRequestId, &'static str> {
        self.open_on_at(peer_id, connection_id, open, Instant::now())
    }
    pub fn open_on_at(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        open: OpenProxyStreamV1,
        now: Instant,
    ) -> Result<ProxyRequestId, &'static str> {
        if !self.known.contains(&(peer_id, connection_id)) {
            return Err("connection_unknown");
        }
        if self.pending.len() >= MAX_PENDING
            || self
                .pending
                .values()
                .filter(|p| p.request.peer_id == peer_id)
                .count()
                >= MAX_PER_PEER
            || self.commands.len() >= MAX_QUEUE
        {
            return Err("limit.proxy_streams");
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or("proxy.request_id_exhausted")?;
        let request_id = ProxyRequestId(self.next);
        self.pending.insert(
            request_id,
            PendingOpen {
                request: OpenProxy {
                    request_id,
                    peer_id,
                    connection_id,
                    open,
                },
                deadline: now + OPEN_DEADLINE,
                phase: Phase::Queued,
                terminal: None,
            },
        );
        self.commands.push_back(request_id);
        Ok(request_id)
    }
    pub fn inbound_admit(&mut self, peer_id: PeerId) -> Result<(), &'static str> {
        let total: usize = self.inbound_workers.values().sum();
        let count = self.inbound_workers.entry(peer_id).or_default();
        if total >= MAX_INBOUND_WORKERS || *count >= MAX_INBOUND_WORKERS_PER_PEER {
            return Err("limit.proxy_streams");
        }
        *count += 1;
        Ok(())
    }
    pub fn inbound_release(&mut self, peer_id: PeerId) {
        if let Some(count) = self.inbound_workers.get_mut(&peer_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.inbound_workers.remove(&peer_id);
            }
        }
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn expire(&mut self, now: Instant) {
        let requests = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for request in requests {
            self.fail(request, "peer.setup_timeout");
        }
    }
    pub fn cancel(&mut self, request_id: ProxyRequestId) -> bool {
        self.fail(request_id, "proxy.cancelled")
    }
    pub fn shutdown(&mut self) {
        let requests = self.pending.keys().copied().collect::<Vec<_>>();
        for request in requests {
            self.fail(request, "proxy.shutdown");
        }
        self.commands.clear();
    }
    fn fail(&mut self, request_id: ProxyRequestId, code: &'static str) -> bool {
        let Some(request) = self
            .pending
            .get(&request_id)
            .map(|pending| pending.request.clone())
        else {
            return false;
        };
        self.terminal(
            request_id,
            ProxyOutput::OutboundFailed {
                request_id,
                peer_id: request.peer_id,
                connection_id: request.connection_id,
                code,
            },
        )
    }
    fn terminal(&mut self, request_id: ProxyRequestId, output: ProxyOutput) -> bool {
        let Some(pending) = self.pending.get_mut(&request_id) else {
            return false;
        };
        if pending.phase == Phase::TerminalQueued {
            return false;
        }
        self.commands.retain(|id| *id != request_id);
        pending.phase = Phase::TerminalQueued;
        pending.terminal = Some(output);
        self.terminals.push_back(request_id);
        true
    }
    fn pop_terminal(&mut self) -> Option<ProxyOutput> {
        let id = self.terminals.pop_front()?;
        self.pending.remove(&id)?.terminal
    }
}
impl NetworkBehaviour for ProxyStreamBehaviour {
    type ConnectionHandler = ProxyHandler;
    type ToSwarm = ProxyOutput;
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.known.insert((peer, id));
        Ok(ProxyHandler::with_surface(
            self.inbound_enabled,
            self.outbound_enabled,
        ))
    }
    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.known.insert((peer, id));
        Ok(ProxyHandler::with_surface(
            self.inbound_enabled,
            self.outbound_enabled,
        ))
    }
    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionClosed(closed) = event {
            self.known.remove(&(closed.peer_id, closed.connection_id));
            let requests = self
                .pending
                .iter()
                .filter(|(_, pending)| {
                    pending.request.peer_id == closed.peer_id
                        && pending.request.connection_id == closed.connection_id
                })
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            for request in requests {
                self.fail(request, "proxy.connection_closed");
            }
        }
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            ProxyEvent::OutboundOpened { request_id, stream } => {
                if let Some(request) = self
                    .pending
                    .get(&request_id)
                    .map(|pending| pending.request.clone())
                {
                    if request.peer_id == peer && request.connection_id == id {
                        self.terminal(
                            request_id,
                            ProxyOutput::OutboundOpened {
                                request_id,
                                peer_id: peer,
                                connection_id: id,
                                stream,
                            },
                        );
                    } else {
                        self.terminal(
                            request_id,
                            ProxyOutput::OutboundFailed {
                                request_id,
                                peer_id: request.peer_id,
                                connection_id: request.connection_id,
                                code: "proxy.internal_identity_mismatch",
                            },
                        );
                    }
                }
            }
            ProxyEvent::OutboundFailed { request_id, code } => {
                if let Some(request) = self
                    .pending
                    .get(&request_id)
                    .map(|pending| pending.request.clone())
                {
                    let (peer_id, connection_id, code) =
                        if request.peer_id == peer && request.connection_id == id {
                            (peer, id, code)
                        } else {
                            (
                                request.peer_id,
                                request.connection_id,
                                "proxy.internal_identity_mismatch",
                            )
                        };
                    self.terminal(
                        request_id,
                        ProxyOutput::OutboundFailed {
                            request_id,
                            peer_id,
                            connection_id,
                            code,
                        },
                    );
                }
            }
            ProxyEvent::InboundOpened { stream } => {
                if self.inbound_events.len() < MAX_PENDING && self.inbound_admit(peer).is_ok() {
                    self.inbound_events.push_back(ProxyOutput::InboundOpened {
                        peer_id: peer,
                        connection_id: id,
                        stream,
                    });
                } else if self.inbound_events.len() < MAX_PENDING {
                    self.inbound_events.push_back(ProxyOutput::InboundRejected {
                        peer_id: peer,
                        connection_id: id,
                        code: "limit.proxy_streams",
                    });
                }
            }
        }
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.pop_terminal() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        if let Some(event) = self.inbound_events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        while let Some(id) = self.commands.pop_front() {
            let Some(pending) = self.pending.get_mut(&id) else {
                continue;
            };
            if pending.phase != Phase::Queued {
                continue;
            }
            pending.phase = Phase::Notified;
            return Poll::Ready(ToSwarm::NotifyHandler {
                peer_id: pending.request.peer_id,
                handler: NotifyHandler::One(pending.request.connection_id),
                event: pending.request.clone(),
            });
        }
        Poll::Pending
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_open_is_bounded_and_terminal_once() {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(1);
        let mut behaviour = ProxyStreamBehaviour::default();
        behaviour.known.insert((peer, connection));
        let open = OpenProxyStreamV1 {
            request_id: [1; 16],
            ticket: p2x_protocol::RawTicket::new(vec![7; 16]).unwrap(),
            upstream_id: p2x_protocol::UpstreamId::new("orders").unwrap(),
            registration_revision: p2x_protocol::RegistrationRevision::new(1).unwrap(),
            ingress_kind: p2x_protocol::IngressKind::FixedTcp,
        };
        let request = behaviour.open_on(peer, connection, open).unwrap();
        assert!(behaviour.cancel(request));
        assert!(!behaviour.cancel(request));
        assert_eq!(behaviour.pending_count(), 1);
    }
}
