use super::handler::{OpenProbe, ProbeEvent, ProbeHandler, RequestId};
use libp2p::core::{Endpoint, transport::PortUse};
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::{Context, Poll},
    time::{Duration, Instant},
};

const MAX_PENDING: usize = 128;
const MAX_PER_PEER: usize = 64;
const MAX_QUEUE: usize = 128;
const OPEN_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum ProbeOutput {
    OutboundOpened {
        request_id: RequestId,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream: libp2p::swarm::Stream,
    },
    OutboundFailed {
        request_id: RequestId,
        peer_id: PeerId,
        connection_id: ConnectionId,
        code: &'static str,
    },
    InboundOpened {
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream: libp2p::swarm::Stream,
    },
}
#[derive(Default)]
pub struct ProbeStreamBehaviour {
    next: u64,
    known: HashSet<(PeerId, ConnectionId)>,
    pending: HashMap<RequestId, PendingOpen>,
    commands: VecDeque<(PeerId, ConnectionId, OpenProbe)>,
    events: VecDeque<ProbeOutput>,
}
struct PendingOpen {
    peer_id: PeerId,
    connection_id: ConnectionId,
    deadline: Instant,
}
impl ProbeStreamBehaviour {
    pub fn open_on(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) -> Result<RequestId, &'static str> {
        if !self.known.contains(&(peer_id, connection_id)) {
            return Err("connection_unknown");
        }
        if self.pending.len() >= MAX_PENDING
            || self
                .pending
                .values()
                .filter(|p| p.peer_id == peer_id)
                .count()
                >= MAX_PER_PEER
            || self.commands.len() >= MAX_QUEUE
        {
            return Err("limit.command_queue_full");
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or("probe.request_id_exhausted")?;
        let request_id = RequestId(self.next);
        self.pending.insert(
            request_id,
            PendingOpen {
                peer_id,
                connection_id,
                deadline: Instant::now() + OPEN_DEADLINE,
            },
        );
        self.commands.push_back((
            peer_id,
            connection_id,
            OpenProbe {
                request_id,
                peer_id,
                connection_id,
            },
        ));
        Ok(request_id)
    }
    pub fn expire(&mut self, now: Instant) {
        let ids: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.fail(id, "probe.open_timeout");
        }
    }
    pub fn cancel(&mut self, request_id: RequestId) -> bool {
        self.fail(request_id, "probe.cancelled")
    }
    pub fn shutdown(&mut self) {
        let ids: Vec<_> = self.pending.keys().copied().collect();
        for id in ids {
            self.fail(id, "probe.shutdown");
        }
        self.commands.clear();
    }
    fn fail(&mut self, request_id: RequestId, code: &'static str) -> bool {
        if let Some(p) = self.pending.remove(&request_id) {
            self.events.push_back(ProbeOutput::OutboundFailed {
                request_id,
                peer_id: p.peer_id,
                connection_id: p.connection_id,
                code,
            });
            true
        } else {
            false
        }
    }
}
impl NetworkBehaviour for ProbeStreamBehaviour {
    type ConnectionHandler = ProbeHandler;
    type ToSwarm = ProbeOutput;
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.known.insert((peer, id));
        Ok(ProbeHandler::default())
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
        Ok(ProbeHandler::default())
    }
    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionClosed(c) = event {
            self.known.remove(&(c.peer_id, c.connection_id));
            let ids: Vec<_> = self
                .pending
                .iter()
                .filter(|(_, p)| (p.peer_id, p.connection_id) == (c.peer_id, c.connection_id))
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                self.fail(id, "probe.connection_closed");
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
            ProbeEvent::OutboundOpened { request_id, stream } => {
                if let Some(pending) = self.pending.remove(&request_id) {
                    if pending.peer_id != peer || pending.connection_id != id {
                        self.events.push_back(ProbeOutput::OutboundFailed {
                            request_id,
                            peer_id: pending.peer_id,
                            connection_id: pending.connection_id,
                            code: "probe.internal_identity_mismatch",
                        });
                        return;
                    }
                    self.events.push_back(ProbeOutput::OutboundOpened {
                        request_id,
                        peer_id: peer,
                        connection_id: id,
                        stream,
                    });
                }
            }
            ProbeEvent::OutboundFailed { request_id, code } => {
                if let Some(pending) = self.pending.remove(&request_id) {
                    if pending.peer_id != peer || pending.connection_id != id {
                        self.events.push_back(ProbeOutput::OutboundFailed {
                            request_id,
                            peer_id: pending.peer_id,
                            connection_id: pending.connection_id,
                            code: "probe.internal_identity_mismatch",
                        });
                        return;
                    }
                    self.events.push_back(ProbeOutput::OutboundFailed {
                        request_id,
                        peer_id: peer,
                        connection_id: id,
                        code,
                    });
                }
            }
            ProbeEvent::InboundOpened { stream } => {
                self.events.push_back(ProbeOutput::InboundOpened {
                    peer_id: peer,
                    connection_id: id,
                    stream,
                })
            }
        }
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        if let Some((peer_id, connection_id, event)) = self.commands.pop_front() {
            return Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::One(connection_id),
                event,
            });
        }
        Poll::Pending
    }
}
