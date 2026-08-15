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
const MAX_INBOUND_EVENTS: usize = 128;
const OPEN_DEADLINE: Duration = Duration::from_secs(5);
pub const MAX_INBOUND_WORKERS: usize = 128;
pub const MAX_INBOUND_WORKERS_PER_PEER: usize = 64;

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
    InboundRejected {
        peer_id: PeerId,
        connection_id: ConnectionId,
        code: &'static str,
    },
}
#[derive(Default)]
pub struct ProbeStreamBehaviour {
    next: u64,
    known: HashSet<(PeerId, ConnectionId)>,
    pending: HashMap<RequestId, PendingOpen>,
    commands: VecDeque<RequestId>,
    inbound_events: VecDeque<ProbeOutput>,
    outbound_terminals: VecDeque<RequestId>,
    inbound_workers: HashMap<PeerId, usize>,
    inbound_rejected: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingPhase {
    Queued,
    Notified,
    TerminalQueued,
}
struct PendingOpen {
    request: OpenProbe,
    deadline: Instant,
    phase: PendingPhase,
    terminal: Option<ProbeOutput>,
}
impl ProbeStreamBehaviour {
    pub fn inbound_admit(&mut self, peer_id: PeerId) -> Result<(), &'static str> {
        let total: usize = self.inbound_workers.values().sum();
        let peer = self.inbound_workers.entry(peer_id).or_default();
        if total >= MAX_INBOUND_WORKERS || *peer >= MAX_INBOUND_WORKERS_PER_PEER {
            return Err("limit.inbound_workers");
        }
        *peer += 1;
        Ok(())
    }

    pub fn inbound_release(&mut self, peer_id: PeerId) {
        if let Some(count) = self.inbound_workers.get_mut(&peer_id) {
            *count -= 1;
            if *count == 0 {
                self.inbound_workers.remove(&peer_id);
            }
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    pub fn terminal_count(&self) -> usize {
        self.outbound_terminals.len()
    }

    pub fn inbound_event_count(&self) -> usize {
        self.inbound_events.len()
    }

    pub fn inbound_rejected_count(&self) -> u64 {
        self.inbound_rejected
    }

    pub fn open_on(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) -> Result<RequestId, &'static str> {
        self.open_on_at(peer_id, connection_id, Instant::now())
    }

    pub fn open_on_at(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        now: Instant,
    ) -> Result<RequestId, &'static str> {
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
            return Err("limit.command_queue_full");
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or("probe.request_id_exhausted")?;
        let request_id = RequestId(self.next);
        let request = OpenProbe {
            request_id,
            peer_id,
            connection_id,
        };
        self.pending.insert(
            request_id,
            PendingOpen {
                request,
                deadline: now + OPEN_DEADLINE,
                phase: PendingPhase::Queued,
                terminal: None,
            },
        );
        self.commands.push_back(request_id);
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
        let Some(pending) = self.pending.get(&request_id) else {
            return false;
        };
        let request = pending.request;
        self.terminal(
            request_id,
            ProbeOutput::OutboundFailed {
                request_id,
                peer_id: request.peer_id,
                connection_id: request.connection_id,
                code,
            },
        )
    }

    fn terminal(&mut self, request_id: RequestId, output: ProbeOutput) -> bool {
        let Some(pending) = self.pending.get_mut(&request_id) else {
            return false;
        };
        if pending.phase == PendingPhase::TerminalQueued {
            return false;
        }
        self.commands.retain(|queued| *queued != request_id);
        pending.phase = PendingPhase::TerminalQueued;
        pending.terminal = Some(output);
        self.outbound_terminals.push_back(request_id);
        true
    }

    fn pop_terminal(&mut self) -> Option<ProbeOutput> {
        let request_id = self.outbound_terminals.pop_front()?;
        self.pending.remove(&request_id)?.terminal
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
                .filter(|(_, p)| {
                    (p.request.peer_id, p.request.connection_id) == (c.peer_id, c.connection_id)
                })
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
                if let Some(request) = self.pending.get(&request_id).map(|p| p.request) {
                    let output = if request.peer_id != peer || request.connection_id != id {
                        ProbeOutput::OutboundFailed {
                            request_id,
                            peer_id: request.peer_id,
                            connection_id: request.connection_id,
                            code: "probe.internal_identity_mismatch",
                        }
                    } else {
                        ProbeOutput::OutboundOpened {
                            request_id,
                            peer_id: peer,
                            connection_id: id,
                            stream,
                        }
                    };
                    self.terminal(request_id, output);
                }
            }
            ProbeEvent::OutboundFailed { request_id, code } => {
                if let Some(request) = self.pending.get(&request_id).map(|p| p.request) {
                    let (peer_id, connection_id, code) =
                        if request.peer_id != peer || request.connection_id != id {
                            (
                                request.peer_id,
                                request.connection_id,
                                "probe.internal_identity_mismatch",
                            )
                        } else {
                            (peer, id, code)
                        };
                    self.terminal(
                        request_id,
                        ProbeOutput::OutboundFailed {
                            request_id,
                            peer_id,
                            connection_id,
                            code,
                        },
                    );
                }
            }
            ProbeEvent::InboundOpened { stream } => {
                if self.inbound_events.len() < MAX_INBOUND_EVENTS
                    && self.inbound_admit(peer).is_ok()
                {
                    self.inbound_events.push_back(ProbeOutput::InboundOpened {
                        peer_id: peer,
                        connection_id: id,
                        stream,
                    });
                } else {
                    self.inbound_rejected = self.inbound_rejected.saturating_add(1);
                    if self.inbound_events.len() < MAX_INBOUND_EVENTS {
                        self.inbound_events.push_back(ProbeOutput::InboundRejected {
                            peer_id: peer,
                            connection_id: id,
                            code: "limit.inbound_workers",
                        });
                    }
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
        while let Some(request_id) = self.commands.pop_front() {
            let Some(pending) = self.pending.get_mut(&request_id) else {
                continue;
            };
            if pending.phase != PendingPhase::Queued {
                continue;
            }
            pending.phase = PendingPhase::Notified;
            let event = pending.request;
            return Poll::Ready(ToSwarm::NotifyHandler {
                peer_id: event.peer_id,
                handler: NotifyHandler::One(event.connection_id),
                event,
            });
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn inbound_admission_is_bounded_and_released_once() {
        let mut behaviour = ProbeStreamBehaviour::default();
        let p = peer();
        for _ in 0..MAX_INBOUND_WORKERS_PER_PEER {
            assert!(behaviour.inbound_admit(p).is_ok());
        }
        assert_eq!(behaviour.inbound_admit(p), Err("limit.inbound_workers"));
        behaviour.inbound_release(p);
        assert!(behaviour.inbound_admit(p).is_ok());
        behaviour.inbound_release(p);
        behaviour.inbound_release(p);
    }

    #[test]
    fn outbound_pending_count_tracks_completion() {
        let mut behaviour = ProbeStreamBehaviour::default();
        let p = peer();
        let connection = ConnectionId::new_unchecked(1);
        behaviour.known.insert((p, connection));
        let request = behaviour.open_on(p, connection).unwrap();
        assert_eq!(behaviour.pending_count(), 1);
        assert!(behaviour.fail(request, "probe.test"));
        assert_eq!(behaviour.pending_count(), 1);
        assert_eq!(behaviour.terminal_count(), 1);
        assert!(matches!(
            behaviour.pop_terminal(),
            Some(ProbeOutput::OutboundFailed {
                code: "probe.test",
                ..
            })
        ));
        assert_eq!(behaviour.pending_count(), 0);
    }

    #[test]
    fn expiry_removes_stale_command_and_delivers_once() {
        let now = Instant::now();
        let mut behaviour = ProbeStreamBehaviour::default();
        let p = peer();
        let connection = ConnectionId::new_unchecked(1);
        behaviour.known.insert((p, connection));
        let request = behaviour.open_on_at(p, connection, now).unwrap();
        behaviour.expire(now + OPEN_DEADLINE);
        assert_eq!(behaviour.command_count(), 0);
        assert_eq!(behaviour.pending_count(), 1);
        assert!(!behaviour.cancel(request));
        assert!(matches!(
            behaviour.pop_terminal(),
            Some(ProbeOutput::OutboundFailed {
                code: "probe.open_timeout",
                ..
            })
        ));
        assert!(behaviour.pop_terminal().is_none());
        assert_eq!(behaviour.pending_count(), 0);
    }

    #[test]
    fn per_peer_limit_counts_terminals_until_delivery() {
        let now = Instant::now();
        let mut behaviour = ProbeStreamBehaviour::default();
        let p = peer();
        let connection = ConnectionId::new_unchecked(1);
        behaviour.known.insert((p, connection));
        let mut requests = Vec::new();
        for _ in 0..MAX_PER_PEER {
            requests.push(behaviour.open_on_at(p, connection, now).unwrap());
        }
        for request in requests {
            assert!(behaviour.fail(request, "probe.test"));
        }
        assert_eq!(
            behaviour.open_on_at(p, connection, now),
            Err("limit.command_queue_full")
        );
        let _ = behaviour.pop_terminal();
        assert!(behaviour.open_on_at(p, connection, now).is_ok());
    }
}
