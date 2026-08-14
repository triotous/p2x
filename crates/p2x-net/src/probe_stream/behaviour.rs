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
    collections::{HashSet, VecDeque},
    task::{Context, Poll},
};

#[derive(Debug)]
pub enum ProbeOutput {
    OutboundOpened(OpenProbe),
    OutboundFailed(OpenProbe),
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestMarker;
#[derive(Default)]
pub struct ProbeStreamBehaviour {
    next: u64,
    known: HashSet<(PeerId, ConnectionId)>,
    pending: HashSet<RequestId>,
    commands: VecDeque<(PeerId, ConnectionId, OpenProbe)>,
    events: VecDeque<ProbeOutput>,
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
        if self.pending.len() >= 128 {
            return Err("limit.command_queue_full");
        }
        if self.pending.iter().filter(|_| true).count() >= 64 && self.pending.iter().any(|_| true) {
            return Err("limit.command_queue_full");
        }
        self.next += 1;
        let request_id = RequestId(self.next);
        self.pending.insert(request_id);
        let open = OpenProbe { request_id };
        self.commands.push_back((peer_id, connection_id, open));
        Ok(request_id)
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
        }
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            ProbeEvent::Opened(request_id) => {
                self.pending.remove(&request_id);
                self.events
                    .push_back(ProbeOutput::OutboundOpened(OpenProbe { request_id }));
            }
            ProbeEvent::Failed(request_id) => {
                self.pending.remove(&request_id);
                self.events
                    .push_back(ProbeOutput::OutboundFailed(OpenProbe { request_id }));
            }
        };
        self.known.insert((peer, id));
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
