use super::upgrade::ProbeUpgrade;
use libp2p::{
    Stream,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, ConnectionId, SubstreamProtocol,
        handler::ConnectionEvent,
    },
};
use std::{
    collections::VecDeque,
    task::{Context, Poll},
    time::Duration,
};

const MAX_HANDLER_QUEUE: usize = 64;
const MAX_HANDLER_EVENTS: usize = 64;
const MAX_HANDLER_INBOUND: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(pub u64);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenProbe {
    pub request_id: RequestId,
    pub peer_id: libp2p::PeerId,
    pub connection_id: ConnectionId,
}
#[derive(Debug)]
pub enum ProbeEvent {
    OutboundOpened {
        request_id: RequestId,
        stream: Stream,
    },
    OutboundFailed {
        request_id: RequestId,
        code: &'static str,
    },
    InboundOpened {
        stream: Stream,
    },
}

#[derive(Default)]
pub struct ProbeHandler {
    queue: VecDeque<OpenProbe>,
    outbound_events: VecDeque<ProbeEvent>,
    inbound_events: VecDeque<ProbeEvent>,
    inbound_rejected: u64,
}
impl ConnectionHandler for ProbeHandler {
    type FromBehaviour = OpenProbe;
    type ToBehaviour = ProbeEvent;
    type InboundProtocol = ProbeUpgrade;
    type OutboundProtocol = ProbeUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = OpenProbe;
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(ProbeUpgrade, ())
    }
    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(event) = self.outbound_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }
        if let Some(event) = self.inbound_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }
        if let Some(open) = self.queue.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ProbeUpgrade, open)
                    .with_timeout(Duration::from_secs(5)),
            });
        }
        Poll::Pending
    }
    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        if self.queue.len() + self.outbound_events.len() < MAX_HANDLER_QUEUE {
            self.queue.push_back(event);
        } else {
            // Behaviour admission limits each peer to the same bound. Reaching this
            // branch therefore indicates an internal accounting mismatch; replace
            // no existing completion and retain the new terminal if capacity exists.
            if self.outbound_events.len() < MAX_HANDLER_EVENTS {
                self.outbound_events.push_back(ProbeEvent::OutboundFailed {
                    request_id: event.request_id,
                    code: "limit.handler_queue_full",
                });
            }
        }
    }
    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol, (), OpenProbe>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(e) => {
                if self.inbound_events.len() < MAX_HANDLER_INBOUND {
                    self.inbound_events
                        .push_back(ProbeEvent::InboundOpened { stream: e.protocol });
                } else {
                    self.inbound_rejected = self.inbound_rejected.saturating_add(1);
                }
            }
            ConnectionEvent::FullyNegotiatedOutbound(e) => {
                debug_assert!(self.outbound_events.len() < MAX_HANDLER_EVENTS);
                if self.outbound_events.len() < MAX_HANDLER_EVENTS {
                    self.outbound_events.push_back(ProbeEvent::OutboundOpened {
                        request_id: e.info.request_id,
                        stream: e.protocol,
                    });
                } else {
                    // The behaviour never admits more than 64 requests per peer,
                    // so an outbound completion always has a reserved slot.
                    unreachable!("outbound completion capacity invariant violated");
                }
            }
            ConnectionEvent::DialUpgradeError(e) => {
                debug_assert!(self.outbound_events.len() < MAX_HANDLER_EVENTS);
                if self.outbound_events.len() < MAX_HANDLER_EVENTS {
                    self.outbound_events.push_back(ProbeEvent::OutboundFailed {
                        request_id: e.info.request_id,
                        code: "probe.negotiation_failed",
                    });
                } else {
                    unreachable!("outbound completion capacity invariant violated");
                }
            }
            ConnectionEvent::AddressChange(_)
            | ConnectionEvent::ListenUpgradeError(_)
            | ConnectionEvent::LocalProtocolsChange(_)
            | ConnectionEvent::RemoteProtocolsChange(_) => {}
            _ => {}
        }
    }
}
