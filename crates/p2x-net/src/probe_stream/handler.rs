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
    events: VecDeque<ProbeEvent>,
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
        if let Some(event) = self.events.pop_front() {
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
        self.queue.push_back(event);
    }
    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol, (), OpenProbe>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(e) => self
                .events
                .push_back(ProbeEvent::InboundOpened { stream: e.protocol }),
            ConnectionEvent::FullyNegotiatedOutbound(e) => {
                self.events.push_back(ProbeEvent::OutboundOpened {
                    request_id: e.info.request_id,
                    stream: e.protocol,
                })
            }
            ConnectionEvent::DialUpgradeError(e) => {
                self.events.push_back(ProbeEvent::OutboundFailed {
                    request_id: e.info.request_id,
                    code: "probe.negotiation_failed",
                })
            }
            ConnectionEvent::AddressChange(_)
            | ConnectionEvent::ListenUpgradeError(_)
            | ConnectionEvent::LocalProtocolsChange(_)
            | ConnectionEvent::RemoteProtocolsChange(_) => {}
            _ => {}
        }
    }
}
