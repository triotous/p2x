use super::upgrade::ProbeUpgrade;
use libp2p::swarm::{
    ConnectionHandler, ConnectionHandlerEvent, SubstreamProtocol, handler::ConnectionEvent,
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
}
#[derive(Debug)]
pub enum ProbeEvent {
    Opened(RequestId),
    Failed(RequestId),
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
            ConnectionEvent::FullyNegotiatedInbound(_) => {}
            ConnectionEvent::FullyNegotiatedOutbound(e) => {
                self.events.push_back(ProbeEvent::Opened(e.info.request_id))
            }
            ConnectionEvent::DialUpgradeError(e) => {
                self.events.push_back(ProbeEvent::Failed(e.info.request_id))
            }
            ConnectionEvent::AddressChange(_)
            | ConnectionEvent::ListenUpgradeError(_)
            | ConnectionEvent::LocalProtocolsChange(_)
            | ConnectionEvent::RemoteProtocolsChange(_)
            | _ => {}
        }
    }
}
