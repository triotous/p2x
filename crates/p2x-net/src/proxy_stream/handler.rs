use super::upgrade::ProxyUpgrade;
use libp2p::{
    Stream,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, ConnectionId, SubstreamProtocol,
        handler::ConnectionEvent,
    },
};
use p2x_protocol::OpenProxyStreamV1;
use std::{
    collections::VecDeque,
    task::{Context, Poll},
    time::Duration,
};

const MAX_HANDLER_QUEUE: usize = 64;
const MAX_HANDLER_EVENTS: usize = 64;
const MAX_HANDLER_INBOUND: usize = 64;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProxyRequestId(pub u64);
#[derive(Clone, Debug)]
pub struct OpenProxy {
    pub request_id: ProxyRequestId,
    pub peer_id: libp2p::PeerId,
    pub connection_id: ConnectionId,
    pub open: OpenProxyStreamV1,
}
#[derive(Debug)]
pub enum ProxyEvent {
    OutboundOpened {
        request_id: ProxyRequestId,
        stream: Stream,
    },
    OutboundFailed {
        request_id: ProxyRequestId,
        code: &'static str,
    },
    InboundOpened {
        stream: Stream,
    },
}
#[derive(Default)]
pub struct ProxyHandler {
    pub inbound_enabled: bool,
    pub outbound_enabled: bool,
    queue: VecDeque<OpenProxy>,
    outbound_events: VecDeque<ProxyEvent>,
    inbound_events: VecDeque<ProxyEvent>,
}
impl ProxyHandler {
    pub fn with_surface(inbound_enabled: bool, outbound_enabled: bool) -> Self {
        Self {
            inbound_enabled,
            outbound_enabled,
            ..Self::default()
        }
    }
}
impl ConnectionHandler for ProxyHandler {
    type FromBehaviour = OpenProxy;
    type ToBehaviour = ProxyEvent;
    type InboundProtocol = ProxyUpgrade;
    type OutboundProtocol = ProxyUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = OpenProxy;
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(
            ProxyUpgrade {
                enabled: self.inbound_enabled,
            },
            (),
        )
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
                protocol: SubstreamProtocol::new(
                    ProxyUpgrade {
                        enabled: self.outbound_enabled,
                    },
                    open,
                )
                .with_timeout(Duration::from_secs(5)),
            });
        }
        Poll::Pending
    }
    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        if self.queue.len() + self.outbound_events.len() < MAX_HANDLER_QUEUE {
            self.queue.push_back(event);
        } else if self.outbound_events.len() < MAX_HANDLER_EVENTS {
            self.outbound_events.push_back(ProxyEvent::OutboundFailed {
                request_id: event.request_id,
                code: "limit.proxy_streams",
            });
        }
    }
    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol, (), OpenProxy>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(event)
                if self.inbound_events.len() < MAX_HANDLER_INBOUND =>
            {
                self.inbound_events.push_back(ProxyEvent::InboundOpened {
                    stream: event.protocol,
                })
            }
            ConnectionEvent::FullyNegotiatedOutbound(event)
                if self.outbound_events.len() < MAX_HANDLER_EVENTS =>
            {
                self.outbound_events.push_back(ProxyEvent::OutboundOpened {
                    request_id: event.info.request_id,
                    stream: event.protocol,
                })
            }
            ConnectionEvent::DialUpgradeError(event)
                if self.outbound_events.len() < MAX_HANDLER_EVENTS =>
            {
                self.outbound_events.push_back(ProxyEvent::OutboundFailed {
                    request_id: event.info.request_id,
                    code: "proxy.negotiation_failed",
                })
            }
            _ => {}
        }
    }
}
