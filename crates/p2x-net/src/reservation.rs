use libp2p::{PeerId, swarm::ConnectionId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    Disconnected,
    ExchangeDialing,
    ExchangeConnected,
    ReservationRequested,
    ReservationAccepted,
    RelayAddressConfirmed,
    Ready,
    Degraded,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationEvent {
    ExchangeConnected,
    ReservationRequested,
    ReservationAccepted { renewal: bool },
    RelayAddressConfirmed,
    ExchangeLost,
    RelayAddressLost,
    ListenerClosed,
}

#[derive(Debug)]
pub struct ReservationContext {
    pub generation: u64,
    pub exchange_peer_id: Option<PeerId>,
    pub exchange_connection_id: Option<ConnectionId>,
    pub listener_id: Option<u64>,
    pub accepted: bool,
    pub address_confirmed: bool,
    pub renewal_count: u64,
    pub retry_attempt: u32,
    degraded: bool,
}
impl ReservationContext {
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            exchange_peer_id: None,
            exchange_connection_id: None,
            listener_id: None,
            accepted: false,
            address_confirmed: false,
            renewal_count: 0,
            retry_attempt: 0,
            degraded: false,
        }
    }
    pub fn phase(&self) -> ReservationState {
        if self.degraded {
            ReservationState::Degraded
        } else if self.is_ready() {
            ReservationState::Ready
        } else if self.accepted {
            ReservationState::ReservationAccepted
        } else if self.address_confirmed {
            ReservationState::RelayAddressConfirmed
        } else {
            ReservationState::ExchangeConnected
        }
    }
    pub fn is_ready(&self) -> bool {
        !self.degraded && self.accepted && self.address_confirmed
    }
    pub fn apply(&mut self, event: ReservationEvent) {
        match event {
            ReservationEvent::ExchangeConnected => self.degraded = false,
            ReservationEvent::ReservationRequested => {}
            ReservationEvent::ReservationAccepted { renewal } => {
                self.accepted = true;
                if renewal {
                    self.renewal_count += 1;
                }
            }
            ReservationEvent::RelayAddressConfirmed => self.address_confirmed = true,
            ReservationEvent::ExchangeLost
            | ReservationEvent::RelayAddressLost
            | ReservationEvent::ListenerClosed => self.degraded = true,
        }
    }
}
pub fn transition(state: ReservationState, event: ReservationEvent) -> ReservationState {
    let mut context = ReservationContext::new(0);
    context.degraded = state == ReservationState::Degraded;
    context.accepted = matches!(
        state,
        ReservationState::ReservationAccepted | ReservationState::Ready
    );
    context.address_confirmed = matches!(
        state,
        ReservationState::RelayAddressConfirmed | ReservationState::Ready
    );
    context.apply(event);
    context.phase()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn facts_commute_and_renewal_does_not_flap_ready() {
        let mut c = ReservationContext::new(7);
        c.apply(ReservationEvent::ReservationAccepted { renewal: false });
        c.apply(ReservationEvent::RelayAddressConfirmed);
        assert!(c.is_ready());
        c.apply(ReservationEvent::ReservationAccepted { renewal: true });
        assert!(c.is_ready());
        assert_eq!(c.renewal_count, 1);
    }
    #[test]
    fn legacy_transition_still_reaches_ready() {
        let s = transition(
            ReservationState::Disconnected,
            ReservationEvent::ReservationAccepted { renewal: false },
        );
        assert_eq!(
            transition(s, ReservationEvent::RelayAddressConfirmed),
            ReservationState::Ready
        );
    }
}
