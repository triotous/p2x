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
pub fn transition(state: ReservationState, event: ReservationEvent) -> ReservationState {
    match event {
        ReservationEvent::ExchangeConnected => ReservationState::ExchangeConnected,
        ReservationEvent::ReservationRequested => ReservationState::ReservationRequested,
        ReservationEvent::ReservationAccepted { .. } => match state {
            ReservationState::RelayAddressConfirmed => ReservationState::Ready,
            _ => ReservationState::ReservationAccepted,
        },
        ReservationEvent::RelayAddressConfirmed => match state {
            ReservationState::ReservationAccepted => ReservationState::Ready,
            _ => ReservationState::RelayAddressConfirmed,
        },
        ReservationEvent::ExchangeLost
        | ReservationEvent::RelayAddressLost
        | ReservationEvent::ListenerClosed => ReservationState::Degraded,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acceptance_and_address_order_reaches_ready() {
        let s = transition(
            ReservationState::Disconnected,
            ReservationEvent::ReservationAccepted { renewal: false },
        );
        assert_eq!(
            transition(s, ReservationEvent::RelayAddressConfirmed),
            ReservationState::Ready
        );
        let s = transition(
            ReservationState::Disconnected,
            ReservationEvent::RelayAddressConfirmed,
        );
        assert_eq!(
            transition(s, ReservationEvent::ReservationAccepted { renewal: false }),
            ReservationState::Ready
        );
    }
}
