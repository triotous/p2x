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
        ReservationEvent::ReservationAccepted { .. } => ReservationState::ReservationAccepted,
        ReservationEvent::RelayAddressConfirmed
            if matches!(
                state,
                ReservationState::ReservationAccepted | ReservationState::RelayAddressConfirmed
            ) =>
        {
            ReservationState::Ready
        }
        ReservationEvent::ExchangeLost
        | ReservationEvent::RelayAddressLost
        | ReservationEvent::ListenerClosed => ReservationState::Degraded,
        _ => state,
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
    }
}
