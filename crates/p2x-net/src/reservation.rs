use libp2p::{Multiaddr, PeerId, core::transport::ListenerId, swarm::ConnectionId};
use std::time::{Duration, Instant};

pub const INITIAL_RETRY: Duration = Duration::from_millis(250);
pub const MAX_RETRY: Duration = Duration::from_secs(10);
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservationEvent {
    GenerationStarted {
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
    },
    ReservationRequested {
        generation: u64,
    },
    ReservationAccepted {
        generation: u64,
        listener_id: ListenerId,
        renewal: bool,
    },
    RelayAddressConfirmed {
        generation: u64,
        address: Multiaddr,
    },
    ExchangeLost {
        generation: u64,
        connection_id: ConnectionId,
    },
    ListenerClosed {
        generation: u64,
        listener_id: ListenerId,
    },
    RelayAddressLost {
        generation: u64,
    },
}
#[derive(Debug)]
pub struct ReservationContext {
    pub generation: u64,
    pub exchange_peer_id: Option<PeerId>,
    pub exchange_connection_id: Option<ConnectionId>,
    pub listener_id: Option<ListenerId>,
    pub canonical_address: Option<Multiaddr>,
    pub accepted: bool,
    pub address_confirmed: bool,
    pub last_acceptance: Option<Instant>,
    pub renewal_count: u64,
    pub retry_attempt: u32,
    pub retry_deadline: Option<Instant>,
    degraded: bool,
}
impl ReservationContext {
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            exchange_peer_id: None,
            exchange_connection_id: None,
            listener_id: None,
            canonical_address: None,
            accepted: false,
            address_confirmed: false,
            last_acceptance: None,
            renewal_count: 0,
            retry_attempt: 0,
            retry_deadline: None,
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
    pub fn apply_at(&mut self, event: ReservationEvent, now: Instant) {
        match event {
            ReservationEvent::GenerationStarted {
                generation,
                peer_id,
                connection_id,
            } if generation >= self.generation => {
                self.generation = generation;
                self.exchange_peer_id = Some(peer_id);
                self.exchange_connection_id = Some(connection_id);
                self.listener_id = None;
                self.canonical_address = None;
                self.accepted = false;
                self.address_confirmed = false;
                self.last_acceptance = None;
                self.renewal_count = 0;
                self.degraded = false;
                self.retry_attempt = 0;
                self.retry_deadline = None;
            }
            ReservationEvent::ReservationRequested { .. } => {}
            ReservationEvent::ReservationAccepted {
                generation,
                listener_id,
                renewal,
            } if generation == self.generation => {
                self.listener_id = Some(listener_id);
                self.accepted = true;
                self.last_acceptance = Some(now);
                if renewal {
                    self.renewal_count += 1;
                }
            }
            ReservationEvent::RelayAddressConfirmed {
                generation,
                address,
            } if generation == self.generation => {
                self.canonical_address = Some(address);
                self.address_confirmed = true;
                self.degraded = false;
                if self.accepted {
                    self.retry_attempt = 0;
                    self.retry_deadline = None;
                }
            }
            ReservationEvent::ExchangeLost {
                generation,
                connection_id,
            } if generation == self.generation
                && self.exchange_connection_id == Some(connection_id) =>
            {
                self.degrade(now)
            }
            ReservationEvent::ListenerClosed {
                generation,
                listener_id,
            } if generation == self.generation && self.listener_id == Some(listener_id) => {
                self.degrade(now)
            }
            ReservationEvent::RelayAddressLost { generation } if generation == self.generation => {
                self.degrade(now)
            }
            _ => {}
        }
    }
    pub fn apply(&mut self, event: ReservationEvent) {
        self.apply_at(event, Instant::now());
    }
    pub fn retry_delay(&self, jitter_per_mille: u16) -> Duration {
        let base = INITIAL_RETRY
            .saturating_mul(2u32.saturating_pow(self.retry_attempt.saturating_sub(1)))
            .min(MAX_RETRY);
        let jitter = base.mul_f64((jitter_per_mille.min(200) as f64) / 1000.0);
        base + jitter
    }

    fn degrade(&mut self, now: Instant) {
        self.degraded = true;
        self.retry_attempt = self.retry_attempt.saturating_add(1);
        self.retry_deadline = Some(now + self.retry_delay(0));
    }
}
pub fn transition(state: ReservationState, event: ReservationEvent) -> ReservationState {
    let mut c = ReservationContext::new(0);
    c.degraded = state == ReservationState::Degraded;
    c.apply(event);
    c.phase()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> PeerId {
        PeerId::random()
    }
    fn id(n: u8) -> ConnectionId {
        ConnectionId::new_unchecked(n as usize)
    }
    fn ready(c: &mut ReservationContext) {
        c.apply(ReservationEvent::GenerationStarted {
            generation: 1,
            peer_id: p(),
            connection_id: id(1),
        });
        c.apply(ReservationEvent::ReservationAccepted {
            generation: 1,
            listener_id: ListenerId::next(),
            renewal: false,
        });
        c.apply(ReservationEvent::RelayAddressConfirmed {
            generation: 1,
            address: "/ip4/127.0.0.1/tcp/1/p2p-circuit".parse().unwrap(),
        });
    }
    #[test]
    fn readiness_is_generation_scoped() {
        let mut c = ReservationContext::new(0);
        ready(&mut c);
        assert!(c.is_ready());
        c.apply(ReservationEvent::GenerationStarted {
            generation: 2,
            peer_id: p(),
            connection_id: id(3),
        });
        assert!(!c.is_ready());
    }
    #[test]
    fn stale_loss_does_not_degrade_new_generation() {
        let mut c = ReservationContext::new(2);
        c.apply(ReservationEvent::GenerationStarted {
            generation: 2,
            peer_id: p(),
            connection_id: id(1),
        });
        c.apply(ReservationEvent::ExchangeLost {
            generation: 1,
            connection_id: id(1),
        });
        assert!(!c.degraded);
    }
    #[test]
    fn retry_is_bounded() {
        let mut c = ReservationContext::new(1);
        c.apply(ReservationEvent::GenerationStarted {
            generation: 1,
            peer_id: p(),
            connection_id: id(1),
        });
        let now = Instant::now();
        for _ in 0..20 {
            c.apply_at(ReservationEvent::RelayAddressLost { generation: 1 }, now);
        }
        assert!(c.retry_deadline.unwrap() <= now + MAX_RETRY);
    }
}
