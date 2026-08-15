use libp2p::{Multiaddr, PeerId, core::transport::ListenerId, swarm::ConnectionId};
use std::time::{Duration, Instant};

pub const INITIAL_RETRY: Duration = Duration::from_millis(250);
pub const MAX_RETRY: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    Disconnected,
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
        peer_id: PeerId,
        connection_id: ConnectionId,
    },
    ReservationAccepted {
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
        listener_id: ListenerId,
        renewal: bool,
    },
    RelayAddressConfirmed {
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
        listener_id: ListenerId,
        address: Multiaddr,
    },
    ExchangeLost {
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
    },
    ListenerClosed {
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
        listener_id: ListenerId,
    },
    RelayAddressLost {
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
        listener_id: ListenerId,
        address: Multiaddr,
    },
    RetryElapsed {
        generation: u64,
        attempt: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservationAction {
    CreateCircuitListener {
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
    },
    DialExchange {
        generation: u64,
    },
    ScheduleRetry {
        generation: u64,
        attempt: u32,
        deadline: Instant,
    },
    PublishReady {
        generation: u64,
        address: Multiaddr,
    },
    PublishDegraded {
        generation: u64,
    },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ReservationError {
    #[error("generation {0} was reused with different identities")]
    GenerationConflict(u64),
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
    requested: bool,
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
            requested: false,
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
        } else if self.requested {
            ReservationState::ReservationRequested
        } else if self.exchange_connection_id.is_some() {
            ReservationState::ExchangeConnected
        } else {
            ReservationState::Disconnected
        }
    }

    pub fn is_ready(&self) -> bool {
        !self.degraded && self.accepted && self.address_confirmed
    }

    pub fn apply(
        &mut self,
        event: ReservationEvent,
    ) -> Result<Vec<ReservationAction>, ReservationError> {
        self.apply_at(event, Instant::now(), 0)
    }

    pub fn apply_at(
        &mut self,
        event: ReservationEvent,
        now: Instant,
        jitter_per_mille: i16,
    ) -> Result<Vec<ReservationAction>, ReservationError> {
        match event {
            ReservationEvent::GenerationStarted {
                generation,
                peer_id,
                connection_id,
            } => self.start_generation(generation, peer_id, connection_id),
            ReservationEvent::ReservationRequested {
                generation,
                peer_id,
                connection_id,
            } if self.matches(generation, peer_id, connection_id) => {
                self.requested = true;
                Ok(vec![])
            }
            ReservationEvent::ReservationAccepted {
                generation,
                peer_id,
                connection_id,
                listener_id,
                renewal,
            } if self.matches(generation, peer_id, connection_id)
                && self
                    .listener_id
                    .is_none_or(|current| current == listener_id) =>
            {
                let was_ready = self.is_ready();
                self.listener_id = Some(listener_id);
                self.accepted = true;
                self.last_acceptance = Some(now);
                if renewal {
                    self.renewal_count = self.renewal_count.saturating_add(1);
                }
                Ok(self.publish_if_ready(was_ready))
            }
            ReservationEvent::RelayAddressConfirmed {
                generation,
                peer_id,
                connection_id,
                listener_id,
                address,
            } if self.matches(generation, peer_id, connection_id)
                && self
                    .listener_id
                    .is_none_or(|current| current == listener_id) =>
            {
                let was_ready = self.is_ready();
                self.listener_id = Some(listener_id);
                self.canonical_address = Some(address);
                self.address_confirmed = true;
                Ok(self.publish_if_ready(was_ready))
            }
            ReservationEvent::ExchangeLost {
                generation,
                peer_id,
                connection_id,
            } if self.matches(generation, peer_id, connection_id) => {
                self.exchange_connection_id = None;
                self.listener_id = None;
                self.canonical_address = None;
                self.accepted = false;
                self.address_confirmed = false;
                Ok(self.degrade(now, jitter_per_mille))
            }
            ReservationEvent::ListenerClosed {
                generation,
                peer_id,
                connection_id,
                listener_id,
            } if self.matches(generation, peer_id, connection_id)
                && self.listener_id == Some(listener_id) =>
            {
                self.listener_id = None;
                self.canonical_address = None;
                self.accepted = false;
                self.address_confirmed = false;
                Ok(self.degrade(now, jitter_per_mille))
            }
            ReservationEvent::RelayAddressLost {
                generation,
                peer_id,
                connection_id,
                listener_id,
                address,
            } if self.matches(generation, peer_id, connection_id)
                && self.listener_id == Some(listener_id)
                && self.canonical_address.as_ref() == Some(&address) =>
            {
                self.canonical_address = None;
                self.address_confirmed = false;
                Ok(self.degrade(now, jitter_per_mille))
            }
            ReservationEvent::RetryElapsed {
                generation,
                attempt,
            } if generation == self.generation
                && self.retry_attempt == attempt
                && self.retry_deadline.is_some_and(|deadline| now >= deadline) =>
            {
                self.retry_deadline = None;
                if let (Some(peer_id), Some(connection_id)) =
                    (self.exchange_peer_id, self.exchange_connection_id)
                {
                    Ok(vec![ReservationAction::CreateCircuitListener {
                        generation,
                        peer_id,
                        connection_id,
                    }])
                } else {
                    Ok(vec![ReservationAction::DialExchange { generation }])
                }
            }
            _ => Ok(vec![]),
        }
    }

    pub fn retry_delay(&self, jitter_per_mille: i16) -> Duration {
        let exponent = self.retry_attempt.saturating_sub(1).min(31);
        let base = INITIAL_RETRY
            .saturating_mul(2u32.saturating_pow(exponent))
            .min(MAX_RETRY);
        let jitter = i32::from(jitter_per_mille.clamp(-200, 200));
        let micros = base.as_micros() as i128;
        let adjusted = micros + (micros * i128::from(jitter) / 1000);
        Duration::from_micros(adjusted.max(0).min(u64::MAX as i128) as u64)
    }

    fn start_generation(
        &mut self,
        generation: u64,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) -> Result<Vec<ReservationAction>, ReservationError> {
        if generation < self.generation {
            return Ok(vec![]);
        }
        if generation == self.generation {
            match (self.exchange_peer_id, self.exchange_connection_id) {
                (None, None) => {}
                (Some(current_peer), Some(current_connection))
                    if current_peer == peer_id && current_connection == connection_id =>
                {
                    return Ok(vec![]);
                }
                _ => return Err(ReservationError::GenerationConflict(generation)),
            }
        }
        self.generation = generation;
        self.exchange_peer_id = Some(peer_id);
        self.exchange_connection_id = Some(connection_id);
        self.listener_id = None;
        self.canonical_address = None;
        self.accepted = false;
        self.address_confirmed = false;
        self.last_acceptance = None;
        self.renewal_count = 0;
        self.retry_attempt = 0;
        self.retry_deadline = None;
        self.requested = false;
        self.degraded = false;
        Ok(vec![ReservationAction::CreateCircuitListener {
            generation,
            peer_id,
            connection_id,
        }])
    }

    fn matches(&self, generation: u64, peer_id: PeerId, connection_id: ConnectionId) -> bool {
        generation == self.generation
            && self.exchange_peer_id == Some(peer_id)
            && self.exchange_connection_id == Some(connection_id)
    }

    fn publish_if_ready(&mut self, was_ready: bool) -> Vec<ReservationAction> {
        if !self.accepted || !self.address_confirmed {
            return vec![];
        }
        self.degraded = false;
        self.retry_attempt = 0;
        self.retry_deadline = None;
        if !was_ready && let Some(address) = self.canonical_address.clone() {
            return vec![ReservationAction::PublishReady {
                generation: self.generation,
                address,
            }];
        }
        vec![]
    }

    fn degrade(&mut self, now: Instant, jitter_per_mille: i16) -> Vec<ReservationAction> {
        if self.degraded && self.retry_deadline.is_some() {
            return vec![];
        }
        let first_degradation = !self.degraded;
        self.degraded = true;
        self.retry_attempt = self.retry_attempt.saturating_add(1);
        let deadline = now + self.retry_delay(jitter_per_mille);
        self.retry_deadline = Some(deadline);
        let mut actions = Vec::new();
        if first_degradation {
            actions.push(ReservationAction::PublishDegraded {
                generation: self.generation,
            });
        }
        actions.push(ReservationAction::ScheduleRetry {
            generation: self.generation,
            attempt: self.retry_attempt,
            deadline,
        });
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: usize) -> ConnectionId {
        ConnectionId::new_unchecked(value)
    }

    struct Fixture {
        peer: PeerId,
        connection: ConnectionId,
        listener: ListenerId,
        address: Multiaddr,
    }

    fn fixture() -> Fixture {
        Fixture {
            peer: PeerId::random(),
            connection: id(1),
            listener: ListenerId::next(),
            address: "/ip4/127.0.0.1/tcp/1/p2p-circuit".parse().unwrap(),
        }
    }

    fn start(context: &mut ReservationContext, fixture: &Fixture) {
        context
            .apply(ReservationEvent::GenerationStarted {
                generation: 1,
                peer_id: fixture.peer,
                connection_id: fixture.connection,
            })
            .unwrap();
    }

    #[test]
    fn acceptance_and_address_commute_and_renewal_does_not_flap() {
        let fixture = fixture();
        let mut context = ReservationContext::new(0);
        start(&mut context, &fixture);
        context
            .apply(ReservationEvent::RelayAddressConfirmed {
                generation: 1,
                peer_id: fixture.peer,
                connection_id: fixture.connection,
                listener_id: fixture.listener,
                address: fixture.address.clone(),
            })
            .unwrap();
        context
            .apply(ReservationEvent::ReservationAccepted {
                generation: 1,
                peer_id: fixture.peer,
                connection_id: fixture.connection,
                listener_id: fixture.listener,
                renewal: false,
            })
            .unwrap();
        assert!(context.is_ready());
        context
            .apply(ReservationEvent::ReservationAccepted {
                generation: 1,
                peer_id: fixture.peer,
                connection_id: fixture.connection,
                listener_id: fixture.listener,
                renewal: true,
            })
            .unwrap();
        assert!(context.is_ready());
        assert_eq!(context.renewal_count, 1);
    }

    #[test]
    fn identical_generation_is_idempotent_but_conflict_fails() {
        let fixture = fixture();
        let mut context = ReservationContext::new(0);
        start(&mut context, &fixture);
        assert!(
            context
                .apply(ReservationEvent::GenerationStarted {
                    generation: 1,
                    peer_id: fixture.peer,
                    connection_id: fixture.connection,
                })
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            context.apply(ReservationEvent::GenerationStarted {
                generation: 1,
                peer_id: PeerId::random(),
                connection_id: fixture.connection,
            }),
            Err(ReservationError::GenerationConflict(1))
        );
    }

    #[test]
    fn duplicate_loss_schedules_only_one_retry() {
        let fixture = fixture();
        let now = Instant::now();
        let mut context = ReservationContext::new(0);
        start(&mut context, &fixture);
        let loss = ReservationEvent::ListenerClosed {
            generation: 1,
            peer_id: fixture.peer,
            connection_id: fixture.connection,
            listener_id: fixture.listener,
        };
        context.listener_id = Some(fixture.listener);
        let first = context.apply_at(loss.clone(), now, 0).unwrap();
        let second = context.apply_at(loss, now, 0).unwrap();
        assert_eq!(context.retry_attempt, 1);
        assert!(matches!(
            first.as_slice(),
            [
                ReservationAction::PublishDegraded { .. },
                ReservationAction::ScheduleRetry { .. }
            ]
        ));
        assert!(second.is_empty());
    }

    #[test]
    fn jitter_covers_both_sides_and_is_capped() {
        let mut context = ReservationContext::new(1);
        context.retry_attempt = 1;
        assert_eq!(context.retry_delay(-200), Duration::from_millis(200));
        assert_eq!(context.retry_delay(200), Duration::from_millis(300));
        context.retry_attempt = 20;
        assert_eq!(context.retry_delay(0), MAX_RETRY);
    }

    #[test]
    fn stale_retry_cannot_replace_current_generation() {
        let fixture = fixture();
        let mut context = ReservationContext::new(0);
        start(&mut context, &fixture);
        assert!(
            context
                .apply(ReservationEvent::RetryElapsed {
                    generation: 0,
                    attempt: 1,
                })
                .unwrap()
                .is_empty()
        );
    }
}
