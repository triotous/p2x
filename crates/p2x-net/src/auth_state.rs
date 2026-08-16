use p2x_protocol::PublicErrorCode;
use std::{collections::HashSet, hash::Hash};

pub const AUTH_TIMEOUT_SECONDS: i64 = 5;
const BACKOFF_BASE_SECONDS: i64 = 1;
const BACKOFF_MAX_SECONDS: i64 = 30;
const BACKOFF_JITTER_PER_MILLE: i64 = 100;
const REDIAL_BASE_MILLIS: i64 = 250;
const REDIAL_MAX_MILLIS: i64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionLoss {
    Unknown,
    Remaining,
    Final,
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeConnections<T> {
    ids: HashSet<T>,
}

impl<T: Eq + Hash> ExchangeConnections<T> {
    pub fn new() -> Self {
        Self {
            ids: HashSet::new(),
        }
    }

    pub fn established(&mut self, id: T) -> bool {
        self.ids.insert(id)
    }

    pub fn closed(&mut self, id: &T) -> ConnectionLoss {
        if !self.ids.remove(id) {
            ConnectionLoss::Unknown
        } else if self.ids.is_empty() {
            ConnectionLoss::Final
        } else {
            ConnectionLoss::Remaining
        }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingRequest<T> {
    current: Option<T>,
}

impl<T: Eq> PendingRequest<T> {
    pub const fn new() -> Self {
        Self { current: None }
    }

    pub fn begin(&mut self, id: T) -> bool {
        if self.current.is_some() {
            return false;
        }
        self.current = Some(id);
        true
    }

    pub fn complete(&mut self, id: &T) -> bool {
        if self.current.as_ref() != Some(id) {
            return false;
        }
        self.current = None;
        true
    }

    pub fn clear(&mut self) {
        self.current = None;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RedialBackoff {
    attempts: u32,
    due_at_millis: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddressCursor {
    next: usize,
}

impl AddressCursor {
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    pub fn next(&mut self, len: usize) -> Option<usize> {
        if len == 0 {
            return None;
        }
        let selected = self.next % len;
        self.next = (selected + 1) % len;
        Some(selected)
    }
}

impl RedialBackoff {
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            due_at_millis: None,
        }
    }

    pub fn schedule(&mut self, now_millis: i64, jitter_per_mille: i16) -> i64 {
        self.attempts = self.attempts.saturating_add(1);
        let shift = self.attempts.saturating_sub(1).min(7);
        let delay = (REDIAL_BASE_MILLIS << shift).min(REDIAL_MAX_MILLIS);
        let jitter = delay * i64::from(jitter_per_mille.clamp(-100, 100)) / 1000;
        let due = now_millis.saturating_add(delay + jitter);
        self.due_at_millis = Some(due);
        due
    }

    pub fn take_due(&mut self, now_millis: i64) -> bool {
        if self.due_at_millis.is_none_or(|due| now_millis < due) {
            return false;
        }
        self.due_at_millis = None;
        true
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
        self.due_at_millis = None;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthPhase {
    Disconnected,
    Authenticating {
        request_id: [u8; 16],
        deadline: i64,
    },
    AwaitingPong {
        request_id: [u8; 16],
        session_id: [u8; 16],
        nonce: u64,
        deadline: i64,
    },
    Authenticated {
        session_id: [u8; 16],
        expires_at: i64,
    },
    Reauthenticating {
        session_id: [u8; 16],
        expires_at: i64,
        request_id: [u8; 16],
        deadline: i64,
    },
    Backoff {
        until: i64,
    },
    Terminal(PublicErrorCode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAction {
    Authenticate {
        request_id: [u8; 16],
    },
    Ping {
        request_id: [u8; 16],
        session_id: [u8; 16],
        nonce: u64,
    },
    Ready,
    Retry,
    Ignore,
    Terminal(PublicErrorCode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthState {
    phase: AuthPhase,
    attempts: u32,
    session_expires_at: i64,
}
impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}
impl AuthState {
    pub const fn new() -> Self {
        Self {
            phase: AuthPhase::Disconnected,
            attempts: 0,
            session_expires_at: 0,
        }
    }
    pub const fn phase(&self) -> AuthPhase {
        self.phase
    }

    pub fn connected(&mut self, request_id: [u8; 16], now: i64) -> AuthAction {
        if !matches!(self.phase, AuthPhase::Disconnected) {
            return AuthAction::Ignore;
        }
        self.phase = AuthPhase::Authenticating {
            request_id,
            deadline: now + AUTH_TIMEOUT_SECONDS,
        };
        AuthAction::Authenticate { request_id }
    }
    pub fn authenticated(
        &mut self,
        request_id: [u8; 16],
        session_id: [u8; 16],
        ping_request_id: [u8; 16],
        nonce: u64,
        now: i64,
    ) -> AuthAction {
        match self.phase {
            AuthPhase::Authenticating {
                request_id: expected,
                ..
            }
            | AuthPhase::Reauthenticating {
                request_id: expected,
                ..
            } if expected == request_id => {
                self.phase = AuthPhase::AwaitingPong {
                    request_id: ping_request_id,
                    session_id,
                    nonce,
                    deadline: now + AUTH_TIMEOUT_SECONDS,
                };
                AuthAction::Ping {
                    request_id: ping_request_id,
                    session_id,
                    nonce,
                }
            }
            _ => AuthAction::Ignore,
        }
    }
    pub fn set_session_expiry(&mut self, expires_at: i64) {
        self.session_expires_at = expires_at;
        if let AuthPhase::Authenticated { session_id, .. } = self.phase {
            self.phase = AuthPhase::Authenticated {
                session_id,
                expires_at,
            };
        }
    }
    pub fn current_session(&self, now: i64) -> Option<[u8; 16]> {
        match self.phase {
            AuthPhase::Authenticated {
                session_id,
                expires_at,
            }
            | AuthPhase::Reauthenticating {
                session_id,
                expires_at,
                ..
            } if expires_at > now => Some(session_id),
            _ => None,
        }
    }
    pub fn renewal_due(&self, now: i64) -> bool {
        match self.phase {
            AuthPhase::Authenticated { expires_at, .. } => now >= expires_at.saturating_sub(60),
            _ => false,
        }
    }
    pub fn begin_renewal(&mut self, request_id: [u8; 16], now: i64) -> AuthAction {
        let AuthPhase::Authenticated {
            session_id,
            expires_at,
        } = self.phase
        else {
            return AuthAction::Ignore;
        };
        if expires_at <= now {
            self.phase = AuthPhase::Disconnected;
            return AuthAction::Retry;
        }
        self.phase = AuthPhase::Reauthenticating {
            session_id,
            expires_at,
            request_id,
            deadline: now + AUTH_TIMEOUT_SECONDS,
        };
        AuthAction::Authenticate { request_id }
    }
    pub fn pong(&mut self, request_id: [u8; 16], nonce: u64) -> AuthAction {
        match self.phase {
            AuthPhase::AwaitingPong {
                request_id: expected,
                session_id,
                nonce: expected_nonce,
                ..
            } if expected == request_id && expected_nonce == nonce => {
                self.phase = AuthPhase::Authenticated {
                    session_id,
                    expires_at: self.session_expires_at,
                };
                self.attempts = 0;
                AuthAction::Ready
            }
            _ => AuthAction::Ignore,
        }
    }
    pub fn transport_failure(&mut self, code: PublicErrorCode, now: i64) -> AuthAction {
        self.transport_failure_with_jitter(code, now, 0)
    }
    pub fn transport_failure_with_jitter(
        &mut self,
        code: PublicErrorCode,
        now: i64,
        jitter_per_mille: i16,
    ) -> AuthAction {
        if matches!(
            code,
            PublicErrorCode::ProtocolCapabilityMismatch
                | PublicErrorCode::ProtocolUnsupportedVersion
        ) {
            self.phase = AuthPhase::Terminal(code);
            return AuthAction::Terminal(code);
        }
        self.enter_backoff(now, jitter_per_mille);
        AuthAction::Retry
    }
    pub fn rejected(
        &mut self,
        request_id: Option<[u8; 16]>,
        code: PublicErrorCode,
        now: i64,
    ) -> AuthAction {
        let matches = match (self.phase, request_id) {
            (
                AuthPhase::Authenticating {
                    request_id: expected,
                    ..
                },
                Some(id),
            ) => expected == id,
            (
                AuthPhase::AwaitingPong {
                    request_id: expected,
                    ..
                },
                Some(id),
            ) => expected == id,
            _ => false,
        };
        if !matches {
            return AuthAction::Ignore;
        }
        if matches!(
            code,
            PublicErrorCode::ExchangeTimeout
                | PublicErrorCode::ExchangeOverloaded
                | PublicErrorCode::LimitAuthRequests
        ) {
            self.enter_backoff(now, 0);
            AuthAction::Retry
        } else {
            self.phase = AuthPhase::Terminal(code);
            AuthAction::Terminal(code)
        }
    }
    pub fn timeout(&mut self, now: i64) -> AuthAction {
        self.timeout_with_jitter(now, 0)
    }
    pub fn timeout_with_jitter(&mut self, now: i64, jitter_per_mille: i16) -> AuthAction {
        match self.phase {
            AuthPhase::Authenticating { deadline, .. }
            | AuthPhase::AwaitingPong { deadline, .. }
            | AuthPhase::Reauthenticating { deadline, .. }
                if now >= deadline =>
            {
                self.enter_backoff(now, jitter_per_mille);
                AuthAction::Retry
            }
            _ => AuthAction::Ignore,
        }
    }
    pub fn tick_with_jitter(
        &mut self,
        request_id: [u8; 16],
        now: i64,
        jitter_per_mille: i16,
    ) -> AuthAction {
        if let AuthPhase::Backoff { until } = self.phase
            && now >= until
        {
            self.phase = AuthPhase::Disconnected;
            return self.connected(request_id, now);
        }
        self.timeout_with_jitter(now, jitter_per_mille)
    }
    pub fn tick(&mut self, request_id: [u8; 16], now: i64) -> AuthAction {
        self.tick_with_jitter(request_id, now, 0)
    }
    pub fn disconnected(&mut self) -> AuthAction {
        if matches!(
            self.phase,
            AuthPhase::Authenticated { .. }
                | AuthPhase::Reauthenticating { .. }
                | AuthPhase::Authenticating { .. }
                | AuthPhase::AwaitingPong { .. }
        ) {
            self.phase = AuthPhase::Disconnected;
            return AuthAction::Retry;
        }
        self.phase = AuthPhase::Disconnected;
        AuthAction::Ignore
    }
    pub fn ready(&self) -> bool {
        matches!(self.phase, AuthPhase::Authenticated { expires_at, .. } if expires_at > i64::MIN)
    }
    fn enter_backoff(&mut self, now: i64, jitter_per_mille: i16) {
        self.attempts = self.attempts.saturating_add(1);
        let shift = self.attempts.saturating_sub(1).min(5);
        let delay = (BACKOFF_BASE_SECONDS << shift).min(BACKOFF_MAX_SECONDS);
        let jitter =
            (delay * BACKOFF_JITTER_PER_MILLE * i64::from(jitter_per_mille.clamp(-1000, 1000)))
                / 1000;
        self.phase = AuthPhase::Backoff {
            until: now.saturating_add(delay + jitter),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const AUTH: [u8; 16] = [1; 16];
    const PING: [u8; 16] = [2; 16];
    const SESSION: [u8; 16] = [3; 16];
    #[test]
    fn correlation_and_readiness_require_pong() {
        let mut state = AuthState::new();
        assert_eq!(
            state.connected(AUTH, 10),
            AuthAction::Authenticate { request_id: AUTH }
        );
        assert_eq!(
            state.authenticated([9; 16], SESSION, PING, 7, 10),
            AuthAction::Ignore
        );
        assert!(matches!(state.phase(), AuthPhase::Authenticating { .. }));
        assert_eq!(
            state.authenticated(AUTH, SESSION, PING, 7, 10),
            AuthAction::Ping {
                request_id: PING,
                session_id: SESSION,
                nonce: 7
            }
        );
        assert_eq!(state.pong([9; 16], 7), AuthAction::Ignore);
        assert_eq!(state.pong(PING, 7), AuthAction::Ready);
        assert!(matches!(state.phase(), AuthPhase::Authenticated { .. }));
    }
    #[test]
    fn timeout_enters_bounded_backoff_and_retries() {
        let mut state = AuthState::new();
        assert!(matches!(
            state.connected(AUTH, 0),
            AuthAction::Authenticate { .. }
        ));
        assert_eq!(state.tick(AUTH, AUTH_TIMEOUT_SECONDS), AuthAction::Retry);
        assert_eq!(state.tick(AUTH, AUTH_TIMEOUT_SECONDS), AuthAction::Ignore);
        assert_eq!(
            state.tick(AUTH, AUTH_TIMEOUT_SECONDS + 1),
            AuthAction::Authenticate { request_id: AUTH }
        );
    }

    #[test]
    fn only_final_known_exchange_connection_is_a_loss() {
        let mut connections = ExchangeConnections::new();
        assert!(connections.established(1));
        assert!(connections.established(2));
        assert!(!connections.established(2));
        assert_eq!(connections.len(), 2);
        assert_eq!(connections.closed(&9), ConnectionLoss::Unknown);
        assert_eq!(connections.closed(&1), ConnectionLoss::Remaining);
        assert_eq!(connections.closed(&1), ConnectionLoss::Unknown);
        assert_eq!(connections.closed(&2), ConnectionLoss::Final);
    }

    #[test]
    fn stale_outbound_completion_cannot_release_current_request() {
        let mut pending = PendingRequest::new();
        assert!(pending.begin(7));
        assert!(!pending.begin(8));
        assert!(!pending.complete(&6));
        assert!(pending.complete(&7));
        assert!(!pending.complete(&7));
        assert!(pending.begin(8));
        pending.clear();
        assert!(pending.begin(9));
    }

    #[test]
    fn redial_backoff_is_capped_jittered_and_resettable() {
        let mut backoff = RedialBackoff::new();
        assert_eq!(backoff.schedule(1_000, -100), 1_225);
        assert!(!backoff.take_due(1_224));
        assert!(backoff.take_due(1_225));
        assert_eq!(backoff.schedule(2_000, 100), 2_550);
        for _ in 0..20 {
            backoff.schedule(0, 100);
        }
        assert!(backoff.due_at_millis <= Some(REDIAL_MAX_MILLIS + 3_000));
        backoff.reset();
        assert_eq!(backoff.schedule(0, 0), REDIAL_BASE_MILLIS);
    }

    #[test]
    fn address_cursor_retries_every_configured_address_in_order() {
        let mut cursor = AddressCursor::new();
        assert_eq!(cursor.next(0), None);
        assert_eq!(cursor.next(3), Some(0));
        assert_eq!(cursor.next(3), Some(1));
        assert_eq!(cursor.next(3), Some(2));
        assert_eq!(cursor.next(3), Some(0));
    }
    #[test]
    fn renewal_keeps_valid_session_until_replacement_ping() {
        let mut state = AuthState::new();
        state.connected(AUTH, 0);
        state.authenticated(AUTH, SESSION, PING, 7, 0);
        state.set_session_expiry(100);
        assert_eq!(state.pong(PING, 7), AuthAction::Ready);
        assert_eq!(state.current_session(99), Some(SESSION));
        assert!(state.renewal_due(40));
        assert_eq!(
            state.begin_renewal([4; 16], 40),
            AuthAction::Authenticate {
                request_id: [4; 16]
            }
        );
        assert_eq!(state.current_session(50), Some(SESSION));
    }

    #[test]
    fn non_retryable_rejection_is_terminal() {
        let mut state = AuthState::new();
        state.connected(AUTH, 0);
        assert_eq!(
            state.rejected(Some(AUTH), PublicErrorCode::AuthInvalidCredential, 1),
            AuthAction::Terminal(PublicErrorCode::AuthInvalidCredential)
        );
        assert_eq!(state.connected([4; 16], 2), AuthAction::Ignore);
        assert_eq!(state.disconnected(), AuthAction::Ignore);
        state.connected(AUTH, 3);
        assert_eq!(
            state.transport_failure(PublicErrorCode::ProtocolCapabilityMismatch, 3),
            AuthAction::Terminal(PublicErrorCode::ProtocolCapabilityMismatch)
        );
    }
}
