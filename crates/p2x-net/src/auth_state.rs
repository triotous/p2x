use p2x_protocol::PublicErrorCode;

pub const AUTH_TIMEOUT_SECONDS: i64 = 5;
const BACKOFF_BASE_SECONDS: i64 = 1;
const BACKOFF_MAX_SECONDS: i64 = 30;
const BACKOFF_JITTER_PER_MILLE: i64 = 100;

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
    pub fn pong(&mut self, request_id: [u8; 16], nonce: u64) -> AuthAction {
        match self.phase {
            AuthPhase::AwaitingPong {
                request_id: expected,
                session_id,
                nonce: expected_nonce,
                ..
            } if expected == request_id && expected_nonce == nonce => {
                self.phase = AuthPhase::Authenticated { session_id };
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
        matches!(self.phase, AuthPhase::Authenticated { .. })
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
