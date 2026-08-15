use crate::authn::AuthPrincipal;
use crate::authn::FixedTokenProvider;
use p2x_protocol::PublicErrorCode;
use std::{collections::HashMap, time::Duration};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSession {
    pub session_id: [u8; 16],
    pub principal: AuthPrincipal,
    pub established_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionAction {
    Authenticated(AuthSession),
    Rejected(PublicErrorCode),
    Removed(String),
}
pub struct AuthSessionLedger {
    sessions: HashMap<String, AuthSession>,
    connections: HashMap<String, usize>,
    max_sessions: usize,
    lifetime: Duration,
}
impl Default for AuthSessionLedger {
    fn default() -> Self {
        Self::new(256)
    }
}
impl AuthSessionLedger {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            connections: HashMap::new(),
            max_sessions,
            lifetime: Duration::from_secs(15 * 60),
        }
    }
    pub fn authenticate(
        &mut self,
        principal: AuthPrincipal,
        session_id: [u8; 16],
        now: i64,
    ) -> SessionAction {
        self.sweep(now);
        if self.sessions.len() >= self.max_sessions
            && !self.sessions.contains_key(&principal.peer_id)
        {
            return SessionAction::Rejected(PublicErrorCode::LimitAuthSessions);
        }
        let expires_at =
            (now + self.lifetime.as_secs() as i64).min(principal.credential_expires_at);
        let session = AuthSession {
            session_id,
            principal: principal.clone(),
            established_at: now,
            expires_at,
        };
        self.sessions.insert(principal.peer_id, session.clone());
        SessionAction::Authenticated(session)
    }
    pub fn authorize_ping(
        &mut self,
        peer_id: &str,
        session_id: [u8; 16],
        now: i64,
    ) -> SessionAction {
        self.sweep(now);
        match self.sessions.get(peer_id) {
            Some(session) if session.session_id == session_id => {
                SessionAction::Authenticated(session.clone())
            }
            Some(_) => SessionAction::Rejected(PublicErrorCode::AuthSessionRequired),
            None => SessionAction::Rejected(PublicErrorCode::AuthSessionRequired),
        }
    }
    pub fn connection_established(&mut self, peer_id: &str) {
        *self.connections.entry(peer_id.to_owned()).or_default() += 1;
    }
    pub fn connection_closed(&mut self, peer_id: &str) -> Option<SessionAction> {
        let count = self.connections.get_mut(peer_id)?;
        *count = count.saturating_sub(1);
        if *count != 0 {
            return None;
        }
        self.connections.remove(peer_id);
        self.sessions
            .remove(peer_id)
            .map(|_| SessionAction::Removed(peer_id.to_owned()))
    }
    pub fn replace_snapshot(&mut self, provider: &FixedTokenProvider) {
        self.sessions
            .retain(|peer, session| provider.binding_matches(peer, &session.principal));
    }
    pub fn replace_revision(&mut self, revision: u64) {
        self.sessions
            .retain(|_, session| session.principal.authorization_revision >= revision);
    }
    pub fn sweep(&mut self, now: i64) {
        self.sessions.retain(|_, session| session.expires_at > now);
    }
    pub fn len(&self) -> usize {
        self.sessions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::*;
    use p2x_protocol::*;
    fn principal(revision: u64) -> AuthPrincipal {
        AuthPrincipal {
            peer_id: "peer".into(),
            credential_id: CredentialId::new("id").unwrap(),
            tenant: Tenant::new("t").unwrap(),
            role: Role::Client,
            scopes: 1,
            quota_profile: QuotaProfile::new("q").unwrap(),
            authorization_revision: revision,
            credential_expires_at: 100,
        }
    }
    #[test]
    fn replacement_expiry_and_close_are_bounded() {
        let mut ledger = AuthSessionLedger::new(1);
        ledger.connection_established("peer");
        ledger.connection_established("peer");
        assert!(matches!(
            ledger.authenticate(principal(1), [1; 16], 1),
            SessionAction::Authenticated(_)
        ));
        assert!(matches!(
            ledger.authorize_ping("peer", [1; 16], 2),
            SessionAction::Authenticated(_)
        ));
        assert!(matches!(
            ledger.authorize_ping("peer", [2; 16], 2),
            SessionAction::Rejected(PublicErrorCode::AuthSessionRequired)
        ));
        assert!(ledger.connection_closed("peer").is_none());
        assert!(matches!(
            ledger.connection_closed("peer"),
            Some(SessionAction::Removed(_))
        ));
        assert_eq!(ledger.len(), 0);
        ledger.connection_established("peer");
        assert!(matches!(
            ledger.authenticate(principal(1), [1; 16], 1),
            SessionAction::Authenticated(_)
        ));
        ledger.replace_revision(2);
        assert_eq!(ledger.len(), 0);
        ledger.sweep(100);
        assert_eq!(ledger.len(), 0);
        assert!(ledger.connection_closed("peer").is_none());
    }
}
