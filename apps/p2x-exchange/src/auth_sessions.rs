use crate::authn::AuthPrincipal;
use crate::authn::FixedTokenProvider;
use libp2p::swarm::ConnectionId;
use p2x_protocol::PublicErrorCode;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
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
    PrincipalRevoked(String),
    ClosePeerConnections {
        peer_id: String,
        connection_ids: Vec<ConnectionId>,
    },
}
pub struct AuthSessionLedger {
    sessions: HashMap<String, AuthSession>,
    connections: HashMap<String, HashSet<ConnectionId>>,
    max_sessions: usize,
    lifetime: Duration,
}
impl Default for AuthSessionLedger {
    fn default() -> Self {
        Self::new(256)
    }
}
impl AuthSessionLedger {
    pub fn apply_actions<F>(
        &mut self,
        actions: Vec<SessionAction>,
        mut close: F,
    ) -> Vec<SessionAction>
    where
        F: FnMut(ConnectionId),
    {
        for action in &actions {
            if let SessionAction::ClosePeerConnections { connection_ids, .. } = action {
                for connection_id in connection_ids {
                    close(*connection_id);
                }
            }
        }
        actions
    }
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self::new(max_sessions)
    }
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
        if self
            .sessions
            .get(peer_id)
            .is_some_and(|session| session.expires_at <= now)
        {
            self.sessions.remove(peer_id);
            return SessionAction::Rejected(PublicErrorCode::AuthSessionExpired);
        }
        self.sweep(now);
        match self.sessions.get(peer_id) {
            Some(session) if session.session_id == session_id => {
                SessionAction::Authenticated(session.clone())
            }
            Some(_) => SessionAction::Rejected(PublicErrorCode::AuthSessionRequired),
            None => SessionAction::Rejected(PublicErrorCode::AuthSessionRequired),
        }
    }
    pub fn connection_established(&mut self, peer_id: &str, connection_id: ConnectionId) {
        self.connections
            .entry(peer_id.to_owned())
            .or_default()
            .insert(connection_id);
    }
    pub fn connection_closed(
        &mut self,
        peer_id: &str,
        connection_id: ConnectionId,
    ) -> Option<SessionAction> {
        let connections = self.connections.get_mut(peer_id)?;
        connections.remove(&connection_id);
        if !connections.is_empty() {
            return None;
        }
        self.connections.remove(peer_id);
        self.sessions
            .remove(peer_id)
            .map(|_| SessionAction::Removed(peer_id.to_owned()))
    }
    pub fn replace_snapshot(&mut self, provider: &FixedTokenProvider) -> Vec<SessionAction> {
        let revoked = self
            .sessions
            .iter()
            .filter(|(peer, session)| !provider.binding_matches(peer, &session.principal))
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>();
        self.remove_revoked(revoked)
    }
    pub fn replace_snapshot_at(
        &mut self,
        provider: &FixedTokenProvider,
        now: i64,
    ) -> Vec<SessionAction> {
        let revoked = self
            .sessions
            .iter()
            .filter(|(peer, session)| !provider.binding_matches_at(peer, &session.principal, now))
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>();
        self.remove_revoked(revoked)
    }
    fn remove_revoked(&mut self, revoked: Vec<String>) -> Vec<SessionAction> {
        let mut actions = Vec::new();
        for peer in revoked {
            self.sessions.remove(&peer);
            let connection_ids = self
                .connections
                .get(&peer)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default();
            actions.push(SessionAction::PrincipalRevoked(peer.clone()));
            actions.push(SessionAction::ClosePeerConnections {
                peer_id: peer,
                connection_ids,
            });
        }
        actions
    }
    pub fn replace_revision(&mut self, revision: u64) -> Vec<SessionAction> {
        let revoked = self
            .sessions
            .iter()
            .filter(|(_, session)| session.principal.authorization_revision < revision)
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>();
        self.remove_revoked(revoked)
    }
    pub fn sweep(&mut self, now: i64) -> Vec<SessionAction> {
        let expired = self
            .sessions
            .iter()
            .filter(|(_, session)| session.expires_at <= now)
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>();
        let mut actions = Vec::new();
        for peer in expired {
            self.sessions.remove(&peer);
            let connection_ids = self
                .connections
                .get(&peer)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default();
            actions.push(SessionAction::Removed(peer.clone()));
            actions.push(SessionAction::ClosePeerConnections {
                peer_id: peer,
                connection_ids,
            });
        }
        actions
    }
    pub fn current(&self, peer_id: &str, now: i64) -> Option<AuthSession> {
        self.sessions
            .get(peer_id)
            .filter(|session| session.expires_at > now)
            .cloned()
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
            credential_not_before: 0,
            credential_expires_at: 100,
            credential_digest: TokenDigest::from_bytes([9; 32]),
        }
    }
    #[test]
    fn snapshot_replacement_detects_digest_changes() {
        let id = CredentialId::new("id").unwrap();
        let binding = |digest| CredentialBinding {
            credential_id: id.clone(),
            digest: TokenDigest::from_bytes(digest),
            peer_id: "peer".into(),
            tenant: Tenant::new("t").unwrap(),
            role: Role::Client,
            scopes: 1,
            quota_profile: QuotaProfile::new("q").unwrap(),
            not_before: 0,
            expires_at: 100,
            revoked: false,
        };
        let provider = FixedTokenProvider::new(1, [binding([9; 32])]);
        let mut ledger = AuthSessionLedger::new(1);
        ledger.connection_established("peer", ConnectionId::new_unchecked(1));
        assert!(matches!(
            ledger.authenticate(principal(1), [1; 16], 1),
            SessionAction::Authenticated(_)
        ));
        assert!(ledger.replace_snapshot_at(&provider, 2).is_empty());
        let changed = FixedTokenProvider::new(2, [binding([8; 32])]);
        assert_eq!(
            ledger.replace_snapshot_at(&changed, 2),
            vec![
                SessionAction::PrincipalRevoked("peer".into()),
                SessionAction::ClosePeerConnections {
                    peer_id: "peer".into(),
                    connection_ids: vec![ConnectionId::new_unchecked(1)]
                }
            ]
        );
    }
    #[test]
    fn owner_consumes_close_action_for_every_connection() {
        let mut ledger = AuthSessionLedger::new(1);
        ledger.connection_established("peer", ConnectionId::new_unchecked(1));
        ledger.connection_established("peer", ConnectionId::new_unchecked(2));
        ledger.authenticate(principal(1), [1; 16], 1);
        let actions = ledger.replace_revision(2);
        let mut closed = Vec::new();
        ledger.apply_actions(actions, |id| closed.push(id));
        closed.sort_by_key(|id| format!("{id:?}"));
        assert_eq!(
            closed,
            vec![
                ConnectionId::new_unchecked(1),
                ConnectionId::new_unchecked(2)
            ]
        );
    }
    #[test]
    fn replacement_expiry_and_close_are_bounded() {
        let mut ledger = AuthSessionLedger::new(1);
        ledger.connection_established("peer", ConnectionId::new_unchecked(1));
        ledger.connection_established("peer", ConnectionId::new_unchecked(2));
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
        assert!(
            ledger
                .connection_closed("peer", ConnectionId::new_unchecked(1))
                .is_none()
        );
        assert!(matches!(
            ledger.connection_closed("peer", ConnectionId::new_unchecked(2)),
            Some(SessionAction::Removed(_))
        ));
        assert_eq!(ledger.len(), 0);
        ledger.connection_established("peer", ConnectionId::new_unchecked(1));
        assert!(matches!(
            ledger.authenticate(principal(1), [1; 16], 1),
            SessionAction::Authenticated(_)
        ));
        assert_eq!(
            ledger.replace_revision(2),
            vec![
                SessionAction::PrincipalRevoked("peer".into()),
                SessionAction::ClosePeerConnections {
                    peer_id: "peer".into(),
                    connection_ids: vec![ConnectionId::new_unchecked(1)]
                }
            ]
        );
        assert_eq!(ledger.len(), 0);
        ledger.sweep(100);
        assert_eq!(ledger.len(), 0);
        ledger.connection_established("peer", ConnectionId::new_unchecked(1));
        assert!(matches!(
            ledger.authenticate(principal(1), [3; 16], 1),
            SessionAction::Authenticated(_)
        ));
        assert!(matches!(
            ledger.authorize_ping("peer", [3; 16], 100),
            SessionAction::Rejected(PublicErrorCode::AuthSessionExpired)
        ));
        assert!(
            ledger
                .connection_closed("peer", ConnectionId::new_unchecked(1))
                .is_none()
        );
    }
}
