use crate::resolver::{AuthorizationGrant, ResolverState};
use libp2p::PeerId;
use p2x_net::{PathAttempt, PathEvent, PathEventKind, PathRequestId};
use p2x_protocol::{
    IngressKind, OpenProxyStreamV1, PublicErrorCode, ResolveRequestV1, ResolveResponseV1,
    UnscopedSelector,
};
use std::{collections::HashMap, time::Instant};

pub const MAX_ROUTE_OPENS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    PreHandshake,
    Ambiguous,
}

#[derive(Debug)]
pub struct TunnelHandoff {
    pub open_id: OpenId,
    pub server: PeerId,
    pub connection: p2x_net::ConnectionId,
    pub request_id: [u8; 16],
    pub stream_id: [u8; 16],
}

pub enum RouteAction {
    SendResolve {
        open_id: OpenId,
        request: ResolveRequestV1,
    },
    OpenExact {
        open_id: OpenId,
        connection: p2x_net::ConnectionId,
        open: OpenProxyStreamV1,
    },
    DialRelay {
        open_id: OpenId,
        peer: PeerId,
        address: Vec<u8>,
    },
    StartHandshakeWorker {
        open_id: OpenId,
        proxy_request_id: u64,
        connection: p2x_net::ConnectionId,
        open: OpenProxyStreamV1,
    },
    CloseConnection {
        open_id: OpenId,
        connection: p2x_net::ConnectionId,
    },
    Complete {
        open_id: OpenId,
        server: Option<PeerId>,
        request_id: [u8; 16],
        result: Result<(), PublicErrorCode>,
    },
}

#[derive(Debug)]
struct RouteOpen {
    selector: UnscopedSelector,
    binding: p2x_net::auth_state::PrincipalBinding,
    session_id: [u8; 16],
    resolve_request: ResolveRequestV1,
    resolve_wire_id: Option<u64>,
    grant: Option<AuthorizationGrant>,
    server_peer_id: Option<PeerId>,
    registration_revision: Option<p2x_protocol::RegistrationRevision>,
    path_attempt: Option<PathAttempt>,
    proxy_request_id: Option<u64>,
    selected_connection: Option<p2x_net::ConnectionId>,
    deadline: Instant,
    resolve_retransmissions: u8,
    fresh_ticket_retries: u8,
    handshake_started: bool,
    terminal_delivered: bool,
}

#[derive(Debug)]
pub struct RouteOpenSupervisor {
    next_open_id: u64,
    next_request_id: u64,
    max_opens: usize,
    high_water: usize,
    opens: HashMap<OpenId, RouteOpen>,
}
impl Default for RouteOpenSupervisor {
    fn default() -> Self {
        Self::new(MAX_ROUTE_OPENS)
    }
}
impl RouteOpenSupervisor {
    pub fn new(max_opens: usize) -> Self {
        Self {
            next_open_id: 0,
            next_request_id: 0,
            max_opens: max_opens.clamp(1, MAX_ROUTE_OPENS),
            high_water: 0,
            opens: HashMap::new(),
        }
    }

    pub fn admit(
        &mut self,
        resolver: &mut ResolverState,
        binding: p2x_net::auth_state::PrincipalBinding,
        session_id: [u8; 16],
        selector: UnscopedSelector,
        now: i64,
        deadline: Instant,
    ) -> Result<(OpenId, Vec<RouteAction>), PublicErrorCode> {
        if self.opens.len() >= self.max_opens || deadline <= Instant::now() {
            return Err(PublicErrorCode::LimitProxyStreams);
        }
        self.next_open_id = self
            .next_open_id
            .checked_add(1)
            .ok_or(PublicErrorCode::LimitProxyStreams)?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(PublicErrorCode::LimitResolveRequests)?;
        let open_id = OpenId(self.next_open_id);
        let request_id = request_id(self.next_request_id);
        let request = ResolveRequestV1::Resolve {
            request_id,
            session_id,
            selector: selector.clone(),
            client_capabilities: p2x_protocol::Capabilities::from_bits(31)
                .expect("known capabilities"),
        };
        let actions = resolver
            .begin(
                request_id,
                binding.clone(),
                session_id,
                selector.clone(),
                now,
            )?
            .map(|request| vec![RouteAction::SendResolve { open_id, request }])
            .unwrap_or_default();
        self.opens.insert(
            open_id,
            RouteOpen {
                selector,
                binding,
                session_id,
                resolve_request: request,
                resolve_wire_id: None,
                grant: None,
                server_peer_id: None,
                registration_revision: None,
                path_attempt: None,
                proxy_request_id: None,
                selected_connection: None,
                deadline,
                resolve_retransmissions: 0,
                fresh_ticket_retries: 0,
                handshake_started: false,
                terminal_delivered: false,
            },
        );
        self.high_water = self.high_water.max(self.opens.len());
        Ok((open_id, actions))
    }

    pub fn high_water(&self) -> usize {
        self.high_water
    }

    pub fn resolve_sent(&mut self, open_id: OpenId, wire_id: u64) -> bool {
        let Some(open) = self.opens.get_mut(&open_id) else {
            return false;
        };
        if open.resolve_wire_id.is_some() || open.terminal_delivered {
            return false;
        }
        open.resolve_wire_id = Some(wire_id);
        true
    }

    pub fn resolve_timed_out(
        &mut self,
        open_id: OpenId,
        wire_id: u64,
        now: Instant,
    ) -> Option<RouteAction> {
        let open = self.opens.get_mut(&open_id)?;
        if open.resolve_wire_id != Some(wire_id) || open.terminal_delivered {
            return None;
        }
        open.resolve_wire_id = None;
        if open.resolve_retransmissions == 0 && now < open.deadline {
            open.resolve_retransmissions = 1;
            Some(RouteAction::SendResolve {
                open_id,
                request: open.resolve_request.clone(),
            })
        } else {
            Some(self.finish(open_id, Err(PublicErrorCode::ExchangeTimeout)))
        }
    }

    pub fn resolve_completed(
        &mut self,
        resolver: &mut ResolverState,
        open_id: OpenId,
        wire_id: u64,
        response: ResolveResponseV1,
        now: i64,
    ) -> Result<Vec<RouteAction>, PublicErrorCode> {
        self.resolve_completed_at(resolver, open_id, wire_id, response, now, Instant::now())
    }

    pub fn resolve_completed_at(
        &mut self,
        resolver: &mut ResolverState,
        open_id: OpenId,
        wire_id: u64,
        response: ResolveResponseV1,
        now: i64,
        now_instant: Instant,
    ) -> Result<Vec<RouteAction>, PublicErrorCode> {
        let open = self
            .opens
            .get_mut(&open_id)
            .ok_or(PublicErrorCode::ProtocolMalformed)?;
        if open.resolve_wire_id != Some(wire_id) || open.terminal_delivered {
            return Err(PublicErrorCode::ProtocolMalformed);
        }
        open.resolve_wire_id = None;
        if now_instant >= open.deadline {
            resolver.cancel(open.resolve_request.resolve_request_id());
            return Err(PublicErrorCode::PeerSetupTimeout);
        }
        let grant = resolver.complete(
            response,
            &open.binding,
            open.session_id,
            &open.selector,
            now,
        )?;
        open.server_peer_id = Some(grant.metadata.server_peer_id);
        open.registration_revision = Some(grant.metadata.registration_revision);
        open.grant = Some(grant);
        Ok(Vec::new())
    }

    pub fn promote_waiters(&mut self, resolver: &mut ResolverState) -> Vec<RouteAction> {
        let mut actions = Vec::new();
        while let Some(request) = resolver.next_request() {
            let request_id = request.resolve_request_id();
            if let Some((open_id, _open)) = self.opens.iter_mut().find(|(_, open)| {
                open.resolve_request.resolve_request_id() == request_id
                    && open.resolve_wire_id.is_none()
                    && !open.terminal_delivered
            }) {
                actions.push(RouteAction::SendResolve {
                    open_id: *open_id,
                    request,
                });
            }
        }
        actions
    }

    pub fn begin_path(
        &mut self,
        open_id: OpenId,
        attempt: PathAttempt,
        actions: Vec<p2x_net::PathAction>,
    ) -> Option<Vec<RouteAction>> {
        let open = self.opens.get_mut(&open_id)?;
        open.path_attempt = Some(attempt);
        Some(self.convert_path_actions(open_id, actions))
    }

    pub fn path_event(&mut self, open_id: OpenId, event: PathEvent) -> Option<Vec<RouteAction>> {
        let actions = self
            .opens
            .get_mut(&open_id)?
            .path_attempt
            .as_mut()?
            .apply(event);
        Some(self.convert_path_actions(open_id, actions))
    }

    pub fn path_input(
        &self,
        open_id: OpenId,
    ) -> Option<(
        PeerId,
        p2x_protocol::Capabilities,
        Vec<u8>,
        p2x_protocol::RegistrationRevision,
        i64,
        Instant,
    )> {
        let open = self.opens.get(&open_id)?;
        let grant = open.grant.as_ref()?;
        Some((
            grant.metadata.server_peer_id,
            grant.metadata.compatible_capabilities,
            grant.metadata.relay_addresses.first()?.clone(),
            grant.metadata.registration_revision,
            grant.metadata.registration_expires_at,
            open.deadline,
        ))
    }

    pub fn resolve_request_id(&self, open_id: OpenId) -> Option<[u8; 16]> {
        self.opens
            .get(&open_id)
            .map(|open| open.resolve_request.resolve_request_id())
    }

    pub fn selected_connection(&self, open_id: OpenId) -> Option<p2x_net::ConnectionId> {
        self.opens
            .get(&open_id)
            .and_then(|open| open.selected_connection)
    }

    pub fn proxy_request_id(&self, open_id: OpenId) -> Option<u64> {
        self.opens
            .get(&open_id)
            .and_then(|open| open.proxy_request_id)
    }

    pub fn open_ids_for_server(&self, server: PeerId) -> Vec<OpenId> {
        self.opens
            .iter()
            .filter_map(|(open_id, open)| {
                (open.server_peer_id == Some(server) && open.path_attempt.is_some())
                    .then_some(*open_id)
            })
            .collect()
    }

    pub fn path_attempt_id(&self, open_id: OpenId) -> Option<p2x_net::AttemptId> {
        self.opens
            .get(&open_id)
            .and_then(|open| open.path_attempt.as_ref())
            .map(|attempt| attempt.id)
    }

    pub fn tick_paths(&mut self, now: Instant) -> Vec<RouteAction> {
        let open_ids = self.opens.keys().copied().collect::<Vec<_>>();
        let mut result = Vec::new();
        for open_id in open_ids {
            let Some(open) = self.opens.get_mut(&open_id) else {
                continue;
            };
            let Some(attempt) = open.path_attempt.as_mut() else {
                continue;
            };
            let actions = attempt.apply(PathEvent {
                attempt_id: attempt.id,
                now,
                kind: PathEventKind::DirectDeadlineElapsed,
            });
            result.extend(self.convert_path_actions(open_id, actions));
        }
        result
    }

    pub fn proxy_queued(
        &mut self,
        open_id: OpenId,
        proxy_request_id: u64,
        connection: p2x_net::ConnectionId,
    ) -> bool {
        let Some(open) = self.opens.get_mut(&open_id) else {
            return false;
        };
        if open.proxy_request_id.is_some() || open.terminal_delivered {
            return false;
        }
        open.proxy_request_id = Some(proxy_request_id);
        open.selected_connection = Some(connection);
        true
    }

    pub fn handshake_started(
        &mut self,
        open_id: OpenId,
        proxy_request_id: u64,
    ) -> Option<RouteAction> {
        let open = self.opens.get_mut(&open_id)?;
        if open.proxy_request_id != Some(proxy_request_id) || open.terminal_delivered {
            return None;
        }
        open.handshake_started = true;
        let grant = open.grant.as_ref()?;
        Some(RouteAction::StartHandshakeWorker {
            open_id,
            proxy_request_id,
            connection: open.selected_connection?,
            open: make_open(open.resolve_request.resolve_request_id(), grant),
        })
    }

    pub fn proxy_failed(
        &mut self,
        resolver: &mut ResolverState,
        open_id: OpenId,
        proxy_request_id: u64,
        class: RetryClass,
        now: i64,
    ) -> Option<RouteAction> {
        self.proxy_failed_at(
            resolver,
            open_id,
            proxy_request_id,
            class,
            now,
            Instant::now(),
        )
    }

    pub fn proxy_failed_at(
        &mut self,
        resolver: &mut ResolverState,
        open_id: OpenId,
        proxy_request_id: u64,
        class: RetryClass,
        now: i64,
        now_instant: Instant,
    ) -> Option<RouteAction> {
        let fresh_request_id =
            matches!(class, RetryClass::Ambiguous).then(|| self.next_request_id());
        let open = self.opens.get_mut(&open_id)?;
        if open.proxy_request_id != Some(proxy_request_id) || open.terminal_delivered {
            return None;
        }
        if matches!(class, RetryClass::PreHandshake) {
            let attempt_id = open.path_attempt.as_ref()?.id;
            let connection = open.selected_connection?;
            let actions = open.path_attempt.as_mut()?.apply(PathEvent {
                attempt_id,
                now: now_instant,
                kind: PathEventKind::ExactOpenFailed {
                    request_id: PathRequestId(proxy_request_id),
                    connection,
                },
            });
            open.proxy_request_id = None;
            open.selected_connection = None;
            return self
                .convert_path_actions(open_id, actions)
                .into_iter()
                .next();
        }
        if open.fresh_ticket_retries == 0 && now_instant < open.deadline {
            open.fresh_ticket_retries = 1;
            open.grant = None;
            open.proxy_request_id = None;
            open.selected_connection = None;
            let request_id = fresh_request_id?;
            let request = resolver
                .begin(
                    request_id,
                    open.binding.clone(),
                    open.session_id,
                    open.selector.clone(),
                    now,
                )
                .ok()
                .flatten()?;
            open.resolve_request = request.clone();
            return Some(RouteAction::SendResolve { open_id, request });
        }
        Some(self.finish(open_id, Err(PublicErrorCode::PeerConnectionFailed)))
    }

    pub fn cancel(&mut self, resolver: &mut ResolverState, open_id: OpenId) -> Option<RouteAction> {
        let open = self.opens.remove(&open_id)?;
        let request_id = open.resolve_request.resolve_request_id();
        resolver.cancel(request_id);
        Some(RouteAction::Complete {
            open_id,
            server: open.server_peer_id,
            request_id,
            result: Err(PublicErrorCode::PeerSetupTimeout),
        })
    }

    pub fn cancel_with_promotion(
        &mut self,
        resolver: &mut ResolverState,
        open_id: OpenId,
    ) -> (Option<RouteAction>, Vec<RouteAction>) {
        let completed = self.cancel(resolver, open_id);
        let promoted = self.promote_waiters(resolver);
        (completed, promoted)
    }

    pub fn accepted(
        &mut self,
        open_id: OpenId,
        proxy_request_id: u64,
        request_id: [u8; 16],
        stream_id: [u8; 16],
    ) -> Option<TunnelHandoff> {
        let open = self.opens.get(&open_id)?;
        if open.proxy_request_id != Some(proxy_request_id)
            || open.resolve_request.resolve_request_id() != request_id
            || stream_id == [0; 16]
            || open.terminal_delivered
            || !open.handshake_started
        {
            return None;
        }
        let server = open.server_peer_id?;
        let connection = open.selected_connection?;
        let removed = self.opens.remove(&open_id)?;
        let _ = removed;
        Some(TunnelHandoff {
            open_id,
            server,
            connection,
            request_id,
            stream_id,
        })
    }

    pub fn complete(
        &mut self,
        open_id: OpenId,
        result: Result<(), PublicErrorCode>,
    ) -> Option<RouteAction> {
        self.opens
            .contains_key(&open_id)
            .then(|| self.finish(open_id, result))
    }

    pub fn open_id_for_resolve_wire(&self, wire_id: u64) -> Option<OpenId> {
        self.opens
            .iter()
            .find_map(|(open_id, open)| (open.resolve_wire_id == Some(wire_id)).then_some(*open_id))
    }

    pub fn open_id_for_proxy_request(&self, proxy_request_id: u64) -> Option<OpenId> {
        self.opens.iter().find_map(|(open_id, open)| {
            (open.proxy_request_id == Some(proxy_request_id)).then_some(*open_id)
        })
    }

    pub fn len(&self) -> usize {
        self.opens.len()
    }
    pub fn contains(&self, open_id: OpenId) -> bool {
        self.opens.contains_key(&open_id)
    }
    pub fn pending(&self) -> usize {
        self.opens
            .values()
            .filter(|open| open.resolve_wire_id.is_some())
            .count()
    }
    pub fn handshake_count(&self) -> usize {
        self.opens
            .values()
            .filter(|open| open.handshake_started)
            .count()
    }

    fn convert_path_actions(
        &mut self,
        open_id: OpenId,
        actions: Vec<p2x_net::PathAction>,
    ) -> Vec<RouteAction> {
        let Some(open) = self.opens.get_mut(&open_id) else {
            return Vec::new();
        };
        let Some(grant) = open.grant.as_ref() else {
            return Vec::new();
        };
        let open_message = make_open(open.resolve_request.resolve_request_id(), grant);
        actions
            .into_iter()
            .filter_map(|action| match action {
                p2x_net::PathAction::OpenExact { connection } => Some(RouteAction::OpenExact {
                    open_id,
                    connection,
                    open: open_message.clone(),
                }),
                p2x_net::PathAction::Finish(reason) => Some(RouteAction::Complete {
                    open_id,
                    server: open.server_peer_id,
                    request_id: open.resolve_request.resolve_request_id(),
                    result: Err(match reason {
                        p2x_net::PathFailure::SetupExpired => PublicErrorCode::PeerSetupTimeout,
                        _ => PublicErrorCode::PeerConnectionFailed,
                    }),
                }),
                p2x_net::PathAction::CloseStream => Some(RouteAction::CloseConnection {
                    open_id,
                    connection: open.selected_connection?,
                }),
                p2x_net::PathAction::DialRelay => Some(RouteAction::DialRelay {
                    open_id,
                    peer: open.server_peer_id?,
                    address: open
                        .grant
                        .as_ref()?
                        .metadata
                        .relay_addresses
                        .first()?
                        .clone(),
                }),
                p2x_net::PathAction::CancelOpen { .. } => None,
            })
            .collect()
    }

    fn finish(&mut self, open_id: OpenId, result: Result<(), PublicErrorCode>) -> RouteAction {
        let (server, request_id) = if let Some(mut open) = self.opens.remove(&open_id) {
            open.terminal_delivered = true;
            (
                open.server_peer_id,
                open.resolve_request.resolve_request_id(),
            )
        } else {
            (None, [0; 16])
        };
        RouteAction::Complete {
            open_id,
            server,
            request_id,
            result,
        }
    }

    fn next_request_id(&mut self) -> [u8; 16] {
        self.next_request_id = self.next_request_id.saturating_add(1);
        request_id(self.next_request_id)
    }
}

fn request_id(counter: u64) -> [u8; 16] {
    let mut id = [0; 16];
    id[8..].copy_from_slice(&counter.to_be_bytes());
    id
}

fn make_open(request_id: [u8; 16], grant: &AuthorizationGrant) -> OpenProxyStreamV1 {
    OpenProxyStreamV1 {
        request_id,
        ticket: grant.ticket.clone(),
        upstream_id: grant.metadata.upstream_id.clone(),
        registration_revision: grant.metadata.registration_revision,
        ingress_kind: IngressKind::FixedTcp,
    }
}

trait RequestId {
    fn resolve_request_id(&self) -> [u8; 16];
}
impl RequestId for ResolveRequestV1 {
    fn resolve_request_id(&self) -> [u8; 16] {
        match self {
            ResolveRequestV1::Resolve { request_id, .. } => *request_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2x_protocol::{
        MetadataKey, MetadataValue, ProtocolClass, QuotaProfile, Role, Scope, Tenant,
    };
    use std::collections::BTreeMap;

    fn selector() -> UnscopedSelector {
        UnscopedSelector::new(
            ProtocolClass::Http,
            BTreeMap::from([(
                MetadataKey::new("service").unwrap(),
                MetadataValue::new("orders").unwrap(),
            )]),
        )
        .unwrap()
    }
    fn binding() -> p2x_net::auth_state::PrincipalBinding {
        p2x_net::auth_state::PrincipalBinding {
            tenant: Tenant::new("tenant").unwrap(),
            role: Role::Client,
            scopes: Scope::OpenProxyStream.bit(),
            quota_profile: QuotaProfile::new("standard").unwrap(),
            authorization_revision: 1,
        }
    }

    #[test]
    fn bounded_admission_and_cancellation_release_once() {
        let mut owner = RouteOpenSupervisor::new(1);
        let mut resolver = ResolverState::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let (id, actions) = owner
            .admit(&mut resolver, binding(), [2; 16], selector(), 1, deadline)
            .unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(owner.len(), 1);
        assert!(owner.cancel(&mut resolver, id).is_some());
        assert!(owner.cancel(&mut resolver, id).is_none());
        assert_eq!(owner.len(), 0);
    }

    #[test]
    fn concurrent_same_selector_opens_have_distinct_ids_and_one_wire_owner() {
        let mut owner = RouteOpenSupervisor::new(64);
        let mut resolver = ResolverState::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let mut ids = std::collections::HashSet::new();
        let mut sends = 0;
        for _ in 0..64 {
            let (id, actions) = owner
                .admit(&mut resolver, binding(), [2; 16], selector(), 1, deadline)
                .unwrap();
            assert!(ids.insert(id));
            sends += actions
                .iter()
                .filter(|action| matches!(action, RouteAction::SendResolve { .. }))
                .count();
        }
        assert_eq!(owner.len(), 64);
        assert_eq!(resolver.waiter_count(), 64);
        assert_eq!(resolver.pending(), 1);
        assert_eq!(sends, 1);
        assert!(matches!(
            owner.admit(&mut resolver, binding(), [2; 16], selector(), 1, deadline,),
            Err(PublicErrorCode::LimitProxyStreams)
        ));
    }

    #[test]
    fn timeout_retransmits_exact_request_once_and_rejects_late_wire_event() {
        let mut owner = RouteOpenSupervisor::new(1);
        let mut resolver = ResolverState::default();
        let (id, actions) = owner
            .admit(
                &mut resolver,
                binding(),
                [2; 16],
                selector(),
                1,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap();
        let request = match &actions[0] {
            RouteAction::SendResolve { request, .. } => request.clone(),
            _ => panic!(),
        };
        assert!(owner.resolve_sent(id, 7));
        let retry = owner.resolve_timed_out(id, 7, Instant::now()).unwrap();
        match retry {
            RouteAction::SendResolve {
                request: retried, ..
            } => assert_eq!(retried, request),
            _ => panic!(),
        }
        assert!(owner.resolve_sent(id, 8));
        assert!(owner.resolve_timed_out(id, 7, Instant::now()).is_none());
    }

    #[test]
    fn response_at_absolute_deadline_is_rejected_and_releases_resolver_owner() {
        let mut owner = RouteOpenSupervisor::new(1);
        let mut resolver = ResolverState::default();
        let deadline = Instant::now() + std::time::Duration::from_millis(10);
        let (id, _) = owner
            .admit(&mut resolver, binding(), [2; 16], selector(), 1, deadline)
            .unwrap();
        assert!(owner.resolve_sent(id, 7));
        let response = ResolveResponseV1::Rejected {
            request_id: Some(request_id(1)),
            error: p2x_protocol::PublicError::new(PublicErrorCode::RegistryOffline, true),
        };
        assert!(matches!(
            owner.resolve_completed_at(&mut resolver, id, 7, response, 1, deadline),
            Err(PublicErrorCode::PeerSetupTimeout)
        ));
        assert_eq!(resolver.pending(), 0);
    }

    #[test]
    fn accepted_handoff_removes_setup_and_rejects_late_events() {
        let mut owner = RouteOpenSupervisor::new(1);
        let mut resolver = ResolverState::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let (id, _) = owner
            .admit(&mut resolver, binding(), [2; 16], selector(), 1, deadline)
            .unwrap();
        assert!(owner.proxy_queued(id, 7, p2x_net::ConnectionId::new_unchecked(1)));
        let server = PeerId::random();
        owner.opens.get_mut(&id).unwrap().server_peer_id = Some(server);
        owner.opens.get_mut(&id).unwrap().registration_revision =
            Some(p2x_protocol::RegistrationRevision::new(1).unwrap());
        owner.opens.get_mut(&id).unwrap().grant = Some(AuthorizationGrant {
            metadata: crate::resolver::ResolvedServiceMetadata {
                server_peer_id: server,
                upstream_id: p2x_protocol::UpstreamId::new("orders").unwrap(),
                selector_fingerprint: [0; 32],
                registration_revision: p2x_protocol::RegistrationRevision::new(1).unwrap(),
                relay_addresses: Vec::new(),
                compatible_capabilities: p2x_protocol::Capabilities::from_bits(17).unwrap(),
                registration_expires_at: 100,
            },
            ticket: p2x_protocol::RawTicket::new(vec![1; 16]).unwrap(),
            ticket_expires_at: 100,
        });
        assert!(owner.handshake_started(id, 7).is_some());
        let handoff = owner.accepted(id, 7, request_id(1), [4; 16]).unwrap();
        assert_eq!(handoff.request_id, request_id(1));
        assert!(!owner.contains(id));
        assert!(owner.accepted(id, 7, [3; 16], [4; 16]).is_none());
        assert!(
            owner
                .path_event(
                    id,
                    PathEvent {
                        attempt_id: p2x_net::AttemptId(1),
                        now: Instant::now(),
                        kind: PathEventKind::PayloadAccepted,
                    },
                )
                .is_none()
        );
    }

    #[test]
    fn cancellation_promotes_the_next_same_selector_waiter() {
        let mut owner = RouteOpenSupervisor::new(2);
        let mut resolver = ResolverState::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let (first, _) = owner
            .admit(&mut resolver, binding(), [2; 16], selector(), 1, deadline)
            .unwrap();
        let (second, _) = owner
            .admit(&mut resolver, binding(), [2; 16], selector(), 1, deadline)
            .unwrap();
        let (completed, promoted) = owner.cancel_with_promotion(&mut resolver, first);
        assert!(completed.is_some());
        assert!(promoted.iter().any(|action| matches!(action, RouteAction::SendResolve { open_id, .. } if *open_id == second)));
        assert_eq!(resolver.pending(), 1);
    }

    #[test]
    fn ambiguous_failure_allows_one_fresh_ticket_request() {
        let mut owner = RouteOpenSupervisor::new(1);
        let mut resolver = ResolverState::default();
        let (id, _) = owner
            .admit(
                &mut resolver,
                binding(),
                [2; 16],
                selector(),
                1,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap();
        resolver.cancel(request_id(1));
        assert!(owner.proxy_queued(id, 1, p2x_net::ConnectionId::new_unchecked(1)));
        assert!(
            owner
                .proxy_failed(&mut resolver, id, 1, RetryClass::Ambiguous, 1)
                .is_some()
        );
        assert!(
            owner
                .proxy_failed(&mut resolver, id, 1, RetryClass::Ambiguous, 1)
                .is_none()
        );
    }
}
