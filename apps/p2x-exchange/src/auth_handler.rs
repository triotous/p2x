use crate::{
    auth_sessions::{AuthSessionLedger, SessionAction},
    authn::FixedTokenProvider,
};
use p2x_protocol::{AuthRequest, AuthResponse, PublicError, PublicErrorCode};

fn random_session_id() -> Result<[u8; 16], PublicErrorCode> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| PublicErrorCode::ExchangeOverloaded)?;
    Ok(id)
}

pub fn handle_request(
    provider: &FixedTokenProvider,
    sessions: &mut AuthSessionLedger,
    peer_id: &str,
    request: AuthRequest,
    now: i64,
) -> AuthResponse {
    match request {
        AuthRequest::Authenticate {
            request_id,
            credential_id,
            token_secret,
            requested_role,
            supported_features,
        } => {
            if supported_features != p2x_protocol::KNOWN_AUTH_FEATURES_V1 {
                return AuthResponse::Rejected {
                    request_id: Some(request_id),
                    error: PublicError::new(PublicErrorCode::ProtocolCapabilityMismatch, false),
                };
            }
            let result =
                provider.authenticate(peer_id, &credential_id, &token_secret, requested_role, now);
            match result {
                Ok(principal) => match random_session_id() {
                    Ok(session_id) => match sessions.authenticate(principal, session_id, now) {
                        SessionAction::Authenticated(session) => AuthResponse::Authenticated {
                            request_id,
                            session_id: session.session_id,
                            tenant: session.principal.tenant,
                            role: session.principal.role,
                            scopes: session.principal.scopes,
                            quota_profile: session.principal.quota_profile,
                            authorization_revision: session.principal.authorization_revision,
                            expires_at: session.expires_at,
                            exchange_features: 0,
                        },
                        SessionAction::Rejected(code) => AuthResponse::Rejected {
                            request_id: Some(request_id),
                            error: PublicError::new(code, true),
                        },
                        SessionAction::Removed(_)
                        | SessionAction::PrincipalRevoked(_)
                        | SessionAction::ClosePeerConnections { .. } => AuthResponse::Rejected {
                            request_id: Some(request_id),
                            error: PublicError::new(PublicErrorCode::ExchangeOverloaded, true),
                        },
                    },
                    Err(_) => AuthResponse::Rejected {
                        request_id: Some(request_id),
                        error: PublicError::new(PublicErrorCode::ExchangeOverloaded, true),
                    },
                },
                Err(crate::authn::AuthFailure::ForbiddenRole) => AuthResponse::Rejected {
                    request_id: Some(request_id),
                    error: PublicError::new(PublicErrorCode::AuthRoleForbidden, false),
                },
                Err(crate::authn::AuthFailure::InvalidCredential) => AuthResponse::Rejected {
                    request_id: Some(request_id),
                    error: PublicError::new(PublicErrorCode::AuthInvalidCredential, false),
                },
            }
        }
        AuthRequest::Ping {
            request_id,
            session_id,
            nonce,
        } => match sessions.authorize_ping(peer_id, session_id, now) {
            SessionAction::Authenticated(_) => AuthResponse::Pong {
                request_id,
                nonce,
                exchange_time: now,
            },
            SessionAction::Rejected(code) => AuthResponse::Rejected {
                request_id: Some(request_id),
                error: PublicError::new(code, false),
            },
            _ => AuthResponse::Rejected {
                request_id: Some(request_id),
                error: PublicError::new(PublicErrorCode::AuthSessionRequired, false),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::*;
    use p2x_protocol::*;
    #[test]
    fn unsupported_features_are_rejected_before_credential_lookup() {
        let (_, token) =
            TokenSecret::parse("p2x1.id.AwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc").unwrap();
        let id = CredentialId::new("id").unwrap();
        let provider = FixedTokenProvider::new(1, []);
        let mut ledger = AuthSessionLedger::default();
        assert!(matches!(
            handle_request(
                &provider,
                &mut ledger,
                "peer",
                AuthRequest::Authenticate {
                    request_id: [1; 16],
                    credential_id: id,
                    token_secret: token,
                    requested_role: Role::Client,
                    supported_features: 1
                },
                1
            ),
            AuthResponse::Rejected {
                error: PublicError {
                    code: PublicErrorCode::ProtocolCapabilityMismatch,
                    ..
                },
                ..
            }
        ));
    }
    #[test]
    fn authenticate_then_ping_is_correlated() {
        let (_, token) =
            TokenSecret::parse("p2x1.id.AwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc").unwrap();
        let id = CredentialId::new("id").unwrap();
        let provider = FixedTokenProvider::new(
            1,
            [CredentialBinding {
                credential_id: id.clone(),
                digest: token.digest(),
                peer_id: "peer".into(),
                tenant: Tenant::new("t").unwrap(),
                role: Role::Client,
                scopes: 1,
                quota_profile: QuotaProfile::new("q").unwrap(),
                not_before: 0,
                expires_at: 100,
                revoked: false,
            }],
        );
        let mut ledger = AuthSessionLedger::default();
        let response = handle_request(
            &provider,
            &mut ledger,
            "peer",
            AuthRequest::Authenticate {
                request_id: [1; 16],
                credential_id: id,
                token_secret: p2x_protocol::TokenSecret::from_bytes(*token.as_bytes()),
                requested_role: Role::Client,
                supported_features: 0,
            },
            1,
        );
        let session_id = match response {
            AuthResponse::Authenticated { session_id, .. } => session_id,
            _ => panic!("authentication failed"),
        };
        let pong = handle_request(
            &provider,
            &mut ledger,
            "peer",
            AuthRequest::Ping {
                request_id: [3; 16],
                session_id,
                nonce: 9,
            },
            2,
        );
        assert!(matches!(pong, AuthResponse::Pong { nonce: 9, .. }));
    }
}
