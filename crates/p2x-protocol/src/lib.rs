pub mod auth;
pub mod credential;
pub mod error;
pub mod frame;
pub mod ids;
pub mod proxy;
pub mod registry;
pub mod resolve;
pub mod selector;
pub mod ticket;

pub use auth::{AuthRequest, AuthResponse, KNOWN_AUTH_FEATURES_V1, Role, Scope};
pub use credential::{TokenDigest, TokenSecret};
pub use error::{PublicError, PublicErrorCode};
pub use ids::{
    CorrelationIdExhausted, CorrelationIdGenerator, CredentialId, InstanceId, QuotaProfile,
    RegistrationRevision, Tenant, UpstreamId,
};
pub use proxy::{
    IngressKind, MAX_PROXY_HANDSHAKE_FRAME, OpenProxyStreamV1, ProxyOpenResponseV1,
    ProxyProtocolError, UpstreamMode,
};
pub use registry::{
    Capabilities, Health, RegistryRequestV1, RegistryResponseV1, ServiceAdvertisementV1, ServiceSet,
};
pub use resolve::{MAX_RESOLVE_FRAME, ResolveProtocolError, ResolveRequestV1, ResolveResponseV1};
pub use selector::{MetadataKey, MetadataValue, ProtocolClass, ScopedSelector, UnscopedSelector};
pub use ticket::{RawTicket, TicketKeyResolver, TicketSigner, TicketSigningKey, TicketValidation};
