use p2x_protocol::ProtocolClass;
use p2x_proxy::domain::{CanonicalDomain, DomainError};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ListenerId(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterKind {
    Http,
    TlsSni,
}
impl AdapterKind {
    pub fn protocol(self) -> ProtocolClass {
        match self {
            Self::Http => ProtocolClass::Http,
            Self::TlsSni => ProtocolClass::TlsPassthrough,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTarget {
    pub target_index: usize,
    pub route_id: String,
    pub kind: AdapterKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRouteSpec {
    pub listener: String,
    pub domain: String,
    pub route_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouterError {
    InvalidDomain,
    UnknownListener,
    WrongListenerKind,
    UnknownRoute,
    DuplicateDomain,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainRouter {
    routes: HashMap<(ListenerId, CanonicalDomain), RouteTarget>,
}
impl DomainRouter {
    pub fn build(
        listeners: &[(ListenerId, String, AdapterKind)],
        routes: &[DomainRouteSpec],
        targets: &[(String, ProtocolClass)],
    ) -> Result<Self, RouterError> {
        let mut by_listener = HashMap::new();
        for &(id, ref name, kind) in listeners {
            by_listener.insert(name.as_str(), (id, kind));
        }
        let mut by_route = HashMap::new();
        for (index, (route_id, protocol)) in targets.iter().enumerate() {
            by_route.insert(route_id.as_str(), (index, *protocol));
        }
        let mut result = Self::default();
        for route in routes {
            let (listener_id, kind) = by_listener
                .get(route.listener.as_str())
                .copied()
                .ok_or(RouterError::UnknownListener)?;
            let (target_index, protocol) = by_route
                .get(route.route_id.as_str())
                .copied()
                .ok_or(RouterError::UnknownRoute)?;
            if protocol != kind.protocol() {
                return Err(RouterError::WrongListenerKind);
            }
            let domain = CanonicalDomain::from_config(&route.domain)
                .map_err(|_: DomainError| RouterError::InvalidDomain)?;
            if result
                .routes
                .insert(
                    (listener_id, domain),
                    RouteTarget {
                        target_index,
                        route_id: route.route_id.clone(),
                        kind,
                    },
                )
                .is_some()
            {
                return Err(RouterError::DuplicateDomain);
            }
        }
        for &(listener_id, _, _) in listeners {
            if !routes.iter().any(|route| {
                by_listener
                    .get(route.listener.as_str())
                    .is_some_and(|(id, _)| *id == listener_id)
            }) {
                return Err(RouterError::UnknownListener);
            }
        }
        Ok(result)
    }

    #[allow(dead_code)]
    pub fn lookup(&self, listener: ListenerId, domain: &CanonicalDomain) -> Option<&RouteTarget> {
        self.routes.get(&(listener, domain.clone()))
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listeners() -> Vec<(ListenerId, String, AdapterKind)> {
        vec![(ListenerId(1), "http".into(), AdapterKind::Http)]
    }
    fn targets() -> Vec<(String, ProtocolClass)> {
        vec![("orders".into(), ProtocolClass::Http)]
    }

    #[test]
    fn exact_routes_are_listener_scoped() {
        let router = DomainRouter::build(
            &listeners(),
            &[DomainRouteSpec {
                listener: "http".into(),
                domain: "Orders.Example".into(),
                route_id: "orders".into(),
            }],
            &targets(),
        )
        .unwrap();
        let domain = CanonicalDomain::from_config("orders.example.").unwrap();
        assert_eq!(
            router.lookup(ListenerId(1), &domain).unwrap().target_index,
            0
        );
        assert!(router.lookup(ListenerId(2), &domain).is_none());
    }

    #[test]
    fn duplicate_and_unused_routes_are_rejected() {
        let duplicate = vec![
            DomainRouteSpec {
                listener: "http".into(),
                domain: "a.example".into(),
                route_id: "orders".into(),
            },
            DomainRouteSpec {
                listener: "http".into(),
                domain: "A.EXAMPLE.".into(),
                route_id: "orders".into(),
            },
        ];
        assert_eq!(
            DomainRouter::build(&listeners(), &duplicate, &targets()),
            Err(RouterError::DuplicateDomain)
        );
        assert_eq!(
            DomainRouter::build(&listeners(), &[], &targets()),
            Err(RouterError::UnknownListener)
        );
    }
}
