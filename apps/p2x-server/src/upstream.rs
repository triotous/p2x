use super::config::LocalUpstream;
use std::time::Duration;
use tokio::{
    net::TcpStream,
    select,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectError {
    Timeout,
    Failed,
}
impl ConnectError {
    pub const fn code(self) -> p2x_protocol::PublicErrorCode {
        match self {
            Self::Timeout => p2x_protocol::PublicErrorCode::UpstreamConnectTimeout,
            Self::Failed => p2x_protocol::PublicErrorCode::UpstreamConnectFailed,
        }
    }
}

pub async fn connect(
    upstream: &LocalUpstream,
    remaining: Duration,
    cancel: CancellationToken,
) -> Result<TcpStream, ConnectError> {
    let budget = timeout_for(upstream, remaining);
    if budget.is_zero() {
        return Err(ConnectError::Timeout);
    }
    select! {
        _ = cancel.cancelled() => Err(ConnectError::Timeout),
        result = timeout(budget, TcpStream::connect(upstream.connect)) => {
            result.map_err(|_| ConnectError::Timeout)?.map_err(|_| ConnectError::Failed)
        }
    }
}

pub async fn hold(
    delay: Duration,
    remaining: Duration,
    cancel: CancellationToken,
) -> Result<(), ConnectError> {
    if delay > remaining {
        return Err(ConnectError::Timeout);
    }
    select! {
        _ = cancel.cancelled() => Err(ConnectError::Timeout),
        _ = sleep(delay) => Ok(()),
    }
}

pub fn timeout_for(upstream: &LocalUpstream, remaining: Duration) -> Duration {
    upstream.connect_timeout.min(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2x_protocol::{Health, ServiceAdvertisementV1, UnscopedSelector, UpstreamId};
    use std::collections::BTreeMap;

    fn upstream(address: &str) -> LocalUpstream {
        LocalUpstream {
            advertisement: ServiceAdvertisementV1::new(
                UpstreamId::new("orders").unwrap(),
                UnscopedSelector::new(
                    p2x_protocol::ProtocolClass::Tcp,
                    BTreeMap::from([(
                        p2x_protocol::MetadataKey::new("service").unwrap(),
                        p2x_protocol::MetadataValue::new("orders").unwrap(),
                    )]),
                )
                .unwrap(),
                Health::Ready,
            ),
            connect: address.parse().unwrap(),
            connect_timeout: Duration::from_millis(10),
            idle_timeout: Duration::from_secs(1),
            concurrency_limit: 1,
        }
    }

    #[tokio::test]
    async fn cancellation_stops_connector_without_waiting_for_full_budget() {
        let target = upstream("127.0.0.1:1");
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(
            connect(&target, Duration::from_secs(1), cancel).await,
            Err(ConnectError::Timeout)
        ));
    }

    #[tokio::test]
    async fn hold_uses_the_same_remaining_budget_and_cancellation() {
        let cancel = CancellationToken::new();
        assert_eq!(
            hold(
                Duration::from_millis(2),
                Duration::from_millis(1),
                cancel.clone()
            )
            .await,
            Err(ConnectError::Timeout)
        );
        cancel.cancel();
        assert_eq!(
            hold(Duration::from_secs(1), Duration::from_secs(2), cancel).await,
            Err(ConnectError::Timeout)
        );
    }

    #[tokio::test]
    async fn connector_classifies_refusal_without_leaking_address() {
        let target = upstream("127.0.0.1:1");
        let error = connect(&target, Duration::from_millis(10), CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error, ConnectError::Failed);
        assert!(!format!("{error:?}").contains("127.0.0.1"));
        assert_eq!(
            error.code(),
            p2x_protocol::PublicErrorCode::UpstreamConnectFailed
        );
    }

    #[test]
    fn connect_timeout_is_clipped_to_remaining_setup_budget() {
        let target = upstream("127.0.0.1:1");
        assert_eq!(
            timeout_for(&target, Duration::from_millis(1)),
            Duration::from_millis(1)
        );
    }
}
