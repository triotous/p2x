use libp2p_identity::PeerId;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ExchangeTrustConfig {
    pub peer_id: PeerId,
    pub addresses: Vec<libp2p_identity::PeerId>,
}
#[derive(Debug, Error)]
pub enum TrustError {
    #[error("exchange address is not pinned to the configured peer")]
    AddressMismatch,
    #[error("invalid peer id")]
    InvalidPeerId,
}
pub fn validate_exchange_pin(
    peer_id: &str,
    address_peer_ids: &[&str],
) -> Result<PeerId, TrustError> {
    let expected = PeerId::from_str(peer_id).map_err(|_| TrustError::InvalidPeerId)?;
    if address_peer_ids
        .iter()
        .any(|value| PeerId::from_str(value).ok().as_ref() != Some(&expected))
    {
        return Err(TrustError::AddressMismatch);
    }
    Ok(expected)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pin_is_required() {
        let peer = PeerId::random().to_string();
        assert!(validate_exchange_pin(&peer, &[&peer]).is_ok());
        assert!(matches!(
            validate_exchange_pin(&peer, &["bad"]),
            Err(TrustError::AddressMismatch)
        ));
    }
}
