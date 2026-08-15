use libp2p::{Multiaddr, multiaddr::Protocol};
use libp2p_identity::PeerId;
use std::str::FromStr;
use thiserror::Error;

pub const MAX_EXCHANGE_ADDRESSES: usize = 8;

#[derive(Clone, Debug)]
pub struct ExchangeTrustConfig {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
}
#[derive(Debug, Error)]
pub enum TrustError {
    #[error("exchange address is not pinned to the configured peer")]
    AddressMismatch,
    #[error("invalid peer id")]
    InvalidPeerId,
}
pub fn validate_exchange_trust(
    peer_id: &str,
    addresses: &[Multiaddr],
) -> Result<ExchangeTrustConfig, TrustError> {
    let expected = PeerId::from_str(peer_id).map_err(|_| TrustError::InvalidPeerId)?;
    if addresses.is_empty() || addresses.len() > MAX_EXCHANGE_ADDRESSES {
        return Err(TrustError::AddressMismatch);
    }
    let mut validated = Vec::with_capacity(addresses.len());
    for address in addresses {
        let mut terminal = None;
        for component in address.iter() {
            if let Protocol::P2p(peer) = component
                && terminal.replace(peer).is_some()
            {
                return Err(TrustError::AddressMismatch);
            }
        }
        if terminal != Some(expected)
            || address
                .iter()
                .last()
                .is_none_or(|part| !matches!(part, Protocol::P2p(_)))
        {
            return Err(TrustError::AddressMismatch);
        }
        validated.push(address.clone());
    }
    Ok(ExchangeTrustConfig {
        peer_id: expected,
        addresses: validated,
    })
}

pub fn validate_exchange_pin(
    peer_id: &str,
    address_peer_ids: &[&str],
) -> Result<PeerId, TrustError> {
    let expected = PeerId::from_str(peer_id).map_err(|_| TrustError::InvalidPeerId)?;
    if address_peer_ids.len() != 1 || address_peer_ids[0] != peer_id {
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

    #[test]
    fn trust_requires_one_terminal_matching_peer_component() {
        let peer = PeerId::random();
        let base: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let address = base.clone().with(Protocol::P2p(peer));
        let trust = validate_exchange_trust(&peer.to_string(), &[address]).unwrap();
        assert_eq!(trust.peer_id, peer);
        assert!(validate_exchange_trust(&peer.to_string(), &[base]).is_err());
        let middle = "/ip4/127.0.0.1/tcp/4001/p2p-circuit".parse().unwrap();
        assert!(validate_exchange_trust(&peer.to_string(), &[middle]).is_err());
        let other = PeerId::random();
        let duplicate = "/ip4/127.0.0.1/tcp/4001"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(peer))
            .with(Protocol::P2p(other));
        assert!(validate_exchange_trust(&peer.to_string(), &[duplicate]).is_err());
    }
}
