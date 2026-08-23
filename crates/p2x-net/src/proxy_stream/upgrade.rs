use libp2p::{
    StreamProtocol,
    core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo},
};
use std::{future::Ready, io};
#[derive(Clone, Copy, Debug)]
pub struct ProxyUpgrade {
    pub enabled: bool,
}
impl Default for ProxyUpgrade {
    fn default() -> Self {
        Self { enabled: true }
    }
}
impl UpgradeInfo for ProxyUpgrade {
    type Info = StreamProtocol;
    type InfoIter = std::vec::IntoIter<Self::Info>;
    fn protocol_info(&self) -> Self::InfoIter {
        if self.enabled {
            vec![StreamProtocol::new("/p2x/proxy/1")].into_iter()
        } else {
            Vec::new().into_iter()
        }
    }
}
impl<C: Send + 'static> InboundUpgrade<C> for ProxyUpgrade {
    type Output = C;
    type Error = io::Error;
    type Future = Ready<Result<C, io::Error>>;
    fn upgrade_inbound(self, socket: C, _: Self::Info) -> Self::Future {
        std::future::ready(Ok(socket))
    }
}
impl<C: Send + 'static> OutboundUpgrade<C> for ProxyUpgrade {
    type Output = C;
    type Error = io::Error;
    type Future = Ready<Result<C, io::Error>>;
    fn upgrade_outbound(self, socket: C, _: Self::Info) -> Self::Future {
        std::future::ready(Ok(socket))
    }
}
