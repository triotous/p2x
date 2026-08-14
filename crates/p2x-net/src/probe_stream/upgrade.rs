use libp2p::{
    StreamProtocol,
    core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo},
};
use std::{future::Ready, io};

#[derive(Clone, Copy, Debug, Default)]
pub struct ProbeUpgrade;
impl UpgradeInfo for ProbeUpgrade {
    type Info = StreamProtocol;
    type InfoIter = std::iter::Once<Self::Info>;
    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(StreamProtocol::new("/p2x/spike/1"))
    }
}
impl<C: Send + 'static> InboundUpgrade<C> for ProbeUpgrade {
    type Output = C;
    type Error = io::Error;
    type Future = Ready<Result<C, io::Error>>;
    fn upgrade_inbound(self, socket: C, _: Self::Info) -> Self::Future {
        std::future::ready(Ok(socket))
    }
}
impl<C: Send + 'static> OutboundUpgrade<C> for ProbeUpgrade {
    type Output = C;
    type Error = io::Error;
    type Future = Ready<Result<C, io::Error>>;
    fn upgrade_outbound(self, socket: C, _: Self::Info) -> Self::Future {
        std::future::ready(Ok(socket))
    }
}
