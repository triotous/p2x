use crate::{
    ingress::{IngressCommand, IngressId},
    route_open::{OpenId, TunnelHandoff},
};
use p2x_net::{ConnectionId, probe::ProbePath};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct IngressSetupOwner {
    pub ingress_id: IngressId,
    pub route_id: String,
    pub accepted_at: Instant,
    pub deadline: Instant,
    pub command: mpsc::Sender<IngressCommand>,
    pub cancel: CancellationToken,
    pub open_id: Option<OpenId>,
}

#[derive(Clone)]
pub struct ActiveTunnelOwner {
    pub ingress_id: IngressId,
    pub open_id: OpenId,
    pub server: libp2p::PeerId,
    pub connection: ConnectionId,
    pub request_id_hash: u64,
    pub stream_id_hash: u64,
    pub selected_path: ProbePath,
    pub setup_duration: Duration,
    pub command: mpsc::Sender<IngressCommand>,
    pub cancel: CancellationToken,
}

#[derive(Default)]
pub struct IngressOwnerBook {
    setup: HashMap<IngressId, IngressSetupOwner>,
    active: HashMap<IngressId, ActiveTunnelOwner>,
    by_open: HashMap<OpenId, IngressId>,
    proxy_tasks: HashMap<OpenId, tokio::task::AbortHandle>,
    high_water: usize,
}

impl IngressOwnerBook {
    pub fn insert_setup(&mut self, owner: IngressSetupOwner) -> Result<(), &'static str> {
        debug_assert!(owner.deadline >= owner.accepted_at);
        let id = owner.ingress_id;
        if self.setup.contains_key(&id) || self.active.contains_key(&id) {
            return Err("ingress owner already exists");
        }
        self.setup.insert(id, owner);
        self.high_water = self.high_water.max(self.len());
        Ok(())
    }

    pub fn attach_open(
        &mut self,
        ingress_id: IngressId,
        open_id: OpenId,
    ) -> Result<(), &'static str> {
        let owner = self
            .setup
            .get_mut(&ingress_id)
            .ok_or("ingress setup owner missing")?;
        if owner.open_id.is_some() || self.by_open.contains_key(&open_id) {
            return Err("ingress open owner already exists");
        }
        owner.open_id = Some(open_id);
        self.by_open.insert(open_id, ingress_id);
        Ok(())
    }

    pub fn setup(&self, ingress_id: IngressId) -> Option<&IngressSetupOwner> {
        self.setup.get(&ingress_id)
    }

    pub fn ingress_for_open(&self, open_id: OpenId) -> Option<IngressId> {
        self.by_open.get(&open_id).copied()
    }

    pub fn cancel_for_open(&self, open_id: OpenId) -> Option<CancellationToken> {
        self.ingress_for_open(open_id)
            .and_then(|ingress_id| self.setup.get(&ingress_id))
            .map(|owner| owner.cancel.clone())
    }

    pub fn set_proxy_task(
        &mut self,
        open_id: OpenId,
        task: tokio::task::AbortHandle,
    ) -> Result<(), &'static str> {
        if !self.by_open.contains_key(&open_id) || self.proxy_tasks.contains_key(&open_id) {
            return Err("ingress proxy task owner missing");
        }
        self.proxy_tasks.insert(open_id, task);
        Ok(())
    }

    pub fn take_proxy_task(&mut self, open_id: OpenId) -> Option<tokio::task::AbortHandle> {
        self.proxy_tasks.remove(&open_id)
    }

    pub fn take_proxy_task_id(&mut self, task_id: tokio::task::Id) -> Option<OpenId> {
        let open_id = self
            .proxy_tasks
            .iter()
            .find_map(|(open_id, task)| (task.id() == task_id).then_some(*open_id))?;
        self.proxy_tasks.remove(&open_id);
        Some(open_id)
    }

    pub fn take_setup(&mut self, ingress_id: IngressId) -> Option<IngressSetupOwner> {
        let owner = self.setup.remove(&ingress_id)?;
        if let Some(open_id) = owner.open_id {
            self.by_open.remove(&open_id);
            self.proxy_tasks.remove(&open_id);
        }
        Some(owner)
    }

    pub fn take_setup_for_open(&mut self, open_id: OpenId) -> Option<IngressSetupOwner> {
        let ingress_id = self.ingress_for_open(open_id)?;
        self.take_setup(ingress_id)
    }

    pub fn promote_active(
        &mut self,
        handoff: &TunnelHandoff,
        selected_path: ProbePath,
    ) -> Result<ActiveTunnelOwner, &'static str> {
        let ingress_id = self
            .ingress_for_open(handoff.open_id)
            .ok_or("ingress setup owner missing")?;
        let setup = self
            .setup
            .get(&ingress_id)
            .ok_or("ingress setup owner missing")?;
        if setup.open_id != Some(handoff.open_id) {
            return Err("ingress generation mismatch");
        }
        let setup = self
            .take_setup(ingress_id)
            .ok_or("ingress setup owner missing")?;
        let active = ActiveTunnelOwner {
            ingress_id,
            open_id: handoff.open_id,
            server: handoff.server,
            connection: handoff.connection,
            request_id_hash: p2x_net::lifecycle::stable_hash(handoff.request_id),
            stream_id_hash: p2x_net::lifecycle::stable_hash(handoff.stream_id),
            selected_path,
            setup_duration: setup.accepted_at.elapsed(),
            command: setup.command,
            cancel: setup.cancel,
        };
        self.active.insert(ingress_id, active.clone());
        Ok(active)
    }

    pub fn setup_open_id(&self, ingress_id: IngressId) -> Option<OpenId> {
        self.setup.get(&ingress_id).and_then(|owner| owner.open_id)
    }

    pub async fn start_tunnel(
        &self,
        ingress_id: IngressId,
        stream: Box<dyn crate::ingress::TunnelIo>,
    ) -> Result<(), ()> {
        let Some(owner) = self.active.get(&ingress_id) else {
            return Err(());
        };
        owner
            .command
            .send(IngressCommand::StartTunnel { stream })
            .await
            .map_err(|_| ())
    }

    pub fn take_active(&mut self, ingress_id: IngressId) -> Option<ActiveTunnelOwner> {
        self.active.remove(&ingress_id)
    }

    pub fn active_for_connection(&self, connection: ConnectionId) -> Vec<ActiveTunnelOwner> {
        self.active
            .values()
            .filter(|owner| owner.connection == connection)
            .cloned()
            .collect()
    }

    pub fn setup_ids(&self) -> impl Iterator<Item = IngressId> + '_ {
        self.setup.keys().copied()
    }

    pub fn active_ids(&self) -> impl Iterator<Item = IngressId> + '_ {
        self.active.keys().copied()
    }

    #[allow(dead_code)]
    pub fn setup_len(&self) -> usize {
        self.setup.len()
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    #[cfg(test)]
    pub fn proxy_task_len(&self) -> usize {
        self.proxy_tasks.len()
    }

    #[allow(dead_code)]
    pub fn high_water(&self) -> usize {
        self.high_water
    }

    pub fn len(&self) -> usize {
        self.setup.len() + self.active.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.setup.is_empty() && self.active.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(id: u64) -> IngressSetupOwner {
        let (command, _) = mpsc::channel(1);
        IngressSetupOwner {
            ingress_id: IngressId(id),
            route_id: "orders".into(),
            accepted_at: Instant::now(),
            deadline: Instant::now() + Duration::from_secs(1),
            command,
            cancel: CancellationToken::new(),
            open_id: None,
        }
    }

    #[test]
    fn setup_and_active_are_disjoint_and_release_once() {
        let mut book = IngressOwnerBook::default();
        book.insert_setup(setup(1)).unwrap();
        book.attach_open(IngressId(1), OpenId(9)).unwrap();
        let handoff = TunnelHandoff {
            open_id: OpenId(9),
            server: libp2p::PeerId::random(),
            connection: ConnectionId::new_unchecked(1),
            request_id: [2; 16],
            stream_id: [3; 16],
        };
        let active = book.promote_active(&handoff, ProbePath::Direct).unwrap();
        assert_eq!((book.setup_len(), book.active_len(), book.len()), (0, 1, 1));
        assert_eq!(active.selected_path, ProbePath::Direct);
        assert!(book.promote_active(&handoff, ProbePath::Direct).is_err());
        assert!(book.take_active(IngressId(1)).is_some());
        assert!(book.take_active(IngressId(1)).is_none());
        assert!(book.is_empty());
    }

    #[tokio::test]
    async fn proxy_task_owner_is_released_with_setup() {
        let mut book = IngressOwnerBook::default();
        book.insert_setup(setup(1)).unwrap();
        book.attach_open(IngressId(1), OpenId(9)).unwrap();
        book.set_proxy_task(OpenId(9), tokio::spawn(async {}).abort_handle())
            .unwrap();

        assert!(book.take_setup_for_open(OpenId(9)).is_some());
        assert!(book.take_proxy_task(OpenId(9)).is_none());
    }

    #[test]
    fn stale_open_does_not_remove_live_setup() {
        let mut book = IngressOwnerBook::default();
        book.insert_setup(setup(1)).unwrap();
        assert!(book.take_setup_for_open(OpenId(42)).is_none());
        assert_eq!(book.setup_len(), 1);
    }
}
