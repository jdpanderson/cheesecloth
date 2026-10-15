//! What this node knows about the members: records, relays, public addresses,
//! and where to reach each one on the control plane.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use cheesecloth_core::NodeId;
use ipnet::IpNet;

use super::{Chosen, Node};
use crate::{RelayMode, soft::public_ip};

impl Node {
    /// The latest agreed state this node has learned.
    pub fn agreed(&self) -> Arc<Chosen> {
        self.state.borrow().clone()
    }

    pub fn is_member(&self, node: &NodeId) -> bool {
        self.agreed().state().is_member(node)
    }

    /// Current relay role (see `SoftTable::is_relay`). Reachability alone
    /// grants no relay role.
    pub fn is_relay(&self, node: &NodeId) -> bool {
        let agreed = self.agreed();
        let Some(member) = agreed.state().members.get(node) else {
            return false;
        };
        let my_relay = self.facts.lock().relay;
        self.soft.lock().is_relay(self.me, my_relay, node, member)
    }

    pub fn relays(&self) -> Vec<NodeId> {
        self.agreed()
            .state()
            .members
            .keys()
            .filter(|n| self.is_relay(n))
            .copied()
            .collect()
    }

    pub fn have_relays(&self) -> bool {
        !self.relays().is_empty()
    }

    /// Membership and connectivity warnings, using current relay roles.
    pub fn warnings(&self) -> Vec<String> {
        let agreed = self.agreed();
        let mut warnings = agreed.state().warnings();
        if agreed.state().members.len() > 1 && !self.have_relays() {
            warnings.push(
                "the cluster has no relay: members behind different NATs may not reach each other"
                    .into(),
            );
        }
        if !agreed.state().may_relay(&self.me) && self.opts.relay == RelayMode::Always {
            warnings.push(
                "this node is an unprivileged member, so it doesn't relay; --relay always is \
                 ignored"
                    .into(),
            );
        }
        if self.facts.lock().only_local_vias {
            warnings.push(
                "reachability not checked: no member outside our network is connected".into(),
            );
        }
        warnings
    }

    /// A node's public IP (see `soft::public_ip`).
    pub fn public_ip_of(&self, node: &NodeId) -> Option<IpAddr> {
        let own = (*node == self.me).then(|| self.facts.lock().clone());
        let agreed = self.agreed();
        let soft = self.soft.lock();
        public_ip(
            own.as_ref(),
            soft.get(node),
            soft.observed_by_public(node, &agreed.state().members),
        )
    }

    /// A member's current control-plane addresses: ours from our own facts,
    /// others' from their soft state, falling back to their member record.
    pub fn control_addrs_of(&self, node: &NodeId) -> Vec<SocketAddr> {
        if *node == self.me {
            return self.facts.lock().control_addrs.clone();
        }
        let soft = self.soft.lock().get(node).map(|s| s.control_addrs.clone());
        match soft {
            Some(addrs) if !addrs.is_empty() => addrs,
            _ => self
                .agreed()
                .state()
                .members
                .get(node)
                .map(|m| m.info.control_addrs.clone())
                .unwrap_or_default(),
        }
    }

    /// WireGuard persistent keepalive towards peers with a direct path.
    pub fn wg_keepalive(&self) -> u16 {
        self.opts.keepalive.unwrap_or_else(|| {
            let f = self.facts.lock();
            if f.mapped_wg.is_some() {
                cheesecloth_core::MAPPED_KEEPALIVE_SECS
            } else if f.public {
                0
            } else {
                cheesecloth_core::NAT_KEEPALIVE_SECS
            }
        })
    }

    /// Router port mappings: `None` when port mapping is off.
    pub fn port_mapping(&self) -> Option<Vec<crate::api::PortMapView>> {
        self.portmaps.as_ref().map(|p| p.views())
    }

    pub fn overlay_nets(&self) -> Vec<IpNet> {
        let mut nets = vec![IpNet::V6(cheesecloth_core::addr::ula_prefix(
            &self.cluster_id,
        ))];
        if let Some(s) = self.agreed().state().settings() {
            nets.push(IpNet::V4(s.ipv4_range));
        }
        nets
    }

    /// Where to dial `node` directly, if at all. Relays are always dialled;
    /// other members only on the same LAN, or in a cluster without relays.
    pub fn dial_addrs(&self, node: &NodeId) -> Vec<SocketAddr> {
        if !self.is_member(node) {
            return Vec::new();
        }
        let mut addrs = self.control_addrs_of(node);
        if self.is_relay(node) || !self.have_relays() {
            return addrs;
        }
        let same_site = match (self.public_ip_of(&self.me), self.public_ip_of(node)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        };
        if !same_site {
            return Vec::new();
        }
        let facts = self.facts.lock();
        addrs.retain(|a| facts.ifaces.contains(a.ip()));
        addrs
    }

    /// Relays that may forward to `node`: those connected to it first.
    pub fn forwarders(&self, node: &NodeId) -> Vec<NodeId> {
        let relays = self.relays();
        let soft = self.soft.lock();
        let mut relays: Vec<(bool, NodeId)> = relays
            .into_iter()
            .filter(|r| r != node && *r != self.me)
            .map(|r| {
                let connected = soft.get(&r).is_some_and(|s| s.connected.contains(node));
                (!connected, r)
            })
            .collect();
        relays.sort();
        relays.into_iter().map(|(_, r)| r).collect()
    }
}
