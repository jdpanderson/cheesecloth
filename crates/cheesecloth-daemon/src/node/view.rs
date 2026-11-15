//! What this node knows about the members: records, relays, public addresses,
//! and where to reach each one on the control plane.

use std::{
    cell::OnceCell,
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use cheesecloth_core::{NodeId, state::Member};
use ipnet::IpNet;
use parking_lot::MutexGuard;

use super::{Chosen, Learned, LocalFacts, Node};
use crate::{
    RelayMode,
    soft::{SoftTable, public_ip, relay_role},
};

/// What this node knows about the members at one moment: the agreed state,
/// this node's own facts and the soft table. Every question about a member
/// that needs more than one of these is answered here, so the answers to
/// several questions agree with each other.
///
/// It holds the `facts` and `soft` locks, taken in their order (see `Node`).
/// While one lives, don't take either lock again: `Node`'s methods of the
/// same names as the ones here do. It can't be kept across an `.await`.
pub struct View<'a> {
    me: NodeId,
    agreed: Arc<Chosen>,
    facts: MutexGuard<'a, LocalFacts>,
    soft: MutexGuard<'a, SoftTable>,
    /// Each member's endpoint as public members observe it (see
    /// `SoftTable::observations`), worked out when first asked for.
    observed: OnceCell<HashMap<NodeId, SocketAddr>>,
}

impl View<'_> {
    /// The agreed state this view is of.
    pub fn agreed(&self) -> &Arc<Chosen> {
        &self.agreed
    }

    pub fn members(&self) -> &BTreeMap<NodeId, Member> {
        &self.agreed.state().members
    }

    /// This node's own facts.
    pub fn facts(&self) -> &LocalFacts {
        &self.facts
    }

    pub fn soft(&self) -> &SoftTable {
        &self.soft
    }

    /// Each member's WireGuard endpoint as public members observe it.
    pub fn observations(&self) -> &HashMap<NodeId, SocketAddr> {
        self.observed
            .get_or_init(|| self.soft.observations(self.members()))
    }

    /// Whether `node` is a relay now: for this node, its own facts; for
    /// another member, `relay_role` with its soft state. Reachability alone
    /// grants no relay role.
    pub fn is_relay(&self, node: &NodeId) -> bool {
        let Some(member) = self.members().get(node) else {
            return false;
        };
        if *node == self.me {
            self.facts.relay
        } else {
            relay_role(member, self.soft.get(node))
        }
    }

    pub fn relays(&self) -> Vec<NodeId> {
        self.members()
            .keys()
            .filter(|n| self.is_relay(n))
            .copied()
            .collect()
    }

    pub fn have_relays(&self) -> bool {
        self.members().keys().any(|n| self.is_relay(n))
    }

    /// A node's public IP (see `soft::public_ip`).
    pub fn public_ip_of(&self, node: &NodeId) -> Option<IpAddr> {
        let own = (*node == self.me).then_some(&*self.facts);
        public_ip(
            own,
            self.soft.get(node),
            self.observations().get(node).copied(),
        )
    }

    /// A member's current control-plane addresses: ours from our own facts,
    /// others' from their soft state, falling back to their member record.
    pub fn control_addrs_of(&self, node: &NodeId) -> Vec<SocketAddr> {
        if *node == self.me {
            return self.facts.control_addrs.clone();
        }
        match self.soft.get(node).map(|s| &s.control_addrs) {
            Some(addrs) if !addrs.is_empty() => addrs.clone(),
            _ => self
                .members()
                .get(node)
                .map(|m| m.info.control_addrs.clone())
                .unwrap_or_default(),
        }
    }

    /// Where to dial `node` directly, if at all. Relays are always dialled;
    /// other members only on the same LAN, or in a cluster without relays.
    pub fn dial_addrs(&self, node: &NodeId) -> Vec<SocketAddr> {
        if !self.members().contains_key(node) {
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
        addrs.retain(|a| self.facts.ifaces.contains(a.ip()));
        addrs
    }

    /// Relays that may forward to `node`: those connected to it first.
    pub fn forwarders(&self, node: &NodeId) -> Vec<NodeId> {
        let mut relays: Vec<(bool, NodeId)> = self
            .relays()
            .into_iter()
            .filter(|r| r != node && *r != self.me)
            .map(|r| {
                let connected = self
                    .soft
                    .get(&r)
                    .is_some_and(|s| s.connected.contains(node));
                (!connected, r)
            })
            .collect();
        relays.sort();
        relays.into_iter().map(|(_, r)| r).collect()
    }
}

impl Node {
    /// The latest agreed state this node has learned.
    pub fn agreed(&self) -> Arc<Chosen> {
        self.state.borrow().chosen.clone()
    }

    /// The latest agreed state this node has learned, with its proof.
    pub fn learned(&self) -> Learned {
        self.state.borrow().clone()
    }

    pub fn is_member(&self, node: &NodeId) -> bool {
        self.agreed().state().is_member(node)
    }

    /// What this node knows about the members now. For one question, the
    /// methods below do; for several, ask one view.
    pub fn view(&self) -> View<'_> {
        let agreed = self.agreed();
        let facts = self.facts.lock();
        let soft = self.soft.lock();
        View {
            me: self.me,
            agreed,
            facts,
            soft,
            observed: OnceCell::new(),
        }
    }

    /// See `View::is_relay`.
    pub fn is_relay(&self, node: &NodeId) -> bool {
        self.view().is_relay(node)
    }

    pub fn relays(&self) -> Vec<NodeId> {
        self.view().relays()
    }

    /// Membership and connectivity warnings, using current relay roles.
    pub fn warnings(&self) -> Vec<String> {
        let view = self.view();
        let state = view.agreed().state();
        let mut warnings = state.warnings();
        if state.members.len() > 1 && !view.have_relays() {
            warnings.push(
                "the cluster has no relay: members behind different NATs may not reach each other"
                    .into(),
            );
        }
        if !state.may_relay(&self.me) && self.opts.relay == RelayMode::Always {
            warnings.push(
                "this node doesn't have the relay permission, so it doesn't relay; --relay \
                 always is ignored"
                    .into(),
            );
        }
        if view.facts().only_local_vias {
            warnings.push(
                "reachability not checked: no member outside our network is connected".into(),
            );
        }
        warnings
    }

    /// See `View::public_ip_of`.
    pub fn public_ip_of(&self, node: &NodeId) -> Option<IpAddr> {
        self.view().public_ip_of(node)
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

    /// See `View::dial_addrs`.
    pub fn dial_addrs(&self, node: &NodeId) -> Vec<SocketAddr> {
        self.view().dial_addrs(node)
    }

    /// See `View::forwarders`.
    pub fn forwarders(&self, node: &NodeId) -> Vec<NodeId> {
        self.view().forwarders(node)
    }
}
