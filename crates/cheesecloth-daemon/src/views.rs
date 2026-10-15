//! `status` and `peers`.

use anyhow::Result;
use cheesecloth_core::state::Member;

use crate::{
    Daemon, Phase,
    api::{NodePhase, PathState, PeerView, StatusView},
    clock,
    node::acceptors,
    wgrec::PathReport,
};

impl Daemon {
    pub async fn status(&self) -> Result<StatusView> {
        let me = self.node_id();
        let mut v = StatusView {
            security: "uninitialized".into(),
            quorum: 0,
            reachable_voters: 0,
            changes_paused: false,
            strict_security: false,
            buffer_nodes: 0,
            node_id: me,
            name: self.opts.name.clone(),
            phase: NodePhase::None,
            cluster_id: None,
            pending_proposal: None,
            ipv4: None,
            ipv6: None,
            privileged: None,
            relay: false,
            public: false,
            keepalive: 0,
            acceptors: Vec::new(),
            config: None,
            version: None,
            members: 0,
            control_addr: self.net.local_addr().ok(),
            wg_backend: None,
            wg_interface: self.opts.interface.clone(),
            wg_port: self.opts.wg_port,
            port_mapping: None,
            warnings: Vec::new(),
        };
        let node = match &*self.phase.read() {
            Phase::None | Phase::Stopped => return Ok(v),
            Phase::Stopping { cleanup, error, .. } => {
                v.phase = NodePhase::Stopping;
                v.cluster_id = Some(cleanup.cluster_id.to_string());
                v.changes_paused = true;
                v.warnings.extend(error.clone());
                return Ok(v);
            }
            Phase::Pending {
                cluster_id,
                pending,
            } => {
                v.phase = NodePhase::Pending;
                v.cluster_id = Some(cluster_id.to_string());
                v.pending_proposal = Some(pending.proposal);
                return Ok(v);
            }
            Phase::Member(n) => n.clone(),
        };
        v.phase = NodePhase::Member;
        v.cluster_id = Some(node.cluster_id.to_string());
        let agreed = node.agreed();
        let members = &agreed.state().members;
        v.members = members.len();
        v.ipv4 = members.get(&me).map(|m| m.ipv4);
        v.privileged = members.get(&me).map(|m| m.privileged);
        v.ipv6 = Some(cheesecloth_core::addr::node_ipv6(&node.cluster_id, &me));
        {
            let f = node.facts.lock();
            v.relay = f.relay;
            v.public = f.public;
        }
        v.port_mapping = node.port_mapping();
        v.keepalive = node.wg_keepalive();
        v.acceptors = agreed.value.acceptors().iter().copied().collect();
        let config = agreed.value.active_config();
        v.security = if config.protected {
            "protected"
        } else {
            "relaxed"
        }
        .into();
        v.quorum = config.quorum();
        let live = node.live();
        v.reachable_voters = acceptors::reachable(config, &live);
        v.changes_paused = !acceptors::present_quorum(config, &live);
        if let Some(settings) = agreed.state().settings() {
            v.strict_security = settings.strict_security;
            v.buffer_nodes = settings.buffer_nodes;
        }
        if !config.protected {
            v.warnings
                .push("Byzantine safety guarantees are suspended in relaxed mode".into());
        }
        if v.changes_paused {
            v.warnings
                .push("Current quorum unavailable; changes paused".into());
        }
        v.config = Some(config.number);
        v.version = Some(agreed.value.version);
        {
            let wg = node.wg.lock();
            v.wg_backend = wg.backend_kind().map(String::from);
            v.warnings.extend(wg.warnings());
        }
        v.warnings.extend(node.warnings());
        v.warnings
            .extend(clock::warnings(&node.net.clock_offsets()));
        v.warnings.extend(node.problems());
        Ok(v)
    }

    pub fn peers(&self) -> Result<Vec<PeerView>> {
        let node = self.require_node()?;
        let me = self.node_id();
        let agreed = node.agreed();
        let acceptors = agreed.value.acceptors();
        let live = node.live();
        let relays = node.relays();
        let wg = node.wg.lock();
        Ok(agreed
            .state()
            .members
            .iter()
            .map(
                |(
                    &id,
                    Member {
                        info,
                        ipv4,
                        privileged,
                        ..
                    },
                )| {
                    let path = if id == me {
                        PathReport {
                            kind: "self",
                            state: PathState::ThisNode,
                            retry_in_secs: None,
                            endpoint: None,
                            handshake_age_secs: None,
                        }
                    } else {
                        wg.describe(&id)
                    };
                    PeerView {
                        node_id: id,
                        name: info.name.clone(),
                        ipv4: *ipv4,
                        ipv6: Some(cheesecloth_core::addr::node_ipv6(&node.cluster_id, &id)),
                        privileged: *privileged,
                        relay: relays.contains(&id),
                        acceptor: acceptors.contains(&id),
                        this_node: id == me,
                        connected: node.net.is_connected(&id),
                        present: live.contains(&id),
                        wg_key: info.wg_key,
                        path: path.kind.into(),
                        path_state: path.state,
                        path_detail: path.state.detail(path.retry_in_secs),
                        retry_in_secs: path.retry_in_secs,
                        wg_endpoint: path.endpoint,
                        handshake_age_secs: path.handshake_age_secs,
                    }
                },
            )
            .collect())
    }
}
