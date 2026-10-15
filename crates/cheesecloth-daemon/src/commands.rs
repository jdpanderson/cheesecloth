//! Cluster commands: invites, removal, approvals and settings.

use anyhow::{Result, bail};
use cheesecloth_core::{
    Domain, NodeId, now_ms,
    state::{Command, MemberInfo, Outcome, Permission, Permissions, ProposalKind, SettingChange},
    token::{InviteToken, TOKEN_PEERS, TokenPeer},
};

use crate::{
    Daemon,
    api::{
        ApiError, ConfigView, ErrorCode, InviteView, ProposalKindView, ProposalView, SettingView,
    },
    node::Node,
};

impl Daemon {
    /// An invite token for a joiner with `permissions`.
    pub async fn invite(&self, permissions: Permissions) -> Result<InviteView> {
        let node = self.require_node()?;
        let secret: [u8; 32] = rand::random();
        let outcome = node
            .submit(Command::CreateInvite {
                invite_id: cheesecloth_core::state::invite_id(&secret),
                permissions,
            })
            .await?;
        let Outcome::InviteCreated { expires_at_ms } = outcome else {
            bail!(ApiError::new(
                ErrorCode::InternalError,
                format!("unexpected outcome {outcome:?}"),
            ));
        };
        // Only members with the vote permission take a redemption to
        // consensus, and only once they know the invite. List this node
        // first, as it knows the invite. Then relays, then others.
        let me = self.node_id();
        let mut members: Vec<(bool, bool, NodeId)> = node
            .agreed()
            .state()
            .with(Permission::Vote)
            .map(|id| (*id != me, !node.is_relay(id), *id))
            .collect();
        members.sort();
        let peers: Vec<TokenPeer> = members
            .into_iter()
            .map(|(_, _, id)| TokenPeer {
                node_id: id,
                addrs: node.control_addrs_of(&id),
            })
            .filter(|p| !p.addrs.is_empty())
            .take(TOKEN_PEERS)
            .collect();
        let token = InviteToken {
            cluster_id: node.cluster_id,
            secret,
            peers,
        };
        Ok(InviteView {
            token: token.to_string(),
            expires_at_ms,
        })
    }

    fn resolve_node(&self, node: &Node, prefix: &str) -> Result<NodeId> {
        let prefix = prefix.to_lowercase();
        let matches: Vec<NodeId> = node
            .agreed()
            .state()
            .members
            .iter()
            .filter(|(id, m)| {
                id.to_string().starts_with(&prefix) || m.info.name.to_lowercase() == prefix
            })
            .map(|(id, _)| *id)
            .collect();
        match matches.as_slice() {
            [one] => Ok(*one),
            [] => bail!(ApiError::new(
                ErrorCode::NoSuchMember,
                format!("no member matches {prefix:?}"),
            )),
            _ => bail!(ApiError::new(
                ErrorCode::AmbiguousNode,
                format!("{prefix:?} matches several members; use more of the node ID"),
            )),
        }
    }

    pub async fn remove(&self, target: &str) -> Result<Outcome> {
        let node = self.require_node()?;
        let target = self.resolve_node(&node, target)?;
        if target == self.node_id() {
            bail!(ApiError::new(
                ErrorCode::RemoveSelf,
                "use `cheesecloth leave` to remove this node",
            ));
        }
        node.submit(Command::ProposeRemove { target }).await
    }

    // ---------------------------------------------------- approvals

    pub fn pending(&self) -> Result<Vec<ProposalView>> {
        let node = self.require_node()?;
        let agreed = node.agreed();
        let st = agreed.state();
        let needed = st.settings().map_or(0, |s| s.approvals_required);
        let now = now_ms();
        Ok(st
            .proposals
            .values()
            .map(|p| {
                let (kind, n, name, permissions, setting) = match &p.kind {
                    ProposalKind::Join {
                        joiner,
                        permissions,
                    } => {
                        let info = joiner.open(Domain::MemberInfo).ok();
                        (
                            ProposalKindView::Join,
                            Some(joiner.signer),
                            info.map(|i: MemberInfo| i.name),
                            Some(*permissions),
                            None,
                        )
                    }
                    ProposalKind::Remove { target } => (
                        ProposalKindView::Remove,
                        Some(*target),
                        st.members.get(target).map(|m| m.info.name.clone()),
                        None,
                        None,
                    ),
                    ProposalKind::Setting { change } => (
                        ProposalKindView::Setting,
                        None,
                        None,
                        None,
                        Some(SettingView::from(change)),
                    ),
                };
                ProposalView {
                    id: p.id,
                    kind,
                    node: n,
                    name,
                    permissions,
                    setting,
                    proposer: p.proposer,
                    approvals: p.approvals.keys().copied().collect(),
                    needed,
                    expires_in_secs: p.expires_at_ms.saturating_sub(now) / 1000,
                }
            })
            .collect())
    }

    pub async fn vote(
        &self,
        proposal: cheesecloth_core::ProposalId,
        approve: bool,
    ) -> Result<Outcome> {
        let node = self.require_node()?;
        let cmd = if approve {
            Command::Approve { proposal }
        } else {
            Command::Reject { proposal }
        };
        node.submit(cmd).await
    }

    // ------------------------------------------------------ settings

    pub fn config_get(&self) -> Result<ConfigView> {
        let node = self.require_node()?;
        let agreed = node.agreed();
        let Some(s) = agreed.state().settings() else {
            bail!(ApiError::new(
                ErrorCode::InternalError,
                "the agreed state has no settings",
            ));
        };
        Ok(ConfigView {
            settings: s.clone(),
            ipv6_prefix: cheesecloth_core::addr::ula_prefix(&node.cluster_id).to_string(),
        })
    }

    pub async fn config_set(&self, key: &str, value: &str) -> Result<Outcome> {
        let node = self.require_node()?;
        if key == "ipv4_range" {
            bail!(ApiError::new(
                ErrorCode::InvalidSetting,
                "the IPv4 range is fixed once the cluster exists",
            ));
        }
        let change = SettingChange::parse(key, value)
            .map_err(|e| ApiError::new(ErrorCode::InvalidSetting, e.to_string()))?;
        node.submit(Command::ProposeSetting { change }).await
    }
}
