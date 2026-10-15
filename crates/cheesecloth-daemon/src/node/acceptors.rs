//! Adaptive voter selection. Every transition is certified by the installed
//! configuration. Reachability never changes voting authority by itself.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use cheesecloth_core::{
    Domain, NodeId,
    state::{ClusterState, Command, MAX_ACCEPTORS, MIN_PROTECTED_ACCEPTORS},
};
use pnyx::Change;
use tracing::info;

use super::{
    Node,
    consensus::{Refused, short},
};

/// An acceptor that no member has seen for this long is replaced.
const ABSENT_AFTER: Duration = Duration::from_secs(600);
/// How often the acceptor set is checked. Checking sends nothing.
const CHECK_EVERY: Duration = Duration::from_secs(10);

/// Desired size; absence only proposes a change, never installs a quorum.
fn size(st: &ClusterState, available: usize) -> usize {
    usize::from(st.settings().map_or(MAX_ACCEPTORS, |s| s.acceptors))
        .min(available)
        .max(1)
}

pub(super) fn check_policy(base: &super::Agreed, st: &ClusterState) -> Result<(), String> {
    if base.config.protected
        && st
            .settings()
            .is_some_and(|s| s.strict_security && s.acceptors < MIN_PROTECTED_ACCEPTORS)
    {
        return Err("disable strict_security before reducing the voter cap below four".into());
    }
    Ok(())
}

pub fn configuration(
    base: &super::Agreed,
    st: &ClusterState,
    acceptors: BTreeSet<NodeId>,
) -> Result<pnyx::Config<NodeId>, String> {
    let settings = st.settings().ok_or("cluster has no settings")?;
    let n = acceptors.len();
    let latched = settings.strict_security && base.config.protected;
    let protected = n >= usize::from(MIN_PROTECTED_ACCEPTORS)
        && (latched || n - pnyx::quorum(n, true) >= settings.buffer_nodes as usize);
    if latched && !protected {
        return Err("strict security forbids reducing the protected configuration".into());
    }
    Ok(base.config.successor(acceptors, protected))
}

pub fn check_set(
    next: &pnyx::Config<NodeId>,
    base: &super::Agreed,
    st: &ClusterState,
) -> Result<(), String> {
    if next.acceptors.is_empty() || next.acceptors.len() > size(st, st.privileged().count()) {
        return Err("invalid acceptor count".into());
    }
    if next.acceptors.iter().any(|id| !st.is_privileged(id)) {
        return Err("acceptor is not a privileged member".into());
    }
    if *next != configuration(base, st, next.acceptors.clone())? {
        return Err("invalid configuration policy or sequence".into());
    }
    Ok(())
}

/// What is known about a member when choosing acceptors.
#[derive(Clone, Copy, Debug, Default)]
pub struct Candidate {
    pub relay: bool,
    /// Known to be alive now (see `SoftTable::live`).
    pub present: bool,
    /// Not seen for `ABSENT_AFTER`.
    pub absent: bool,
}

/// Keep eligible voters, preferring present members and relays. Fill up to
/// the configured cap with privileged members not absent for the grace
/// period. A buffer absorbs absences without changing the installed group.
/// Unprivileged members never vote.
pub fn choose(
    current: &BTreeSet<NodeId>,
    st: &ClusterState,
    facts: impl Fn(&NodeId) -> Candidate,
) -> BTreeSet<NodeId> {
    let available = st.privileged().filter(|id| !facts(id).absent).count();
    let buffer = st.settings().map_or(0, |s| s.buffer_nodes as usize);
    let absent = current.iter().filter(|id| facts(id).absent).count();
    if absent > 0
        && absent <= buffer
        && current.len() <= size(st, st.privileged().count())
        && current.iter().all(|id| st.is_privileged(id))
        && available <= current.len()
    {
        return current.clone();
    }
    let target = size(st, available);
    let key = |id: &NodeId| {
        let f = facts(id);
        (f.absent, !f.present, !f.relay, *id)
    };
    let mut keep: Vec<NodeId> = current
        .iter()
        .filter(|a| st.is_privileged(a) && !facts(a).absent)
        .copied()
        .collect();
    keep.sort_by_key(key);
    keep.truncate(target);
    let mut spare: Vec<NodeId> = st
        .privileged()
        .filter(|m| !keep.contains(m) && !facts(m).absent)
        .copied()
        .collect();
    spare.sort_by_key(key);
    let missing = target - keep.len();
    keep.extend(spare.into_iter().take(missing));
    if keep.is_empty() {
        return current.clone();
    }
    keep.into_iter().collect()
}

/// Whether a quorum of `config`'s acceptors is present, so that they could
/// agree on changes now. A change to a set without one would stop the
/// cluster until enough of them come back.
pub(super) fn present_quorum(
    config: &pnyx::Config<NodeId>,
    facts: impl Fn(&NodeId) -> Candidate,
) -> bool {
    config.acceptors.iter().filter(|a| facts(a).present).count() >= config.quorum()
}

impl Node {
    /// Availability is an input to a proposed transition, never authority to
    /// install one. Each honest verifier checks its own observations.
    pub(super) fn check_reconfiguration(
        &self,
        base: &super::Agreed,
        value: &super::Agreed,
    ) -> Result<()> {
        let Some(next) = &value.next else {
            return Ok(());
        };
        let mut eligible = value.value.clone();
        if let Some(request) = eligible.step.as_ref().and_then(|s| s.command.as_ref()) {
            let body = request.command.open(Domain::Command)?;
            if body.command == Command::GiveUpAcceptor {
                eligible.members.remove(&request.command.signer);
                ensure!(
                    !next.acceptors.contains(&request.command.signer),
                    "giving-up member remains an acceptor"
                );
            }
        }
        let live = self.live();
        let expected = choose(base.acceptors(), &eligible, |id| self.candidate(id, &live));
        ensure!(
            next.acceptors.len() >= expected.len(),
            "configuration omits available voters"
        );
        ensure!(
            next.acceptors.intersection(&live).count() >= next.quorum(),
            "new configuration has no reachable quorum"
        );
        Ok(())
    }

    /// The nodes known to be alive now (see `SoftTable::live`).
    pub fn live(&self) -> BTreeSet<NodeId> {
        let direct: Vec<NodeId> = self.net.connections().iter().map(|c| c.node).collect();
        self.soft.lock().live(self.me, direct)
    }

    /// What `choose` needs to know about `node`, given the live nodes.
    pub(super) fn candidate(&self, node: &NodeId, live: &BTreeSet<NodeId>) -> Candidate {
        let absent = self
            .absent
            .lock()
            .get(node)
            .is_some_and(|t| t.elapsed() >= ABSENT_AFTER);
        Candidate {
            relay: self.is_relay(node),
            present: live.contains(node),
            absent,
        }
    }

    pub(super) async fn acceptors_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        loop {
            tick.tick().await;
            self.acceptors_problem.record(self.check_acceptors().await);
        }
    }

    pub(super) async fn check_acceptors(&self) -> Result<()> {
        let agreed = self.agreed();
        let current = agreed.value.acceptors().clone();
        let live = self.live();
        for a in agreed.state().members.keys() {
            let mut absent = self.absent.lock();
            if live.contains(a) {
                absent.remove(a);
            } else {
                absent.entry(*a).or_insert_with(Instant::now);
            }
        }
        self.absent
            .lock()
            .retain(|n, _| agreed.state().is_member(n));
        if !current.contains(&self.me) {
            return Ok(());
        }
        let installed = agreed.value.active_config();
        // The present acceptor with the lowest node ID acts. Two acting at
        // once is still safe: one of them finds the change made.
        if current.iter().find(|a| live.contains(a)) != Some(&self.me) {
            return Ok(());
        }
        let facts = |n: &NodeId| self.candidate(n, &live);
        let desired = choose(&current, agreed.state(), facts);
        let wanted = configuration(&agreed.value, agreed.state(), desired.clone())
            .map_err(anyhow::Error::msg)?;
        if desired == current && wanted.protected == installed.protected {
            return Ok(());
        }
        if !present_quorum(installed, facts) {
            anyhow::bail!("current quorum unavailable; configuration changes paused");
        }
        if !present_quorum(&wanted, facts) {
            return Err(Refused::NoPresentMajority.into());
        }
        self.propose_change(|agreed| {
            let current = agreed.acceptors();
            let desired = choose(current, &agreed.value, facts);
            let config = match configuration(agreed, &agreed.value, desired.clone()) {
                Ok(c) => c,
                Err(e) => return (Change::Keep, Err(Refused::Security(e))),
            };
            if desired == *current && config.protected == agreed.config.protected {
                return (Change::Keep, Ok(()));
            }
            if !present_quorum(&config, facts) {
                return (Change::Keep, Err(Refused::NoPresentMajority));
            }
            info!(acceptors = ?short(&desired), "changing the acceptors");
            let mut next = agreed.value.clone();
            next.record_step(&agreed.value, None);
            (Change::Close(next, config), Ok(()))
        })
        .await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
