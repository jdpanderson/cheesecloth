//! Verification and acceptance certificates, plus configuration transitions
//! (see *Authenticated round* in CONSENSUS-SAFETY.md).
//!
//! A verification quorum permits acceptance; an acceptance quorum proves the
//! value was chosen. A node checks a certificate against an acceptor set
//! it trusts: its own latest state's, or one that a chain of transitions (the
//! certificates of closing values) leads to from there.

use std::{collections::BTreeMap, io, path::Path};

use anyhow::{Result, bail};
use cheesecloth_core::{
    ClusterId, Domain, Identity, NodeId, Signature,
    state::{MAX_ACCEPTORS, MIN_PROTECTED_ACCEPTORS},
    verify,
};
use pnyx::{Ballot, Config};
use serde::{Deserialize, Serialize};

use super::{Agreed, Chosen};
use crate::files;

/// The most bytes of transitions sent with a state. A message may be 1 MiB,
/// and a state 320 KiB.
const MAX_TRANSITION_BYTES: usize = 256 << 10;

/// The complete value context that voters sign, with a hash of the state body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Header {
    pub cluster_id: ClusterId,
    pub version: u64,
    pub config: Config<NodeId>,
    /// The next acceptors, if the value closes its configuration.
    pub next: Option<Config<NodeId>>,
    /// The state's time, so that old transitions can be dropped.
    pub now_ms: u64,
    /// The hash of the state (see `ClusterState::hash`).
    pub state: [u8; 32],
}

impl Header {
    pub fn of(cluster_id: ClusterId, value: &Agreed) -> Header {
        Header {
            cluster_id,
            version: value.version,
            config: value.config.clone(),
            next: value.next.clone(),
            now_ms: value.value.now_ms,
            state: value.value.hash(),
        }
    }
    /// Header of the opening derived from this closing value, without
    /// cloning or hashing the state body.
    pub fn opened(&self) -> Option<Self> {
        Some(Self {
            version: self.version.checked_add(1)?,
            config: self.next.clone()?,
            next: None,
            ..self.clone()
        })
    }
}

/// Votes on a value's header at a ballot. A verification quorum authorizes
/// acceptance; an acceptance quorum proves agreement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub verified: bool,
    pub header: Header,
    pub ballot: Ballot<NodeId>,
    pub sigs: BTreeMap<NodeId, Signature>,
}

impl Certificate {
    fn message(header: &Header, ballot: &Ballot<NodeId>) -> Vec<u8> {
        postcard::to_stdvec(&(header, ballot)).expect("serializable")
    }

    /// One acceptor's statement that it accepted the value with `header` at
    /// `ballot`.
    pub fn sign(identity: &Identity, header: Header, ballot: Ballot<NodeId>) -> Certificate {
        Self::sign_phase(identity, header, ballot, false)
    }

    pub fn sign_verified(identity: &Identity, header: Header, ballot: Ballot<NodeId>) -> Self {
        Self::sign_phase(identity, header, ballot, true)
    }

    fn domain(verified: bool) -> Domain {
        if verified {
            Domain::Verification
        } else {
            Domain::Accept
        }
    }

    fn sign_phase(
        identity: &Identity,
        header: Header,
        ballot: Ballot<NodeId>,
        verified: bool,
    ) -> Self {
        let sig = identity.sign(Self::domain(verified), &Self::message(&header, &ballot));
        Self {
            verified,
            header,
            ballot,
            sigs: BTreeMap::from([(identity.node_id(), sig)]),
        }
    }

    pub fn check_signer(&self, signer: &NodeId) -> Result<()> {
        let sig = self
            .sigs
            .get(signer)
            .ok_or_else(|| anyhow::anyhow!("missing signature"))?;
        verify(
            signer,
            Self::domain(self.verified),
            &Self::message(&self.header, &self.ballot),
            sig,
        )?;
        Ok(())
    }

    /// Checks the phase, complete trusted configuration and quorum signatures.
    /// Signatures from outside the configuration do not count.
    pub fn check_config(&self, config: &Config<NodeId>, verified: bool) -> Result<()> {
        if !valid_config(config) {
            bail!("invalid voter configuration");
        }
        if self.verified != verified || self.header.config != *config {
            bail!("certificate phase or configuration mismatch");
        }
        let message = Self::message(&self.header, &self.ballot);
        let valid = self
            .sigs
            .iter()
            .filter(|(a, sig)| {
                config.acceptors.contains(a)
                    && verify(a, Self::domain(self.verified), &message, sig).is_ok()
            })
            .count();
        let need = config.quorum();
        if valid < need {
            bail!(
                "{valid} valid acceptor signatures, {need} needed (configuration {})",
                self.header.config.number
            );
        }
        Ok(())
    }

    /// Whether this is about `chosen`: the same value at its ballot. The
    /// first value of a configuration has no ballot; this must then be about
    /// the closing value it's opened from.
    pub fn proves(&self, chosen: &Chosen) -> bool {
        self.proves_header(
            &Header::of(self.header.cluster_id, &chosen.value),
            chosen.ballot.as_ref(),
        )
    }

    pub fn proves_header(&self, header: &Header, ballot: Option<&Ballot<NodeId>>) -> bool {
        match ballot {
            Some(ballot) => self.header == *header && self.ballot == *ballot,
            None => self.header.opened().as_ref() == Some(header),
        }
    }

    /// A transition: the certificate of a value that closes its
    /// configuration.
    pub fn is_transition(&self) -> bool {
        self.header.next.is_some()
    }

    /// Checks that this certificate proves `chosen` as a state of
    /// `cluster_id`: a quorum of the acceptors `trust` names signed it, it is
    /// about `chosen`, and the state's member records are what the members
    /// signed. The one check for every state this node takes in.
    pub fn check_proves(
        &self,
        cluster_id: ClusterId,
        chosen: &Chosen,
        trust: Trust<'_>,
    ) -> Result<()> {
        same_cluster(cluster_id, chosen, self)?;
        match trust {
            Trust::SelfCertified => self.check_config(&self.header.config, false)?,
            Trust::Sets(trusted) => trusted.check(self)?,
        }
        if !self.proves(chosen) {
            bail!("the proof is for another value");
        }
        chosen.state().verify_members()?;
        Ok(())
    }

    fn size(&self) -> usize {
        postcard::to_stdvec(self).map_or(usize::MAX, |b| b.len())
    }
}

/// Whether a voter configuration has a shape a certificate may be checked
/// against.
fn valid_config(config: &Config<NodeId>) -> bool {
    !config.acceptors.is_empty()
        && config.acceptors.len() <= usize::from(MAX_ACCEPTORS)
        && (!config.protected || config.acceptors.len() >= usize::from(MIN_PROTECTED_ACCEPTORS))
}

/// Checks that `chosen` and `cert` are about `cluster_id`.
pub fn same_cluster(cluster_id: ClusterId, chosen: &Chosen, cert: &Certificate) -> Result<()> {
    if chosen.state().cluster_id != Some(cluster_id) || cert.header.cluster_id != cluster_id {
        bail!("the agreed state is from another cluster");
    }
    Ok(())
}

/// Which acceptor set a certificate is checked against.
#[derive(Clone, Copy)]
pub enum Trust<'a> {
    /// The certificate's own configuration. For a state from a source this
    /// node trusts anyway: its own disk, or the member that redeemed its
    /// invite.
    SelfCertified,
    /// The sets this node trusts.
    Sets(&'a Trusted),
}

/// The proof of a cluster's first state: its founder, the only acceptor,
/// signs it.
pub fn genesis(identity: &Identity, cluster_id: ClusterId, first: &Chosen) -> Certificate {
    let ballot = first.ballot.clone().expect("the first state has a ballot");
    Certificate::sign(identity, Header::of(cluster_id, &first.value), ballot)
}

/// An agreed state with its proof, and transitions the receiver may need to
/// check the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proven {
    pub chosen: Chosen,
    pub cert: Certificate,
    pub transitions: Vec<Certificate>,
}

/// The acceptor sets a node trusts, by configuration number: its latest
/// state's, the one that proved that state, and the ones that checked
/// transitions lead to from there.
#[derive(Clone, Debug)]
pub struct Trusted(BTreeMap<u64, Config<NodeId>>);

impl Trusted {
    /// The sets that `latest`, a state this node has checked, names, and
    /// the set of `proof`, its certificate. The opening of a configuration is
    /// proved by the closing certificate of the one before, so that set is
    /// trusted too.
    pub fn new(latest: &Agreed, proof: &Certificate) -> Trusted {
        let mut sets = BTreeMap::from([
            (proof.header.config.number, proof.header.config.clone()),
            (latest.config.number, latest.config.clone()),
        ]);
        if let Some(next) = &latest.next {
            sets.insert(next.number, next.clone());
        }
        Trusted(sets)
    }

    /// The latest configuration whose acceptors are trusted.
    pub fn frontier(&self) -> u64 {
        *self.0.keys().next_back().expect("never empty")
    }

    /// Checks `cert` against the trusted set of its configuration.
    pub fn check(&self, cert: &Certificate) -> Result<()> {
        let number = cert.header.config.number;
        let Some(set) = self.0.get(&number) else {
            bail!(
                "this node can't check configuration {number} yet: it knows the acceptors \
                 up to configuration {}",
                self.frontier()
            );
        };
        cert.check_config(set, false)
    }

    /// Checks `transition`, a closing value's certificate for the frontier,
    /// and then trusts the set it names.
    pub fn follow(&mut self, transition: &Certificate) -> Result<()> {
        let Some(next) = &transition.header.next else {
            bail!("not a transition");
        };
        self.check(transition)?;
        if next.number != transition.header.config.number + 1 || !valid_config(next) {
            bail!("invalid successor configuration");
        }
        self.0
            .insert(transition.header.config.number + 1, next.clone());
        Ok(())
    }

    /// Follows `transitions`, which another node sent, from the frontier on,
    /// in configuration order. A transition for another cluster is an error.
    /// One that doesn't close the frontier is skipped: it is already trusted,
    /// or not reachable yet. Returns the transitions followed, in order.
    pub fn follow_all<'a>(
        &mut self,
        cluster_id: ClusterId,
        transitions: &'a [Certificate],
    ) -> Result<Vec<&'a Certificate>> {
        let mut ordered: Vec<&Certificate> = transitions.iter().collect();
        ordered.sort_by_key(|t| t.header.config.number);
        let mut followed = Vec::new();
        for t in ordered {
            if t.header.cluster_id != cluster_id {
                bail!("transition from another cluster");
            }
            if t.header.config.number == self.frontier() {
                self.follow(t)?;
                followed.push(t);
            }
        }
        Ok(followed)
    }
}

/// The transitions a node has checked, by the configuration they close. They
/// are kept to help nodes that are behind, for the `catch_up_days` setting.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transitions(BTreeMap<u64, Certificate>);

impl Transitions {
    /// The transitions saved in `path`, or none if there is no file.
    pub fn load(path: &Path) -> io::Result<Transitions> {
        Ok(files::load(path)?.unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        files::save(path, self)
    }

    /// Adds a checked transition. Returns true if it's new.
    pub fn insert(&mut self, transition: Certificate) -> bool {
        debug_assert!(transition.is_transition());
        let number = transition.header.config.number;
        if self.0.contains_key(&number) {
            return false;
        }
        self.0.insert(number, transition);
        true
    }

    /// The acceptor sets trusted from `latest`, a state this node has
    /// checked, and `proof`, its certificate: theirs, and the ones the stored
    /// transitions lead to.
    pub fn trusted(&self, latest: &Agreed, proof: &Certificate) -> Trusted {
        let mut trusted = Trusted::new(latest, proof);
        for t in self.0.range(trusted.frontier()..).map(|(_, t)| t) {
            if t.header.config.number != trusted.frontier() || trusted.follow(t).is_err() {
                break;
            }
        }
        trusted
    }

    /// The transitions from configuration `from` on, in order, up to the
    /// size a message may carry.
    pub fn since(&self, from: u64) -> Vec<Certificate> {
        let mut size = 0;
        self.0
            .range(from..)
            .map(|(_, t)| t)
            .take_while(|t| {
                size += t.size();
                size <= MAX_TRANSITION_BYTES
            })
            .cloned()
            .collect()
    }

    /// Drops the transitions agreed more than `days` days before `now_ms`.
    /// Returns true if any were dropped.
    pub fn prune(&mut self, now_ms: u64, days: u32) -> bool {
        let keep_from = now_ms.saturating_sub(u64::from(days) * 24 * 60 * 60 * 1000);
        let before = self.0.len();
        self.0.retain(|_, t| t.header.now_ms >= keep_from);
        self.0.len() != before
    }
}

#[cfg(test)]
mod tests;
