//! Messages between daemons, carried by the control plane.

use std::net::SocketAddr;

use cheesecloth_core::{
    ClusterId, NodeId, Signed,
    state::{ClusterState, CommandError, MemberInfo},
};
use pnyx::Reply;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    node::{Chosen, proof::Certificate},
    soft::SoftState,
};

/// A service that members ask of each other on the control plane: its
/// number, and the request and the response it carries. `Node::call` sends
/// a request and `Node` answers it as its `Serve` says, both with these
/// types, so the two sides can't disagree on them.
pub trait Service {
    /// The service's number on the wire.
    const ID: u8;
    type Request: Serialize + DeserializeOwned + Send;
    type Response: Serialize + DeserializeOwned + Send;
}

/// The member services.
pub mod svc {
    use super::{Certificate, PaxosAnswer, PunchMessage, PunchReply, Service};
    use crate::node::{
        proof::Proven,
        round::{Verification, WireRequest},
    };

    /// A CASPaxos request to this node's acceptor.
    pub struct Paxos;

    impl Service for Paxos {
        const ID: u8 = 1;
        type Request = WireRequest;
        type Response = PaxosAnswer;
    }

    /// "Send me your agreed state, and the transitions from this
    /// configuration on."
    pub struct Fetch;

    impl Service for Fetch {
        const ID: u8 = 2;
        type Request = u64;
        type Response = Proven;
    }

    /// WireGuard hole-punch coordination.
    pub struct Punch;

    impl Service for Punch {
        const ID: u8 = 3;
        type Request = PunchMessage;
        type Response = PunchReply;
    }

    /// "Here is an agreed state": sent to removed members, and by a leaving
    /// member to the acceptors. The answer is the version the receiver
    /// holds.
    pub struct State;

    impl Service for State {
        const ID: u8 = 4;
        type Request = Proven;
        type Response = u64;
    }

    /// "The value you accepted in this configuration at this ballot is
    /// agreed": its certificate.
    pub struct Commit;

    impl Service for Commit {
        const ID: u8 = 5;
        type Request = Certificate;
        type Response = ();
    }

    /// "Check this round's candidate value and endorse it." The answer is
    /// the acceptor's signed verification certificate.
    pub struct Verify;

    impl Service for Verify {
        const ID: u8 = 6;
        type Request = Verification;
        type Response = Certificate;
    }
}

/// An acceptor's answer to a CASPaxos request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaxosAnswer {
    pub promise: Option<Signed<crate::node::round::Promise>>,
    pub reply: Reply<NodeId, ClusterState>,
    /// The acceptor's signature on the value it accepted, when `reply`
    /// reports one.
    pub share: Option<Certificate>,
    /// With a stale answer: the proof of the state it carries, and the
    /// transitions from the request's configuration on.
    pub stale_proof: Option<(Certificate, Vec<Certificate>)>,
}

/// On the `join` stream, the only one open to non-members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinMessage {
    /// Redeem an invite. `info` must be signed by the connecting key.
    Redeem {
        secret: [u8; 32],
        info: Signed<MemberInfo>,
    },
    /// Check on a join waiting for approvals.
    Status {
        proposal: cheesecloth_core::ProposalId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JoinReply {
    /// The agreed state with the new member in it and a bounded seed of
    /// signed discovery entries. Normal synchronization supplies the rest.
    Joined {
        cluster_id: ClusterId,
        state: Box<Chosen>,
        /// The proof of `state`.
        cert: Box<Certificate>,
        soft: Vec<Signed<SoftState>>,
    },
    Pending {
        proposal: cheesecloth_core::ProposalId,
    },
    Rejected {
        reason: JoinRefusal,
    },
}

/// Why a member turned a join down, so the joiner can say so with a code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum JoinRefusal {
    /// The cluster refused the redemption, such as for an unknown invite.
    #[error("{0}")]
    Command(CommandError),
    /// The members rejected the join, or its proposal expired.
    #[error("the join was rejected or expired")]
    RejectedOrExpired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PunchMessage {
    /// From the designated initiator: "let's punch; you'll see me at
    /// `initiator`, I'll send to you at `responder`".
    Offer {
        id: u64,
        initiator: SocketAddr,
        responder: SocketAddr,
    },
    /// Delivered by a relay at the same moment the initiator is told: send
    /// the NAT opener now.
    Go { id: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PunchReply {
    Accepted,
    Refused(String),
    Done,
}
