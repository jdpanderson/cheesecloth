//! Whole daemons in one process on localhost, with a mock WireGuard backend.
//! One node is a relay; the others count as NATed, so they only reach each
//! other through it.

use std::{sync::Arc, time::Duration};

use cheesecloth_core::state::{Outcome, Permissions};
use cheesecloth_daemon::{
    Daemon, RelayMode,
    api::{self, ApiError, ErrorCode, NodePhase, PeerView, StatusView},
    testing::{eventually, options},
};

struct TestNode {
    daemon: Arc<Daemon>,
    name: String,
    relay: RelayMode,
    _dir: tempfile::TempDir,
}

impl TestNode {
    /// Stops the daemon and starts another on its state directory.
    async fn restart(self) -> TestNode {
        let TestNode {
            daemon,
            name,
            relay,
            _dir,
        } = self;
        daemon.shutdown().await;
        drop(daemon);
        start_in(&name, relay, _dir).await
    }
}

async fn start(name: &str, relay: RelayMode) -> TestNode {
    start_in(name, relay, tempfile::tempdir().unwrap()).await
}

/// `a` founds a cluster, and `b` joins it and catches up.
async fn founded_pair() -> (TestNode, TestNode) {
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    b.daemon.join(&invite(&a).await).await.unwrap();
    eventually("b caught up", 30, || async { members(&b).await == 2 }).await;
    (a, b)
}

/// A founded pair (see `founded_pair`) whose joins now need one approval,
/// and `c`, which isn't in the cluster yet.
async fn gated_trio() -> (TestNode, TestNode, TestNode) {
    let (a, b) = founded_pair().await;
    let c = start("c", RelayMode::Auto).await;
    // Needs the current threshold (0), so it applies at once.
    let v = a
        .daemon
        .config_set("approvals_required", "1")
        .await
        .unwrap();
    assert_eq!(v, Outcome::SettingChanged);
    (a, b, c)
}

fn assert_invite_unknown(err: &anyhow::Error) {
    assert!(
        format!("{err:#}").contains("unknown, expired or already used invite"),
        "{err:#}"
    );
}

/// A second daemon with the same keys as `like` (as if it had lost its
/// cluster state, or never got the answer to its join).
async fn start_as(name: &str, like: &TestNode) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    for f in ["identity.key", "wireguard.key"] {
        std::fs::copy(like._dir.path().join(f), dir.path().join(f)).unwrap();
    }
    start_in(name, RelayMode::Auto, dir).await
}

async fn start_in(name: &str, relay: RelayMode, dir: tempfile::TempDir) -> TestNode {
    init_tracing();
    let daemon = Daemon::start(options(name, relay, dir.path()))
        .await
        .unwrap();
    TestNode {
        daemon,
        name: name.into(),
        relay,
        _dir: dir,
    }
}

/// Logs with the filter in `RUST_LOG`, or only errors without it.
fn init_tracing() {
    use tracing_subscriber::{
        filter::{LevelFilter, Targets},
        prelude::*,
    };
    let filter: Targets = match std::env::var("RUST_LOG") {
        Ok(s) => s.parse().expect("a valid RUST_LOG filter"),
        Err(_) => Targets::new().with_default(LevelFilter::ERROR),
    };
    let output = tracing_subscriber::fmt::layer().with_test_writer();
    let _ = tracing_subscriber::registry()
        .with(output)
        .with(filter)
        .try_init();
}

async fn status(n: &TestNode) -> StatusView {
    n.daemon.status().await.unwrap()
}

async fn members(n: &TestNode) -> usize {
    n.daemon.peers().map(|p| p.len()).unwrap_or(0)
}

async fn invite(n: &TestNode) -> String {
    let v = n.daemon.invite(Permissions::ALL).await.unwrap();
    v.token
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cluster_lifecycle() {
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;

    // Genesis.
    let v = a
        .daemon
        .init(Some("100.64.42.0/24".parse().unwrap()))
        .await
        .unwrap();
    assert_eq!(v.ipv4_range.to_string(), "100.64.42.0/24");
    let s = status(&a).await;
    assert_eq!(s.phase, NodePhase::Member);
    assert_eq!(s.ipv4, Some("100.64.42.1".parse().unwrap()));
    assert!(a.daemon.init(None).await.is_err(), "init twice");

    // Joins.
    let token = invite(&a).await;
    let v = b.daemon.join(&token).await.unwrap();
    assert!(v.joined);
    assert_eq!(v.ipv4, Some("100.64.42.2".parse().unwrap()));

    // An invite from a NATed member works too (redeemed through the relay).
    let token = invite(&b).await;
    c.daemon.join(&token).await.unwrap();

    for n in [&a, &b, &c] {
        eventually(&format!("{} sees 3 members", n.name), 30, || async {
            members(n).await == 3
        })
        .await;
    }
    // Every member becomes an acceptor (3 is the target).
    eventually("3 acceptors", 30, || async {
        status(&a).await.acceptors.len() == 3
    })
    .await;

    // b and c are "behind NAT": no direct connection, but the control plane
    // still works between them via the relay.
    let peers: Vec<PeerView> = b.daemon.peers().unwrap();
    let pc = peers.iter().find(|p| p.name == "c").unwrap();
    assert!(!pc.connected, "b must not dial c directly");
    let pa = peers.iter().find(|p| p.name == "a").unwrap();
    assert!(pa.relay && pa.connected);
    assert_eq!(pa.path, "public");

    // Any member can make changes.
    let token = invite(&c).await;
    assert!(token.starts_with("cc1"));

    // Remove c (no approvals needed by default); c notices and forgets the cluster.
    let cid = status(&c).await.node_id.to_string();
    b.daemon.remove(&cid[..10]).await.unwrap();
    eventually("c removed everywhere", 30, || async {
        members(&a).await == 2 && members(&b).await == 2
    })
    .await;
    eventually("c forgets the cluster", 30, || async {
        status(&c).await.phase == NodePhase::None
    })
    .await;

    // b leaves (it's an acceptor): a keeps working on its own.
    b.daemon.leave(false).await.unwrap();
    assert_eq!(status(&b).await.phase, NodePhase::None);
    eventually("a alone", 30, || async { members(&a).await == 1 }).await;
    eventually("a is the only acceptor", 30, || async {
        status(&a).await.acceptors.len() == 1
    })
    .await;

    // A node that left can join again with a new invite.
    let token = invite(&a).await;
    b.daemon.join(&token).await.unwrap();
    eventually("b back", 30, || async { members(&a).await == 2 }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_only_acceptor_can_leave() {
    let (a, b) = founded_pair().await;
    eventually("a connected to b", 30, || async {
        let peers = a.daemon.peers().unwrap();
        peers.iter().any(|p| p.name == "b" && p.connected)
    })
    .await;
    // With two members there is one acceptor: a, which founded the cluster.
    let a_id = status(&a).await.node_id;
    assert_eq!(status(&a).await.acceptors, [a_id]);

    let v = a.daemon.leave(false).await.unwrap();
    assert!(
        matches!(v, api::LeaveView::Left { ref problems, .. } if problems.is_empty()),
        "{v:?}"
    );
    assert_eq!(status(&a).await.phase, NodePhase::None);
    // b was handed the role and the state before a stopped, so it can make
    // changes at once.
    assert_eq!(status(&b).await.acceptors, [status(&b).await.node_id]);
    invite(&b).await;
    assert_eq!(members(&b).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forced_leave_stops_even_if_a_step_fails() {
    let (a, b) = founded_pair().await;
    b.daemon.shutdown().await;

    // b can't take over the role or the state.
    assert!(a.daemon.leave(false).await.is_err());
    assert_eq!(status(&a).await.phase, NodePhase::Member);

    let v = a.daemon.leave(true).await.unwrap();
    assert!(
        matches!(v, api::LeaveView::Left { ref problems, .. } if !problems.is_empty()),
        "{v:?}"
    );
    assert_eq!(status(&a).await.phase, NodePhase::None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_stopped_relay_is_quick() {
    let r1 = start("r1", RelayMode::Always).await;
    let r2 = start("r2", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    r1.daemon.init(None).await.unwrap();
    r2.daemon.join(&invite(&r1).await).await.unwrap();
    b.daemon.join(&invite(&r1).await).await.unwrap();
    eventually("3 acceptors", 30, || async {
        status(&r1).await.acceptors.len() == 3
    })
    .await;
    let r2_id = status(&r2).await.node_id.to_string();
    r2.daemon.shutdown().await;
    eventually("r2 no longer present for r1", 30, || async {
        let peers = r1.daemon.peers().unwrap();
        peers.iter().any(|p| p.name == "r2" && !p.present)
    })
    .await;

    // r2's addresses don't answer. Telling it of its removal, or of the
    // change as an acceptor, would wait for the requests to time out.
    let started = std::time::Instant::now();
    r1.daemon.remove(&r2_id[..10]).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(members(&r1).await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approvals_gate_joins() {
    let (a, b, c) = gated_trio().await;
    // Can't exceed the members who could approve.
    assert!(
        a.daemon
            .config_set("approvals_required", "5")
            .await
            .is_err()
    );

    // c's join waits for one approval from someone other than a.
    let v = c.daemon.join(&invite(&a).await).await.unwrap();
    assert!(!v.joined);
    let proposal = v.proposal.unwrap();
    assert_eq!(status(&c).await.phase, NodePhase::Pending);
    let pending = a.daemon.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, api::ProposalKindView::Join);
    assert_eq!(pending[0].node, Some(status(&c).await.node_id));
    assert!(
        a.daemon.vote(proposal, true).await.is_err(),
        "proposer can't approve"
    );

    eventually("b sees the proposal", 30, || async {
        b.daemon.pending().map(|p| p.len() == 1).unwrap_or(false)
    })
    .await;
    let v = b.daemon.vote(proposal, true).await.unwrap();
    assert!(matches!(v, Outcome::Joined { .. }), "{v:?}");
    eventually("c joins after approval", 30, || async {
        status(&c).await.phase == NodePhase::Member
    })
    .await;
    eventually("c caught up", 30, || async { members(&c).await == 3 }).await;

    // Lowering the threshold is itself a proposal now.
    let v = a
        .daemon
        .config_set("approvals_required", "0")
        .await
        .unwrap();
    assert!(matches!(v, Outcome::Pending { .. }), "{v:?}");

    // Leaving never needs approvals.
    c.daemon.leave(false).await.unwrap();
    eventually("c gone", 30, || async { members(&a).await == 2 }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_redemption_is_answered_like_the_first() {
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;
    a.daemon.init(None).await.unwrap();
    let token = invite(&a).await;
    let first = b.daemon.join(&token).await.unwrap();

    // b never saw that answer and asks again with the same (now used) token.
    b.daemon.shutdown().await;
    let b2 = start_as("b", &b).await;
    let again = b2.daemon.join(&token).await.unwrap();
    assert!(again.joined, "{again:?}");
    assert_eq!(again.ipv4, first.ipv4);

    // An existing member redeeming a live token still burns it.
    b2.daemon.shutdown().await;
    let b3 = start_as("b", &b).await;
    let fresh = invite(&a).await;
    let v = b3.daemon.join(&fresh).await.unwrap();
    assert_eq!(v.ipv4, first.ipv4);
    assert_invite_unknown(&c.daemon.join(&fresh).await.unwrap_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_join_is_forgotten_even_after_a_restart() {
    let (a, b, c) = gated_trio().await;

    let v = c.daemon.join(&invite(&a).await).await.unwrap();
    let proposal = v.proposal.unwrap();
    let err = c.daemon.join(&invite(&a).await).await.unwrap_err();
    assert!(format!("{err:#}").contains("waiting to join"), "{err:#}");

    // c restarts while waiting, and picks up where it was.
    let c = c.restart().await;
    let s = status(&c).await;
    assert_eq!(s.phase, NodePhase::Pending);
    assert_eq!(s.pending_proposal, Some(proposal));

    eventually("b sees the proposal", 30, || async {
        b.daemon.pending().map(|p| p.len() == 1).unwrap_or(false)
    })
    .await;
    b.daemon.vote(proposal, false).await.unwrap();
    eventually("c gives up", 30, || async {
        status(&c).await.phase == NodePhase::None
    })
    .await;
    assert!(!c._dir.path().join("cluster.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_join_can_be_cancelled_offline_and_stays_cancelled_after_restart() {
    let (a, b, c) = gated_trio().await;
    let join = c.daemon.join(&invite(&a).await).await.unwrap();
    assert!(!join.joined);
    let id = c.daemon.node_id();
    let keys = ["identity.key", "wireguard.key"]
        .map(|file| std::fs::read(c._dir.path().join(file)).unwrap());
    a.daemon.shutdown().await;
    b.daemon.shutdown().await;
    let result = tokio::time::timeout(Duration::from_secs(2), c.daemon.leave(false))
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, api::LeaveView::JoinCancelled { proposal, .. } if Some(proposal) == join.proposal)
    );
    assert_eq!(status(&c).await.phase, NodePhase::None);
    let c = c.restart().await;
    assert_eq!(status(&c).await.phase, NodePhase::None);
    assert_eq!(c.daemon.node_id(), id);
    for (file, key) in ["identity.key", "wireguard.key"].into_iter().zip(keys) {
        assert_eq!(std::fs::read(c._dir.path().join(file)).unwrap(), key);
    }
    c.daemon.init(None).await.unwrap();
    assert_eq!(status(&c).await.phase, NodePhase::Member);
    c.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commands_explain_what_went_wrong() {
    let a = start("a", RelayMode::Always).await;
    let b = start("b", RelayMode::Auto).await;
    let c = start("c", RelayMode::Auto).await;
    // The code a client gets, as the local API gives it. (The codes of
    // requests to one daemon are tested in `local_api`.)
    fn code<T>(r: anyhow::Result<T>) -> ErrorCode {
        let Err(e) = r else { panic!("succeeded") };
        ApiError::classify(&e, ErrorCode::OperationFailed).code
    }
    a.daemon.init(None).await.unwrap();

    // Nobody listed in the token can be reached; nothing was sent.
    let mut dead: cheesecloth_core::token::InviteToken = invite(&a).await.parse().unwrap();
    dead.peers[0].addrs = vec!["127.0.0.1:9".parse().unwrap()];
    let e = b.daemon.join(&dead.to_string()).await;
    assert_eq!(code(e), ErrorCode::MembersUnreachable);
    assert_eq!(
        code(b.daemon.join("not a token").await),
        ErrorCode::InvalidToken
    );
    // The same secret still works through a reachable member.
    let mut live = dead.clone();
    live.peers[0].addrs = vec![status(&a).await.control_addr.unwrap()];
    b.daemon.join(&live.to_string()).await.unwrap();
    let e = b.daemon.join(&invite(&a).await).await;
    assert_eq!(code(e), ErrorCode::AlreadyInCluster);
    // The member's refusal of a used invite reaches another joiner typed.
    let e = c.daemon.join(&live.to_string()).await;
    assert_eq!(code(e), ErrorCode::InviteUnknown);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_security_bootstraps_then_keeps_protection_and_pauses_without_quorum() {
    let a = start("strict-a", RelayMode::Always).await;
    let b = start("strict-b", RelayMode::Always).await;
    let c = start("strict-c", RelayMode::Always).await;
    let d = start("strict-d", RelayMode::Always).await;
    a.daemon.init_with_security(None, true).await.unwrap();
    let bootstrap = status(&a).await;
    assert!(bootstrap.strict_security);
    assert_eq!(bootstrap.security, "relaxed");
    for peer in [&b, &c, &d] {
        peer.daemon.join(&invite(&a).await).await.unwrap();
    }
    eventually("four protected voters", 40, || async {
        status(&a).await.security == "protected"
            && status(&b).await.security == "protected"
            && status(&c).await.security == "protected"
            && status(&d).await.security == "protected"
    })
    .await;
    let protected = status(&a).await;
    assert_eq!((protected.acceptors.len(), protected.quorum), (4, 3));
    a.daemon.config_set("buffer_nodes", "2").await.unwrap();
    assert_eq!(
        status(&a).await.security,
        "protected",
        "strict latch overrides requested reserve"
    );
    let error = a.daemon.config_set("acceptors", "3").await.unwrap_err();
    assert!(
        error.to_string().contains("disable strict_security"),
        "{error:#}"
    );
    c.daemon.shutdown().await;
    d.daemon.shutdown().await;
    eventually("loss of the installed quorum", 30, || async {
        status(&a).await.changes_paused
    })
    .await;
    let paused = status(&a).await;
    assert_eq!(
        (
            paused.security.as_str(),
            paused.acceptors.len(),
            paused.quorum
        ),
        ("protected", 4, 3)
    );
    assert!(paused.reachable_voters < paused.quorum);
    assert!(
        a.daemon.invite(Permissions::ALL).await.is_err(),
        "two cannot commit using the four-voter configuration"
    );
    a.daemon.shutdown().await;
    b.daemon.shutdown().await;
}
