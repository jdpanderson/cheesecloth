//! Test support: a single `Node` for unit tests (a real cluster in which this
//! node is the founder and the only acceptor, a control-plane endpoint on
//! localhost, the mock WireGuard backend, and no loops running; the peers are
//! members that exist only as member records and the soft state tests publish
//! for them), whole daemons on localhost, and the fixtures and waits the tests
//! share. With the `test-util` feature, the integration tests use it too.

use std::{future::Future, sync::Arc, time::Duration};

use anyhow::Result;
use cheesecloth_core::{
    ClusterId, Domain, Identity, NodeId, WgKey, now_ms,
    state::{
        ClusterState, Command, Member, MemberInfo, Outcome, Permissions, Request, Settings,
        SignedCommand, invite_id,
    },
};
use cheesecloth_net::{Net, NetOptions};
use cheesecloth_wg::BackendKind;
use pnyx::{Acceptor, Ballot};

use crate::{
    Daemon, Options, RelayMode,
    files::Files,
    local::Interfaces,
    node::{Chosen, Node, StoredAcceptor, proof},
    soft::SoftState,
};

/// A peer that exists only as a member record and signed soft state.
pub struct Peer {
    pub identity: Identity,
    pub info: MemberInfo,
}

impl Peer {
    pub fn id(&self) -> NodeId {
        self.identity.node_id()
    }
}

pub struct Harness {
    pub node: Arc<Node>,
    pub peers: Vec<Peer>,
    /// The node's interfaces; none unless a test adds some. The node reads
    /// them at its next `refresh_facts`.
    pub interfaces: Arc<parking_lot::Mutex<Interfaces>>,
    seq: std::sync::atomic::AtomicU64,
    /// Holds the node's state directory.
    pub dir: tempfile::TempDir,
}

/// The WireGuard port of a harness node, so that tests know the endpoints.
pub const HARNESS_WG_PORT: u16 = 51999;

/// Starts a node that founded a cluster (100.64.0.0/24, so it's 100.64.0.1)
/// and admitted one peer per `relays` entry (100.64.0.2, ...); `true` makes
/// the peer a relay.
pub async fn harness(relay: RelayMode, relays: &[bool]) -> Harness {
    harness_with(relay, relays, |_| {}).await
}

/// Like `harness`, with further changes to the options.
pub async fn harness_with(
    relay: RelayMode,
    relays: &[bool],
    tweak: impl FnOnce(&mut Options),
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options("me", relay, dir.path());
    opts.wg_port = HARNESS_WG_PORT;
    opts.interface = "mock-test".into();
    // The node is in no daemon, so its facts come only from these.
    opts.advertise.clear();
    let interfaces = Arc::<parking_lot::Mutex<Interfaces>>::default();
    opts.interfaces = Some(interfaces.clone());
    tweak(&mut opts);
    let identity = Arc::new(Identity::generate());
    // The node is in no daemon, so the control plane serves no one: requests
    // to it are answered as by a node that is in no cluster.
    let callbacks = Arc::new(crate::Callbacks(std::sync::Weak::new()));
    let net = Net::bind(
        NetOptions::new("127.0.0.1:0".parse().unwrap()),
        identity.clone(),
    )
    .unwrap()
    .start(callbacks.clone(), callbacks);
    let (wg_private, wg_public) = cheesecloth_wg::generate_keypair();
    let me = MemberInfo {
        wg_key: wg_public,
        control_addrs: vec![net.local_addr().unwrap()],
        wg_port: HARNESS_WG_PORT,
        relay: relay == RelayMode::Always,
        ..member_info(identity.node_id(), "me")
    };
    let peers: Vec<Peer> = relays
        .iter()
        .enumerate()
        .map(|(i, relay)| {
            let identity = Identity::generate();
            let info = MemberInfo {
                control_addrs: vec![format!("192.0.2.{}:51821", i + 2).parse().unwrap()],
                relay: *relay,
                ..member_info(identity.node_id(), &format!("peer{i}"))
            };
            Peer { identity, info }
        })
        .collect();

    // The first state: genesis, then an invite and its redemption for each
    // peer.
    let mut state = ClusterState::default();
    let mut apply = |command| {
        let out = state.apply(&Request {
            at_ms: now_ms(),
            command: signed(&identity, state.cluster_id, command),
        });
        out.unwrap()
    };
    let founder = identity.seal(Domain::MemberInfo, &me);
    let Outcome::Genesis { cluster_id } = apply(Command::Genesis {
        nonce: [0; 16],
        settings: Settings::new("100.64.0.0/24".parse().unwrap()),
        founder,
    }) else {
        panic!("genesis failed");
    };
    for (i, p) in peers.iter().enumerate() {
        let secret = [i as u8 + 1; 32];
        apply(create_invite(invite_id(&secret)));
        let joiner = p.identity.seal(Domain::MemberInfo, &p.info);
        apply(Command::RedeemInvite { secret, joiner });
    }
    let files = Files::new(&dir.path().join("state")).unwrap();
    let first = Chosen::genesis(identity.node_id(), state);
    let cert = proof::genesis(&identity, cluster_id, &first);
    StoredAcceptor::create(files.acceptor(), Acceptor::genesis(first, cert)).unwrap();

    let node = Node::start(Arc::new(opts), cluster_id, identity, wg_private, net, files).unwrap();
    Harness {
        node,
        peers,
        interfaces,
        seq: 1.into(),
        dir,
    }
}

impl Harness {
    /// Starts a second node on this node's state directory, as after a
    /// restart, for `cluster_id` (this node's by default).
    pub fn restart(&self, cluster_id: Option<ClusterId>) -> Result<Arc<Node>> {
        let n = &self.node;
        Node::start(
            n.opts.clone(),
            cluster_id.unwrap_or(n.cluster_id),
            n.identity.clone(),
            n.wg_private,
            n.net.clone(),
            n.files.clone(),
        )
    }

    /// A proof of `chosen`, signed by those of this node and its peers that
    /// are acceptors of its configuration.
    pub fn certify(&self, chosen: &Chosen) -> proof::Certificate {
        let header = proof::Header::of(self.node.cluster_id, &chosen.value);
        let ballot = chosen.ballot.clone().expect("a ballot");
        let signers: Vec<&Identity> = std::iter::once(&*self.node.identity)
            .chain(self.peers.iter().map(|p| &p.identity))
            .filter(|id| chosen.value.config.acceptors.contains(&id.node_id()))
            .collect();
        certificate(&signers, header, ballot, false)
    }

    /// `chosen` with its proof (see `certify`), as another member sends it.
    pub fn proven(&self, chosen: Chosen) -> proof::Proven {
        proof::Proven {
            cert: self.certify(&chosen),
            chosen,
            transitions: Vec::new(),
        }
    }

    /// Has the node learn `chosen`, with its proof.
    pub async fn learn(&self, chosen: Chosen) -> anyhow::Result<()> {
        let p = self.proven(chosen);
        self.node.learn(p.chosen, p.cert, p.transitions).await
    }

    /// Publishes `state` as peer `i`'s soft state entry.
    pub fn soft(&self, i: usize, state: SoftState) {
        let p = &self.peers[i];
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let signed = soft_entry(&p.identity, SoftState { seq, ..state });
        assert!(self.node.soft.lock().merge(signed, |_| true));
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.node.net.close();
    }
}

// ------------------------------------------------------------ fixtures

/// A command signed by `id`, as a member would submit it now.
pub fn signed(id: &Identity, cluster_id: Option<ClusterId>, command: Command) -> SignedCommand {
    SignedCommand::sign(id, cluster_id, now_ms(), command)
}

/// An invite for `invite_id` that gives every permission.
pub fn create_invite(invite_id: [u8; 32]) -> Command {
    Command::CreateInvite {
        invite_id,
        permissions: Permissions::ALL,
    }
}

/// `node`'s ballot number `counter`.
pub fn ballot(counter: u64, node: NodeId) -> Ballot<NodeId> {
    Ballot { counter, node }
}

/// `state` as `id`'s soft state entry, signed by it.
pub fn soft_entry(id: &Identity, state: SoftState) -> cheesecloth_core::Signed<SoftState> {
    id.seal(
        Domain::SoftState,
        &SoftState {
            node: id.node_id(),
            ..state
        },
    )
}

/// A member record's contents for `node`, called `name`: a WireGuard key
/// made from the ID, no addresses, the default port, not a relay.
pub fn member_info(node: NodeId, name: &str) -> MemberInfo {
    MemberInfo {
        node_id: node,
        wg_key: WgKey(node.0),
        name: name.into(),
        control_addrs: vec![],
        wg_port: 51820,
        relay: false,
    }
}

/// A member record for `node`, for tests that need only the record. The
/// first byte of the ID gives its name and address. Its signature is by
/// another key.
pub fn member_record(node: NodeId, permissions: Permissions) -> Member {
    let identity = Identity::generate();
    let i = node.0[0];
    let info = member_info(node, &format!("m{i}"));
    Member {
        signed_info: identity.seal(Domain::MemberInfo, &info),
        info,
        ipv4: std::net::Ipv4Addr::new(100, 64, 0, i),
        added_at_ms: 0,
        added_by: node,
        approved_by: vec![],
        permissions,
    }
}

/// A certificate for `header` at `ballot` with the signatures of all of
/// `signers`: an acceptance, or a verification if `verified`.
pub fn certificate(
    signers: &[&Identity],
    header: proof::Header,
    ballot: Ballot<NodeId>,
    verified: bool,
) -> proof::Certificate {
    let sign = |id: &Identity| {
        if verified {
            proof::Certificate::sign_verified(id, header.clone(), ballot.clone())
        } else {
            proof::Certificate::sign(id, header.clone(), ballot.clone())
        }
    };
    let (first, rest) = signers.split_first().expect("a signer");
    let mut cert = sign(first);
    for id in rest {
        cert.sigs.extend(sign(id).sigs);
    }
    cert
}

/// Whether `files` holds an acceptor state. Opening it creates nothing.
pub fn has_acceptor(files: &Files) -> bool {
    StoredAcceptor::open_existing(files.acceptor())
        .unwrap()
        .is_some()
}

/// The acceptor state saved in `files`, which must exist. Opening it
/// creates nothing.
pub fn saved_acceptor(files: &Files) -> Acceptor<NodeId, ClusterState, proof::Certificate> {
    StoredAcceptor::open_existing(files.acceptor())
        .unwrap()
        .expect("an acceptor state")
        .acceptor()
        .clone()
}

// ------------------------------------------------------------- daemons

/// A free UDP port on localhost.
pub fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Options for a daemon called `name` on localhost, with the mock WireGuard
/// backend, in the state directory `dir`. An `Always` relay gets a public
/// address (unreachable, like the host's own global ones), so the tests
/// don't depend on the host having one. The real router of the machine
/// running the tests is never touched.
pub fn options(name: &str, relay: RelayMode, dir: &std::path::Path) -> Options {
    let mut opts = Options::new(dir.to_path_buf(), Some(name.into())).unwrap();
    opts.bind_ip = "127.0.0.1".parse().unwrap();
    opts.listen_port = 0;
    opts.wg_port = free_port();
    opts.relay = relay;
    if relay == RelayMode::Always {
        opts.advertise = vec!["203.0.113.1".parse().unwrap()];
    }
    opts.backend = BackendKind::Mock;
    opts.interface = format!("mock-{name}");
    opts.port_mapping = false;
    opts
}

/// A whole daemon on localhost (see `options`), for tests that need real
/// connections.
pub async fn daemon(name: &str, relay: RelayMode) -> (Arc<Daemon>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(options(name, relay, dir.path()))
        .await
        .unwrap();
    (d, dir)
}

/// Starts a daemon again on `stopped`'s state directory, with its options,
/// as after a restart.
pub async fn restart(stopped: &Daemon) -> Arc<Daemon> {
    let mut opts = (*stopped.opts).clone();
    opts.listen_port = 0;
    Daemon::start(opts).await.unwrap()
}

/// A cluster of daemons, one per entry of `relays`: the first founds it,
/// the others join with invites that give every permission, and all of them
/// see each other alive before this returns.
pub async fn cluster(relays: &[RelayMode]) -> (Vec<Arc<Daemon>>, Vec<tempfile::TempDir>) {
    let mut daemons = Vec::new();
    let mut dirs = Vec::new();
    for (i, relay) in relays.iter().enumerate() {
        let (d, dir) = daemon(&format!("d{i}"), *relay).await;
        daemons.push(d);
        dirs.push(dir);
    }
    daemons[0].init(None).await.unwrap();
    for d in &daemons[1..] {
        let token = daemons[0].invite(Permissions::ALL).await.unwrap().token;
        d.join(&token).await.unwrap();
    }
    let nodes: Vec<Arc<Node>> = daemons.iter().map(|d| d.node().unwrap()).collect();
    connected(&nodes).await;
    (daemons, dirs)
}

/// Waits until every one of `nodes` sees all of them alive.
pub async fn connected(nodes: &[Arc<Node>]) {
    let ids: std::collections::BTreeSet<NodeId> = nodes.iter().map(|n| n.me).collect();
    eventually("the nodes to see each other", 30, || async {
        nodes.iter().all(|n| n.live().is_superset(&ids))
    })
    .await;
}

/// Runs `crate::serve` for `d` with a signal that never comes, so only a
/// `stop` request ends it. Returns once the local API answers connections.
pub async fn serve(
    d: &Arc<Daemon>,
) -> (
    tokio::task::JoinHandle<anyhow::Result<()>>,
    std::path::PathBuf,
) {
    let socket = d.opts.socket_path().unwrap();
    let server = tokio::spawn(crate::serve(d.clone(), std::future::pending()));
    api_client(&socket).await;
    (server, socket)
}

/// Connects to the local API at `addr`, waiting up to 5 s for the daemon to
/// serve it. (A pipe has no file to wait for.)
pub async fn api_client(addr: &std::path::Path) -> crate::ipc::ClientStream {
    within(async {
        loop {
            if let Ok(client) = crate::ipc::connect(addr).await {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
}

// --------------------------------------------------------------- waits

/// Polls `f` every 200 ms until it's true, for up to `secs` seconds, then
/// fails the test with `what` it waited for.
pub async fn eventually<F, Fut>(what: &str, secs: u64, f: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..secs * 5 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Fails the test instead of hanging when `f` doesn't finish in 5 s.
pub async fn within<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("finished in time")
}
