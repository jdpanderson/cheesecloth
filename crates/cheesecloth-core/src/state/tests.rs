//! State machine tests.

use super::*;
use crate::Identity;

struct Node {
    id: Identity,
}

impl Node {
    fn new() -> Self {
        Self {
            id: Identity::generate(),
        }
    }

    fn nid(&self) -> NodeId {
        self.id.node_id()
    }

    fn info(&self) -> Signed<MemberInfo> {
        self.info_with(|_| {})
    }

    /// The node's own record, with `change` applied before it is sealed.
    fn info_with(&self, change: impl FnOnce(&mut MemberInfo)) -> Signed<MemberInfo> {
        let mut info = MemberInfo {
            node_id: self.nid(),
            wg_key: WgKey(self.nid().0),
            name: "n".into(),
            control_addrs: vec![],
            wg_port: 51820,
            relay: false,
        };
        change(&mut info);
        self.id.seal(Domain::MemberInfo, &info)
    }

    fn cmd(&self, cluster_id: Option<ClusterId>, at: u64, command: Command) -> Request {
        Request {
            at_ms: at,
            command: SignedCommand::sign(&self.id, cluster_id, at, command),
        }
    }
}

fn genesis_cmd(nonce: u8, range: &str, founder: Signed<MemberInfo>) -> Command {
    Command::Genesis {
        nonce: [nonce; 16],
        settings: Settings::new(range.parse().unwrap()),
        founder,
    }
}

fn create_invite(invite_id: [u8; 32]) -> Command {
    Command::CreateInvite {
        invite_id,
        permissions: Permissions::ALL,
    }
}

/// The proposal of a pending outcome.
fn pending(out: Response) -> crate::ProposalId {
    match out {
        Ok(Outcome::Pending { proposal }) => proposal,
        other => panic!("expected pending: {other:?}"),
    }
}

fn assert_invalid_member(out: &Response) {
    assert!(
        matches!(out, Err(CommandError::InvalidMember(_))),
        "{out:?}"
    );
}

fn genesis(founder: &Node) -> ClusterState {
    let mut st = ClusterState::default();
    let out = st.apply(&founder.cmd(
        st.cluster_id,
        1000,
        genesis_cmd(0, "100.64.7.0/24", founder.info()),
    ));
    assert!(matches!(out, Ok(Outcome::Genesis { .. })), "{out:?}");
    st
}

fn invite(st: &mut ClusterState, by: &Node, at: u64, secret: [u8; 32]) {
    invite_as(st, by, at, secret, Permissions::ALL);
}

fn invite_as(
    st: &mut ClusterState,
    by: &Node,
    at: u64,
    secret: [u8; 32],
    permissions: Permissions,
) {
    let out = st.apply(&by.cmd(
        st.cluster_id,
        at,
        Command::CreateInvite {
            invite_id: invite_id(&secret),
            permissions,
        },
    ));
    assert!(matches!(out, Ok(Outcome::InviteCreated { .. })), "{out:?}");
}

fn redeem(st: &mut ClusterState, by: &Node, joiner: &Node, at: u64, secret: [u8; 32]) -> Response {
    st.apply(&by.cmd(
        st.cluster_id,
        at,
        Command::RedeemInvite {
            secret,
            joiner: joiner.info(),
        },
    ))
}

#[test]
fn genesis_founder_is_first_member() {
    let a = Node::new();
    let st = genesis(&a);
    assert!(st.is_member(&a.nid()));
    assert_eq!(
        st.members[&a.nid()].ipv4,
        "100.64.7.1".parse::<Ipv4Addr>().unwrap()
    );
    let mut st2 = st.clone();
    let again = st2.apply(&a.cmd(None, 2000, genesis_cmd(1, "100.64.8.0/24", a.info())));
    assert_eq!(again, Err(CommandError::AlreadyInitialized));
}

#[test]
fn invite_is_single_use_and_burnt_on_failure() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [5; 32]);
    let out = redeem(&mut st, &a, &b, 3000, [5; 32]);
    assert!(matches!(out, Ok(Outcome::Joined { .. })), "{out:?}");
    assert_eq!(
        st.members[&b.nid()].ipv4,
        "100.64.7.2".parse::<Ipv4Addr>().unwrap()
    );
    // Used up.
    assert_eq!(
        redeem(&mut st, &b, &c, 4000, [5; 32]),
        Err(CommandError::InviteUnknown)
    );

    // A failed redemption (already a member) still burns the token.
    invite(&mut st, &a, 5000, [6; 32]);
    assert_eq!(
        redeem(&mut st, &a, &b, 6000, [6; 32]),
        Err(CommandError::AlreadyMember)
    );
    assert_eq!(
        redeem(&mut st, &a, &c, 7000, [6; 32]),
        Err(CommandError::InviteUnknown)
    );
}

#[test]
fn invite_expires_after_ttl() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [5; 32]);
    let late = 2000 + ms(INVITE_TTL) + 1;
    assert_eq!(
        redeem(&mut st, &a, &b, late, [5; 32]),
        Err(CommandError::InviteUnknown)
    );
}

#[test]
fn non_members_and_replays_are_refused() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    let out = st.apply(&b.cmd(st.cluster_id, 2000, create_invite([1; 32])));
    assert_eq!(out, Err(CommandError::NotMember));

    let req = a.cmd(st.cluster_id, 3000, create_invite([1; 32]));
    let first = st.apply(&req);
    assert!(first.is_ok());
    assert_eq!(st.apply(&req), Err(CommandError::Replay));
    // The first answer is kept with the command, refusals too.
    assert_eq!(st.applied(&req.command), Some(&first));
    let refused = a.cmd(
        st.cluster_id,
        3100,
        Command::Approve {
            proposal: crate::ProposalId([9; 32]),
        },
    );
    assert_eq!(st.apply(&refused), Err(CommandError::NoSuchProposal));
    assert_eq!(
        st.applied(&refused.command),
        Some(&Err(CommandError::NoSuchProposal))
    );

    let mut stale = a.cmd(st.cluster_id, 3000, create_invite([2; 32]));
    stale.at_ms = 3000 + ms(REPLAY_WINDOW) + 1;
    assert_eq!(st.apply(&stale), Err(CommandError::Stale));
    // Refused before the replay check: not recorded, so it can be sent
    // again at a better time.
    assert_eq!(st.applied(&stale.command), None);
}

#[test]
fn approvals_gate_joins_and_removals_but_not_leaving() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b, &c]);
    // Raise the threshold to 1 (needs 0 approvals right now).
    let out = set(&mut st, &a, 3000, SettingChange::ApprovalsRequired(1));
    assert_eq!(out, Ok(Outcome::SettingChanged));

    // Join now needs one approval from someone other than the proposer.
    invite(&mut st, &a, 4000, [20; 32]);
    let proposal = pending(redeem(&mut st, &a, &d, 4100, [20; 32]));
    assert!(!st.is_member(&d.nid()));
    assert!(st.invites.is_empty(), "the invite is burnt while pending");
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 4200, Command::Approve { proposal })),
        Err(CommandError::OwnProposal)
    );
    let out = st.apply(&b.cmd(st.cluster_id, 4300, Command::Approve { proposal }));
    assert!(matches!(out, Ok(Outcome::Joined { .. })), "{out:?}");
    assert!(st.is_member(&d.nid()));

    // Lowering the threshold needs the current threshold.
    pending(set(&mut st, &a, 5000, SettingChange::ApprovalsRequired(0)));

    // Removal needs approval, and the target can't approve or reject.
    let proposal = pending(st.apply(&a.cmd(
        st.cluster_id,
        6000,
        Command::ProposeRemove { target: c.nid() },
    )));
    assert_eq!(
        st.apply(&c.cmd(st.cluster_id, 6100, Command::Approve { proposal })),
        Err(CommandError::OwnRemoval)
    );
    assert_eq!(
        st.apply(&c.cmd(st.cluster_id, 6150, Command::Reject { proposal })),
        Err(CommandError::OwnRemoval)
    );
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 6200, Command::Approve { proposal })),
        Ok(Outcome::Removed { node: c.nid() })
    );

    // Leaving skips approvals.
    assert_eq!(
        st.apply(&d.cmd(st.cluster_id, 7000, Command::Leave)),
        Ok(Outcome::Left { node: d.nid() })
    );
    assert!(!st.is_member(&d.nid()));
}

#[test]
fn rejection_drops_a_pending_join() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    set(&mut st, &a, 3000, SettingChange::ApprovalsRequired(1)).unwrap();
    invite(&mut st, &a, 4000, [2; 32]);
    let proposal = pending(redeem(&mut st, &a, &c, 4100, [2; 32]));
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 4200, Command::Reject { proposal })),
        Ok(Outcome::Rejected { proposal })
    );
    assert!(st.proposals.is_empty());
    assert!(!st.is_member(&c.nid()));
}

#[test]
fn threshold_cannot_exceed_possible_approvers() {
    let a = Node::new();
    let mut st = genesis(&a);
    let out = set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(1));
    assert!(
        matches!(out, Err(CommandError::InvalidSetting(_))),
        "{out:?}"
    );
}

#[test]
fn ipv4_addresses_are_reused_after_removal() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    st.apply(&b.cmd(st.cluster_id, 3000, Command::Leave))
        .unwrap();
    invite(&mut st, &a, 4000, [2; 32]);
    let out = redeem(&mut st, &a, &c, 4100, [2; 32]).unwrap();
    assert_eq!(
        out,
        Outcome::Joined {
            node: c.nid(),
            ipv4: "100.64.7.2".parse().unwrap()
        }
    );
}

#[test]
fn wireguard_keys_are_unique() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    invite(&mut st, &a, 2000, [1; 32]);
    let out = st.apply(&a.cmd(
        st.cluster_id,
        2100,
        Command::RedeemInvite {
            secret: [1; 32],
            joiner: b.info_with(|i| i.wg_key = WgKey(a.nid().0)),
        },
    ));
    assert_invalid_member(&out);
    assert!(!st.is_member(&b.nid()));
}

#[test]
fn tampered_member_records_are_detected() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    assert!(st.verify_members().is_ok());
    // Swapping b's WireGuard key without b's signature is caught.
    st.members.get_mut(&b.nid()).unwrap().info.wg_key = WgKey([1; 32]);
    assert!(st.verify_members().is_err());
}

#[test]
fn members_update_only_themselves() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    let out = st.apply(&a.cmd(st.cluster_id, 3000, Command::UpdateSelf { info: b.info() }));
    assert_invalid_member(&out);
    let signed = a.info_with(|i| i.relay = true);
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 3100, Command::UpdateSelf { info: signed })),
        Ok(Outcome::Updated)
    );
    assert!(st.members[&a.nid()].info.relay);
}

#[test]
fn member_records_have_size_limits() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    let update = |st: &mut ClusterState, at, change: &dyn Fn(&mut MemberInfo)| {
        let info = a.info_with(change);
        st.apply(&a.cmd(st.cluster_id, at, Command::UpdateSelf { info }))
    };

    assert!(update(&mut st, 3000, &|i| i.name = "n".repeat(MAX_NAME_LEN)).is_ok());
    assert_invalid_member(&update(&mut st, 3001, &|i| {
        i.name = "n".repeat(MAX_NAME_LEN + 1)
    }));
    let addrs = |n: usize| -> Vec<SocketAddr> {
        (0..n)
            .map(|i| SocketAddr::from(([10, 0, 0, i as u8], 51821)))
            .collect()
    };
    assert!(
        update(&mut st, 3002, &|i| i.control_addrs =
            addrs(MAX_CONTROL_ADDRS))
        .is_ok()
    );
    assert_invalid_member(&update(&mut st, 3003, &|i| {
        i.control_addrs = addrs(MAX_CONTROL_ADDRS + 1)
    }));

    // Joining with a record that breaks them is refused too.
    invite(&mut st, &a, 4000, [1; 32]);
    let out = st.apply(&a.cmd(
        st.cluster_id,
        4100,
        Command::RedeemInvite {
            secret: [1; 32],
            joiner: b.info_with(|i| i.name = "n".repeat(MAX_NAME_LEN + 1)),
        },
    ));
    assert_invalid_member(&out);
}

/// A cluster of `a` plus `others`, all admitted without approvals.
fn cluster(a: &Node, others: &[&Node]) -> ClusterState {
    let mut st = genesis(a);
    for (i, n) in others.iter().enumerate() {
        let s = [100 + i as u8; 32];
        invite(&mut st, a, 1500, s);
        redeem(&mut st, a, n, 1600, s).unwrap();
    }
    st
}

fn set(st: &mut ClusterState, by: &Node, at: u64, change: SettingChange) -> Response {
    st.apply(&by.cmd(st.cluster_id, at, Command::ProposeSetting { change }))
}

#[test]
fn commands_before_genesis_are_refused() {
    let a = Node::new();
    let mut st = ClusterState::default();
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 1000, Command::Leave)),
        Err(CommandError::NotInitialized)
    );
    assert!(genesis(&a).cluster_id.is_some());
}

#[test]
fn genesis_needs_the_founders_own_record() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = ClusterState::default();
    let out = st.apply(&a.cmd(
        st.cluster_id,
        1000,
        genesis_cmd(0, "100.64.7.0/24", b.info()),
    ));
    assert_invalid_member(&out);

    // A record naming someone other than its signer.
    let founder = b.info_with(|i| i.node_id = a.nid());
    let out = st.apply(&a.cmd(
        st.cluster_id,
        1000,
        genesis_cmd(1, "100.64.7.0/24", founder),
    ));
    assert_invalid_member(&out);

    // A forged signature.
    let mut forged = a.cmd(st.cluster_id, 1000, Command::Leave);
    forged.command.body.push(0);
    assert_eq!(st.apply(&forged), Err(CommandError::BadSignature));
    assert!(st.cluster_id.is_none());
}

#[test]
fn a_joiner_can_only_be_waiting_once() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(1)).unwrap();
    invite(&mut st, &a, 3000, [1; 32]);
    assert!(matches!(
        redeem(&mut st, &a, &c, 3100, [1; 32]),
        Ok(Outcome::Pending { .. })
    ));
    invite(&mut st, &b, 3200, [2; 32]);
    assert_eq!(
        redeem(&mut st, &b, &c, 3300, [2; 32]),
        Err(CommandError::AlreadyPending)
    );
}

#[test]
fn removals_of_self_and_strangers() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    assert_eq!(
        st.apply(&a.cmd(
            st.cluster_id,
            2000,
            Command::ProposeRemove { target: c.nid() }
        )),
        Err(CommandError::NoSuchMember)
    );
    // Removing yourself is leaving, even when removals need approval.
    set(&mut st, &a, 2100, SettingChange::ApprovalsRequired(1)).unwrap();
    assert_eq!(
        st.apply(&b.cmd(
            st.cluster_id,
            2200,
            Command::ProposeRemove { target: b.nid() }
        )),
        Ok(Outcome::Left { node: b.nid() })
    );
}

#[test]
fn approvals_count_once_per_member() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b, &c, &d]);
    set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(2)).unwrap();
    let proposal = pending(set(&mut st, &a, 2100, SettingChange::Acceptors(5)));
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 2200, Command::Approve { proposal })),
        Ok(Outcome::Approved {
            proposal,
            remaining: 1
        })
    );
    assert_eq!(
        st.apply(&b.cmd(st.cluster_id, 2300, Command::Approve { proposal })),
        Err(CommandError::AlreadyApproved)
    );
    assert_eq!(
        st.apply(&c.cmd(st.cluster_id, 2400, Command::Approve { proposal })),
        Ok(Outcome::SettingChanged)
    );
    assert_eq!(st.settings().unwrap().acceptors, 5);
    assert_eq!(
        st.apply(&d.cmd(st.cluster_id, 2500, Command::Approve { proposal })),
        Err(CommandError::NoSuchProposal)
    );
    assert_eq!(
        st.apply(&d.cmd(st.cluster_id, 2600, Command::Reject { proposal })),
        Err(CommandError::NoSuchProposal)
    );
}

#[test]
fn a_departing_member_takes_its_proposals_and_approvals_along() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b, &c, &d]);
    set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(2)).unwrap();
    invite(&mut st, &b, 2050, [9; 32]);
    let by_b = pending(set(&mut st, &b, 2100, SettingChange::Acceptors(5)));
    let by_a = pending(set(&mut st, &a, 2200, SettingChange::Acceptors(1)));
    st.apply(&b.cmd(st.cluster_id, 2300, Command::Approve { proposal: by_a }))
        .unwrap();
    st.apply(&b.cmd(st.cluster_id, 2400, Command::Leave))
        .unwrap();
    assert!(
        !st.proposals.contains_key(&by_b),
        "b's own proposal is gone"
    );
    assert!(
        st.proposals[&by_a].approvals.is_empty(),
        "b's approval is gone"
    );
    assert!(st.invites.is_empty(), "b's invite is gone");
}

#[test]
fn every_setting_key_parses_and_shows_its_value() {
    let st = cluster(&Node::new(), &[]);
    let settings = st.settings().unwrap();
    for key in SettingChange::KEYS {
        let value = settings.value(key).unwrap();
        let change = SettingChange::parse(key, &value).unwrap();
        assert_eq!(change.key(), key);
        assert_eq!(change.value(), value);
    }
    assert!(matches!(
        SettingChange::parse("colour", "1"),
        Err(ParseSettingError::UnknownKey { .. })
    ));
    assert!(matches!(
        SettingChange::parse("acceptors", "many"),
        Err(ParseSettingError::BadValue {
            key: "acceptors",
            ..
        })
    ));
    assert_eq!(settings.value("ipv4_range"), None);
}

#[test]
fn settings_are_validated() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    for v in [0, 8, 9] {
        let out = set(&mut st, &a, 2000 + v as u64, SettingChange::Acceptors(v));
        assert!(
            matches!(out, Err(CommandError::InvalidSetting(_))),
            "{v}: {out:?}"
        );
    }
    assert_eq!(
        set(&mut st, &a, 2100, SettingChange::Acceptors(3)),
        Ok(Outcome::SettingChanged)
    );
    assert_eq!(st.settings().unwrap().acceptors, 3);
}

#[test]
fn the_wireguard_key_is_fixed_for_life() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    let info = a.info_with(|i| i.wg_key = WgKey([42; 32]));
    let out = st.apply(&a.cmd(st.cluster_id, 2000, Command::UpdateSelf { info }));
    assert_invalid_member(&out);
}

#[test]
fn a_full_range_refuses_joins() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    let mut st = ClusterState::default();
    st.apply(&a.cmd(
        st.cluster_id,
        1000,
        genesis_cmd(0, "100.64.7.0/30", a.info()),
    ))
    .unwrap();
    invite(&mut st, &a, 2000, [1; 32]);
    redeem(&mut st, &a, &b, 2100, [1; 32]).unwrap();
    invite(&mut st, &a, 2200, [2; 32]);
    let out = redeem(&mut st, &a, &c, 2300, [2; 32]);
    assert!(matches!(out, Err(CommandError::RangeFull(_))), "{out:?}");
}

#[test]
fn a_record_filed_under_the_wrong_node_is_detected() {
    let (a, b) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    let m = st.members.remove(&b.nid()).unwrap();
    st.members.insert(NodeId([1; 32]), m);
    assert!(st.verify_members().is_err());
}

#[test]
fn warnings_explain_what_the_cluster_cant_do() {
    let (a, b, c) = (Node::new(), Node::new(), Node::new());
    assert!(genesis(&a).warnings().is_empty());

    let mut st2 = cluster(&a, &[&b]);
    // With 2 members and 1 approval, removals are stuck.
    set(&mut st2, &a, 2100, SettingChange::ApprovalsRequired(1)).unwrap();
    let w = st2.warnings();
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].contains("removals of admins can no longer be approved"),
        "{w:?}"
    );

    // When a member leaves, joins can't be approved either.
    st2.apply(&b.cmd(st2.cluster_id, 2200, Command::Leave))
        .unwrap();
    let w = st2.warnings();
    assert!(w[0].contains("joins can no longer be approved"), "{w:?}");

    // Enough members: no warnings.
    let mut st = cluster(&a, &[&b, &c]);
    set(&mut st, &a, 3500, SettingChange::ApprovalsRequired(1)).unwrap();
    assert!(st.warnings().is_empty(), "{:?}", st.warnings());
}

/// Vote and relay, but not admin: a router the owner runs.
const ROUTER: Permissions = Permissions {
    admin: false,
    vote: true,
    relay: true,
};
/// Admin only: a manager that takes no network role.
const MANAGER: Permissions = Permissions {
    admin: true,
    vote: false,
    relay: false,
};

/// `node` joins `st` through an invite from `by` that gives `permissions`.
fn join_as(st: &mut ClusterState, by: &Node, node: &Node, at: u64, permissions: Permissions) {
    let secret = [at as u8; 32];
    invite_as(st, by, at, secret, permissions);
    let out = redeem(st, by, node, at + 1, secret);
    assert!(matches!(out, Ok(Outcome::Joined { .. })), "{out:?}");
}

#[test]
fn the_invite_decides_the_joiners_permissions() {
    let (a, r, f) = (Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    join_as(&mut st, &a, &r, 1700, ROUTER);
    join_as(&mut st, &a, &f, 1800, Permissions::NONE);
    assert_eq!(st.members[&a.nid()].permissions, Permissions::ALL);
    assert_eq!(st.members[&r.nid()].permissions, ROUTER);
    assert_eq!(st.members[&f.nid()].permissions, Permissions::NONE);
    assert_eq!(st.with(Permission::Admin).count(), 1, "only a");
    assert_eq!(st.with(Permission::Vote).count(), 2, "a and r");
    assert!(st.may_relay(&r.nid()) && !st.may_relay(&f.nid()));

    // Through a proposal too: the permissions are kept while it waits.
    let (b, c) = (Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(1)).unwrap();
    invite_as(&mut st, &a, 2100, [51; 32], ROUTER);
    let proposal = pending(redeem(&mut st, &a, &c, 2200, [51; 32]));
    st.apply(&b.cmd(st.cluster_id, 2300, Command::Approve { proposal }))
        .unwrap();
    assert_eq!(st.members[&c.nid()].permissions, ROUTER);
}

#[test]
fn changing_the_cluster_needs_the_admin_permission() {
    let (a, b, r, f) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    join_as(&mut st, &a, &r, 1700, ROUTER);
    join_as(&mut st, &a, &f, 1800, Permissions::NONE);
    let refused = [
        Command::CreateInvite {
            invite_id: [1; 32],
            permissions: Permissions::NONE,
        },
        Command::ProposeRemove { target: f.nid() },
        Command::ProposeSetting {
            change: SettingChange::BufferNodes(1),
        },
        Command::Approve {
            proposal: crate::ProposalId([9; 32]),
        },
        Command::Reject {
            proposal: crate::ProposalId([9; 32]),
        },
    ];
    for (i, command) in refused.into_iter().enumerate() {
        let before = st.members.clone();
        let out = st.apply(&r.cmd(st.cluster_id, 2000 + i as u64, command.clone()));
        let missing = Err(CommandError::MissingPermission(Permission::Admin));
        assert_eq!(out, missing, "{command:?}");
        assert_eq!(st.members, before);
    }
    assert!(st.invites.is_empty() && st.proposals.is_empty());

    // Not a real proposal either.
    set(&mut st, &a, 3000, SettingChange::ApprovalsRequired(1)).unwrap();
    let proposal = pending(set(&mut st, &a, 3100, SettingChange::BufferNodes(1)));
    assert_eq!(
        st.apply(&r.cmd(st.cluster_id, 3200, Command::Approve { proposal })),
        Err(CommandError::MissingPermission(Permission::Admin))
    );
    assert!(st.proposals.contains_key(&proposal));
}

#[test]
fn an_admin_gives_permissions_it_doesnt_have() {
    let (a, m, r, g) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    join_as(&mut st, &a, &m, 1700, MANAGER);
    join_as(&mut st, &a, &r, 1800, ROUTER);
    // The manager makes the invite, and a voter takes the redemption.
    invite_as(&mut st, &m, 1900, [60; 32], Permissions::ALL);
    let out = redeem(&mut st, &r, &g, 1901, [60; 32]);
    assert!(matches!(out, Ok(Outcome::Joined { .. })), "{out:?}");
    assert_eq!(st.members[&g.nid()].permissions, Permissions::ALL);
    // And it removes any member.
    assert_eq!(
        st.apply(&m.cmd(
            st.cluster_id,
            2000,
            Command::ProposeRemove { target: a.nid() }
        )),
        Ok(Outcome::Removed { node: a.nid() })
    );
}

#[test]
fn redemptions_and_the_acceptor_role_need_the_vote_permission() {
    let (a, m, g) = (Node::new(), Node::new(), Node::new());
    let mut st = genesis(&a);
    join_as(&mut st, &a, &m, 1700, MANAGER);
    // The manager can't take a redemption, even of its own invite. The
    // invite isn't used up.
    invite(&mut st, &m, 2100, [53; 32]);
    let out = redeem(&mut st, &m, &g, 2200, [53; 32]);
    assert_eq!(out, Err(CommandError::MissingPermission(Permission::Vote)));
    assert!(!st.is_member(&g.nid()));
    let out = redeem(&mut st, &a, &g, 2250, [53; 32]);
    assert!(matches!(out, Ok(Outcome::Joined { .. })), "{out:?}");

    assert_eq!(
        st.apply(&m.cmd(st.cluster_id, 2300, Command::GiveUpAcceptor)),
        Err(CommandError::MissingPermission(Permission::Vote))
    );
}

#[test]
fn every_member_updates_itself_and_leaves() {
    let (a, f) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    join_as(&mut st, &a, &f, 1700, Permissions::NONE);
    let out = st.apply(&f.cmd(st.cluster_id, 2000, Command::UpdateSelf { info: f.info() }));
    assert_eq!(out, Ok(Outcome::Updated));
    assert_eq!(
        st.apply(&f.cmd(st.cluster_id, 2300, Command::Leave)),
        Ok(Outcome::Left { node: f.nid() })
    );
    assert!(!st.is_member(&f.nid()));
}

#[test]
fn the_last_admin_and_the_last_voter_may_leave() {
    // Without an admin, the cluster keeps working, but can't be changed.
    let (a, r) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    join_as(&mut st, &a, &r, 1700, ROUTER);
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 2000, Command::Leave)),
        Ok(Outcome::Left { node: a.nid() })
    );
    let w = st.warnings();
    assert!(
        w.iter()
            .any(|w| w.contains("no member has the admin permission")),
        "{w:?}"
    );

    // Without a voter, it can agree on nothing more. That's the members'
    // choice: a member can always stop.
    let (a, f) = (Node::new(), Node::new());
    let mut st = genesis(&a);
    join_as(&mut st, &a, &f, 1700, Permissions::NONE);
    assert_eq!(
        st.apply(&a.cmd(st.cluster_id, 2000, Command::Leave)),
        Ok(Outcome::Left { node: a.nid() })
    );
    assert_eq!(st.with(Permission::Vote).count(), 0);
}

#[test]
fn approvals_count_only_admins() {
    let (a, b, r) = (Node::new(), Node::new(), Node::new());
    let mut st = cluster(&a, &[&b]);
    join_as(&mut st, &a, &r, 1700, ROUTER);
    // Three members, but only one other admin can approve.
    assert!(matches!(
        set(&mut st, &a, 2000, SettingChange::ApprovalsRequired(2)),
        Err(CommandError::InvalidSetting(_))
    ));
    set(&mut st, &a, 2100, SettingChange::ApprovalsRequired(1)).unwrap();
    let w = st.warnings();
    assert!(w.iter().any(|w| w.contains("with 2 admin(s)")), "{w:?}");
}

#[test]
fn permissions_are_shown_by_name() {
    assert_eq!(Permissions::ALL.to_string(), "admin,vote,relay");
    assert_eq!(ROUTER.to_string(), "vote,relay");
    assert_eq!(Permissions::NONE.to_string(), "none");
}

/// `base` with `req` applied, and the step recorded. Unlike
/// `ClusterState::stepped`, the step is recorded even if the request changed
/// nothing: these tests build invalid steps on purpose.
fn stepped(base: &ClusterState, req: Option<Request>) -> ClusterState {
    let mut next = base.clone();
    if let Some(req) = &req {
        let _ = next.apply(req);
    }
    next.record_step(base, req);
    next
}

#[test]
fn a_recorded_step_checks_out() {
    let (a, b) = (Node::new(), Node::new());
    let base = cluster(&a, &[&b]);
    let latest = base.now_ms + 30_000;
    let next = stepped(
        &base,
        Some(a.cmd(base.cluster_id, base.now_ms + 5, create_invite([7; 32]))),
    );
    assert_eq!(base.check_step(&next, latest), Ok(()));
    // A refused command is a valid step too.
    let refused = stepped(
        &base,
        Some(b.cmd(
            base.cluster_id,
            base.now_ms + 5,
            Command::ProposeRemove {
                target: NodeId([9; 32]),
            },
        )),
    );
    assert_eq!(base.check_step(&refused, latest), Ok(()));
    // So is a step with no command, which leaves the rest as it was.
    assert_eq!(base.check_step(&stepped(&base, None), latest), Ok(()));
}

#[test]
fn a_made_up_step_is_refused() {
    let (a, b) = (Node::new(), Node::new());
    let base = cluster(&a, &[&b]);
    let latest = base.now_ms + 30_000;
    let invite = |at| Some(a.cmd(base.cluster_id, at, create_invite([7; 32])));

    let mut missing = base.clone();
    missing.now_ms += 1;
    assert_eq!(base.check_step(&missing, latest), Err(StepError::Missing));

    // A member dropped with no command that drops it.
    let mut dropped = stepped(&base, None);
    dropped.members.remove(&b.nid());
    assert_eq!(base.check_step(&dropped, latest), Err(StepError::Different));

    // A valid step, but from another state.
    let mut other = base.clone();
    other.next_proposal += 1;
    let from_other = stepped(&other, invite(base.now_ms + 5));
    assert_eq!(
        base.check_step(&from_other, latest),
        Err(StepError::OtherBase)
    );

    // Times before the state's, or past the latest allowed.
    let early = stepped(&base, invite(base.now_ms - 1));
    assert!(matches!(
        base.check_step(&early, latest),
        Err(StepError::Time { .. })
    ));
    let late = stepped(&base, invite(latest + 1));
    assert!(matches!(
        base.check_step(&late, latest),
        Err(StepError::Time { .. })
    ));
    // A state whose time is already past the latest allows its own time.
    let at_base = stepped(&base, invite(base.now_ms));
    assert_eq!(base.check_step(&at_base, base.now_ms - 10), Ok(()));
}

#[test]
fn approvals_bind_the_action_and_creation_history() {
    let (a, b, c, d) = (Node::new(), Node::new(), Node::new(), Node::new());
    let mut original = cluster(&a, &[&b]);
    set(&mut original, &a, 3000, SettingChange::ApprovalsRequired(1)).unwrap();
    invite(&mut original, &a, 4000, [42; 32]);
    let mut left = original.clone();
    let mut right = original.clone();
    let l = pending(redeem(&mut left, &a, &c, 4100, [42; 32]));
    let r = pending(redeem(&mut right, &a, &d, 4100, [42; 32]));
    assert_eq!(l.sequence(), r.sequence());
    assert_ne!(l, r, "same sequence must not authorize another join");
    let approval = b.cmd(left.cluster_id, 4200, Command::Approve { proposal: l });
    assert_eq!(right.apply(&approval), Err(CommandError::NoSuchProposal));
    assert!(!right.is_member(&d.nid()));
    assert!(left.apply(&approval).is_ok());
    assert!(left.is_member(&c.nid()));
    // A different creation history also yields a different token for the
    // same action and sequence, without depending on later votes.
    let mut changed_history = original;
    invite(&mut changed_history, &a, 4050, [43; 32]);
    let other = pending(redeem(&mut changed_history, &a, &c, 4100, [42; 32]));
    assert_ne!(other, l);
}

#[test]
fn signed_commands_cannot_cross_clusters() {
    let a = Node::new();
    let first = genesis(&a);
    let mut other = ClusterState::default();
    other
        .apply(&a.cmd(None, 1000, genesis_cmd(1, "100.64.7.0/24", a.info())))
        .unwrap();
    assert_ne!(first.cluster_id, other.cluster_id);
    let request = a.cmd(first.cluster_id, 2000, create_invite([7; 32]));
    assert_eq!(other.apply(&request), Err(CommandError::WrongCluster));
    assert!(other.invites.is_empty());
}
