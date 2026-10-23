use super::*;
use crate::testing::ballot;
use cheesecloth_core::Identity;
use pnyx::{Acceptor, store::Stored};

#[test]
fn a_failed_change_reports_every_cause_of_the_transport_error() {
    let cause = anyhow::anyhow!("connection refused").context("request to a1b2 failed");
    let failed: pnyx::Error<TransportError> = pnyx::Error::Timeout {
        last: Some(pnyx::RequestError::Transport(cause.into())),
    };
    let e = format!(
        "{:#}",
        anyhow::Error::from(failed).context("couldn't agree on the change")
    );
    assert!(
        e.ends_with("request to a1b2 failed: connection refused"),
        "{e}"
    );
}

#[test]
fn counter_feedback_must_match_the_request_and_existing_jump_limit() {
    let ballot = ballot(7, NodeId([1; 32]));
    let rejected = |counter| Reply::Rejected {
        config: 3,
        ballot: ballot.clone(),
        promised: crate::testing::ballot(counter, ballot.node),
    };
    for counter in [7, 7 + pnyx::MAX_COUNTER_STEP] {
        let reply = rejected(counter);
        assert!(check_feedback(3, &ballot, &reply).is_ok());
        assert!(check_feedback(4, &ballot, &reply).is_err());
    }
    for counter in [6, 8 + pnyx::MAX_COUNTER_STEP, u64::MAX] {
        assert!(check_feedback(3, &ballot, &rejected(counter)).is_err());
    }
    for limit in [0, 6, u64::MAX] {
        assert!(
            check_feedback(
                3,
                &ballot,
                &Reply::TooHigh {
                    config: 3,
                    ballot: ballot.clone(),
                    limit
                }
            )
            .is_err()
        );
    }
    let high = Ballot {
        counter: 2 * pnyx::MAX_COUNTER_STEP,
        ..ballot
    };
    let reply = Reply::TooHigh {
        config: 3,
        ballot: high.clone(),
        limit: pnyx::MAX_COUNTER_STEP,
    };
    assert!(check_feedback(3, &high, &reply).is_ok());
}

#[tokio::test]
async fn evidence_index_deduplicates_values_and_preserves_openings_and_phases() {
    let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
    let n = &h.node;
    let transport = Acceptors::new(n);
    let mut closing = n.agreed().value.clone();
    closing.version += 1;
    closing.next = Some(
        closing
            .config
            .successor(closing.config.acceptors.clone(), false),
    );
    let header = Header::of(n.cluster_id, &closing);
    let ballot = ballot(1, n.me);
    for _ in 0..7 {
        transport.add_value(header.clone(), &closing);
        transport.add_share(Certificate::sign_verified(
            &n.identity,
            header.clone(),
            ballot.clone(),
        ));
    }
    assert_eq!(transport.collected.lock().values.len(), 2);
    assert_eq!(transport.collected.lock().shares.len(), 2);
    // A verification quorum must never be treated as acceptance.
    assert!(transport.base(0, Some(&header)).is_none());
    assert!(transport.base(1, None).is_none());
    transport.add_share(Certificate::sign(
        &n.identity,
        header.clone(),
        ballot.clone(),
    ));
    let closed = transport.base(0, Some(&header)).unwrap();
    assert_eq!(closed.chosen.value, closing);
    assert_eq!(closed.chosen.ballot, Some(ballot));
    assert!(closed.cert.proves(&closed.chosen));
    let opened = transport.base(1, None).unwrap();
    assert_eq!(opened.chosen.value, closing.open().unwrap());
    assert!(opened.chosen.ballot.is_none());
    assert!(opened.cert.proves(&opened.chosen));
    let mut foreign = header;
    foreign.cluster_id = ClusterId([99; 32]);
    assert!(transport.base(0, Some(&foreign)).is_none());
}

#[tokio::test]
async fn cached_quorum_results_follow_signature_replacement() {
    let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
    let round = Acceptors::new(&h.node);
    let valid = h.node.cert.lock().clone();
    let mut invalid = valid.clone();
    invalid.sigs.insert(
        h.node.me,
        h.node.identity.sign(Domain::Accept, b"another value"),
    );
    round.add_share(invalid);
    assert!(round.base(0, None).is_none());
    round.add_share(valid);
    assert!(round.base(0, None).is_some());
}

#[tokio::test]
async fn a_state_learned_during_a_change_can_be_built_on() {
    let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
    let n = &h.node;
    let transport = Acceptors::new(n);
    // Another proposer's change is agreed while this change runs.
    let mut newer = (*n.agreed()).clone();
    newer.value.version += 1;
    newer.value.value.now_ms += 1;
    h.learn(newer.clone()).await.unwrap();
    // The proposer takes it at the start of its next round, and treats
    // it as agreed. So the round must hold its proof as a predecessor.
    assert_eq!(transport.learned(), Some(newer.clone()));
    let header = Header::of(n.cluster_id, &newer.value);
    let base = transport
        .base(newer.value.config.number, Some(&header))
        .unwrap();
    assert_eq!(base.chosen, newer);
}

#[tokio::test]
async fn a_round_asks_for_its_verification_once() {
    let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
    let n = &h.node;
    let transport = Acceptors::new(n);
    let prepare = |ballot: &Ballot<NodeId>| Request::Prepare {
        config: 0,
        ballot: ballot.clone(),
        have: None,
    };
    let mut next = n.agreed().value.clone();
    next.version += 1;
    next.value = n.agreed().state().reconfigured();
    // Asked before the round has its prepare evidence: it fails.
    let first = ballot(1, n.me);
    let e = transport.verification(&first, &next).await.unwrap_err();
    let refused = e.to_string();
    assert!(refused.contains("missing prepare evidence"), "{refused}");
    // The evidence comes in, but every accept request of the round gets the
    // same answer: the acceptors aren't asked again.
    transport.call(&n.me, prepare(&first)).await.unwrap();
    let e = transport.verification(&first, &next).await.unwrap_err();
    assert_eq!(e.to_string(), refused);
    // A new round asks.
    let second = ballot(2, n.me);
    transport.call(&n.me, prepare(&second)).await.unwrap();
    assert!(transport.verification(&second, &next).await.is_ok());
}

#[tokio::test]
async fn a_ballot_can_be_reused_in_a_new_configuration() {
    let h = crate::testing::harness(crate::RelayMode::Never, &[]).await;
    let n = &h.node;
    let transport = Acceptors::new(n);
    let ballot = ballot(1, n.me);
    transport
        .call(
            &n.me,
            Request::Prepare {
                config: 0,
                ballot: ballot.clone(),
                have: None,
            },
        )
        .await
        .unwrap();
    let mut closing = n.agreed().value.clone();
    closing.version += 1;
    closing.value = n.agreed().state().reconfigured();
    closing.next = Some(
        closing
            .config
            .successor(closing.config.acceptors.clone(), false),
    );
    transport
        .call(
            &n.me,
            Request::Accept {
                config: 0,
                ballot: ballot.clone(),
                value: closing.clone(),
            },
        )
        .await
        .unwrap();
    let opened = closing.open().unwrap();
    transport
        .call(
            &n.me,
            Request::Prepare {
                config: 1,
                ballot: ballot.clone(),
                have: None,
            },
        )
        .await
        .unwrap();
    let mut next = opened.clone();
    next.version += 1;
    next.value = opened.value.reconfigured();
    let reply = transport
        .call(
            &n.me,
            Request::Accept {
                config: 1,
                ballot,
                value: next,
            },
        )
        .await
        .unwrap();
    assert!(matches!(reply, Reply::Accepted { config: 1, .. }));
}

fn setup() -> (Vec<Identity>, Agreed, ClusterId) {
    let ids: Vec<_> = (0..4).map(|_| Identity::generate()).collect();
    let cluster = ClusterId([7; 32]);
    let mut value = Chosen::genesis(ids[0].node_id(), ClusterState::default()).value;
    value.value.cluster_id = Some(cluster);
    value.config.acceptors = ids.iter().map(Identity::node_id).collect();
    value.config.protected = true;
    (ids, value, cluster)
}
/// A verification of `value` by the first three of `ids`.
fn certificate(
    ids: &[Identity],
    value: &Agreed,
    cluster: ClusterId,
    ballot: &Ballot<NodeId>,
) -> Certificate {
    let signers: Vec<&Identity> = ids[..3].iter().collect();
    crate::testing::certificate(&signers, Header::of(cluster, value), ballot.clone(), true)
}
#[test]
fn signed_prepare_evidence_rejects_fabrication_replay_and_duplicates() {
    let (ids, value, cluster) = setup();
    let previous = ballot(1, ids[0].node_id());
    let ballot = ballot(2, ids[0].node_id());
    let c = certificate(&ids, &value, cluster, &previous);
    let p = Promise {
        cluster,
        config: value.config.number,
        ballot: ballot.clone(),
        accepted: Some(c.clone()),
    };
    let evidence: Vec<_> = ids[..3]
        .iter()
        .map(|id| id.seal(Domain::Promise, &p))
        .collect();
    assert_eq!(
        promises(cluster, &value.config, &ballot, &evidence).unwrap(),
        Some(c)
    );
    assert!(promises(cluster, &value.config, &ballot, &evidence[..2]).is_err());
    assert!(
        promises(
            cluster,
            &value.config,
            &ballot,
            &[
                evidence[0].clone(),
                evidence[0].clone(),
                evidence[1].clone()
            ]
        )
        .is_err()
    );
    let wrong_ballot = crate::testing::ballot(3, ballot.node);
    assert!(promises(cluster, &value.config, &wrong_ballot, &evidence).is_err());
    assert!(promises(ClusterId([8; 32]), &value.config, &ballot, &evidence).is_err());
    let mut forged = p.clone();
    forged.accepted.as_mut().unwrap().ballot.counter = 99;
    let mut bad = evidence.clone();
    bad[0] = ids[0].seal(Domain::Promise, &forged);
    assert!(promises(cluster, &value.config, &ballot, &bad).is_err());
    forged = p;
    let cert = forged.accepted.as_mut().unwrap();
    cert.sigs.retain(|id, _| *id == ids[0].node_id());
    bad[0] = ids[0].seal(Domain::Promise, &forged);
    assert!(promises(cluster, &value.config, &ballot, &bad).is_err());
}

#[test]
fn verification_and_acceptance_have_separate_signature_domains() {
    let (ids, value, cluster) = setup();
    let ballot = ballot(1, ids[0].node_id());
    let mut c = certificate(&ids, &value, cluster, &ballot);
    c.check_config(&value.config, true).unwrap();
    assert!(c.check_config(&value.config, false).is_err());
    c.verified = false;
    assert!(c.check_config(&value.config, false).is_err());
    c.verified = true;
    let mut downgraded = value.config.clone();
    downgraded.protected = false;
    assert!(c.check_config(&downgraded, true).is_err());
}

#[test]
fn a_restart_preserves_endorsements_and_accepted_proofs() {
    let (ids, value, cluster) = setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("acceptor");
    let ballot = ballot(1, ids[0].node_id());
    let mut store =
        Stored::<NodeId, ClusterState, Certificate>::create(path.clone(), Acceptor::default())
            .unwrap();
    store.endorse(ballot.clone(), value.clone()).unwrap();
    drop(store);
    let mut store = Stored::<NodeId, ClusterState, Certificate>::open(path.clone()).unwrap();
    let mut conflicting = value.clone();
    conflicting.version += 1;
    assert!(store.endorse(ballot.clone(), conflicting).is_err());
    let proof = certificate(&ids, &value, cluster, &ballot);
    store
        .handle_proven(
            Request::Accept {
                config: value.config.number,
                ballot: ballot.clone(),
                value: value.clone(),
            },
            proof.clone(),
        )
        .unwrap();
    drop(store);
    let store = Stored::<NodeId, ClusterState, Certificate>::open(path).unwrap();
    assert_eq!(
        store.acceptor().accepted_proof(value.config.number),
        Some(&proof)
    );
    assert_eq!(
        store.acceptor().accepted(value.config.number, &ballot),
        Some(&value)
    );
}
