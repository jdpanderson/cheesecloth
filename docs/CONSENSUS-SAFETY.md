# Consensus safety

This is how members agree on the network's state, and what that protects
against. For the user view, see [security](SECURITY.md).

The protocol is CASPaxos, with signed messages and evidence added. It has two
modes:
- **Relaxed** mode is safe only if every voter is honest.
- **Protected** mode aims to stay safe with one Byzantine voter: one that lies,
  sends different answers to different peers, or holds back its vote.

These are design goals. They are not audited and not formally proven.

## Voters and quorums

The agreed state includes a configuration. It names the voters, a sequence
number and the mode. Only members with `vote` are voters. `acceptors` caps the
group at 1 to 7 voters, and is 7 by default.

| Voters | Mode | Votes needed |
| --- | --- | --- |
| 1 to 3 | relaxed | a majority: `floor(n/2) + 1` |
| 4 to 7 | protected | `floor((n+1)/2) + 1` |

Any two protected quorums share at least two voters, so they share at least
one honest voter. This allows **one** bad voter, even with seven voters.

Protection assumes:
- signatures can't be forged;
- honest voters keep their records on disk;
- all voters start from the same trusted history.

It does not stop everything:
- A bad member can stall changes with competing proposals.
- A relay can block messages.
- Consensus can't tell that several keys belong to one attacker. Only invite
  voters you trust.

## Changing the voters

The **current** quorum must approve every change to the voter group, before
the new quorum takes over. A voter that is gone for ten minutes may be
replaced. Its membership stays, and nothing else changes without agreement.

For example, starting with four protected voters:

| Event | Result |
| --- | --- |
| Two go offline at once | Three votes are still needed, so changes stop. |
| One goes offline | The other three can move to a relaxed group of three, unless strict mode is on. |
| Then another goes offline | The last two can move to a group of two. Both must vote. |

If changes stop, WireGuard keeps working with the last known members. There
is no automatic reset.

### Buffer and strict mode

`buffer_nodes`, from 0 to 3, is how many voters may be offline while changes
still work. A bad voter that holds back its vote counts toward it. All chosen
voters vote. Protection starts only with at least four voters and
`n - quorum >= buffer_nodes`. With a buffer of two, five voters stay relaxed
and need three votes; six are protected and need four. With a buffer of
three, protection can't start under the cap of seven.

`strict_security`, off by default, stops a protected group from moving to
relaxed mode. It holds across restarts, even if the buffer can't be met. It
can stop a member from leaving if that would leave fewer than four voters.
Turn it off before you lower `acceptors` below four.

`status` shows the mode, quorum, reachable voters, strict mode, buffer, and
whether changes have stopped. Reachability can lag behind real failures.

Moving back to protected mode can't repair a fork made in relaxed mode.

## Permissions and consensus

Consensus and permissions are separate. Voters check the permission rules on
every change, so a member can't get past them with a changed daemon. But
protected mode does not limit what admins may do, and `approvals_required`
does not make relaxed mode safe. See
[membership and approvals](DESIGN.md#membership-and-approvals).

Each approval or rejection signs a full 32-byte proposal token. Eight bytes
are a sequence number. The other 24 are a BLAKE3 hash of the cluster, the
state it was made from, the action, the proposer, the sequence, the time and
the expiry. A join's action includes the signed identity and WireGuard key.
So a signature for one proposal can't approve a different one.

Every command except the first signs the cluster ID. The first command
defines that ID. Each phase of a round signs in its own domain, so a vote in
one phase can't be reused in another.

## Authenticated round

1. **Prepare.** Each voter saves its promise to disk, then signs the cluster,
   configuration, ballot, and the certificate for the value it last accepted.
   That value needs quorum evidence at its ballot. One voter's word is not
   enough.
2. **Select.** The proposer checks the promises and the state they carry,
   then picks the highest accepted ballot. It refuses conflicting evidence at
   the same ballot.
3. **Verify.** Each voter checks the prepare quorum. An unfinished candidate
   can only be written back unchanged. A new command must build on a value
   with an acceptance certificate, or on the previous configuration's closing
   certificate. The voter replays the change, and checks the configuration
   rules and what it sees of other voters.
4. **Endorse.** Before it signs, the voter saves its promise and the
   candidate to disk. It can't endorse two candidates at one ballot, even
   after a restart. A higher ballot can recover an abandoned candidate.
5. **Accept.** Voters need a verification quorum certificate. They save the
   value and its proof together, then sign acceptance.
6. **Learn.** An acceptance quorum certificate proves the result.
   Verification votes don't count as acceptance votes. The proposer reports
   success only after it saves the result.

A certificate covers the cluster, the full voter configuration and mode, the
ballot, state version, time, hash, and any next configuration. Vote counts come
from a trusted configuration, never from a peer's claim. A certificate holds
headers and signatures, not the evidence of earlier rounds.

Compared to plain CASPaxos, this adds one exchange and one disk write. State is
capped at 320 KiB, so a candidate, its base and evidence fit in the 1 MiB
message limit. See also
[resource bounds](DESIGN.md#discovery-and-resource-bounds).

## Validation and limits

Safety rests on quorums overlapping:
- Two verification quorums share an honest voter. Its saved endorsement stops
  two candidates at one ballot.
- A prepare quorum and an acceptance quorum share an honest voter. It reports
  the accepted value, or promises the new ballot before an older acceptance
  can finish.
- Quorum evidence stops a bad voter from inventing a higher accepted ballot.

This is an argument, **not a machine-checked proof**. Tests cover forged and
replayed evidence, mixed-up phases, swapped proposals, saved endorsements,
partial acceptance, configuration recovery and voter selection.

The consensus engine, [pnyx](https://crates.io/crates/pnyx), has its own
checks. A Stateright model checks crashes and reconfiguration, and property
tests check its promises against random requests. They don't cover the signed
evidence added here. See
[*Byzantine faults*](https://docs.rs/pnyx/latest/pnyx/#byzantine-faults) in
its docs.

The design draws on [CASPaxos](https://arxiv.org/html/1802.07000v9) and
[Byzantizing Paxos by Refinement](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/12/Byzantizing-Paxos-by-Refinement.pdf).
Neither proves this code. Cheesecloth is not PBFT, and does not have PBFT's
liveness.

Wire and disk formats may change during development. The control protocol is
`cheesecloth/2`. Older versions can't join.
