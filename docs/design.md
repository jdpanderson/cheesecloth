# Design

This document describes how cheesecloth is put together and why. It covers the
parts that would be expensive to change later: the trust model, the two planes,
how membership becomes an interface configuration, and the seams that keep the
code portable. It does not describe individual functions.

[Membership](membership.md) has the full specification of identities, records,
the enrolment exchange and the transport. This document refers to it rather
than repeating it.

## What the software does

cheesecloth builds a WireGuard mesh between machines that have never met. An
operator starts one node, which becomes a cluster of one, then invites the
others one at a time. Each node ends up with a WireGuard interface holding
every other member as a peer, an address on a private overlay network, and a
name that resolves to that address.

Every node runs the same binary and the same code. There is no server, no
controller and no coordinator. The node that founded the cluster has no standing
the others lack and may be revoked or switched off like any of them.

## Design goals

- **No shared secret.** Nothing that grants cluster access exists on disk.
  Compromising a node gives an attacker that node, not the cluster.
- **Unattended restart.** A node that reboots rejoins with what it has on
  disk. All nodes may restart at once, and no operator is needed.
- **One membership, agreed.** Every node reads who belongs from the same signed
  list, and a change to it takes a quorum of the members. There is no ordered
  rollout and no leader, but a cluster with too few members reachable changes
  nothing until they are back.
- **One binary per platform.** The same commands and the same state format on
  Linux, macOS and Windows.
- **Explicit versions.** Protocol identifiers appear in the enrolment message
  and in the TLS ALPN, so nodes of different versions refuse to talk rather
  than half working.

Deliberately not goals: hub and spoke topologies, NAT traversal or relaying,
central policy, and access control finer than membership. Every member reaches
every other member directly.

## The two planes

The system is two layers with different jobs and different keys.

| | Control plane | Data plane |
|---|---|---|
| Carries | who the members are and what they announce | the traffic between members |
| Protocol | memberlist gossip over QUIC, one UDP port | WireGuard, one UDP port |
| Authenticated by | the node's persistent identity (Ed25519) | the node's WireGuard key |
| Lifetime of the key | the life of the node | until the process restarts |

The control plane decides which WireGuard public keys a node installs as
peers. WireGuard itself is used as it comes, neither modified nor wrapped.

The split matters because the two keys have different lifetimes. The identity
is persistent and is what membership is expressed in. The WireGuard key is
generated on start and never persisted, so a node that restarts announces a new
one. Binding them is the job of the signed metadata each node gossips.

## Trust

Membership is a **checkpoint**: a signed statement of who the members are, with
the name and overlay slot each holds, carrying the signatures of the members
that agree with it. A node holds one — its anchor — and that is the whole of
what it knows about who belongs.

A checkpoint is trusted because the membership below it agreed to it, and that
membership was trusted for the same reason. Once a node has seen that happen it
keeps the result and throws the rest away, so nothing walks a chain of
signatures and nothing has to prove who trusted whom. A node that has been away
takes the membership the cluster is on now in one step, on the strength of a
quorum of the members it knows about having signed it — there is no history to
walk, and none is kept. What matters is that the cluster can move forward, not
that all of it remains provable.

An admission or a revocation is a **proposal**. A member signs one and it
spreads, but it changes nothing until a quorum of the members has attested to
the membership that follows from it. So every node has the same answer to who
belongs, read from one list, and nothing has to weigh one record against
another or ask who admitted whom.

Three properties follow, and they are the reason for the design:

- Records are not secret, so they can travel over gossip and be stored in the
  clear. Publishing them costs nothing.
- Any member can propose a change without asking an authority, because being
  one of the members is what makes its signature worth anything. What it cannot
  do is make the change alone.
- A node reaches the same verdict about the whole cluster offline, from its
  state file, before it contacts anyone.

An operator invites a node with a short-lived token, created by any running
member. The token proves to the admitter that the joiner was invited, and is
discarded by both sides once the joiner has been admitted. It never reaches
disk. It is also what establishes that the member speaks for the cluster, so the
membership it hands over is taken as given: a joiner has no history to check it
against and needs none.

Revocation is a signed record proposing that an identity is no longer a member.
It spreads the same way, and takes effect when the cluster agrees the membership
without it; a node that is out is cut off rather than told, as peers drop its
connections and stop installing it. It removes its subject entirely — identity,
name and overlay slot — and the records go with it, so nothing says it was ever
there. The slot is free for the next joiner, and the identity may be invited
again once the cluster has forgotten it.

Nodes the subject admitted keep their place: the cluster agreed to each of them
in its own right, and removing them automatically would remove nodes the
operator did not ask to remove. Removing them is `revoke --disown`, which names
them in the record.

### Agreeing, and forgetting

Every node works out what the records make the membership and signs it, on its
own, whenever one arrives that would change it. Two nodes that agree produce the
same digest, so their signatures accumulate on one checkpoint; it is taken once
enough of the membership it follows has signed. There is no proposer and no
leader, and nothing to get wrong: no timeout, no retry, no competing proposals.
A node that disagrees simply signs something else, and nothing is settled until
they converge — disagreement costs a delay, never a wrong answer.

"Enough" is the cluster's quorum rule, settled when the cluster is founded and
carried in its checkpoints so no node's configuration can make it disagree with
its peers. It decides what the membership is, not merely when the records may be
discarded, and that is a trade: the cluster gets one answer everywhere, and
gives up the ability to change while too few members are reachable. Two members
is the one size where that would bite hardest — a majority of two is everybody,
so one stopped node would freeze the other for good — and `majority` is relaxed
there so either may agree alone. See [known
limitations](operations.md#known-limitations).

Nothing here reads a clock. No record carries a date, so there is nothing for a
wrong clock to decide.

## From membership to an interface

The agent is a single loop. The cluster package publishes a snapshot of the
members on a channel whenever anything changes, and the loop applies each
snapshot in turn: it configures the WireGuard peers, then writes the hosts
file entries, then reports the peer count to the service manager.

Applying a snapshot is a whole-state operation, not a set of deltas. The peer
set is replaced with the membership as it now stands, rather than being edited.
A missed or failed update cannot accumulate, because the next snapshot
describes the full state again. This is why there is no reconciliation logic
and no repair path.

One goroutine owns the interface and the hosts file. Everything that could
change them arrives on the channel, so there is no lock around the system
state and no ordering question about two updates.

Announcements are checked before they are applied. A node installs a peer only
if the identity is a valid member, the signature over the announcement
verifies, and the address claimed is the one the membership gives the sender. A
member cannot take another member's address, and cannot announce a key on
another member's behalf.

## Portability

Three things differ between operating systems: where the WireGuard interface
comes from, how the network stack is configured, and where files live. Each is
a narrow interface with one implementation per platform, selected at build
time.

- **Device.** On Linux the kernel module is used whenever it is present; the
  probe is the interface creation itself. Otherwise, and on macOS and Windows
  always, WireGuard runs inside the agent and exposes the standard control
  socket, so the configuration code cannot tell the difference.
- **Link.** Addresses, MTU and routes go through netlink on Linux, ioctls and
  the routing socket on macOS, and the IP helper interface on Windows. The
  interface is expressed in address types, not in any one platform's terms.
- **Paths and service manager.** File locations and the readiness protocol are
  one small file per platform. Where a platform has no equivalent, the
  implementation does nothing rather than pretending to succeed at something
  else.

The rule applied throughout is that an implementation refuses at start-up when
nothing real exists on that platform, and does nothing only where the absence
is legitimate. A node never appears to be configured when it is not.

## State and durability

A node persists one file per interface: its identity seed, the cluster's overlay
network, the membership it last satisfied itself of, whatever has been signed
since, and the peers it last saw, each with the address and port it was reached
at. That is everything needed to
rejoin without an operator or a token, whatever port the peers listen on.

The file is written by replacing it, so an interrupted write leaves the
previous version intact. Nothing else is durable. The WireGuard key, the
tokens, the gossip state and the interface itself are all rebuilt on start.
Losing the file loses the node's identity, which is then re-enrolled with a
fresh token and the old identity revoked.

## Operator interface

A running agent is reached over a local socket, one request and one response
per connection. Inviting, revoking and leaving go through it, because they
require the node's identity key, which only the running agent holds. A leave
is answered only once the agent has revoked this node, told the members, torn
the interface down and deleted the state file, so the operator is told what
actually happened rather than what was started. The socket is protected by file
permissions, so the ability to run these commands is the ability to read that
file.

The status command does not use the socket. It reads the interface and the
state file, so it still reports the peers and their names when the agent is not
running.

## Failure behaviour

- **A peer is unreachable.** Gossip suspects it, then declares it failed, and
  it leaves the membership snapshot. The next snapshot replaces the peer set
  without it, and it returns the same way when it comes back. Nothing is
  revoked: failure and removal from the cluster are different events.
- **A node is partitioned.** Each side keeps running with the members it can
  see, and neither changes the membership unless it holds a quorum, so at
  `majority` at most one side can. When the partition heals, the side that
  changed nothing takes the other's membership in one step.
- **A step in applying a snapshot fails.** It is logged and the next snapshot
  retries the whole state. There is no partial state to unwind.
- **The service manager cannot be reached.** It is logged and the agent
  continues. Readiness reporting never blocks the network.

## Testing

The interfaces above exist partly for testing. The agent loop is driven with
fakes for the cluster, the interface and the hosts file, so its behaviour is
tested without a network or a device. The WireGuard code has a recording fake
for its device and link, so the configuration logic is tested on every
platform, while the real implementations are exercised by tests that need
privilege and are skipped without it.

Beyond the unit tests there is a container suite that runs several nodes
against each other, and a live cluster used for tests that no container can
give, such as the kernel module path.

## Known limits

The consequences of the choices above, and what an operator does about them,
are in [known limitations](operations.md#known-limitations). Defects that
should eventually be fixed are in [known issues](known-issues.md). Neither is
repeated here.
