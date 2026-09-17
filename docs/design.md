# Design

Why cheesecloth is put together the way it is. This document covers the choices
that would be expensive to change: the trust model, the threat model, the two
planes, how membership becomes an interface configuration, and the seams that
keep the code portable. It does not describe individual functions.

[Membership](membership.md) has the specification — the records, the agreement
rule, the enrolment exchange and the transport — and this document refers to it
rather than repeating it.

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
  Compromising a node gives an attacker that node, not a key to the cluster.
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

The control plane decides which WireGuard public keys a node installs as peers.
WireGuard itself is used as it comes, neither modified nor wrapped.

The split matters because the two keys have different lifetimes. The identity is
persistent and is what membership is expressed in. The WireGuard key is
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
quorum of the members it knows about having signed it. What matters is that the
cluster can move forward, not that all of it remains provable.

An admission or a revocation is a **proposal**. A member signs one and it
spreads, but it changes nothing until a quorum of the members has attested to
the membership that follows from it. So every node has the same answer to who
belongs, read from one list, and nothing has to weigh one record against another
or ask who admitted whom.

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

### Quorum authorizes rather than ratifies

Every change goes through the membership. The alternative — a member's signature
counting at once, with agreement existing only so the records can be discarded —
is the more available arrangement, since enrolment and revocation would go on
working however few nodes were reachable. What it costs is the single answer: a
record that counts the moment it is signed also counts before anyone has agreed
it is well formed, so two members could admit two joiners to one name and each
joiner would be a member on a different node.

cheesecloth buys the single answer and pays in availability. A cluster with too
few members reachable keeps running exactly as it is and changes nothing. The
rule is the cluster's, settled when the cluster is founded and carried in its
checkpoints so that no node's configuration can make it disagree with its peers,
and it is relaxed at exactly two members so that one stopped node cannot freeze
the other for good. [Quorum](membership.md#quorum) has the mechanism and the
exact bill.

### Agreeing, and forgetting

Every node works out what the records make the membership and signs it, on its
own, whenever one arrives that would change it. Two nodes that agree produce the
same digest, so their signatures accumulate on one checkpoint; it is taken once
enough of the membership it follows has signed. There is no proposer and no
leader, and nothing to get wrong: no timeout, no retry, no competing proposals.
A node that disagrees simply signs something else, and nothing is settled until
they converge — disagreement costs a delay, never a wrong answer.

What a node keeps is the result. The records that led to a membership are
discarded once it is agreed, and the memberships behind it go with them, so a
node holds who the members are now rather than everything that ever happened.

Nothing here reads a clock. No record carries a date, so there is nothing for a
wrong clock to decide.

## The threat model: a member is trusted

**cheesecloth is simple and secure for as long as its nodes are not compromised.
A compromised node is a member, and a member can disrupt the network.** That is
the trade this design makes deliberately. What follows from it is a consequence
of the design, not a defect in it.

Every member is a peer, and there is no lesser kind of membership: any member
may admit, and admitting is signing a record, which needs the key and nothing
else. An attacker holding a node's seed never has to enrol anybody. It signs
admissions for identities of its own making and hands them over at the next
state sync, as fast as it can generate keys. It can equally sign revocations,
rename or renumber a joiner the cluster has not yet agreed on, or advertise
routes to attract traffic. Concretely, an attacker who holds a member's key can:

- reach services exposed on the overlay network
- impersonate that node and disrupt traffic to and from it
- attract traffic for any network outside the overlay by advertising it with
  `--allowed-ips`, since every member trusts every other member's advertisements
- admit nodes of its own, since a member mints its invitation tokens itself and
  signs the admission with its own identity

It cannot decrypt traffic between other nodes.

What the trade buys is the shape of the whole system: no cluster-wide secret on
any disk, no admitting authority to compromise separately, no node having to ask
another before it acts, and a cluster that runs unattended and goes on working
while most of it is unreachable. A design that resisted a compromised member
would give up at least one of those.

**Quorum is not a defence here**, and it is worth being exact about why. It
decides that every node reaches the *same* membership, not that the change was
one anybody wanted: an admission from a member is well formed, so the honest
members attest to the membership that follows from it exactly as they would to
any other. And because quorum is counted over the membership, minting identities
and acquiring quorum are the same act — a member that admits twenty identities
of its own holds a majority of the result, and from then on the honest nodes can
agree nothing at all.

**Refusing enrolment is not a defence either**, and is not meant to be: it
closes the token exchange, which is the door this attacker walks past.

**`cheesecloth revoke` is maintenance, not a remedy.** It is how an operator
takes out a node that has gone, or one that should no longer be in the cluster.
It is not a way to recover from a compromise: a member signing records faster
than an operator can read them has already won, and a revocation of it needs the
agreement of a membership it may already dominate. **Treat a compromised node as
a lost cluster and rebuild** — found a new cluster on a node you trust and enrol
the others into it with fresh identities. Anything short of that leaves an
attacker who may still hold a key the surviving membership counts.

### What can be raised against it

Two things, and neither pretends to make a compromised member safe.

**Confirmations** raise the number of keys an attacker needs to start. With
`--confirmations 1`, an admission or a revocation does nothing until a second
member agrees with `cheesecloth confirm`, so one compromised key cannot add or
remove members by itself. It does not bound what an attacker can do once it has
two, and it is worth nothing if the person confirming does not read what they
are confirming. See [Confirmations](membership.md#confirmations) for the
settings and when each is right.

**Noticing early** is what actually helps. A node reports `node admitted` for
every member that joins, naming who admitted it, and a line naming a node nobody
invited is the first sign of a stolen key. It is logged at `info`, below the
default `warn`, so a cluster that wants to alert on it has to run with
`--log-level info`. Keeping the cluster small and its membership familiar is
what makes that line readable. [Operations](operations.md#what-to-watch) lists
what else is worth an alert.

### One thing taking a membership in one step gives up

A node takes any membership a quorum of the members **it knows about** has
signed. For a node that is up to date those are the current members, so this is
the ordinary case. For a node that has been away they are the members as of
whenever it last looked — so an attacker who has collected enough of *those*
keys, including ones revoked since, can hand it any membership it likes.

Walking one membership at a time would show the revocations on the way past and
stop those keys counting, at the price of every node carrying the last
sixty-four memberships in every state sync — over half a megabyte for a cluster
of fifty, against the 9 KB or so it carries now. Small clusters revoke promptly
and their nodes are not away for long; a node that is away long enough has to
enrol again in any case.

## From membership to an interface

The agent is a single loop. The cluster package publishes a snapshot of the
members on a channel whenever anything changes, and the loop applies each
snapshot in turn: it configures the WireGuard peers, then writes the hosts file
entries, then reports the peer count to the service manager.

Applying a snapshot is a whole-state operation, not a set of deltas. The peer
set is replaced with the membership as it now stands, rather than being edited.
A missed or failed update cannot accumulate, because the next snapshot describes
the full state again. This is why there is no reconciliation logic and no repair
path.

One goroutine owns the interface and the hosts file. Everything that could
change them arrives on the channel, so there is no lock around the system state
and no ordering question about two updates.

Announcements are checked before they are applied. A node installs a peer only
if the identity is a valid member, the signature over the announcement verifies,
and the address claimed is the one the membership gives the sender. A member
cannot take another member's address, and cannot announce a key on another
member's behalf.

## Portability

Three things differ between operating systems: where the WireGuard interface
comes from, how the network stack is configured, and where files live. Each is a
narrow interface with one implementation per platform, selected at build time.

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
nothing real exists on that platform, and does nothing only where the absence is
legitimate. A node never appears to be configured when it is not.

## State and durability

A node persists one file per interface: its identity seed, the cluster's overlay
network, the membership it last satisfied itself of, whatever has been signed
since, and the peers it last saw, each with the address and port it was reached
at. That is everything needed to rejoin without an operator or a token, whatever
port the peers listen on.

The file is written by replacing it, so an interrupted write leaves the previous
version intact. Nothing else is durable. The WireGuard key, the tokens, the
gossip state and the interface itself are all rebuilt on start. Losing the file
loses the node's identity, which is then re-enrolled with a fresh token and the
old identity revoked.

## Operator interface

A running agent is reached over a local socket, one request and one response per
connection. Inviting, revoking, confirming and leaving go through it, because
they require the node's identity key, which only the running agent holds. A
leave is answered only once the agent has revoked this node, told the members,
torn the interface down and deleted the state file, so the operator is told what
actually happened rather than what was started. The socket is protected by file
permissions, so the ability to run these commands is the ability to read that
file.

The status command does not use the socket. It reads the interface and the state
file, so it still reports the peers and their names when the agent is not
running.

## Failure behaviour

- **A peer is unreachable.** Gossip suspects it, then declares it failed, and it
  leaves the membership snapshot. The next snapshot replaces the peer set
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
for its device and link, so the configuration logic is tested on every platform,
while the real implementations are exercised by tests that need privilege and
are skipped without it.

Beyond the unit tests there is a container suite that runs several nodes against
each other, and a live cluster used for tests that no container can give, such
as the kernel module path.

## What follows from all this

The consequences an operator meets — what needs a quorum, what a node can
advertise, what two joiners contest — are collected in
[limitations](limitations.md). They are not repeated here.
