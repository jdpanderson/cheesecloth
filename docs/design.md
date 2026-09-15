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
operator starts one node, which becomes the root of a new cluster, then invites
the others one at a time. Each node ends up with a WireGuard interface holding
every other member as a peer, an address on a private overlay network, and a
name that resolves to that address.

Every node runs the same binary and the same code. There is no server, no
controller and no coordinator. The root node is only the first signature in a
chain; once a cluster is running, it has no further role and may be offline.

## Design goals

- **No shared secret.** Nothing that grants cluster access exists on disk.
  Compromising a node gives an attacker that node, not the cluster.
- **Unattended restart.** A node that reboots rejoins with what it has on
  disk. All nodes may restart at once, and no operator is needed.
- **Converge, do not sequence.** A node acts on the membership it can see now.
  There is no ordered rollout and no agreement protocol to stall.
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

Membership is a set of signed records, held by every node. There are two kinds
— an admission and a revocation — each signed with its signer's identity key.
They only accumulate.

The founding node signs its own admission, and that record is the root. Every
other node pins the root's identity when it enrols. The root is a key, not a
machine, and the node holding it has no standing the others lack. A record is
valid if its signature verifies and its admitter is the root or itself holds a
valid admission. The result is a chain back to the root, evaluated locally by
every node from data it already has.

Three properties follow, and they are the reason for the design:

- Records are not secret, so they can travel over gossip and be stored in the
  clear. Publishing them costs nothing.
- Any member can admit a new node without asking anyone, because its own
  admission is the authority for the signature it makes.
- A node reaches the same verdict about the whole cluster offline, from its
  state file, before it contacts anyone.

An operator invites a node with a short-lived token, created by any running
member. The token proves to the admitter that the joiner was invited, and is
discarded by both sides once the joiner has an admission record. It never
reaches disk. After that the identities are the trust anchors and the token is
worthless.

Revocation is a signed record saying an identity is no longer a member. It
spreads the same way. A revoked node is cut off rather than told: peers drop
its connections and stop installing it.

A revocation marks where its subject's records stop: the mark goes where the
revoker had seen them reach, and everything above it is withdrawn. That is what
keeps the nodes the subject admitted in the cluster — they were legitimately
invited at the time, and removing them is the operator's decision rather than an
automatic consequence — and it is also what makes the revocation final, since
nothing the subject signs afterwards is below a mark fixed before it signed.
A mark works because a signer's records are taken in the order it signed them,
so there is no unused number left below it to sign into and no way to backdate
into the window before the revocation. A lower mark withdraws more, which is how
a member that went wrong is undone; an operator asks for one by naming the nodes
to disown along with it, and the agent works out where to put the mark from its
own records rather than being handed a number. The cost is that a revoker's view
can lag; see [known limitations](operations.md#known-limitations).

A mark can rise — a revocation signed by a node that was already out never
counted, so what it withdrew stands again — which is why no node drops a record
a mark has withdrawn: what stands for nobody today may stand tomorrow, and the
set only grows.

Every member is revoked by that one rule, by itself or by another member, and
the root is no exception. It differs from the rest only in needing no admitter.
Revoking it removes it from the mesh without disturbing anything it admitted,
so the node that founded a cluster can hand in its membership and leave, and
the cluster carries on with that key still pinned as the anchor its chains end
at. This is what makes the mesh a set of peers rather than a tree with an
indispensable machine at its root.

## Addressing

Each member holds a slot number, recorded in its admission. Its overlay address
is the configured network with the host part set to that slot. The root takes
the first slot, and an admitter gives a joiner the lowest slot its record set
does not use.

Addresses are therefore derived, not assigned. Every node computes every
member's address from records it already holds, so the answer is the same
everywhere without anyone distributing an address table. Addresses survive
restarts, and changing the overlay network on every node renumbers the cluster
without re-enrolling anything, because the slots are unchanged.

Two admitters enrolling at the same moment can hand out the same slot. The
records settle it: the earlier admission wins, which is the node that has been
running rather than the one starting now, and every node excludes the other and
logs the collision. The excluded node keeps running with no peers until it is
enrolled again. This is rare and visible, which is preferred to silently giving
two members one address.

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
verifies, and the address claimed is the one the sender's admission assigns. A
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

A node persists one file per interface: its identity seed, the pinned root,
the cluster's overlay network, the record set and the peers it last saw, each
with the address and port it was reached at. That is everything needed to
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
  see. Records only grow, so the sets merge when the partition heals, without
  a winner having to be chosen.
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
