# Identity-based membership

Status: design accepted and implemented 2026-09-08; replaced by agreed
memberships 2026-09-16, which removed the chain of trust, the sequence
numbers, the revocation marks and the clock.

## Goals

- No cluster-wide secret exists, on disk or in memory, after enrolment.
- An operator enrols a node with a short-lived token. After enrolment no
  machine holds the token.
- A stolen node gives the attacker that node's identity and nothing else:
  there is no cluster-wide secret to take with it, and the identity can be
  revoked. Until it is revoked it has everything any member has. See "What a
  stolen member costs".
- Nodes restart unattended, including all of them at once.
- Protocol versions are explicit (enrolment message, TLS ALPN), so nodes
  running different versions refuse to talk instead of partly working.

## Roles of the two key layers

WireGuard gives every node a key pair and protects the data plane with a
Noise handshake. cheesecloth does not change that. cheesecloth is responsible
for choosing which WireGuard public keys a node installs as peers, and for
protecting the gossip that carries them. Both are based on per-node identities
and a signed admission list. There is no shared key.

## Identity

Each node has a 32-byte random seed, generated on first start and persisted
in its state file (mode 0600). One key derives from it: the Ed25519 signing
key, `ed25519.NewKeyFromSeed(seed)`. It signs admission records and node
metadata, and it is the key in the TLS certificate a node presents for gossip
and enrolment.

A node's **identity** is that Ed25519 public key. Nothing else is derived from
the seed: TLS supplies the session keys for every connection, so there is no
long-lived key agreement key of our own.

## Names

A node's **name** is what every other node calls it: it is written to their
hosts files, appears in their logs, and is what `revoke` takes. So it is held
to what a hostname may be, and to one label rather than a dotted name:

    lowercase letters, digits and hyphens, starting and ending with a letter
    or digit, at most 63 characters, and not all digits

A name is checked wherever one arrives, not only where one is made: in the
enrolment exchange, once the joiner has proved its token, in every admission
record, whatever it was carried by, and in the metadata a node gossips. The
names are flat, so no member can hold one that belongs somewhere else in the
DNS, and a member cannot write anything of its own into another node's hosts
file by being named it.

The name a node asks for when it enrols is the first label of its hostname,
lowercased; a host named `web1.example.com` asks for `web1`. A hostname that
cannot be made into a name stops the node with an error rather than being
altered into something that would work.

After that the admission is what says who a node is. A node gossips the name
its admission gives it, and every peer checks that against the record before
it believes anything else in the metadata, exactly as it checks the overlay
address. Renaming the host therefore does not rename the node; enrol it again
to do that.

## The membership

Membership is a **checkpoint**: a signed statement of who the members are, with
the name and overlay slot each holds, carrying the signatures of the members
that agree with it.

```
Checkpoint { Depth, Prev, Quorum,
             Members[{Identity, Name, Host}], Removed[{Identity, Depth}],
             Attestations[{Signer, Signature}] }
Admission  { Identity, Name, Host, Admitter, Signature }
Revocation { Identity, Revoker, Disowned[], Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`cheesecloth/admission/v3`, `cheesecloth/revocation/v3`,
`cheesecloth/checkpoint/v1`, `cheesecloth/attestation/v1`).

A checkpoint is trusted because the membership below it agreed to it, and that
membership was trusted for the same reason. Once a node has seen that happen it
keeps the result and throws the rest away. **There is no chain of trust to
walk.** A node holds one checkpoint — its **anchor** — and that is the whole of
what it knows.

    member(X) = the anchor names X

That is the rule in full, and it is the whole of what a node reads. An admission
or a revocation is a **proposal**: it changes nothing until enough of the
cluster has attested to a membership that accounts for it.

So there is one answer to who belongs, and every node reads it from the same
list. Nothing asks who admitted whom, nothing weighs one record against another,
and no identity is a member on one peer and a stranger on the next. Two nodes
revoking each other cannot chase each other in a circle, because neither
revocation is anything until it is in a membership.

Its cost is a delay, and the delay is the point of the rest of this document. A
node that has been admitted is not a member until the cluster says so, which
takes one round of attestation — well under a second when the members are
reachable, and never at all when too few of them are.

### How a membership is agreed

There is no proposer and no leader. Every node signs what it sees: when a record
arrives that would change the membership, each node independently works out what
the membership would become and signs a digest of it. Two nodes that agree produce
the same digest, so their signatures accumulate on one checkpoint, and the
anchor moves on once `Quorum` of the members it already names have signed.

This fails in the right direction. If two nodes disagree — one has seen a record
the other has not — their digests differ, no digest reaches quorum, and nothing
moves. Disagreement costs a delay, never a wrong answer. When the records
converge, as they do, the digests converge with them.

It also has no protocol to get wrong: no timeout, no retry, no two competing
proposals, no proposer that dies half way.

### Quorum

`Quorum` says **how many members must attest to a membership before it becomes
the membership**. Every change goes through it. An admission, a revocation and a
disown are alike proposals, and none of them takes effect until the cluster has
agreed the membership that follows from it.

An earlier design had quorum ratify rather than authorize: a single member's
signature changed the membership at once, and agreement existed only so the
records could be discarded. That bought availability — enrolment and revocation
went on working however few nodes were reachable — and it cost a single answer.
A record that counted everywhere the moment it was signed also counted before
anyone had agreed it was well formed, so two members could admit two joiners to
one name and each joiner would be a member on a different node.

Making every change go through the membership buys the single answer back, and
pays for it in availability. The bill, plainly:

- **A change needs a reachable quorum.** On `majority`, more than half the
  members must be up and in touch to sign the membership that follows. Below
  that, the cluster keeps running exactly as it is and changes nothing.
- **A cluster of two is a special case**, because a majority of two is
  everybody. Taken literally that would freeze such a cluster the moment one
  node stopped attesting: the other could neither evict it nor enrol a third
  node to break the tie. So `majority` is relaxed at two members and either node
  may agree on its own. What that gives up is the split below.
- **A revocation is not instant.** A compromised node keeps its place until the
  cluster agrees a membership without it. What happens immediately is narrower:
  no admission can put a revoked identity back, so it cannot be re-enrolled
  while the revocation stands.

`majority` (N/2+1) is the default and the only value documented as safe, because
two majorities of one membership always have a member in common — above two
members, where the rule is relaxed as described. `half` and a fixed count are
allowed and are the operator's business: below a majority, a cluster split in
two can agree two different memberships and never merge them.

A cluster of two can do that too, and it is worth knowing exactly when. It takes
both nodes changing the membership while they cannot see each other, which means
an operator at each end: a partition on its own signs no records and so states
no membership, and a change made on one side is one the other accepts as soon as
it hears of it. Two nodes that did fork stay forked — each refuses a membership
that is not further on than its own — and the way out is to rebuild one of them
from the other.

It gives up nothing against a stolen key, because quorum never defended against
one. A node attests to whatever the records propose, its own removal included,
so one compromised node of two would have been handed the other's attestation
even when both were required.

The rule is the cluster's, settled when the cluster is founded and carried in
its checkpoints, so no node's configuration can make it disagree with its peers.
`N` is the membership the checkpoint follows — the subject of a revocation
included, since it is a member until the membership without it is agreed.

### Trimming

Every node discards what its anchor accounts for: the records about every
identity it names, as a member or as one it removed.

Records about anybody the membership does not name go too, once it is clear
nothing can act on them: one asking for a name or an overlay slot a member holds
was settled against, and one nobody who is or is about to be a member vouches
for can never count. Without that they would stay for the life of the cluster,
since no membership would ever name the identity.

A record is accounted for only where the anchor's statement about that identity
is still the node's answer. Records arrive without the lock the anchor was taken
under, so one landing in between leaves the anchor out of date about that
identity; the record that made it so stays, or the change it carries would be
thrown away before anyone agreed to discard it.

Every membership behind the anchor goes too. **Nothing walks from one to the
next**, so there is no chain to keep: a node states its membership, the deeper
ones peers are still signing, and whatever has been signed since. A cluster of
fifty carries about 7 KB of that. Keeping the last sixty-four instead cost it
nearly 400 KB, in every state sync and every enrolment, to serve a walk.

`Removed` is what a node that has been away is told instead. Each entry carries
the depth its identity went at and is dropped 64 agreements later. A returning
node never sees the memberships in between, so the one it lands on naming those
identities is the only thing that tells it they are out — without it, the
admissions it still holds would look unspent and it would offer them back. A
node further behind than that has its records refused for the same reason, and
has to enrol again.

### What a revocation does

Once the cluster has agreed a membership without it, it is gone entirely: the
identity, the name and the overlay slot. The records go with it, and nothing
says it was ever there. Until then the record stands as a proposal, and the
subject is still a member — see [Quorum](#quorum) for what that costs.

Two things follow:

- **Overlay slots are reusable.** Nothing records that a departed member ever
  held one, so the next joiner takes it — once the cluster has agreed the
  membership that gave it up. Until then the slot and the name stay reserved:
  handing either out sooner would make an admission that every node which has
  not yet seen the removal refuses, since its own membership still has somebody
  there.
- **A revoked identity can be invited again**, once the cluster has forgotten
  it — 64 agreements after it went. Until then it is refused at enrolment, so a
  node that was just revoked cannot walk back in. Re-entry has always required
  an admission, which requires a token; an attacker who can obtain a token can
  enrol a fresh key anyway, so refusing the old one was never what kept anyone
  out. To bring a host back sooner, give it a fresh identity.

Nodes the subject admitted keep their place. They proved knowledge of a token at
the time, the cluster agreed to each of them in its own right, and removing them
automatically would remove nodes the operator did not ask to remove. A node the
subject admitted that the cluster has *not* yet agreed on is a different case:
its admission is still only a proposal, and revoking the admitter leaves that
proposal unsigned by any member, so it never becomes a membership at all.

`revoke NAME --disown NAME...` names identities to go with the subject. They are
removed and purged the same way it is, and naming one reaches it whatever else
vouches for it, because the record says who goes rather than describing where to
stop. The identities travel **in the signed record**: a record that said "and
everything this node admitted" would have each node work the list out from its
own records, and nodes that are behind would work out different lists, so no two
of them would agree on a membership and nothing could ever be settled.

The agent will only sign a disown for a node it still holds the record of the
subject admitting, which means since the last agreement. After that the cluster
no longer records who admitted whom, so there is nothing left to disown
by, and that node is revoked in its own right instead. This is the case
`--disown` exists for anyway: a member that has just minted identities has just
admitted them.

### What decides between two records

Almost nothing has to. An identity has one admitter in practice, and a
membership the cluster agreed on settles every contest it covers — a checkpoint
may not even state two members sharing a name or a slot.

What is left is two joiners admitted since the last agreement that contest one
name or one overlay slot, which happens when two members enrol joiners at the
same moment. Neither is a member yet, and a membership holding both could never
be agreed, so the contest is settled before either becomes anything: a joiner
that wants a name or a slot a member already holds does not get it, and between
two joiners it goes by identity order. **The loser is left out of the proposed
membership altogether** rather than admitted and then found to be unusable.

Identity order is arbitrary and has to be no more than that, since both were
admitted moments ago and there is no established node to prefer. Every node
reads it the same way, so all of them leave out the same one, and its enrolment
fails saying so — an operator runs it again and it takes the next free slot.

**Nothing reads a clock.** No record carries a date. There is nothing for a
wrong clock to decide, and nothing to keep in bounds.

### What a stolen member costs

Every member is a peer, and there is no lesser kind of membership: any member
the cluster has agreed on may admit, and admitting is signing a record, which
needs the key and nothing else. An attacker holding a node's seed therefore
never has to enrol anybody. It signs admissions for identities of its own making
and hands them over at the next state sync, as fast as it can generate keys.

Quorum does not help here, and it is worth being clear about why. It decides
that every node reaches the same membership, not that the change was one anybody
wanted: an admission from a member is well formed, so the honest members attest
to the membership that follows from it exactly as they would to any other.

An ordinary revocation does not remove them: they were admitted before it, so
they keep their place, deliberately, the same way the members a departing node
admitted do. What answers it is `cheesecloth revoke NAME --disown FIRST...`,
which names them and takes them out with their admitter. The operator names the
nodes they do not recognise — which is what a cluster's own logs and
`cheesecloth status` show — and the agent says which members the record takes
out before it is signed.

This is the price of the simplicity. Every member is the same as every other, so
there is no admitting authority to compromise separately and no node has to ask
another before it admits, which is what lets a cluster run unattended with no
cluster-wide secret anywhere in it. Buying the other property back means either
an authority, which is the thing this design does not have, or requiring more
than one signer, which is TODO Phase M. A cluster that cares more about the
exposure than the convenience should keep the number of members small and revoke
promptly.

A hostile member can also rename or renumber another member, by signing an
admission for it: the name and slot a newcomer holds come from the record that
admitted it. That costs the victim its peers, since they check what a node
gossips against the membership. Revoking the offender puts it back.

Refusing enrolment does not help here and is not meant to: it closes the token
exchange, which is the door this attacker walks past.

One thing is worth stating exactly, because it is what taking a membership in
one step gives up. A node takes any membership a quorum of the members **it
knows about** has signed. For a node that is up to date those are the current
members, so this is the ordinary case. For a node that has been away they are
the members as of whenever it last looked — so an attacker who has collected
enough of *those* keys, including ones revoked since, can hand it any membership
it likes. Walking one membership at a time would have shown the revocations on
the way past and stopped those keys counting. It also cost every node the last
sixty-four memberships in every state sync, to defend against an attacker
holding a quorum of a stale node's keys. Small clusters revoke promptly and
their nodes are not away for long; a node that is away long enough has to enrol
again in any case.

### When a node has been away too long

A node that returns holds an anchor the cluster may have moved past. It takes
the checkpoints between and steps forward to the present.

It says so rather than guessing, and rather than removing itself: "I cannot
verify this" and "I am too stale" are different statements, and it is the second
one. It goes on running with the membership it has, which is the honest thing to
do with it — the operator is told, at `error` and in the service manager's
status, that the node is configuring peers from a membership the cluster has
left behind and has to be enrolled again.

### Forks

Below a majority, two disjoint quorums can agree two different memberships. A
node commits to the first one it takes and refuses anything that is not further
on, so it never gives up ground it has covered; two nodes that went different
ways stay that way. At `majority` this cannot happen, which is why it is the
default and the only value documented as safe.

### Overlay addresses

`Host` is the member's slot in the overlay network: its address is
`--overlay-net` with the host part set to `Host`. The founding node takes slot
1; an admitter gives a joiner the lowest slot no member holds. Every node
derives every member's address from the same membership, so addresses are
stable across restarts, allocated from the start of the overlay net, and
independent of hostnames. The network itself is part of the welcome, so a joiner
is told which one the cluster uses rather than being configured with it.
Changing `--overlay-net` on every node changes every address without
re-enrolling, because each node keeps its slot number.

## Enrolment

The join token is an invitation created by a running member. It is not a
long-lived cluster secret.

```
member$  cheesecloth invite [--ttl 10m] [--uses 1]     -> prints TOKEN
newnode$ cheesecloth --join member --join-key TOKEN
```

The member keeps the 32-byte token only in memory, with its expiry and
remaining uses. The joiner holds it only for the exchange. Nothing writes it
to disk. Enrolment runs as a QUIC stream on the cluster port under ALPN
`cheesecloth-enrol/1`, so no new port is opened. The joiner is not a member
yet, so on that ALPN both sides only parse the other's identity certificate.
The exchange below then requires the identities named in the messages to match
the certificates on the connection, and the token decides whether the joiner
is admitted.

Exchange, with `J`/`M` the joiner's and member's identities and `K` the token:

1. Joiner -> Member: `Hello{Version, TokenID, J, nJ, Name}` where
   `TokenID = SHA-256(K)[:8]` lets the member pick the pending token without
   revealing it.
2. Both derive
   `kMac = HKDF-SHA256(K, salt = nJ || nM, info="cheesecloth/enrol/v1")`.
   Member -> Joiner: `M, nM, HMAC(kMac, "member" || transcript)`.
3. Joiner verifies; it now knows the member holds `K`. Joiner -> Member:
   `HMAC(kMac, "joiner" || transcript)`.
4. Member verifies, consumes one token use, signs an admission for `J` and
   broadcasts it. It then **waits for the cluster to agree a membership holding
   `J`**, because until one does, `J` is not a member and every peer would
   refuse it. Once one is agreed the member sends the joiner that membership,
   whatever has been signed since, its own gossip address and the cluster's
   overlay network. Both sides discard `K`. A joiner that has got this far but
   cannot be admitted — its identity has been revoked, its name is one no node
   may hold or is taken, the overlay is full, the records no longer fit in a
   message, the cluster could not reach a quorum, or another joiner took the
   name or slot at the same moment — is told why instead of having the
   connection closed on it, and the use it proved is given back to the token.
   The name is checked here rather than at the hello for that reason: a peer
   that has proved nothing is told nothing, so checking it earlier only turned a
   bad name into a closed connection the joiner reads as a bad token. Before
   this point a refusal is silent, so the member is not an oracle for token
   guessing, and the failures are counted rather than logged one line each, so
   that a peer cannot set the rate of a member's log.
5. Joiner -> Member: an acknowledgement once it has checked the welcome, so
   the member knows it arrived and closes the connection.

`transcript = "cheesecloth/enrol/transcript/v1" || 0 || J || M || nJ || nM || Name`,
each field length-prefixed: the canonical encoding the signed records use,
under its own domain string. Because both identities are included in the MACs,
the token can be discarded after step 4; from then on the identities are the
trust anchors. The two different labels prevent a MAC from being reflected back
to its sender. The nonces prevent replay.

The token exchange is also what establishes that this member speaks for the
cluster, so the membership in the welcome is taken as given. A joiner has no
history to check it against and needs none: it is being told who the members
are by somebody that proved it holds an invitation. From there it moves forward
like any other node.

Confidentiality and the binding of each identity to its side of the exchange
come from the QUIC stream, whose TLS peers are the same `J` and `M`: the
identities in the messages must match the certificates on the connection, so
an intermediary cannot pass the MAC check under its own identity, and without
`K` it cannot compute a MAC at all. A member that finds no pending token for
`TokenID` closes the stream without a reply, so an attacker cannot use the
server to test guesses. Tokens are 256-bit random values, so a PAKE is
unnecessary.

## Gossip transport

memberlist's own encryption is disabled; cheesecloth supplies a `Transport`
that runs memberlist over QUIC (quic-go) on the cluster port, one UDP socket
for both listening and dialling so that peers see a node's gossip address as
the source of everything it sends.

Each pair of nodes shares one QUIC connection, authenticated on both sides by
TLS 1.3 with self-signed certificates for the nodes' Ed25519 identity keys:
there is no CA. Certificate verification ignores chains and instead checks
the membership for the peer's key. ALPN `cheesecloth-gossip/1` is required.
memberlist packets travel as QUIC datagrams (RFC 9221), so its packet budget is
set to 1100 bytes; push/pull exchanges travel as streams.

A packet to a node with no connection yet is dropped while a connection is
dialled in the background, in the same way that UDP would drop it, and
memberlist's next round gets through. Failure detection depends on this:
memberlist treats a lost probe as a sign that the peer may be down, but treats
a send error as a local problem and does not suspect the peer. When a member
is revoked while connected, its connection is closed on the next packet or
stream it sends.

## Node metadata

Gossiped per node (memberlist limit 512 bytes):
`{ OverlayAddr, WGPubKey, AllowedIPs, Identity, Signature }` with
`Signature = Ed25519(identity, "cheesecloth/meta/v1" || Name || OverlayAddr || WGPubKey || AllowedIPs...)`.
`AllowedIPs` are the extra networks the node routes (`--allowed-ips`), each
encoded as address bytes plus prefix length.
A node installs a peer's WireGuard key only if the identity is a valid member,
the signature verifies, and `OverlayAddr` is the address the peer's admission
assigns. This binds each node's ephemeral WireGuard key to its persisted
identity without persisting the WireGuard key, and prevents a member from
claiming another member's address.

## Restart and recovery

A restarting node has its seed, the membership it last satisfied itself of,
whatever has been signed since, and its last known peers on disk, each with the
port it was last reached at. It starts from that membership rather than working
one out again, reconnects over QUIC to any of the peers and rejoins; no token
and no operator are involved. If every node restarts at once, each still has
everything it needs and nothing has to be fetched. A node that loses its disk
loses its identity. It is enrolled again with a fresh token, and the old
identity can be revoked.

## Operations

- `cheesecloth` with an overlay network configured and no state: create the
  identity and a first membership holding this node alone; start the cluster.
- `cheesecloth --join HOST --join-key TOKEN`: first start of a new node. The
  overlay network comes with the welcome; the node needs no setting of its own.
- `cheesecloth --join HOST` or bare `cheesecloth`: restart of an admitted node.
- bare `cheesecloth` on a node that is neither a member nor configured with an
  overlay network: create the identity and wait, configuring nothing.
- `cheesecloth invite [--ttl] [--uses]`: mint a token on a member (via the control
  socket `/run/cheesecloth/<interface>.sock`).
- `cheesecloth revoke NAME|IDENTITY [--disown NAME|IDENTITY ...] [--disown-all]`:
  sign and broadcast a revocation. An identity that is already out is refused.
  `--disown` names nodes the subject admitted that are to go with it;
  `--disown-all` names every one the agent still holds a record of it admitting.
  The agent says which members the record takes out before it signs, refuses one
  that would take this node out with its subject, and refuses to disown a node
  it holds no record of the subject admitting.
- `cheesecloth leave`: revoke this node itself, hand the revocation to the
  members, and delete the state file. Any node may leave this way, the founding
  node included. `--force` skips the revocation for a node whose agent is no longer
  running to sign it, and tells the cluster nothing.
- `cheesecloth status`: shows peers with their identity fingerprints.

## Out of scope for now

Cascading revocation; a PAKE for short human codes; requiring more than one
signer before the membership changes, which is the answer to what one stolen key
can do and is noted in TODO Phase M.
