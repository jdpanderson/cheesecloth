# Identity-based membership

Status: design accepted and implemented 2026-09-08.

## Goals

- No cluster-wide secret exists, on disk or in memory, after enrolment.
- An operator enrols a node with a short-lived token. After enrolment no
  machine holds the token.
- A stolen node gives the attacker that node's identity and nothing else:
  there is no cluster-wide secret to take with it, and the identity can be
  revoked. Until it is revoked it has everything any member has, and what it
  signs meanwhile outlives the revocation. See "What a stolen member costs".
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

## Admission records

Membership is a set of signed records that only grows. The records are not
secret.

```
Admission  { Identity, Name, Host, Admitter, Seq, IssuedAt, Signature }
Revocation { Identity, Revoker, Seq, Keeps, IssuedAt, Signature }
Prune      { Identities, Pruner, Seq, IssuedAt, Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`cheesecloth/admission/v1`, `cheesecloth/revocation/v1`,
`cheesecloth/prune/v1`).

`Seq` is the signer's own counter, which every record it signs advances,
starting at 1. A node keeps its own counter in its state file, so it continues
its sequence across a restart even where a prune has since removed the record
that last advanced it (see [below](#pruning)), and a record is persisted before
it is gossiped so that a number handed to a peer is never reused. One
signer's records are ordered by it, which needs no clock: a signer whose clock
jumps cannot reorder what it said, and which of one admitter's records states a
member's current name and slot is its counter's answer rather than its clock's.

The counter orders a signer's records and decides nothing else about them. Two
records at one number are simply two records, and each stands or falls on
whether its signer was a member when it signed, which a revocation settles by
naming records rather than numbers. Nothing therefore rests on a signer using
its numbers honestly, which is just as well: the numbers it has used are its
own to choose, and a rule that trusted them would let a signer that left gaps
sign into them after it was revoked.

- The founding node signs its own admission (`Admitter == Identity`). That
  record is the **root**. Every other node pins the root's identity in its
  state file; a self-signed record is accepted only for the pinned root.
- An admission is valid if its signature verifies and its admitter is the
  root or itself holds a valid admission. Validity is evaluated recursively
  with a cycle guard, which tracks the record each question is asked about as
  well as the identity: asking whether a revoker was a member reaches the
  identity it revokes again, at the earlier record that admitted it.
- Records are held per signer: an identity's admissions are kept by admitter
  and its revocations by revoker, and a signer only ever changes what it said
  itself. Several admitters may therefore have a record for one identity, and
  the identity is a member if any one of them holds. Nothing a signer emits
  can displace what another signed, so a key that is no longer a member cannot
  take out one that is by signing a later record for it, and two nodes with
  the same records reach the same answers whatever order they arrived in.
- Of one admitter's records two are kept: the earliest, which is what vouched
  for the identity in the first place, and the latest, which is that
  admitter's current statement of the identity's name and slot. An admitter
  can therefore rename a member that enrols again, and cannot retract the
  membership it vouched for by signing a further record once it has itself
  been revoked, whatever number that record takes: the revocation names the
  earlier one, and not the later. Where several admitters have a valid record,
  the latest of them decides the name and slot.
- **A revoked identity cannot rejoin under a later admission**, at any sequence
  number; the node needs a fresh identity. What a revocation cannot promise is
  that it lasts for ever: it counts only while its own signer is judged to have
  been a member when it signed, so revoking the revoker can withdraw it. See
  "What a revocation withdraws".
- A revocation is valid if signed by a valid identity, or by the identity it
  revokes: a member may always revoke itself, which is how a node leaves the
  cluster for good. A revoked identity is no longer a member.
- A revocation withdraws **everything the identity ever signed**, except the
  records `Keeps` names: the ones the revoker had already seen, which the
  cluster may be relying on. Those still stand, because the nodes they admitted
  proved knowledge of a token at the time; revoking them automatically would
  remove nodes the operator did not ask to remove, so revoke them explicitly if
  that is wanted. Revoking a node that has signed nothing keeps nothing, which
  is the ordinary case and the smallest record.
- Naming the records is what a revocation is worth against a node that keeps
  its key and goes on signing. Nothing it signs afterwards is on the list,
  however the record is dated and whatever number it takes, so it can neither
  backdate an admission into the window before its revocation nor sign into a
  sequence number it had left unused. A revoker's view can lag: a node its
  admitter enrolled moments before the revocation, whose record had not reached
  the revoker, is not on the list and has to enrol again.
- The root is a peer, not an authority over the others. It is revoked by the
  same rule: by itself, which is how the founding node leaves, or by any
  member. Revoking it removes it from the mesh and nothing else, because the
  records the revoker kept for it still stand. The cluster carries on
  admitting new nodes with the departed root still pinned as the anchor its
  chains end at. A revoked root admits nobody: what it signs afterwards is not
  on the list.
- Records are distributed by memberlist's push/pull state sync (whole set,
  union merge) and by broadcast when a record is created. A record too large
  for a gossip datagram cannot be broadcast, so the node that signed it hands
  it to each member over a stream instead; a revocation of a node that admitted
  many members is the case that reaches that size. The hand-out runs on its
  own and is best-effort: the record is saved before it goes out and travels in
  the state sync, so a member that was unreachable takes it at the next one.
  The members that missed it are named in a warning. The set only grows,
  so it has a ceiling: a welcome carries the whole set in one 1 MiB message,
  which is about 3,500 records at roughly 300 bytes each. A cluster that
  reaches it can still run, but admits nobody until the records are pruned.
  Nodes persist the set, so a restarted node has it before contacting anyone.

### What a stolen member costs

Every member is a peer, and there is no lesser kind of membership: any member
may admit, and admitting is signing a record, which needs the key and nothing
else. An attacker holding a node's seed therefore never has to enrol anybody.
It signs admissions for identities of its own making and hands them over with
the rest of the records at the next push/pull, as fast as it can generate keys,
which is faster than an operator can read a log.

Revoking the stolen identity does not withdraw them. The revocation keeps the
records the revoker had already seen, deliberately, so that the members a
departing node admitted keep their place; the minted identities are members in
their own right and stay. Pruning does not reach them either: it only ever
acts on identities that have themselves been revoked. Recovery is to revoke
each of them, and nothing today lists which identities an admitter vouched
for, so an operator cannot see the set they have to work through.

This is the price of the simplicity. Every member is the same as every other,
so there is no admitting authority to compromise separately and no node has to
ask another before it admits, which is what lets a cluster run unattended with
no cluster-wide secret anywhere in it. Buying the other property back means
either an authority, which is the thing this design does not have, or
cascading revocation, which is out of scope for now. A cluster that cares more
about the exposure than the convenience should keep the number of members that
can admit small, and revoke promptly.

Refusing enrolment does not help here and is not meant to: it closes the token
exchange, which is the door this attacker walks past. A rule that refused
unfamiliar admissions on receipt would help, but it cannot be per node —
two nodes running different rules would disagree about who is a member, and
the union merge only converges because they cannot.

### What a revocation withdraws

A revocation names the records of its subject that still stand. Everything else
the subject ever signed is withdrawn. That list is what the revoker had seen, so
the rule has edges worth knowing before a cluster is changed.

**Keep lists intersect; they do not union.** Any revocation of one identity that
omits a record withdraws it, whatever other revocations keep. A record stands
only if every revocation of its signer names it. That is the safe direction —
what one node has not seen stays out rather than in — but it means a second
revocation of an identity can take out members the first one kept. `cheesecloth
revoke` refuses an identity that is already out for that reason.

**A revocation lasts only while its signer is judged a member.** Revoking a
revoker, with a list that does not name the revocation, withdraws it, and
whoever it had put out is a member again.

This cannot be fixed by making revocations permanent. A record missing from a
keep list was either signed after the revocation, which must not count, or
signed before and never seen by the revoker, which should; the records cannot
tell those apart. Honouring the second would honour the first, and a revoked
node could then go on revoking whoever it liked. Intersecting keep lists buys
the safe half of that; nothing buys both.

**So it is reported as a compromise.** Revoking a node that had itself revoked
somebody, in a way that takes its revocations with it, is not the ordinary
business of running a cluster — leaving keeps everything the node signed. It
means either somebody is restoring a node that was put out, or two revocations
crossed on a cluster that was not in step. The result is the same either way and
an operator cannot tell them apart, so the set logs an error saying the
membership can no longer be relied on and the cluster should be rebuilt. Nothing
is refused: a node cannot mend this on its own, and the records still have to
reach every peer so that they all reach the same answer and see the same alarm.

**Nothing depends on the clock.** No part of this reads `IssuedAt`. A forged
date changes nothing.

**A node can destroy what it granted.** A self-revocation counts unconditionally,
so a node that signs one naming none of its records puts out every node it
admitted, and nothing undoes that. `cheesecloth leave` keeps everything the node
signed; only a hand-made record does otherwise.

**The root is not special.** Every node's admission is signed by the root in the
ordinary cluster, so a revocation of the root that does not keep them withdraws
the whole cluster. This is not worked around: revoking from a node that is out
of touch is the operator's to avoid, not the code's to second-guess.

**Being admitted twice is the real protection.** A node is a member if any one of
its admissions stands, so one admitted by two members survives either one's
revocation.

**A node whose admission is withdrawn does not know.** It still holds the welcome
it enrolled with, believes itself a member, and retries the handshake for ever
while every peer refuses it. Nothing tells it otherwise; watch for that shape.

### Pruning

A `Prune` names identities whose **admissions** may be dropped: ones a
revocation has put out for good, and that nothing still standing runs through,
so that dropping their admissions changes no answer about any member.

The revocation itself stays. It is what says the identity is out once its
admission is gone, and without it a node given the smaller set would have
nothing to weigh a stale admission against. So a pruned identity costs the
revocation rather than nothing, and the admissions are the bulk of what goes.

That cost is not fixed. A revocation's `Keeps` holds one signature per record
its subject had signed, so the revocation of a node that admitted many members
is that much larger, and it is what survives when their admissions go. Once
those admissions are pruned the entries naming them can never match again —
`keeps` is only ever asked about a record the set still holds — but the
revocation is signed, so they cannot be dropped without signing a new one, and
a later revocation by the same revoker is not the one kept.

The prune record is itself a record, and one covers every identity that goes
with it. So pruning a single node leaves the count where it was — one admission
out, one prune in — and the saving starts from the second identity. Pruning is
worth doing in batches, which is what `cheesecloth prune` does: it names
everything prunable at once.

Any identity that is no longer a member may be pruned: revoked, or no longer
reaching the root because the admissions that vouched for it have been
withdrawn. Acting on the second is what makes a compromised member recoverable.
Revoke it keeping only the records that admitted nodes the operator recognises,
prune, and the rest of what it signed is gone rather than sitting in the records
for good — a cluster carrying five thousand identities minted by one bad member
comes back under the enrolment ceiling in two commands.

It rests on the node being in touch with the cluster. A record that has not
arrived yet could put an identity back in reach, and a node that pruned
meanwhile cannot take it back, so it disagrees with one that did not. The same
goes for a revocation that is later withdrawn: a node that pruned while the
subject was out keeps its answer while others change theirs. **Prune from a node
that can see the cluster.** `cheesecloth prune` says how many members it could
reach against how many its records hold, and warns when those differ.

An identity qualifies only if every identity it admitted qualifies too, since
an admission it signed may be what makes a member a member; and only if it
revoked nobody but itself, since a revocation of somebody else counts only
while its signer can still be judged a member. A revocation of one's own needs
nothing of its signer, which is why a node that left by revoking itself — the
usual case — can go. The set is the largest one closed under both, and the root
is never in it.

A prune is a request, not an instruction. Every node derives the same set from
its own records and removes only what it can confirm, so a node holding a
record that makes one of the named identities a member simply keeps it, and a
prune that arrives before the records it covers takes effect when they do. A
node also remembers what it removed and refuses those records afterwards, which
saves handling them again when a peer that has not pruned offers them back; the
answer would be the same either way, because the revocation is still there.

A node's own counter survives the removal of its records, so a number it spent
is never handed out twice. The number is kept in its state file beside them,
because a prune can take the record that last advanced it and a node reading
its counter back from the records alone would sign at a number it had already
used. Every other node would then hold two different records at one of that
node's numbers, which is what says a key has been used outside its agent, and
the alert would fire on a cluster that was never touched. The number is this
node's own and is never gossiped: a counter on the wire would let a member
decide where another node's next record starts.

Overlay slots do not survive a prune: a pruned member's slot is free
for the next node to enrol, where a revoked member's is reused only when
nothing else is free.

`cheesecloth prune` is manual, and `--dry-run` reports what would go. Nothing
prunes on its own. A prune covering more than a hundred identities is logged as
an error: a homelab cluster does not retire that many nodes, so it says a member
has been admitting identities of its own.

### Overlay addresses

`Host` is the member's slot in the overlay network: its address is
`--overlay-net` with the host part set to `Host`. The root takes slot 1; an
admitter gives a joiner the lowest slot no admission in its set uses (slots of
revoked members are reused only when nothing else is free). Every node derives
every member's address from the same records, so addresses are stable across
restarts, allocated from the start of the overlay net, and independent of
hostnames. The network itself is part of the welcome, so a joiner is told
which one the cluster uses rather than being configured with it. Changing
`--overlay-net` on every node changes every address without re-enrolling,
because each node keeps its slot number.

Two members can be handed the same slot only if two admitters enrol joiners
at the same time, before either admission has spread. The records resolve
the conflict: the earlier admission (or, at the same second, the smaller
identity) keeps the slot, and every node excludes the other and logs the
collision. The excluded node keeps running but has no peers until it is
enrolled again (delete its state file and join with a fresh invitation).

A name can be handed out twice the same way, and is settled by the same rule:
an admitter refuses a name another member already holds, so only two admitters
acting at once can get past that, and then the earlier admission keeps the
name. The node that yields must be renamed before it is enrolled again, since
the name it had is held by the node that kept it.

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
4. Member verifies, consumes one token use, signs an admission for `J`,
   broadcasts it, and sends the joiner the root record, the full record set,
   its own gossip address and the cluster's overlay network. Both sides
   discard `K`. A joiner that has got this far but cannot be admitted — its
   name is one no node may hold or is taken, the overlay is full, or the record
   set no longer fits in a message — is told why instead of having the
   connection closed on it, and nothing is signed for it. The name is checked
   here rather than at the hello for that reason: a peer that has proved
   nothing is told nothing, so checking it earlier only turned a bad name into
   a closed connection the joiner reads as a bad token. Before this point a
   refusal is silent, so the member is not an oracle for token guessing, and
   the failures are counted rather than logged one line each, so that a peer
   cannot set the rate of a member's log.
5. Joiner -> Member: an acknowledgement once it has checked the welcome, so
   the member knows it arrived and closes the connection.

`transcript = "cheesecloth/enrol/transcript/v4" || 0 || J || M || nJ || nM || Name`,
each field length-prefixed: the canonical encoding the signed records use,
under its own domain string. Because both identities are included in the MACs,
the token can be discarded after step 4; from then on the identities are the
trust anchors. The two different labels prevent a MAC from being reflected back
to its sender. The nonces prevent replay.

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
the membership set for the peer's key (root pinning is implicit because
validity derives from the root). ALPN `cheesecloth-gossip/1`
is required. memberlist packets travel as QUIC datagrams (RFC 9221), so its
packet budget is set to 1100 bytes; push/pull exchanges travel as streams.

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

A restarting node has its seed, the pinned root, the record set, and its last
known peers on disk, each with the port it was last reached at. It reconnects
over QUIC to any of them and rejoins. No
token and no operator are involved. If every node restarts at once, each still
has everything it needs and nothing has to be fetched. A node that loses its
disk loses its identity. It is enrolled again with a fresh token, and the old
identity can be revoked.

## Operations

- `cheesecloth` with an overlay network configured and no state: create identity
  and root; start the cluster.
- `cheesecloth --join HOST --join-key TOKEN`: first start of a new node. The
  overlay network comes with the welcome; the node needs no setting of its own.
- `cheesecloth --join HOST` or bare `cheesecloth`: restart of an admitted node.
- bare `cheesecloth` on a node that is neither a member nor configured with an
  overlay network: create the identity and wait, configuring nothing.
- `cheesecloth invite [--ttl] [--uses]`: mint a token on a member (via the control
  socket `/run/cheesecloth/<interface>.sock`).
- `cheesecloth revoke NAME|IDENTITY`: sign and broadcast a revocation. An
  identity that is already out is refused, since a second revocation keeps no
  more than the first and may keep less.
- `cheesecloth prune [--dry-run]`: sign and broadcast a prune of the records
  no member needs.
- `cheesecloth leave`: revoke this node itself, hand the revocation to the
  members, and delete the state file. Any node may leave this way, the root
  included. `--force` skips the revocation for a node whose agent is no longer
  running to sign it, and tells the cluster nothing.
- `cheesecloth status`: shows peers with their identity fingerprints.

## Clocks

Membership does not rest on the clock: whether a record was signed while its
signer was a member is decided from the records a revocation keeps. `IssuedAt` is
advisory, and settles only two things, both of which every node answers the
same way from the same records:

- which of two members keeps a contested overlay slot, the earlier admission;
- which of several admitters' records states a member's current name and slot,
  the latest of them.

Nodes are still expected to keep their clocks synchronised (NTP or
equivalent). Skew between admitters can pick the wrong one of two legitimate
records in either case, which re-enrolling the node recovers from.

Two rules keep a wrong clock out of a set that never forgets:

- **A node will not sign a record dated before the last one it signed.** The
  operation fails and says how far behind the clock is. Nothing is adjusted: a
  date is what the signer asserts, and a backdated record would be misread by
  every node that already holds the earlier one. A node whose clock ran fast
  has therefore locked itself out until real time reaches what it signed; that
  is the honest state, and the way out of a long one is to re-enrol. A node
  cannot detect its own skew from its own clock, so the signal has to come
  from the warning below, on another node.
- **A record dated before 2020-01-01, or more than 24 hours in the future, is
  refused.** Past the bound is absolute rather than a sliding window, because
  old records are legitimate — the root's own admission is as old as the
  cluster — and every joiner is sent them. The future bound is deliberately far
  wider than any honest skew, so that two nodes cannot disagree about a record
  in practice, and push/pull re-offers a record refused for being early once
  local time passes it. Anything more than five minutes ahead is logged as a
  warning and kept.

## Out of scope for now

Rotation of the pinned root, which stays the anchor even once revoked;
cascading revocation; a PAKE for short human codes.
