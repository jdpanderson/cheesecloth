# Identity-based membership

Status: design accepted and implemented 2026-09-08; sequence order,
revocation cuts and sweeping added 2026-09-15.

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
Revocation { Identity, Revoker, Seq, UpTo, IssuedAt, Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`cheesecloth/admission/v1` and `cheesecloth/revocation/v1`).

`Seq` is the signer's own counter, which every record it signs advances,
starting at 1. A node keeps its own counter in its state file, so it continues
its sequence across a restart even where the record that last advanced it is no
longer held, and a record is persisted before
it is gossiped so that a number handed to a peer is never reused. One
signer's records are ordered by it, which needs no clock: a signer whose clock
jumps cannot reorder what it said, and which of one admitter's records states a
member's current name and slot is its counter's answer rather than its clock's.

A signer's records are taken in the order it signed them: one is accepted only
once the one before it is in, so its sequence has no gaps and every number it
has reached is spent for good. That is what lets a revocation mark where a
signer's records stop rather than listing them — the numbers a signer has used
are its own to choose, and one that could leave a gap below the mark could sign
into it after it was out.

A record that arrives ahead of its predecessors waits for the next state sync,
which carries the whole set and offers each signer's records in order. A second,
different record at a number already taken is refused, and says the signer's key
has been used outside its agent, since an agent takes each number once.

- The founding node signs its own admission (`Admitter == Identity`). That
  record is the **root**. Every other node pins the root's identity in its
  state file; a self-signed record is accepted only for the pinned root.
- An admission is valid if its signature verifies, its number is at or below
  its admitter's cut, and its admitter is the root or itself holds a valid
  admission. Validity is evaluated recursively with a cycle guard over the two
  questions asked of an identity — whether it reaches the root, and where its
  records stop — since asking whether a revoker was a member reaches the
  identity it revokes again.
- Records are held per signer: an identity's admissions are kept by admitter
  and its revocations by revoker, and a signer only ever changes what it said
  itself. Several admitters may therefore have a record for one identity, and
  the identity is a member if any one of them holds. Nothing a signer emits
  can displace what another signed, so a key that is no longer a member cannot
  take out one that is by signing a later record for it, and two nodes with
  the same records reach the same answers whatever order they arrived in.
- Every record an admitter signed for an identity is kept, in the order it
  signed them. The earliest is what vouched for the identity in the first
  place; the latest is that admitter's current statement of its name and slot,
  so an admitter can rename a member that enrols again. It cannot retract the
  membership it vouched for by signing a further record once it has itself been
  revoked: that record is above its cut and the earlier one is not. Where
  several admitters have a valid record, the latest of them decides the name
  and slot. The records in between decide nothing, and are kept only because
  dropping them would leave a gap in the admitter's sequence.
- **A revoked identity cannot rejoin under a later admission**, at any sequence
  number; the node needs a fresh identity. A revocation by a member is never
  undone. What can happen is that a revocation turns out never to have counted,
  because its signer was already out when it signed; see "What a revocation
  withdraws".
- A revocation is valid if signed by a valid identity, or by the identity it
  revokes: a member may always revoke itself, which is how a node leaves the
  cluster for good. A revoked identity is no longer a member.
- A revocation marks its subject's sequence with `UpTo`: what it signed at that
  number and below still stands, and everything above is withdrawn. The mark
  goes where the revoker had seen the subject's records reach, so the nodes it
  admitted keep their place — they proved knowledge of a token at the time, and
  removing them automatically would remove nodes the operator did not ask to
  remove. A lower mark, which `cheesecloth revoke --up-to` gives, withdraws
  more: it is how a member that was signing records nobody asked for is undone
  back to where it was still trusted.
- The mark is what a revocation is worth against a node that keeps its key and
  goes on signing. Nothing it signs afterwards is below the mark, however the
  record is dated, and there is no unused number left below it to sign into. A
  revoker's view can lag: a node its admitter enrolled moments before the
  revocation, whose record had not reached the revoker, is above the mark and
  has to enrol again.
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
  reaches it can still run, but admits nobody until the cluster is smaller.
  Nodes persist the set, so a restarted node has it before contacting anyone.

### What a stolen member costs

Every member is a peer, and there is no lesser kind of membership: any member
may admit, and admitting is signing a record, which needs the key and nothing
else. An attacker holding a node's seed therefore never has to enrol anybody.
It signs admissions for identities of its own making and hands them over with
the rest of the records at the next push/pull, as fast as it can generate keys,
which is faster than an operator can read a log.

An ordinary revocation does not withdraw them. Its mark goes where the revoker
had seen the subject's records reach, deliberately, so that the members a
departing node admitted keep their place; the minted identities are below the
mark and stay. What answers it is a lower mark. `cheesecloth revoke --up-to N`
withdraws everything the subject signed above N, so setting N to where it was
last trusted takes the whole run of minted identities out at once, on every node
that holds the record, and the records go with them. An operator still has to
work out where that point is; nothing today lists what an admitter vouched
for.

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

A revocation marks where its subject's records stop. The mark is where the
revoker had seen them reach, so the rule has edges worth knowing before a
cluster is changed.

**Cuts intersect; they do not union.** Of several revocations of one identity,
the lowest mark is the one that counts. That is the safe direction — what one
node has not seen stays out rather than in — but it means a second revocation of
an identity can take out members the first one left alone. `cheesecloth revoke`
refuses an identity that is already out for that reason.

**A revocation by a member is never undone.** Nothing puts back a node that a
member revoked. Revoking the revoker does not restore it, and neither does
anything else; the node needs a fresh identity.

**A revocation that never counted is a different thing.** Its signer must have
been a member when it signed, which means at or below its own mark. A later
revocation that marks the signer lower than the revocation it issued is saying
that signer was already out at that point — so the revocation never counted, and
the node it named was never validly revoked and is a member again.

This is not a revocation being withdrawn. It is an invalid one being undone,
which is the same rule that stops a revoked node going on revoking: everything
it signs after its mark counts for nothing, including revocations. The two are
one rule seen from two sides.

**It is still reported.** Two things produce it and the records cannot tell them
apart: the subject's key signed after it was out of the cluster, or the
revocation was signed by a node that had not caught up with what the subject had
done. The first means a key is being used outside its agent and the cluster
should be rebuilt; the second means the cluster was changed from a node that
could not see it. The set logs what it saw — how many admissions and how many
revocations the mark takes away — and leaves the judgement to the operator.
Nothing is refused: a node cannot mend this on its own, and the records still
have to reach every peer so they all reach the same answer.

**A cut is not one-way.** A further revocation lowers it; one that stops
counting raises it again, and the records it had withdrawn stand once more. That
is why a node that has swept records a cut withdrew keeps enough to take them
back; see "Sweeping".

**Nothing depends on the clock.** No part of this reads `IssuedAt`. A forged
date changes nothing.

**A node can destroy what it granted.** A self-revocation counts whatever else
is held, so a node that marks its own sequence at nothing puts out every node it
admitted, and nothing undoes that. `cheesecloth leave` marks it at the number the
record itself takes, keeping everything the node signed; only a hand-made record
does otherwise.

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

### Sweeping

A record above a cut stands for nobody, here or on a node given the smaller set,
so every node drops it on the way to its state file. That is what gives back
what a departure or a member that went wrong cost the set. No signed record
carries it and no operator decides it: each node derives its cuts from the
records it holds, and dropping changes no answer about any member.

That last part is checked rather than reasoned about. "Stands for nobody" holds
of a record above a cut except where the cycle guard is what withdrew it: a
revocation that cuts off the chain its own signer stands on is counted from
outside and not counted from within its own walk, so the records above that cut
are what the revoker's own membership rests on, and dropping them would change
who is a member. So a node works out what would go, asks the smaller set who its
members are, and throws the records away only if the answer is the one it is
already giving. When it keeps them it says so. Nothing is wrong with the set at
that point — every node holding those records answers the same way — and a
revocation of the revoker, signed from a node the revoker did not admit, settles
which of the two answers stands.

Because a cut can rise, a drop has to be reversible. Each node keeps the number
a dropped record took and a digest of its signature. A peer that has not dropped
it offers it back at every state sync, and the digest settles which it is: the
record that was there comes back, and anything else at that number is a second
record at one of the signer's numbers and is refused as one. None of this goes
on the wire — it is the node's own account of what it dropped, 8 bytes and a
32-byte digest against roughly 300 for the record — and it is persisted, since a
node that forgot it could neither take the record back nor keep the number
spent.

Above a node's own departure nothing is kept. A self-revocation counts whatever
else is held, so the mark a node put on its own sequence when it left can never
rise and what is above it is gone for good. The self-revocation itself is the
one record a cut never reaches: dropping it would let the node back in.

What remains in the steady state is one admission per identity that was ever a
member, a constant-size revocation for each that has left, and the sequence
heads. The ceiling is still the 1 MiB enrolment message, but revocations no
longer grow with what their subject signed, and the case that used to fill a
set — a member minting identities of its own — is undone by one `revoke
--up-to` and gone from every node that holds the record.

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

`transcript = "cheesecloth/enrol/transcript/v1" || 0 || J || M || nJ || nM || Name`,
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
validity derives from the root). ALPN `cheesecloth-gossip/1` is required.
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

A restarting node has its seed, the pinned root, the record set, and its last
known peers on disk, each with the port it was last reached at. It reconnects
over QUIC to any of them and rejoins; no token and no operator are involved. If
every node restarts at once, each still has everything it needs and nothing has
to be fetched. A node that loses its disk loses its identity. It is enrolled
again with a fresh token, and the old identity can be revoked.

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
cascading revocation; a PAKE for short human codes; requiring more than one
signer before the membership changes, which is the answer to what one stolen key
can do and is noted in TODO Phase M.
