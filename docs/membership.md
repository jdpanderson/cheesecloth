# Identity-based membership

Status: design accepted and implemented 2026-09-08.

## Goals

- No cluster-wide secret exists, on disk or in memory, after enrolment.
- An operator enrols a node with a short-lived token. After enrolment no
  machine holds the token.
- A stolen node gives the attacker that node's identity, which can be
  revoked. It does not give access to the cluster as a whole.
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

## Admission records

Membership is a set of signed records that only grows. The records are not
secret.

```
Admission  { Identity, Name, Host, Admitter, Seq, IssuedAt, Signature }
Revocation { Identity, Revoker, Seq, Mark, IssuedAt, Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`cheesecloth/admission/v1`, `cheesecloth/revocation/v1`).

`Seq` is the signer's own counter, which every record it signs advances,
starting at 1. It is derived from the records rather than stored separately, so
a node continues its sequence across a restart, and a record is persisted
before it is gossiped so that a number handed to a peer is never reused. One
signer's records are ordered by it, which needs no clock: a signer whose clock
jumps cannot reorder what it said, and which of one admitter's records states a
member's current name and slot is its counter's answer rather than its clock's.

Two different records at one number cannot be told apart, because an honest
signer never reuses one. They count while the signer is still a member, which
is the case where it had nothing to gain by reusing a number, and neither of
them counts once it is not, which is the case where the reuse is what a revoked
node signing under the mark would look like. A third record at that number
proves nothing the first two do not and is dropped, so nobody can grow the
records by signing at one number over and over. Both of the first two are kept
and passed on: they are what tells another node the number was reused, so every
node decides the same way from the same records.

- The founding node signs its own admission (`Admitter == Identity`). That
  record is the **root**. Every other node pins the root's identity in its
  state file; a self-signed record is accepted only for the pinned root.
- An admission is valid if its signature verifies and its admitter is the
  root or itself holds a valid admission. Validity is evaluated recursively
  with a cycle guard, which tracks the sequence number each question is asked
  about as well as the identity: asking whether a revoker was a member reaches
  the identity it revokes again, at the earlier record that admitted it.
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
  been revoked. What it can still do is reuse that record's number, which is
  the limitation below. Where several admitters have a valid record, the
  latest of them decides the name and slot.
- A revocation is valid if signed by a valid identity, or by the identity it
  revokes: a member may always revoke itself, which is how a node leaves the
  cluster for good. A revoked identity is no longer a member. `Mark` is the
  highest sequence number the revoker had seen from it, and records at or
  below that still stand, because those nodes proved knowledge of a token at
  the time. Revoking them automatically would remove nodes the operator did
  not ask to remove; revoke them explicitly if that is wanted.
- The mark is what a revocation is worth against a node that keeps its key and
  goes on signing. Everything past it carries nothing, however the record is
  dated, so a revoked node cannot backdate an admission into the window before
  its revocation and go on admitting members. A mark can lag: a node its
  admitter enrolled moments before the revocation, whose record had not
  reached the revoker, is cut off and has to enrol again.
- The root is a peer, not an authority over the others. It is revoked by the
  same rule: by itself, which is how the founding node leaves, or by any
  member. Revoking it removes it from the mesh and nothing else, because the
  records it signed up to the mark still stand. The cluster carries on
  admitting new nodes with the departed root still pinned as the anchor its
  chains end at. A revoked root admits nobody: what it signs afterwards is
  past the mark.
- Records are distributed by memberlist's push/pull state sync (whole set,
  union merge) and by broadcast when a record is created. The set only grows,
  so it has a ceiling: a welcome carries the whole set in one 1 MiB message,
  which is about 3,500 records at roughly 300 bytes each. A cluster that
  reaches it can still run, but admits nobody until the records are pruned,
  which nothing does yet. Nodes persist the
  set, so a restarted node has it before contacting anyone.

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
   name is taken, the overlay is full, or the record set no longer fits in a
   message — is told why instead of having the connection closed on it, and
   nothing is signed for it. Before that point a refusal is silent, so the
   member is not an oracle for token guessing.
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
- `cheesecloth revoke NAME|IDENTITY`: sign and broadcast a revocation.
- `cheesecloth leave`: revoke this node itself, hand the revocation to the
  members, and delete the state file. Any node may leave this way, the root
  included. `--force` skips the revocation for a node whose agent is no longer
  running to sign it, and tells the cluster nothing.
- `cheesecloth status`: shows peers with their identity fingerprints.

## Clocks

Membership does not rest on the clock: whether a record was signed while its
signer was a member is decided from sequence numbers and marks. `IssuedAt` is
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
