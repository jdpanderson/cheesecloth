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
Admission  { Identity, Name, Host, Admitter, IssuedAt, Signature }
Revocation { Identity, Revoker, IssuedAt, Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`cheesecloth/admission/v2`, `cheesecloth/revocation/v1`).

- The founding node signs its own admission (`Admitter == Identity`). That
  record is the **root**. Every other node pins the root's identity in its
  state file; a self-signed record is accepted only for the pinned root.
- An admission is valid if its signature verifies and its admitter is the
  root or itself holds a valid admission. Validity is evaluated recursively
  with a cycle guard, which tracks the time each question is asked about as
  well as the identity: asking whether a revoker was a member reaches the
  identity it revokes again, at the earlier time that identity was admitted.
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
  can therefore rename a member that enrols again, but cannot retract the
  membership it vouched for once it has itself been revoked. Where several
  admitters have a valid record, the latest of them decides the name and slot.
- A revocation is valid if signed by a valid identity, or by the identity it
  revokes: a member may always revoke itself, which is how a node leaves the
  cluster for good. A revoked identity is no longer a member. Admissions it
  issued earlier stay valid, because those nodes proved knowledge of a token
  at the time. Revoking them automatically would remove nodes the operator did
  not ask to remove; revoke them explicitly if that is wanted.
- The root is a peer, not an authority over the others. It is revoked by the
  same rule: by itself, which is how the founding node leaves, or by any
  member. Revoking it removes it from the mesh and nothing else, because the
  records it signed while it was a member are still judged as of the moment it
  signed them. The cluster carries on admitting new nodes with the departed
  root still pinned as the anchor its chains end at. A revoked root admits
  nobody: records it signs afterwards are judged at their own time, when it was
  no longer a member.
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
   `kMac = HKDF-SHA256(K, salt = nJ || nM, info="cheesecloth/enrol/v4")`.
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

Records carry the issuer's wall-clock time, and the rules compare them: a
revocation counts only against admissions the revoker made before it, and
the earlier of two admissions to one overlay slot wins. Nodes are expected to
keep their clocks synchronised (NTP or equivalent); with skew of more than a
few seconds between admitters, a revocation could appear to predate an
admission it should cover. Revocations are rare enough that this is accepted.

## Out of scope for now

Rotation of the pinned root, which stays the anchor even once revoked;
cascading revocation; a PAKE for short human
codes; clock-independent ordering of records.
