# Membership

The protocol specification: identities, the records, how a membership is
agreed and discarded, the enrolment exchange, and the transport that carries
them.

[Design](design.md) says why the system is shaped this way and states the
threat model. [Commands](commands.md) says what an operator types.
[Limitations](limitations.md) collects what follows from the choices here.

## Goals

- No cluster-wide secret exists, on disk or in memory, after enrolment.
- An operator enrols a node with a short-lived token. After enrolment no
  machine holds the token.
- A stolen node gives the attacker that node's identity and nothing else:
  there is no cluster-wide secret to take with it. Until it is revoked it has
  everything any member has, which is the deliberate trade described in
  [the threat model](design.md#the-threat-model-a-member-is-trusted).
- Nodes restart unattended, including all of them at once.
- Protocol versions are explicit (enrolment message, TLS ALPN), so nodes
  running different versions refuse to talk instead of partly working.

## The two key layers

WireGuard gives every node a key pair and protects the data plane with a Noise
handshake. cheesecloth does not change that. cheesecloth is responsible for
choosing which WireGuard public keys a node installs as peers, and for
protecting the gossip that carries them. Both rest on per-node identities and a
signed membership. There is no shared key.

## Identity

Each node has a 32-byte random seed, generated on first start and persisted in
its state file (mode 0600). One key derives from it: the Ed25519 signing key,
`ed25519.NewKeyFromSeed(seed)`. It signs records and node metadata, and it is
the key in the TLS certificate a node presents for gossip and enrolment.

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
enrolment exchange once the joiner has proved its token, in every admission
record whatever carried it, and in the metadata a node gossips. The names are
flat, so no member can hold one that belongs somewhere else in the DNS, and a
member cannot write anything of its own into another node's hosts file by being
named it.

The name a node asks for when it enrols is the first label of its hostname,
lowercased; a host named `web1.example.com` asks for `web1`. A hostname that
cannot be made into a name stops the node with an error rather than being
altered into something that would work.

After that the membership is what says who a node is. A node goes by the name
the membership gives it, and that name is what every peer looks it up by: the
identity and the overlay address are whatever the membership answers with, and
nothing a node says about itself is taken on its own word. Renaming the host
therefore does not rename the node; enrol it again to do that.

## The membership

Membership is a **checkpoint**: a signed statement of who the members are, with
the name and overlay slot each holds, carrying the signatures of the members
that agree with it.

```
Checkpoint   { Depth, Prev, Quorum, Confirmations,
               Members[{Identity, Name, Host}], Removed[{Identity, Depth}],
               Attestations[{Signer, Signature}] }
Agreement    { Digest, {Signer, Signature} }   // one node's attestation, alone
Admission    { Identity, Name, Host, Admitter, Signature }
Revocation   { Identity, Revoker, Signature }
Confirmation { Record, Confirmer, Signature }
```

`Signature` is Ed25519 over a fixed canonical encoding with a domain-separation
prefix (`cheesecloth/admission/v3`, `cheesecloth/revocation/v3`,
`cheesecloth/checkpoint/v1`, `cheesecloth/attestation/v1`,
`cheesecloth/confirmation/v1`).

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

Its cost is a delay. A node that has been admitted is not a member until the
cluster says so, which takes one round of attestation — well under a second when
the members are reachable, and never at all when too few of them are.

## How a membership is agreed

There is no proposer and no leader. Every node signs what it sees: when a record
arrives that would change the membership, each node independently works out what
the membership would become and signs a digest of it. Two nodes that agree
produce the same digest, so their signatures accumulate on one checkpoint, and
the anchor moves on once `Quorum` of the members it already names have signed.

This fails in the right direction. If two nodes disagree — one has seen a record
the other has not — their digests differ, no digest reaches quorum, and nothing
moves. Disagreement costs a delay, never a wrong answer. When the records
converge, as they do, the digests converge with them.

It also has no protocol to get wrong: no timeout, no retry, no two competing
proposals, no proposer that dies half way.

**What travels is the signature, not the membership.** The first node to work
out a membership hands the whole of it to each member over a stream; every node
that has it already sends a 150-byte agreement — the digest and one signature —
which fits a gossip datagram whatever size the cluster is and spreads
epidemically from there. A membership never gossips, because it is the one
record that grows with the cluster while what the other nodes add to it does
not:

| Members | At quorum | Once every member has signed |
|---|---|---|
| 3 | 0.4 KB | 0.5 KB |
| 5 | 0.6 KB | 0.8 KB |
| 10 | 1.2 KB | 1.6 KB |
| 50 | 5.3 KB | 7.9 KB |

One node handing that out costs a round of streams. Every node doing it, which
is what restating the membership would mean, costs a round from each of them to
each of the others. Single records stay small whatever the cluster size — an
admission is 159 bytes, a revocation 147, a confirmation 147 — so a membership
is the only thing that ever goes by hand, and a record too large for a datagram
takes the same path when one turns up.

## Quorum

`Quorum` says **how many members must attest to a membership before it becomes
the membership**. Every change goes through it. An admission and a revocation
are alike proposals, and neither takes effect until the cluster has agreed the
membership that follows from it.

The alternative is for quorum to ratify rather than authorize: a single
member's signature changes the membership at once, and agreement exists only so
that the records can be discarded. That is the more available arrangement —
enrolment and revocation go on working however few nodes are reachable — and
what it costs is a single answer. A record that counts everywhere the moment it
is signed also counts before anyone has agreed it is well formed, so two members
can admit two joiners to one name and each joiner is a member on a different
node.

Going through the membership buys the single answer, and pays for it in
availability. The bill, plainly:

- **A change needs a reachable quorum.** On `majority`, more than half the
  members must be up and in touch to sign the membership that follows. Below
  that, the cluster keeps running exactly as it is and changes nothing.
- **A cluster of two is a special case**, because a majority of two is
  everybody. Taken literally that would freeze such a cluster the moment one
  node stopped attesting: the other could neither evict it nor enrol a third
  node to break the tie. So `majority` is relaxed at two members and either node
  may agree on its own.
- **A revocation is not instant.** A node keeps its place until the cluster
  agrees a membership without it. What happens immediately is narrower: no
  admission can put a revoked identity back, so it cannot be re-enrolled while
  the revocation stands.

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

Relaxing at two gives up nothing against a stolen key, because quorum never
defended against one. A node attests to whatever the records propose, its own
removal included, so one compromised node of two is handed the other's
attestation even where both signatures are required. See
[the threat model](design.md#the-threat-model-a-member-is-trusted).

The rule is the cluster's, settled when the cluster is founded and carried in
its checkpoints, so no node's configuration can make it disagree with its peers.
`N` is the membership the checkpoint follows — the subject of a revocation
included, since it is a member until the membership without it is agreed.

## Confirmations

`Confirmations` says **how many members besides its signer must agree before a
record counts**. At zero, the default, a member's signature is enough: the
design's ordinary position, that a member is trusted. Above zero, an admission
or a revocation is held and does nothing until that many other members have
signed a confirmation of it, which an operator does with
[`cheesecloth confirm`](commands.md#cheesecloth-confirm).

*Besides its signer* is exact: a confirmation from the member that signed the
record is not counted, wherever it comes from. So a cluster of two asking for
one confirmation always needs the node that did not invite, and a node refuses
to sign a confirmation of its own record rather than send one that every peer
would store and none would count.

It is the cluster's, settled when the cluster is founded and carried in its
checkpoints, for the same reason as `Quorum`: two nodes disagreeing about
whether a record counts would state different memberships and never agree on
one.

It is clamped to one short of the membership, so a cluster smaller than its own
setting asks for what it can supply rather than freezing — a cluster of three
that wants five asks for two. The clamp reads the agreed membership, not the
members that happen to be reachable, since every node has to reach the same
number. What it costs is what quorum costs: enough members have to be there.

This is a security and usability trade, and the right setting depends on who
runs the cluster:

- **0 — a homelab one person runs.** Every node is yours, and asking yourself
  to confirm your own invitations is ceremony. This is the default.
- **1 — one person who wants to be careful.** An invitation or a revocation
  takes an action on a second machine, so a single compromised key cannot add
  or remove members on its own. It raises what an attacker needs from one key
  to two.
- **More than 1** is for a cluster where the cost of a mistake is higher than
  the cost of the ceremony. It raises the bar further, but not without limit:
  an attacker with C+1 keys can admit a node of its own, and that node is then
  a member that can confirm the next one.

What none of these settings does is make a compromised member safe. They raise
the number of keys an attacker needs to start; they do not bound what it can do
once it has them, and they are only worth anything if the person confirming
actually reads what they are confirming. **cheesecloth is not built for a large
cluster run by people whose intentions cannot all be known.** It is built for a
handful of machines with one person, or a few who trust each other, behind them.

A node enrolling into a cluster that asks for confirmations waits for a person
rather than for a round of gossip, so its `--join` blocks until somebody
confirms; Ctrl+C stops waiting, and costs the invitation.

## What decides between two records

Almost nothing has to. An identity has one admitter in practice, and a
membership the cluster agreed on settles every contest it covers — a checkpoint
may not contradict itself, so it can state neither two members sharing a name or
a slot, nor one identity as a member and as having gone.

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

## The life of a record

Every node discards what its anchor accounts for: the records about every
identity it names, as a member or as one it removed.

A record no member signed is never taken in the first place. Only a member's
signature can make one count, so one from anybody else is refused rather than
stored — otherwise a member could hand every node an unbounded pile of records
about identities nobody has heard of, and gossip would spread each one to all of
them. Refusing early costs nothing: a record can reach a node before the
membership that makes its signer a member, but the state sync carries a peer's
whole set every round and applies the memberships in it first, so it is offered
again as soon as it can be judged.

Records about anybody the membership does not name go too, once it is clear
nothing can act on them: one asking for a name or an overlay slot a member holds
was settled against. Collection runs on the sync as well as when the membership
moves, since a cluster that is not changing never moves it.

A record is accounted for only where the anchor's statement about that identity
is still the node's answer. Records arrive without the lock the anchor was taken
under, so one landing in between leaves the anchor out of date about that
identity; the record that made it so stays, or the change it carries would be
thrown away before anyone agreed to discard it.

Every membership behind the anchor goes too. **Nothing walks from one to the
next**, so there is no chain to keep: a node states its membership, the deeper
ones peers are still signing, and whatever has been signed since. Keeping the
last sixty-four memberships to walk would cost a cluster of fifty over half a
megabyte in every state sync and every enrolment, against the 9 KB or so it
carries now.

`Removed` is what a node that has been away is told instead. Each entry carries
the depth its identity went at and is dropped 64 agreements later. A returning
node never sees the memberships in between, so the one it lands on naming those
identities is the only thing that tells it they are out — without it, the
admissions it still holds would look unspent and it would offer them back. A
node further behind than that has its admissions refused for the same reason,
and has to enrol again.

**How far back a node is, is read from the membership it says it stands on.** A
node sends that anchor beside its records rather than among them, because its
records cannot say: what it holds past its own is whatever the cluster is
signing now, so the deepest record in its bag is the cluster's depth and not its
own. Revocations are taken whatever the sender's depth — they can only ever
remove, so a stale one costs a member its place at worst, never a stranger a
place in the cluster.

This guards against a node returning with stale records, not against a member.
Only a member's signature makes an admission count, and a member can sign a
fresh one for any identity whenever it likes, so replaying an old one gains it
nothing it did not already have. See
[the threat model](design.md#the-threat-model-a-member-is-trusted).

## What a revocation does

Once the cluster has agreed a membership without it, the subject is gone
entirely: the identity, the name and the overlay slot. The records go with it,
and nothing says it was ever there. Until then the record stands as a proposal,
and the subject is still a member.

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

**One record takes out one member**, and removing several is several
revocations. Nodes the subject admitted keep their place: they proved knowledge
of a token at the time, the cluster agreed to each of them in its own right, and
removing them automatically would remove nodes the operator did not ask to
remove. Nor could a record say "and everything this node admitted" and mean
anything definite, since each node would work the list out from its own records:
nodes that were behind would work out different lists, and no two of them would
agree on a membership.

A node the subject admitted that the cluster has *not* yet agreed on is a
different case: its admission is still only a proposal, and revoking the
admitter leaves that proposal unsigned by any member, so it never becomes a
membership at all. That joiner goes with its admitter, and the command says so
before it signs.

## When a node has been away too long

A node that returns holds a membership the cluster may have moved past. It takes
the one the cluster is on now in a single step, provided a quorum of the members
it still knows about signed it, so an absence costs nothing as long as enough of
the cluster it remembers is still there.

When the membership has turned over further than that, the node cannot catch up,
and there are two ways to get there.

The plain one is that nothing it is offered can ever be taken: every signature
is from somebody it knows nothing about, and attestations only ever accumulate
on a digest, so no later arrival changes that.

The other is slower to see. A membership only has to carry one signature the
node knows to be worth keeping, but a **quorum** of the members it knows to be
adopted. Where enough of those members have left the cluster for good, both hold
at once: the node is offered every membership the cluster agrees and adopts none
of them, so holding one past its own is no proof it is keeping up. Once it is
more than 64 agreements behind it is not — the cluster refuses its records at
that distance whatever else is true — so it says so, and from then on keeps only
the newest of what it is offered rather than a pile growing with every step the
cluster takes.

Neither test can prove the condition permanent, since a member that left could
always come back. It only decides what the operator is told, so saying it early
costs a line they did not need.

Either way the node says so rather than guessing, and rather than removing
itself: "I cannot verify this" and "I am too stale" are different statements,
and it is the second one. It goes on running with the membership it has, which
is the honest thing to do with it — the operator is told, at `error` and in the
service manager's status, that the node is configuring peers from a membership
the cluster has left behind and has to be enrolled again.

Taking a membership in one step is what makes this cheap, and it gives one thing
up. A node takes any membership a quorum of the members **it knows about** has
signed. For a node that is up to date those are the current members, so this is
the ordinary case. For a node that has been away they are the members as of
whenever it last looked — so an attacker who has collected enough of *those*
keys, including ones revoked since, can hand it any membership it likes. Walking
one membership at a time would show the revocations on the way past and stop
those keys counting, at the price above. Small clusters revoke promptly and
their nodes are not away for long; a node that is away long enough has to enrol
again in any case.

## Forks

Below a majority, two disjoint quorums can agree two different memberships. A
node commits to the first one it takes and refuses anything that is not further
on, so it never gives up ground it has covered; two nodes that went different
ways stay that way. At `majority` this cannot happen, which is why it is the
default and the only value documented as safe.

## Overlay addresses

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
member$  cheesecloth invite [--ttl 10m]     -> prints TOKEN
newnode$ cheesecloth --join member --join-key TOKEN
```

An invitation admits one node. The member keeps the 32-byte token only in
memory, with its expiry. The joiner holds it only for the exchange. Nothing writes it to
disk. Enrolment runs as a QUIC stream on the cluster port under ALPN
`cheesecloth-enrol/1`, so no new port is opened. The joiner is not a member yet,
so on that ALPN both sides only parse the other's identity certificate. The
exchange below then requires the identities named in the messages to match the
certificates on the connection, and the token decides whether the joiner is
admitted.

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
   cannot be admitted — its invitation was taken by another joiner or ran out
   while it was proving it, its identity has been revoked, its name is one no
   node may hold or is taken, the overlay is full, the records no longer fit in
   a message, the cluster could not reach a quorum, or another joiner took the
   name or slot at the same moment — is told why instead of having the
   connection closed on it. The invitation is spent either way: it went on the
   proof, before any of these checks, and the operator issues another rather
   than the member holding one open for an enrolment that did not happen.
   The name is checked here rather than at the hello for that reason: a peer
   that has proved nothing is told nothing, so checking it earlier only turned a
   bad name into a closed connection the joiner reads as a bad token. Before
   this point a refusal is silent, so the member is not an oracle for token
   guessing, and the failures are counted rather than logged one line each, so
   that a peer cannot set the rate of a member's log.
5. Joiner -> Member: an acknowledgement once it has checked the welcome, so the
   member knows it arrived and closes the connection.

`transcript = "cheesecloth/enrol/transcript/v1" || 0 || J || M || nJ || nM || Name`,
each field length-prefixed: the canonical encoding the signed records use, under
its own domain string. Because both identities are included in the MACs, the
token can be discarded after step 4; from then on the identities are the trust
anchors. The two different labels prevent a MAC from being reflected back to its
sender. The nonces prevent replay.

**How long step 4 takes** depends on the cluster. Where `Confirmations` is zero
it is one round of attestation, and the member gives up after 30 seconds and
tells the joiner how many members had to attest. Where the cluster asks for
confirmations it is waiting for a person, so there is no deadline at all and the
joiner blocks until somebody runs `cheesecloth confirm`.

The token exchange is also what establishes that this member speaks for the
cluster, so the membership in the welcome is taken as given. A joiner has no
history to check it against and needs none: it is being told who the members are
by somebody that proved it holds an invitation. From there it moves forward like
any other node.

Confidentiality and the binding of each identity to its side of the exchange
come from the QUIC stream, whose TLS peers are the same `J` and `M`: the
identities in the messages must match the certificates on the connection, so an
intermediary cannot pass the MAC check under its own identity, and without `K`
it cannot compute a MAC at all. A member that finds no pending token for
`TokenID` closes the stream without a reply, so an attacker cannot use the
server to test guesses. Tokens are 256-bit random values, so a PAKE is
unnecessary.

At most eight exchanges run at once; see
[enrolment can be crowded out](limitations.md#enrolment-can-be-crowded-out).

## Gossip transport

memberlist's own encryption is disabled; cheesecloth supplies a `Transport` that
runs memberlist over QUIC (quic-go) on the cluster port, one UDP socket for both
listening and dialling so that peers see a node's gossip address as the source
of everything it sends.

Each pair of nodes shares one QUIC connection, authenticated on both sides by
TLS 1.3 with self-signed certificates for the nodes' Ed25519 identity keys:
there is no CA. Certificate verification ignores chains and instead checks the
membership for the peer's key. ALPN `cheesecloth-gossip/1` is required.
memberlist packets travel as QUIC datagrams (RFC 9221), so its packet budget is
set to 1100 bytes; push/pull exchanges travel as streams. A full state sync runs
every `--sync-interval`, 90 seconds by default.

Records travel as messagepack, which is what memberlist encodes its own messages
with. An identity goes as its 32 bytes and a signature as its 64 rather than as a
third again in base64, and each field is named by one letter, which together take
about a third off everything on the wire. The state file stays JSON and keeps the
long names: what a node keeps is written once per change, and being able to read
it is worth more there than the bytes are.
Nothing about this is load-bearing — every signature is over `wire.Canonical`,
never over the form a record travels in, so what verifies does not depend on how
it arrived.

A packet to a node with no connection yet is dropped while a connection is
dialled in the background, in the same way that UDP would drop it, and
memberlist's next round gets through. Failure detection depends on this:
memberlist treats a lost probe as a sign that the peer may be down, but treats a
send error as a local problem and does not suspect the peer. When a member is
revoked while connected, its connection is closed on the next packet or stream
it sends.

## Node metadata

Gossiped per node, within memberlist's 512-byte limit:
`{ WGPubKey, AllowedIPs, Signature }` with
`Signature = Ed25519(identity, "cheesecloth/meta/v1" || Name || OverlayAddr || WGPubKey || AllowedIPs...)`.
`AllowedIPs` are the extra networks the node routes (`--allowed-ips`), each
encoded as address bytes plus prefix length. The key and the signature take 119
bytes, leaving room for about sixty IPv4 prefixes; how many IPv6 prefixes fit
depends on how long they are written.

The name, the identity and the overlay address are signed but not sent. The name
is what memberlist carries anyway, and the membership turns that into the other
two, so sending them would be sending what a peer has to work out for itself in
order to check them. A node installs a peer's WireGuard key only if the
membership knows the name it goes by and the signature over all of it is by the
identity the membership gives that name. This binds each node's ephemeral
WireGuard key to its persisted identity without persisting the WireGuard key,
and leaves a member no way to claim another's name or address.

## Restart and recovery

A restarting node has its seed, the membership it last satisfied itself of,
whatever has been signed since, and its last known peers on disk, each with the
port it was last reached at. It starts from that membership rather than working
one out again, reconnects over QUIC to any of the peers and rejoins; no token
and no operator are involved. If every node restarts at once, each still has
everything it needs and nothing has to be fetched. A node that loses its disk
loses its identity. It is enrolled again with a fresh token, and the old
identity can be revoked.

## Out of scope

Cascading revocation; a PAKE for short human codes.
