# Limitations

What cheesecloth deliberately does not do, and what follows from the choices in
[design](design.md). These are not expected to change. Defects that should
eventually be fixed are kept apart, at the [end of this document](#open-defects).

This is the whole list; the other documents point here rather than keeping one
of their own.

## A change needs a quorum of the members

Nothing changes the membership until a quorum of the current members has
attested to the one that follows. On the default `majority` that is more than
half of them, so while too few are reachable the cluster goes on running exactly
as it is: existing members keep their peers, their addresses and their hosts
entries, and nothing is added or removed until enough of them are back.

A cluster of **three** therefore keeps working with any one node down, of four
with one down, of five with two. A cluster of **two** is special-cased, since a
majority of two is everybody and the rule taken literally would let a single
stopped node freeze the survivor for good: at two members either node may agree
on its own. The cost is that two nodes which both change the membership while
partitioned from each other can end up with two different memberships and stay
that way — it takes an operator at each end to do, and rebuilding one node from
the other to undo. See [Quorum](membership.md#quorum).

A node enrolling waits for that agreement. Where the cluster asks for no
confirmations it gives up after 30 seconds, telling the operator how many
members had to attest. Where it asks for confirmations it is waiting for a
person rather than a round of gossip, so there is no deadline at all and
`--join` blocks until somebody runs `cheesecloth confirm`; Ctrl+C stops waiting.

## A membership is too large to gossip past about five members

Single records always fit a gossip datagram — an admission is 261 bytes, a
revocation 234, a confirmation 236, and an agreement 237 — but a membership
grows with the cluster and passes the roughly 1100-byte budget at around five
members. Above that, the node that first states a membership hands it to each
peer over a stream, which can leave somebody out if a peer is unreachable just
then. Every other node sends only a signature, which always fits.

Nothing needs doing about it: the record is on disk, and the full state sync
carries it once a minute. It is only worth looking at if the same members keep
missing records, which says they are unreachable rather than merely slow. See
[what travels](membership.md#how-a-membership-is-agreed).

## A node can advertise only so many networks

What a node announces about itself travels in the gossip protocol's per-node
metadata, which is 512 bytes. The overlay address, the WireGuard key, the
identity and the signature take a little over 220 of them, so roughly fifteen
IPv4 prefixes fit alongside; how many IPv6 prefixes fit depends on how long they
are written. A node given more than fit refuses to start and says how many it
was given, rather than starting and being ignored by every peer for metadata
they cannot read. Advertise a shorter prefix that covers them, or spread the
networks over more than one node.

## The control socket is protected by file permissions

Inviting, revoking, confirming and leaving go through a unix socket that the
agent creates owner-only, so the ability to run those commands is the ability to
read that file. That is the whole of the protection, and it holds on Linux and
macOS. On Windows the directory the socket sits in does not carry the same
permissions, so a Windows node's control socket is less protected than the model
assumes. Treat an account on a Windows node as equivalent to membership of the
cluster until that is fixed.

## Two joiners can contest one name or address, and one of them loses

Two members admitting new nodes at the same moment, before either admission has
reached the other, can give two joiners the same name or the same overlay
address. Neither is a member yet, and a membership naming both could never be
agreed, so the cluster settles it before either becomes anything: it agrees a
membership holding one of them, decided the same way on every node, and the
other is left out.

The joiner that loses is told so — its `--join` fails saying another node took
the name or the address at the same moment — and nothing about it is left in the
cluster. Run the join again and it takes the next free slot. A joiner that lost
a *name* has to be given a different one, since the name now belongs to the node
that kept it.

## Revoking a node can fail an enrolment that is in progress

A node becomes a member when the cluster agrees a membership naming it, and its
`--join` waits for that. Revoking the member that admitted it inside that window
leaves the admission signed by nobody who is still a member, so the membership is
never agreed and the enrolment fails rather than half succeeding.

The window is one agreement wide and the joiner is told: `--join` reports that
the cluster did not agree a membership holding it. Run the join again, from a
member that is staying. Where the timing is foreseeable, wait for the new node
to appear in `cheesecloth status` before revoking the node that admitted it.

## A revoked identity cannot rejoin for 64 membership changes

A membership carries the identities removed in the last 64 agreements, so that a
record from before one of them cannot put an identity back. Enrolment refuses
those identities for as long as they are named, which is what stops a node that
was just revoked walking straight back in.

To bring a host back sooner, give it a fresh identity: `cheesecloth leave
--force` on the host, then join again with a new invitation.

## A host's name has to be usable as a node name

A node is known to the cluster by one hostname label: lowercase letters, digits
and hyphens, at most 63 of them. A node takes the first label of its hostname
when it enrols, so `web1.example.com` enrols as `web1`, but a host whose name has
nothing usable in it — one named `Server_01`, say — stops with an error rather
than enrolling under a name the other nodes cannot resolve. Rename the host, or
set its hostname to a plain name, and start it again.

The name is fixed at enrolment. Renaming a host afterwards does not rename the
node: it goes on using the name the membership gives it, which is what its peers
resolve and what `cheesecloth revoke` takes. To change it, revoke the node and
enrol it again.

## A hosts-file line ending in our banner is treated as ours

The agent marks the lines it manages in the hosts file with a banner comment
naming the interface, and finds them again by looking for that banner at the end
of a line. A line somebody wrote by hand that happens to end with exactly the
same text is therefore read as one of ours: it is rewritten if its address
belongs to a member, and removed if it does not.

Nothing in normal use produces such a line. The banner carries the interface
name, and no interface's banner can be a suffix of another's, since a name
cannot contain the banner's fixed part. It matters only if you write hosts
entries that copy the banner text, which is how the agent tells its own lines
from yours.

## Enrolment can be crowded out

Enrolment shares the cluster port and accepts a connection from anyone, since a
joiner is not a member yet and only the token exchange decides. At most eight
exchanges run at once, so anyone who can reach the port can hold those slots and
stop new nodes enrolling for as long as they keep it up. Gossip between the
nodes already in the cluster is unaffected, and nothing is admitted that could
not be admitted anyway: the cost is that `cheesecloth invite` may have to be
retried. Where that matters, reach the cluster port with a firewall rule rather
than leaving it open to everyone, and open it while a node is being added.

A connection that opens no stream holds its slot for two seconds, which is a
round trip's work: a joiner opens its stream as soon as the handshake is done.
Holding a slot for longer than that means running the exchange itself, which
needs the connection kept open and answered.

What such a peer cannot do is fill the log. Everything that fails before the
joiner has proved the token — an unreadable hello, a name that is not the
connection's, an unknown token, a proof that does not check — is counted rather
than written out one line each, and reported at most once a minute:

```
enrolment attempts by peers that proved nothing; a member reports these at its
own rate, since anyone who can reach the port can make them count=1184
since=37 recent="unproven: joiner could not prove knowledge of the token"
from=203.0.113.9:51242
```

A large count with `could not prove knowledge of the token` is someone guessing
at invitations. A failure after the proof is a peer that held a valid one, so
there can only be as many as the token had uses, and those are logged as they
happen under `enrolment failed`.

## Split-brain

cheesecloth does not distinguish a failed node from one that was removed on
purpose. This is intentional, so that a cluster can grow and shrink without
configuration changes. A long connection loss between two parts of the cluster —
across a WAN link between providers, say — therefore causes each side to treat
the other as failed. A workaround is to restart cheesecloth periodically on one
node of each side with `--join` pointing at the other side. Static seed nodes
are a candidate for future work.

## A compromised member is a member

This is the deliberate trade the whole design rests on, and it is stated in full
in [the threat model](design.md#the-threat-model-a-member-is-trusted). In short:
an attacker holding a member's key can act as that member, `cheesecloth revoke`
is maintenance rather than a remedy for it, and a compromised node means a
cluster to rebuild. `--confirmations` raises the number of keys an attacker
needs to start; it does not bound what it can do once it has them.

## Open defects

Things that should eventually change, as distinct from everything above.

_Nothing open._
