# Checkpoints and trimming

Status: proposed 2026-09-16. Nothing here is built. It replaces the parts of
[membership](membership.md) that derive membership from an ever-growing set of
records — "What a revocation withdraws", the sequence numbers, the cuts — and
leaves the rest of that document standing.

## The problem

The set only grows. Nothing is ever dropped, because a cut can rise and two
nodes that had thrown away different things could never agree again. That rule
buys convergence at a price that is stated but not solved:

- **A ceiling.** A welcome carries the whole set in one 1 MiB message, which is
  about 3,800 records at 276 bytes each. A cluster that reaches it goes on
  running but admits nobody.
- **A member that minted identities leaves its records behind.** `revoke
  --disown` withdraws them from the membership; the records stay for good. A
  cluster attacked that way is rebuilt, which is the documented answer today.
- **The machinery that makes a growing set safe is the hardest code here.**
  Sequence numbers exist to make a revocation's mark safe. The mark exists so a
  revocation need not list records. The recursive validity walk and its cycle
  guard exist because a record's standing is derived from every other record.
  Each is sound, and together they are more than the problem deserves.

A checkpoint attacks all three at once: if enough nodes agree what the
membership *is*, everything that led to it can be thrown away.

## What a checkpoint is

A signed statement of the membership: every member, with the name and overlay
slot it holds. Nothing about how any of them got there.

That last part is what does the work. Today membership is **derived** — a record
stands if its admitter's record stands, back to the root — so every record has
to be kept in order to re-derive the answer. A checkpoint **states** it. Once
ratified, provenance is irrelevant: a node does not walk a chain to decide
whether somebody is a member, it reads the list.

## How a checkpoint forms

There is no proposal, no proposer and no leader. Every node signs what it sees:
when the membership changes, each node independently computes the resulting
membership and signs a digest of it. A checkpoint **forms** when signatures from
`k` members over the same digest exist, where `k` is the cluster's quorum.

This fails in the right direction. If two nodes disagree about the resulting
membership — one has seen a record the other has not — their digests differ, no
digest reaches `k`, and nothing is trimmed. Disagreement costs a delay, never a
wrong answer. When the records converge, as they do, the digests converge and
the checkpoint forms.

It also has no protocol to get wrong: no timeout, no retry, no two competing
proposals, no proposer that dies half way. A node signs what it sees and
collects what others signed.

### Quorum is a synchronization knob, not a security one

`k` says **how many nodes must agree on the membership before history is
discarded**. It does not say how many must agree before the membership may
change: a single member still signs a revocation and every node still accepts
it, exactly as today. The quorum ratifies what happened; it does not authorize
it.

This is deliberate. Requiring agreement to *change* membership would mean
enrolment and revocation stop working whenever too few nodes are reachable,
which is the property this project exists to avoid — a two-node cluster could
never revoke either node, and a three-node cluster could not revoke anything
with one node down. Requiring agreement only to *forget* costs nothing when
nodes are unreachable: the cluster carries more history until they come back.

A threshold on the change itself is a separate idea, with separate costs, in
TODO Phase M.

`k` is `majority` (`N/2 + 1`) by default and that is the only value documented
as safe, because two quorums of a majority always intersect. Lower values are
allowed and are the operator's business: at `N/2` a cluster split down the
middle can form two checkpoints and trim to two different histories, and at 1 a
single node's view — possibly a stale one — becomes the truth for everybody.

`N` is the number of members in the cluster at the time, the subject of a
revocation included: nothing is revoked until the record says so, so the node
being removed is still counted in the membership the quorum is measured
against.

### The quorum lives in the records

`k` is part of the cluster, not part of a node's configuration. The root's own
admission establishes it, and changing it is itself a checkpoint.

This is not a detail. A threshold each node held in its own config file would be
a rule that can differ between nodes, and two nodes running different rules
disagree about who is a member — permanently, silently, and with nothing able to
detect it locally, since each is correctly applying the rule it was given. The
union merge converges today only because no local setting can change the answer.
`--quorum` therefore behaves like `--overlay-net`: it means something when
founding a cluster, and anywhere else it is a value to compare against the
cluster's and warn about.

## Trimming and supersession

Every node trims once it holds a checkpoint: records the checkpoint accounts for
are deleted.

One rule makes it stick. **A record a checkpoint supersedes is rejected, not
merged.** Without it a node that has not trimmed yet offers the old records back
at the next push/pull, the node that has trimmed takes them in again, and
nothing is ever actually discarded.

A node that is behind converges in one sync: it applies the checkpoint, trims,
and then accepts whatever came after. Records that arrived out of order and were
rejected are re-offered by the next state sync, which carries everything.

### What is retained

The chain of checkpoints, not the records they replaced.

A node returning after an absence can only judge a checkpoint against a
membership it already believes, so the first checkpoint it accepts must be
signed by members it knows. That one establishes a new membership, which lets it
judge the next, and so on to the present. Ordinary induction — and it works only
as far back as the chain is kept.

Which gives the retention rule its meaning:

> The checkpoint retention depth *is* the maximum staleness a node can return
> from.

Retention is by **depth, not by calendar**. A cluster where nothing has happened
for a year has trimmed nothing and locks nobody out; a node out of a drawer
syncs and carries on. Retention by wall-clock would expire nodes for missing
nothing, and would put the clock back into a membership decision, which this
design has worked to keep out of one.

## What a revocation does

It removes its subject entirely: the identity, the slot it held, and the key.
Once the checkpoint ratifies it, the subject's records are purged and nothing in
the cluster says it was ever there. The journals on each node keep the history;
the record set does not have to.

Two things follow that the current design cannot do:

- **Overlay slots become reusable.** Today every slot any record ever claimed
  stays claimed, so a revoked member's address is reserved for good and a
  re-enrolment burns a fresh one. With the slot purged, the next joiner takes
  it.
- **A revoked identity can be invited again.** There is nothing left to refuse
  it with, and nothing that needs to. Re-entry has always required an admission,
  which requires a token; an attacker who can obtain a token can enrol a fresh
  key anyway, so refusing the old one was never what kept anyone out.

Nodes the subject admitted keep their place, as they do today. They proved
knowledge of a token at the time, and removing them automatically would remove
nodes the operator did not ask to remove.

### Disowning

`revoke NAME --disown NAME...` names identities to go with the subject. They are
removed and purged the same way it is.

The record carries the identities **explicitly**. A record that said "revoke X
and cascade" would have each node compute the descendants from its own records;
nodes that are behind would compute different sets, the digests would differ,
and no checkpoint could ever form. Three thousand identities at 32 bytes each is
about 96 KB in one record, which fits the frame and is trimmed shortly after.

An identity may be named only if the subject admitted it. That is the only bound
on what one revocation reaches: without it, `revoke X --disown Q` removes a node
X never touched. It is not a new capability — one key can already sign a
revocation per member — but it turns wiping a cluster from N records into one,
and the check costs nothing, since the agent still holds the records when it
signs.

`--disown-all` means every identity the subject admitted, worked out by the
agent and written into the record. The current meaning — everything from the
first record the operator does not recognise onwards — was sequence arithmetic
and goes with the sequence numbers. For the case the flag exists for, a stolen
key, "everything it vouched for" is the better answer anyway: once the key is
out, none of its admissions are trustworthy, so there is nothing to be gained by
guessing where the compromise started.

An operator may also state a membership directly — *the members are these five*
— which is the same record the automatic flow produces, initiated by hand. It is
a better answer than a mark to a member that minted identities: no sequence
arithmetic, no naming the first node you do not recognise, and one record.

## Staleness

A node whose records are too far behind to reach the current checkpoint chain
**stops and says so**. It configures nothing, keeps its identity, and waits, the
way a node that is not a member of any cluster already waits. The operator runs
`cheesecloth leave` on it and enrols it again.

It does not evict itself. "I cannot verify this" and "I am too stale" are
different statements, and a node holding an unverifiable chain cannot tell them
apart — the other explanation is that the peer is lying. Acting on the first
reading would mean a gossip ordering artifact could destroy a node's membership
irreversibly, and it would hand one compromised member a way to make honest
nodes remove themselves one at a time.

The judgement is reached only after a complete state sync, never on a single
record that would not verify.

## What this deletes

- The recursive validity walk and its cycle guard: `chain`, `cut`, `counts`,
  `vouched`, and the `question` stack. Membership is read, not derived.
- Sequence numbers and everything that kept them contiguous: `Seq`, `extend`,
  `claim`, `Head`, `NextSeq`, `ErrAhead`, `errSpent`, ordered merge.
- `UpTo` and the marks: `VouchedAt`, `Withdraws`, `with`, `effect`, and the
  refusals built on them.
- "What a revocation withdraws" in full — cuts intersecting, revocations that
  never counted, cuts rising, mutual revocation, the narrowing report.
- Slot reservation for departed members.

Against that, it adds the checkpoint record, the attestation and counting, the
supersession rule, and the retention depth.

## What it costs

- **Forks become possible where they are not today.** Records only accumulate
  now, so union merge cannot fail to converge. Trimmed history can differ
  between two nodes that accepted different checkpoints. At `majority` two
  quorums always intersect and this cannot happen; below it, it can, and that is
  the operator's choice to make.
- **A node can be too stale to return.** Bounded by retention depth and only
  after real churn, but it is a state that does not exist today.
- **Revocation stops being permanent.** The README says twice that a revoked
  identity can never rejoin. Both claims come out.
- **The trust package is rewritten, not adjusted.** This is not an increment on
  the current rules; it replaces the question they answer.

## What it does not change

Identities, signatures and their domain separation; enrolment and the token
exchange; the QUIC transport and its membership check; gossip metadata and how
membership becomes an interface configuration. A member still admits a node
without asking anyone, and a node still restarts from what it has on disk.
