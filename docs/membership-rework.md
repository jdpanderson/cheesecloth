# Membership rework: materialized view, sequence cuts, permanent revocation

Status: accepted 2026-09-15, in progress. Folds into [membership.md](membership.md)
when it lands.

Three changes, taken together. Each is useful alone, but the third is what
makes records deletable, and deletable records are what remove `prune`.

## Why

Validity is a recursive query evaluated from the records every time it is
asked. `Valid()` memoizes; the internal `valid()` does not, and
`validAdmissions()` calls both `valid(id)` and `effective(id)` for every
identity in the set, each a fresh walk with a fresh cycle guard. So
`MemberCount`, `NameTaken`, `ByName`, `Conflicts` and `FreeHost` are each
O(identities x records x depth) per call, over dead records as much as live
ones. Deleting dead records would leave that shape intact.

Underneath it, one field pays for most of the complexity. `Revocation.Keeps`
lists the signatures of the subject's records that still stand. It is what
makes revocation non-cascading, and it is also why revocations are the largest
record in the set, why they survive pruning, why keep lists intersect, why a
revocation can be withdrawn by revoking its signer, and why the cycle guard is
keyed on `(identity, signature)` rather than on an identity.

## The new rules

### Records

```
Admission  { Identity, Name, Host, Admitter, Seq, IssuedAt, Signature }
Revocation { Identity, Revoker, Seq, UpTo, IssuedAt, Signature }
```

`Prune` is deleted. `Keeps` is replaced by `UpTo`: the subject's records at
`Seq <= UpTo` stand, and everything above is withdrawn. `UpTo == 0` withdraws
everything.

### Accepting a record

A record from signer S is accepted only if `Seq == head(S) + 1`, or it is the
signer's first. Anything higher is deferred: refused for now, taken at the next
state sync, which carries the whole set and applies each signer's records in
sequence order. Anything at or below `head(S)` that the set does not already
hold byte for byte is refused.

`head(S)` is the highest sequence number accepted from S. It is persisted per
signer and survives deletion of the records themselves, exactly as the node's
own counter does today.

This is what makes a cut worth anything. A signer that left gaps in its own
sequence could sign into them after it was cut off; with contiguity there are
no gaps, and every position at or below a node's head is spent whether or not
the record that spent it is still held.

Refusing a record at a filled position raises the existing equivocation alarm
only when the set still holds a *different* record at that position. A record
at a position whose record has since been deleted is an ordinary re-offer from
a peer that has not caught up, and is refused without comment.

### Deciding membership

```
stands(a)     = a.Seq <= cut(a.Admitter) && chain(a.Admitter)
chain(X)      = X == root || exists a in admissions[X] : stands(a)
cut(A)        = min UpTo over revocations of A that count, or infinity
counts(r)     = r.Revoker == r.Identity || chain(r.Revoker)
revoked       = { X : exists r revoking X, counts(r) }
member(X)     = chain(X) && X not in revoked
```

`chain` no longer consults revocations, so the cycle guard is a visited set of
identities and `question{id, sig}` goes away. `counts` is judged with the same
guard: a revocation that can only be justified through itself does not count,
which is what today's guard already does.

A revocation is never withdrawn. `cut` applies to admissions only, so revoking
a revoker does not restore whoever it put out.

Two revocations of one identity keep the smaller `UpTo`: cuts only ever shrink,
which is today's intersecting keep lists expressed as a minimum.

### What can be deleted

A cut is permanent and only shrinks, so a record above one can never stand
again. Every node drops those records on receipt of the revocation, with no
signed record and no operator action. That is the whole rule.

It is deliberately narrower than it first looks. Dropping the admissions **of**
a revoked identity was in this plan and is not possible: those records are
signed by the identity's admitters, at arbitrary points in *their* sequences,
so removing them punches gaps into the sequences of signers who have done
nothing wrong. A node that later receives such a set stops at the first gap and
never takes the records after it. Records above a cut are a suffix of one
signer's own sequence, so removing them leaves a contiguous prefix and a node
given the smaller set reaches the same answers.

What remains in the steady state is one admission per identity that was ever a
member, one constant-size revocation per revoked identity, and `head` per
signer. That is the same order of growth as today's prune leaves — the doc
already notes that pruning one node trades an admission for a prune record —
except that revocations no longer grow with what their subject signed, and the
compromise case is handled without an operator deciding anything.

Nothing is dropped that a later record could bring back, so there is no
tombstone map, no refusal warning and no operator judgement about whether this
node is in touch with the cluster.

The compromise case falls out: revoke the compromised member with `UpTo` set
below where it was compromised, and everything it minted is above the cut and
gone on every node at once.

### What this removes

`Keeps`, `keeps()`, `SignedBy`, `sortedSignatures`, `reportNarrowing`'s
withdrawn-revocation error, `question`, the `(id, sig)` cycle guard,
`validFor`'s revocation recursion, `prune.go` entire, `Prunable`, the prunable
fixpoint, `pruned`/`gone`/`reportRefusal`, `Prune` the record, `OpPrune`,
`PruneCmd`, the `manyIdentities` threshold, and the stream hand-out for records
too large for a gossip datagram — a revocation becomes constant size, and it
was the only record that outgrew one.

## Work plan

One notable change per commit; each builds and passes on its own.

1. **`trust: materialize the membership after each change`** — recompute
   members, effective admissions, the name and slot indexes and the conflict
   map in one pass on change; point `members.go` and `Valid` at it. Delete the
   `sync.Map` cache and `forget`. No protocol change, no behaviour change.
2. **`cluster,cli: remove prune`** — the record, the control op, the command.
   It goes first: prune removes records signed by other identities, which is
   what leaves the gaps the next commit cannot step over. The branch reclaims
   nothing between here and commit 5.
3. **`trust: take a signer's records in sequence order`** — the contiguity rule
   on accept, and per-signer `head` in the state file. `Keeps` stays for now.
4. **`trust: revoke by sequence cut instead of a keep list`** — `Keeps` out,
   `UpTo` in; `cheesecloth revoke` gains `--up-to`.
5. **`trust: make a revocation permanent`** — drop the recursive revoker
   judgement and the withdrawn-revocation error path.
6. **`trust: drop the records a cut withdraws`** — the sweep.
7. **`docs: membership under sequence cuts`** — rewrite the affected sections
   of membership.md and fold this file into it.

Tests to add as they become relevant: permutation-invariance in `FuzzRecords`
(merge a record set in several orders, assert identical `Records()` and
membership); equivocation refused and alarmed; the sweep idempotent and
order-independent; `head` surviving a sweep across a restart.

## Security review

### The two decisions

**Revocation is permanent (R1).** A member holding a key can revoke every other
member and nothing undoes it; the cluster has to be rebuilt. That is the
intended behaviour, not a cost reluctantly accepted. In a network of peers
there is no way to tell a legitimate withdrawal of a revocation from a second
compromised member undoing the first, so a withdrawable revocation fails
silently toward inclusion while a permanent one fails loudly toward exclusion.
Fail-closed is the correct default and it is what the established designs do:
OpenPGP revocation certificates are deliberately irreversible, and X.509's one
un-revoking mechanism (`removeFromCRL`, certificate hold) is widely held to be
a misfeature. Requiring several signers before the membership list changes is
the real answer to the denial case; it is noted in TODO Phase M and out of
scope here.

A mis-revocation by an operator is likewise unrecoverable, but that is already
true: a revoked identity cannot rejoin, and the node needs a fresh identity.

**Attacks from inside are out of scope (R2).** `UpTo` names a position where
`Keeps` named records by signature, so a node that is behind the revoker on the
subject's sequence has a window in which it could take a forged record at its
next position. Closing it needs the revocation to pin the chain — a `Prev` hash
on every record and a `Head` hash in the revocation — which is a mitigation for
an attacker who already holds a member's key. The position of this project is
that such a cluster is compromised and gets rebuilt, so the mitigation is not
built: no `Prev`, no `Head`, no chain verification, and the equivocation alarm
keeps no enforcement teeth. This also removes 32 bytes per record, the chain
head from the state file, and a canonicalization surface.

Detection is kept, because rebuilding is a decision an operator can only take
if they are told. Two different records at one of a signer's numbers is still
reported as a key used outside its agent.

### Implementation risks

**I1. `head` per signer is security-critical persisted state.** It is what
makes a spent position stay spent after the record is deleted. A node restored
from an old state file would re-accept records at positions it had already
filled. This is a correctness requirement, not an attacker mitigation, so it
stands whatever the threat model: load `head` as `max(stored, derived from held
records)`, never lower one, and test it across a restart.

**I2. Deletion is automatic, so a bug in `cut` destroys records on disk.**
Today `prune` is operator-initiated and warns. Mitigations: compute the sweep
in the same pass as the membership so there is one code path to get right;
refuse to delete anything if the node would be left holding no standing
admission for itself; and delete at the state-file write rather than eagerly.

**I3. A peer can stall a node by withholding a record.** Withholding record *n*
blocks *n+1* and after. Availability only, the node takes the record from any
other peer at the next sync, and a node with a single peer can already be
starved. Noted, not designed for.

### Checked and found safe

- **Order-independence.** `cut` is a minimum, `revoked` a union, `chain` an
  existence test — all order-independent given the same records. The one hazard
  is the mutual dependence between `cut` and `counts`, which the visited guard
  settles the same way today's code does. It is the main correctness risk in
  the plan, which is why permutation-invariance goes into the fuzz test rather
  than being argued on paper.
- **Replay of a deleted record.** Above a cut, refused by the cut. At a spent
  position, refused by `head`. There is no third case, because nothing else is
  deleted.
- **A revoked identity rejoining.** Unchanged: permanent, needs a fresh
  identity.
- **Self-revocation.** `cheesecloth leave` signs `UpTo = head(self)`, which
  keeps everything the node signed, as today. A hand-made `UpTo = 0` destroys
  what it granted, as today.
- **The root.** Still a peer, still revocable by the same rule, still needs no
  admission. Nothing here makes it an authority.
- **Clocks.** No rule reads `IssuedAt`. `Seq` orders a signer's records and
  `UpTo` cuts them. Unchanged.
- **The enrolment ceiling.** Strictly better: revocations become constant size
  and withdrawn records vanish, so the 1 MiB welcome holds far more cluster.
