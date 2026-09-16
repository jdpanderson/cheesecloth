# Known issues

Defects and rough edges that are understood but not yet fixed, with whatever
workaround there is. These are things that should eventually change, as
distinct from the deliberate design tradeoffs in
[known limitations](operations.md#known-limitations), which are not expected to.

### A node too far behind does not notice for itself

A node that has been away while the cluster agreed 64 or more memberships
cannot walk from the one it holds to the present. Its peers notice — they will
not take the records it offers, and say so — but the node itself does not: it
keeps an obsolete membership, has its connections refused by every peer, and
says nothing about why. It should stop and tell the operator to enrol it again.

Until it does, the symptom is a node that comes up, configures its interface
from a membership nobody else shares, and never reaches anybody. The fix is to
enrol it again: `cheesecloth leave --force` on it, then a fresh invitation from
a member.
