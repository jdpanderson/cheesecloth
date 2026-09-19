package trust

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The founding node is the membership until one is agreed, and an admission is
// a proposal: it changes nothing until enough of the cluster attests to a
// membership that holds the joiner.
func Test_Set_genesis(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	assert.True(t, set.Valid(root.Public()))
	assert.Equal(t, 1, set.MemberCount())
	assert.Equal(t, QuorumMajority, set.Quorum())

	admit(t, set, root, a, "a", 2)
	assert.False(t, set.Valid(a.Public()), "admitted, but not a member of anything yet")
	assert.Equal(t, 1, set.MemberCount())
	m, ok := set.Proposal().Holds(a.Public())
	require.True(t, ok, "the records do propose it")
	assert.Equal(t, "a", m.Name)
	assert.Equal(t, uint64(2), m.Host)

	checkpoint(t, set, root) // the membership below is the root alone
	assert.True(t, set.Valid(a.Public()))
	m, ok = set.Lookup(a.Public())
	require.True(t, ok)
	assert.Equal(t, "a", m.Name)
	assert.Equal(t, uint64(2), m.Host)
}

// A checkpoint ratifies against the membership below it, and the membership is
// read from the list it states and from nothing else.
func Test_Set_checkpointRatifiesAndIsRead(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)

	checkpoint(t, set, root)
	assert.Equal(t, uint64(2), set.Depth(), "past the founding membership")
	base, ok := set.Anchor()
	require.True(t, ok)
	assert.Len(t, base.Members, 2)

	assert.True(t, set.Valid(a.Public()), "read from the checkpoint")
	assert.True(t, set.Valid(root.Public()))
}

// Trimming throws away what the checkpoint accounts for, and the membership is
// unchanged afterwards because the checkpoint is what states it.
func Test_Set_trimKeepsTheAnswer(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	require.Len(t, set.Records().Admissions, 2, "the founding membership needs no admission")

	checkpoint(t, set, root) // agreeing the membership is what spends them

	after := set.Records()
	assert.Empty(t, after.Admissions, "nothing is left to say who admitted whom")
	assert.Empty(t, after.Checkpoints, "the membership is the anchor, stated beside the records")
	agreed, ok := set.Anchor()
	require.True(t, ok)
	assert.Len(t, agreed.Members, 3)
	assert.Equal(t, 3, set.MemberCount(), "and everyone is still a member")
	assert.True(t, set.Valid(b.Public()))
}

// A revocation is a proposal like any other record: it takes its subject out
// when the cluster agrees a membership without it, and not before.
func Test_Set_revocationCountsOnceAgreed(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)

	ok, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, set.Valid(a.Public()), "still a member: nothing has agreed it is not")
	assert.True(t, set.Revoked(a.Public()), "but it is on its way out, so nothing re-admits it")
	_, proposed := set.Proposal().Holds(a.Public())
	assert.False(t, proposed)

	checkpoint(t, set, root)
	assert.False(t, set.Valid(a.Public()))
	assert.True(t, set.Valid(b.Public()))
	assert.Equal(t, 2, set.MemberCount())
}

// A revocation takes out the one member it names. A node that member admitted
// is a member in its own right and stays; the slot the subject held is free
// again.
func Test_Set_revocationTakesOutItsSubjectAlone(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	admit(t, set, a, b, "b", 3)
	checkpoint(t, set, root)
	require.True(t, set.Valid(b.Public()))

	_, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	assert.False(t, set.Valid(a.Public()))
	assert.True(t, set.Valid(b.Public()), "admitted by it, but a member in its own right")

	// and the slot the subject held is free again
	h, err := set.FreeHost(16)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), h)
}

// Once a checkpoint has ratified a removal, a record from before it cannot put
// the identity back: that is what makes trimming safe.
func Test_Set_aCheckpointSupersedesWhatItRemoved(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)

	old := Admit(root, a.Public(), "a", 2)
	_, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	require.False(t, set.Valid(a.Public()))

	_, err = set.AddAdmission(old)
	assert.ErrorIs(t, err, ErrSuperseded, "the record that first admitted it is history now")
	assert.False(t, set.Valid(a.Public()))
}

// Two members that revoke each other both go: each revocation is judged with
// the other held, and the guard makes neither count for its own signer.
func Test_Set_mutualRevocation(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)

	_, err := set.AddRevocation(Revoke(a, b.Public()))
	require.NoError(t, err)
	_, err = set.AddRevocation(Revoke(b, a.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	assert.False(t, set.Valid(a.Public()))
	assert.False(t, set.Valid(b.Public()))
	assert.True(t, set.Valid(root.Public()))
}

// A cluster of two is the one size where a majority is everybody, so majority
// is relaxed there: either node may agree a membership on its own. Without it a
// node that will not attest -- switched off, or the subject of the revocation
// and not co-operating -- would freeze the other's membership for good, since
// it could neither evict its peer nor enrol a third node to break the tie.
func Test_Set_twoNodeClusterAgreesWithEither(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	require.Equal(t, uint64(2), set.Depth())
	require.Equal(t, 2, set.MemberCount())

	// a is gone and attests to nothing; the root removes it by itself
	_, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	assert.Equal(t, uint64(3), set.Depth())
	assert.False(t, set.Valid(a.Public()))
	assert.Equal(t, 1, set.MemberCount())
}

// Above two it is an ordinary majority again, so one member of three cannot
// agree anything by itself.
func Test_Set_majorityAboveTwo(t *testing.T) {
	assert.Equal(t, 1, QuorumMajority.Size(1))
	assert.Equal(t, 1, QuorumMajority.Size(2), "the relaxed case")
	assert.Equal(t, 2, QuorumMajority.Size(3))
	assert.Equal(t, 3, QuorumMajority.Size(4))

	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	require.Equal(t, 3, set.MemberCount())

	_, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	assert.True(t, set.Valid(a.Public()), "one of three agrees nothing")
	checkpoint(t, set, root, b)
	assert.False(t, set.Valid(a.Public()), "two of three do")
}

// A node keeps the membership it has satisfied itself of, not the history that
// led to it: there is no walk, so churn past the retention depth costs nothing
// and a restart from the anchor reaches the same answer.
func Test_Set_startsFromWhatItHasVerified(t *testing.T) {
	root, keep := newID(t), newID(t)
	set := found(t, root, "1") // a cluster of one ratifies on its own
	admit(t, set, root, keep, "keep", 2)
	checkpoint(t, set, root)

	for i := range Keep {
		id := newID(t)
		admit(t, set, root, id, "n", 3)
		checkpoint(t, set, root)
		_, err := set.AddRevocation(Revoke(root, id.Public()))
		require.NoError(t, err)
		checkpoint(t, set, root)
		require.True(t, set.Valid(keep.Public()), "round %d", i)
	}
	require.Greater(t, set.Depth(), uint64(Keep))
	assert.LessOrEqual(t, len(set.Records().Checkpoints), 2, "and everything behind it is let go of")

	anchor, ok := set.Anchor()
	require.True(t, ok)
	b, err := json.Marshal(set.Records())
	require.NoError(t, err)
	var back Records
	require.NoError(t, json.Unmarshal(b, &back))

	// a restart starts where it left off, with none of the history
	reloaded := NewSet()
	require.NoError(t, reloaded.Adopt(anchor))
	reloaded.Merge(back)
	assert.Equal(t, set.Depth(), reloaded.Depth(), "and reaches the same answer")
	assert.True(t, reloaded.Valid(keep.Public()))
	assert.Equal(t, 2, reloaded.MemberCount())
}

// A node given nothing but a membership can use it: that is what a joiner does,
// on the strength of the token exchange rather than of any history.
func Test_Set_AdoptNeedsNoHistory(t *testing.T) {
	root, keep := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, keep, "keep", 2)
	checkpoint(t, set, root)
	anchor, ok := set.Anchor()
	require.True(t, ok)

	fresh := NewSet()
	require.NoError(t, fresh.Adopt(anchor))
	assert.Equal(t, 2, fresh.MemberCount(), "with no records at all")
	assert.True(t, fresh.Valid(keep.Public()))
	assert.Equal(t, anchor.Depth, fresh.Depth())

	// and it will not give up ground it has already covered
	shallower := Propose(root, 1, Digest{}, QuorumMajority, 0, []Member{{Identity: root.Public(), Name: "root", Host: 1}}, nil)
	assert.ErrorContains(t, fresh.Adopt(shallower), "no further on than the one this node holds")
}

// Only a member may propose anything, and a member is what an agreed membership
// names. A node that has been admitted but not yet agreed on cannot admit or
// revoke, which is what makes the rule flat: nothing has to ask whether the
// signer of a record was admitted by somebody who was admitted by somebody.
func Test_Set_onlyMembersMayPropose(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)

	// a has been admitted, but the cluster has agreed nothing yet, so nothing
	// it signs could count -- and a record that could never count is not
	// stored, whoever offers it
	admits, revokes := Admit(a, b.Public(), "b", 3), Revoke(a, root.Public())
	_, err := set.AddAdmission(admits)
	assert.ErrorIs(t, err, ErrSuperseded, "a cannot admit until the cluster has agreed on a")
	_, err = set.AddRevocation(revokes)
	assert.ErrorIs(t, err, ErrSuperseded, "nor revoke")
	assert.Len(t, set.Records().Admissions, 1, "only a's own, which the root signed")

	checkpoint(t, set, root)
	require.True(t, set.Valid(a.Public()), "now a is a member")

	// and what a peer offers at the next sync is taken, which is why refusing
	// early loses nothing: whoever signed it goes on offering it
	res := set.Merge(Records{Admissions: []Admission{admits}, Revocations: []Revocation{revokes}})
	require.Equal(t, 2, res.Changed)
	checkpoint(t, set, root)
	assert.True(t, set.Valid(b.Public()), "and now both of a's records count")
	assert.False(t, set.Valid(root.Public()))
}

// The quorum rule is the cluster's, carried in the root's own record, so no
// node's configuration can make it disagree with its peers.
func Test_Set_quorumComesFromTheRecords(t *testing.T) {
	root := newID(t)
	set := found(t, root, "2")
	assert.Equal(t, QuorumRule("2"), set.Quorum())
	assert.Equal(t, 2, QuorumRule("2").Size(5))
	assert.Equal(t, 3, QuorumMajority.Size(5))
	assert.Equal(t, 2, QuorumHalf.Size(5))
	assert.Error(t, QuorumRule("0").Check())
	assert.Error(t, QuorumRule("most").Check())
}

// A revocation counts only from a member, and that holds for the one record a
// node may sign about itself. Without it, anyone who ever held an invitation --
// or anyone at all, since the signature is over the signer's own key -- could
// sign a revocation of any member they liked.
func Test_Set_onlyMembersMayRevoke(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	require.Equal(t, 2, set.MemberCount())

	stranger := newID(t)
	_, err := set.AddRevocation(Revoke(stranger, stranger.Public()))
	assert.ErrorIs(t, err, ErrSuperseded, "well formed, but no signature that could ever count")
	assert.Empty(t, set.Records().Revocations, "so it is not kept either")
	assert.Len(t, set.Proposal().Members, 2, "a stranger's revocation proposes nothing")
	checkpoint(t, set, root)
	assert.Equal(t, 2, set.MemberCount(), "and takes nobody out")
	assert.True(t, set.Valid(root.Public()))
	assert.True(t, set.Valid(a.Public()))
}

// The same holds for a node the cluster has not agreed on yet: it may be
// admitted and revoked, but nothing it signs about itself reaches anybody else.
func Test_Set_aNewcomerSignsNothingThatCounts(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)

	_, err := set.AddRevocation(Revoke(a, a.Public()))
	assert.ErrorIs(t, err, ErrSuperseded, "a is no member yet, so nothing it signs is kept")
	_, still := set.Proposal().Holds(root.Public())
	assert.True(t, still, "a cannot take the root out by leaving")
	checkpoint(t, set, root)
	assert.True(t, set.Valid(root.Public()))
}

// Two joiners given the same name by different members contest it, and a
// membership naming both could never be agreed. The loser is left out of the
// proposal altogether rather than admitted and then found to be unusable, and
// every node leaves out the same one.
func Test_Set_aContestedNameLeavesTheLoserOut(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)

	x, y := newID(t), newID(t)
	_, err := set.AddAdmission(Admit(root, x.Public(), "dup", 3))
	require.NoError(t, err)
	_, err = set.AddAdmission(Admit(a, y.Public(), "dup", 4))
	require.NoError(t, err)

	p := set.Proposal()
	require.Len(t, p.Members, 3, "one of the two, never both")
	names, hosts := map[string]bool{}, map[uint64]bool{}
	for _, m := range p.Members {
		require.False(t, names[m.Name], "a membership that could never be agreed")
		require.False(t, hosts[m.Host])
		names[m.Name], hosts[m.Host] = true, true
	}

	winner := x
	if _, ok := p.Holds(y.Public()); ok {
		winner = y
	}
	// the same one whichever order the records arrived in
	other := NewSet()
	anchor, _ := set.Anchor()
	require.NoError(t, other.Adopt(anchor))
	_, err = other.AddAdmission(Admit(a, y.Public(), "dup", 4))
	require.NoError(t, err)
	_, err = other.AddAdmission(Admit(root, x.Public(), "dup", 3))
	require.NoError(t, err)
	_, ok := other.Proposal().Holds(winner.Public())
	assert.True(t, ok, "and it is the same winner either way")
	assert.Len(t, other.Proposal().Members, 3)

	checkpoint(t, set, root)
	assert.True(t, set.Valid(winner.Public()))
	assert.Equal(t, 3, set.MemberCount(), "the loser never became a member")
}

// A revocation the cluster has yet to agree still names a member of the anchor,
// so a trim must not take that identity for one the membership fully accounts
// for. If it did, the only record saying the node is on its way out would be
// discarded and the admission that let it in would stand again.
func Test_Set_trimKeepsARevocationNotYetAgreed(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	require.Equal(t, 3, set.MemberCount(), "and from here a majority is two of the three")

	_, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root) // the root alone cannot agree it
	require.True(t, set.Valid(a.Public()))

	assert.True(t, set.Revoked(a.Public()), "the revocation is still held")
	_, proposed := set.Proposal().Holds(a.Public())
	assert.False(t, proposed, "and still proposes the membership without it")

	checkpoint(t, set, root, b) // which is agreed as soon as another attests too
	assert.False(t, set.Valid(a.Public()))
}

// An identity the cluster removed is named as gone for Keep agreements and then
// forgotten. Without that, every membership would carry one entry for every
// node that ever left, for the life of the cluster, and each of the retained
// checkpoints would carry the whole list with it.
func Test_Set_removedIsForgotten(t *testing.T) {
	root, x := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, x, "x", 2)
	checkpoint(t, set, root)
	_, err := set.AddRevocation(Revoke(root, x.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	require.False(t, set.Valid(x.Public()))

	anchor, ok := set.Anchor()
	require.True(t, ok)
	require.Len(t, anchor.Removed, 1, "and it says when x went")
	went := anchor.Removed[0].Depth
	require.Equal(t, x.Public(), anchor.Removed[0].Identity)

	// while the cluster is within Keep agreements of the removal, x stays
	// named, and nothing puts it back
	for set.Depth() < went+Keep {
		checkpoint(t, set, root)
		require.True(t, set.Revoked(x.Public()), "still remembered at depth %d", set.Depth())
	}
	cur, _ := set.Anchor()
	require.Len(t, cur.Removed, 1, "named right up to the edge of the window")

	// and the membership past it drops the entry
	checkpoint(t, set, root)
	cur, _ = set.Anchor()
	assert.Empty(t, cur.Removed, "forgotten once no node that can still catch up could hold the record")
	assert.False(t, set.Revoked(x.Public()))
	assert.False(t, set.Valid(x.Public()), "forgotten is not the same as a member")
}

// Forgetting is safe because of what a peer does on its way here. A peer still
// holding the admission takes the checkpoints between its anchor and this one,
// every one of which names what it removed, and discards the record on the way.
// So by the time the entry is dropped there is no copy left to offer back.
func Test_Set_aPeerCatchingUpLetsGoOfWhatWasRemoved(t *testing.T) {
	root, x := newID(t), newID(t)
	set := found(t, root, "1")
	old := Admit(root, x.Public(), "x", 2)
	_, err := set.AddAdmission(old)
	require.NoError(t, err)
	checkpoint(t, set, root)

	// a peer that has the admission and has seen nothing since
	peer := NewSet()
	require.NoError(t, peer.Adopt(Found(root, "root", "1", 0)))
	_, err = peer.AddAdmission(old)
	require.NoError(t, err)
	require.Len(t, peer.Records().Admissions, 1)

	_, err = set.AddRevocation(Revoke(root, x.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	require.Empty(t, set.Records().Admissions, "the admission is history here")

	here, _ := set.Anchor()
	peer.MergeFrom(&here, set.Records())
	assert.Equal(t, set.Depth(), peer.Depth(), "the peer reaches the present")
	assert.False(t, peer.Valid(x.Public()))
	assert.Empty(t, peer.Records().Admissions, "and has nothing left to offer back")

	// and until it has caught up, the entry is what refuses the record
	stale := NewSet()
	anchor, _ := set.Anchor()
	require.NoError(t, stale.Adopt(anchor))
	_, err = stale.AddAdmission(old)
	assert.ErrorIs(t, err, ErrSuperseded, "a replay while the removal is still named")
	assert.False(t, stale.Valid(x.Public()))
}

// The other half of forgetting safely: a set too far behind to walk to this one
// is not taken at its word about who is a member. It never saw the memberships
// in between, so it can still hold an admission one of them accounted for, and
// once the identity has been forgotten there is nothing left to refuse it by.
// A set that can still reach here is taken as usual.
func Test_Set_admissionsFromTooFarBehindAreNotTaken(t *testing.T) {
	root, x := newID(t), newID(t)
	set := found(t, root, "1")
	old := Admit(root, x.Public(), "x", 2)
	_, err := set.AddAdmission(old)
	require.NoError(t, err)

	// what a peer that stopped here holds, admission and all: taken before the
	// membership is agreed, which is when this set lets go of it. Its anchor is
	// what says how far back it stopped; its records cannot say.
	behind := set.Records()
	behindAt, _ := set.Anchor()
	require.NotEmpty(t, behind.Admissions)

	checkpoint(t, set, root)
	require.True(t, set.Valid(x.Public()))

	// a set only a little further on takes it, and refuses it on its own terms
	near := NewSet()
	anchor, _ := set.Anchor()
	require.NoError(t, near.Adopt(anchor))
	res := near.MergeFrom(&behindAt, behind)
	assert.Zero(t, res.Stale, "near enough to walk here, so its records are judged")

	// meanwhile the cluster removes x and carries on until it has forgotten it
	_, err = set.AddRevocation(Revoke(root, x.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	for cur, _ := set.Anchor(); len(cur.Removed) > 0; cur, _ = set.Anchor() {
		checkpoint(t, set, root)
	}
	require.False(t, set.Valid(x.Public()))
	require.False(t, set.Revoked(x.Public()), "x is forgotten, so nothing refuses its admission by name")

	res = set.MergeFrom(&behindAt, behind)
	assert.Equal(t, 1, res.Stale, "but the records come from too far back to be taken")
	assert.False(t, set.Valid(x.Public()))
	_, proposed := set.Proposal().Holds(x.Public())
	assert.False(t, proposed, "so nothing puts it back")
}

// Records the cluster can never act on do not pile up. A membership only ever
// names its own members and what it recently removed, so without this a record
// about anybody else would be kept for the life of the cluster: nothing would
// ever say it was spent.
func Test_Set_recordsThatCanNeverCountAreCollected(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	require.Empty(t, set.Records().Admissions)

	// a name or a slot a member holds: settled, so it is not even taken
	_, err := set.AddAdmission(Admit(root, newID(t).Public(), "a", 9))
	assert.ErrorIs(t, err, ErrSuperseded, "the membership gave that name to somebody else")
	_, err = set.AddAdmission(Admit(root, newID(t).Public(), "other", 2))
	assert.ErrorIs(t, err, ErrSuperseded, "and that slot")

	// a membership nobody this node knows has signed: it would be kept for
	// good, since the trim reaches nothing past the anchor
	nobody := newID(t)
	far := Propose(nobody, Keep*10, Digest{}, QuorumMajority, 0,
		[]Member{{Identity: nobody.Public(), Name: "nobody", Host: 1}}, nil)
	_, err = set.AddCheckpoint(far)
	assert.ErrorContains(t, err, "has been away too long")

	// and an admission signed by somebody no membership names is refused
	// outright: no signature that could ever make it count
	stranger, ghost := newID(t), newID(t)
	_, err = set.AddAdmission(Admit(stranger, ghost.Public(), "ghost", 7))
	assert.ErrorIs(t, err, ErrSuperseded)
	assert.Empty(t, set.Records().Admissions, "nobody the cluster holds vouches for it")

	checkpoint(t, set, root)
	assert.Equal(t, 2, set.MemberCount(), "and none of it changed the membership")
	assert.False(t, set.Valid(ghost.Public()))
}

// A name or a slot comes free when the cluster has agreed the membership that
// gave it up, and not when a record merely proposes to. Handing one out sooner
// makes an admission that every node which has not yet seen the removal
// refuses, since its own membership still has somebody there.
func Test_Set_aSlotIsNotFreeUntilTheRemovalIsAgreed(t *testing.T) {
	root, a, next := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)

	_, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	_, proposed := set.Proposal().Holds(a.Public())
	require.False(t, proposed, "a is on its way out")

	h, err := set.FreeHost(16)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), h, "but its slot is not handed out yet")
	assert.True(t, set.NameTaken("a", next.Public()), "nor its name")

	checkpoint(t, set, root)
	h, err = set.FreeHost(16)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), h, "and once the cluster has agreed it, both come free")
	assert.False(t, set.NameTaken("a", next.Public()))
}

// A node that has been away takes the membership the cluster is on now in a
// single step, however far ahead it is, as long as a quorum of the members it
// still knows about signed it. When the cluster has turned over further than
// that, nothing it is offered can ever be taken, and it has to say so: otherwise
// it goes on configuring peers from a membership the cluster left behind --
// trusting nodes since revoked, and refusing ones since admitted.
func Test_Set_strandedWhenTheClusterIsOutOfReach(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	require.Equal(t, 2, set.MemberCount())
	_, stranded := set.Stranded()
	require.False(t, stranded, "it has seen nothing beyond its own membership")

	members := []Member{
		{Identity: root.Public(), Name: "root", Host: 1},
		{Identity: a.Public(), Name: "a", Host: 2},
	}
	jump := Propose(root, set.Depth()+500, Digest{}, QuorumMajority, 0, members, nil)
	_, err := set.AddCheckpoint(jump)
	require.NoError(t, err)
	assert.Equal(t, jump.Depth, set.Depth(), "five hundred memberships on, in one step and with no chain")
	_, stranded = set.Stranded()
	assert.False(t, stranded)

	// and one signed by nobody it knows cannot be taken, whatever arrives
	// later: attestations only ever accumulate on a digest
	nobody := newID(t)
	gone := Propose(nobody, set.Depth()+1, Digest{}, QuorumMajority, 0,
		[]Member{{Identity: nobody.Public(), Name: "x", Host: 1}}, nil)
	_, err = set.AddCheckpoint(gone)
	assert.ErrorContains(t, err, "away too long", "and it is not stored, since it could never be used")
	seen, stranded := set.Stranded()
	assert.Equal(t, gone.Depth, seen, "what it could not take still says where the cluster is")
	assert.True(t, stranded)
}

// Once a membership has been stated, a node that agrees with it has nothing to
// add but its signature. The set takes one on its own, and an agreement that
// arrives before the membership it is for is kept rather than lost to the order
// two datagrams happen to arrive in.
func Test_Set_AddAttestation(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	require.Equal(t, 3, set.MemberCount(), "and from here a majority is two of the three")

	// a membership the root has stated and nobody else has signed yet
	c := newID(t)
	admit(t, set, root, c, "c", 4)
	p := set.Proposal()
	base, _ := set.Anchor()
	stated := Propose(root, p.Depth, base.Digest(), base.Quorum, 0, p.Members, p.Removed)
	_, err := set.AddCheckpoint(stated)
	require.NoError(t, err)
	require.False(t, set.Valid(c.Public()), "one of three is not a majority")
	require.True(t, set.Holds(stated.Digest()))

	_, err = set.AddAttestation(stated.Digest(), Attest(a, stated.Digest()))
	require.NoError(t, err)
	assert.True(t, set.Valid(c.Public()), "the second signature agrees it, and it carried no membership")

	// a signature over something else, from anybody, is not one
	forged := Attest(b, stated.Digest())
	forged.Signature[0] ^= 1
	_, err = set.AddAttestation(stated.Digest(), forged)
	assert.ErrorContains(t, err, "does not verify")
}

// An agreement that outruns the membership it is for is kept until it arrives,
// so nothing is lost to the order two datagrams reach a node in. Only from a
// member: what is kept is then bounded by the membership.
func Test_Set_anAttestationMayOutrunItsMembership(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)

	// what the cluster is about to agree, worked out here but not yet held
	c := newID(t)
	other := NewSet()
	anchor, _ := set.Anchor()
	require.NoError(t, other.Adopt(anchor))
	_, err := other.AddAdmission(Admit(root, c.Public(), "c", 4))
	require.NoError(t, err)
	p := other.Proposal()
	coming := Propose(root, p.Depth, anchor.Digest(), anchor.Quorum, 0, p.Members, p.Removed)

	// a's agreement arrives first, and a stranger's is not kept at all
	ok, err := set.AddAttestation(coming.Digest(), Attest(a, coming.Digest()))
	require.NoError(t, err)
	assert.True(t, ok, "kept: a is a member")
	ok, err = set.AddAttestation(coming.Digest(), Attest(newID(t), coming.Digest()))
	require.NoError(t, err)
	assert.False(t, ok, "dropped: a stranger's says nothing this node could use")

	// then the membership itself, with only the root's signature on it
	_, err = set.AddAdmission(Admit(root, c.Public(), "c", 4))
	require.NoError(t, err)
	_, err = set.AddCheckpoint(coming)
	require.NoError(t, err)
	assert.True(t, set.Valid(c.Public()), "the root's and a's together agree it")
}

// A revocation may name any identity at all. Only what the cluster knows about
// is remembered as removed, or a record could put an identity nobody has heard
// of into every checkpoint, state file and welcome, and refuse it enrolment for
// as long as it was named. Such a record is refused outright: the membership
// already accounts for an identity it has never heard of.
func Test_Set_aRevocationOnlyRemembersWhatTheClusterKnows(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)

	stranger := newID(t).Public()
	_, err := set.AddRevocation(Revoke(root, stranger))
	assert.ErrorIs(t, err, ErrSuperseded, "nobody ever admitted it, so there is nothing to take out")
	assert.Empty(t, set.Records().Revocations, "so it is not kept")
	assert.Empty(t, set.Proposal().Removed, "and nothing is remembered as removed")
	checkpoint(t, set, root)
	assert.False(t, set.Revoked(stranger))
	assert.Equal(t, 2, set.MemberCount(), "and nobody went out")

	_, err = set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	assert.Len(t, set.Proposal().Removed, 1, "a member the cluster does know is remembered")
	checkpoint(t, set, root)
	assert.False(t, set.Valid(a.Public()), "the member it named goes")
	assert.True(t, set.Revoked(a.Public()))
	assert.Empty(t, set.Records().Revocations, "and that record is spent too")
}

// A membership nobody has signed is not one, and a claim about where the
// cluster has got to stops counting as soon as this node demonstrably keeps up
// with it. Neither makes a forged depth impossible -- only a member can send
// one, and a member has better things to do -- but between them a false alarm
// costs the cheapest forgery nothing and lasts only until the next real change.
func Test_Set_aStaleClaimAboutTheClusterStopsCounting(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)

	unsigned := Checkpoint{Depth: 1 << 40, Quorum: QuorumMajority,
		Members: []Member{{Identity: newID(t).Public(), Name: "ghost", Host: 1}}}
	assert.ErrorContains(t, unsigned.Validate(), "carries no attestations")

	nobody := newID(t)
	signed := Propose(nobody, 1<<40, Digest{}, QuorumMajority, 0,
		[]Member{{Identity: nobody.Public(), Name: "ghost", Host: 1}}, nil)
	_, err := set.AddCheckpoint(signed)
	require.Error(t, err, "nobody this node knows signed it, so it can never be taken")
	seen, stranded := set.Stranded()
	require.Equal(t, signed.Depth, seen)
	require.True(t, stranded, "and on the face of it the cluster has gone somewhere unreachable")

	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	seen, stranded = set.Stranded()
	assert.Equal(t, set.Depth(), seen, "but the node is keeping up, so the claim is stale evidence")
	assert.False(t, stranded)
}

// A member can offer any record it likes, and the ones nobody could ever act
// on must not reach memory, the state file or the wire. A signature that could
// never make a record count is refused at the door rather than stored and
// judged later, and the collection runs on the sync as well as when the
// membership moves -- a cluster that is not changing never moves it.
func Test_Set_recordsNoSignatureCouldMakeCountAreNotKept(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	require.Empty(t, set.Records().Admissions, "a settled cluster holds nothing but its membership")

	var junk Records
	for i := range 100 {
		stranger := newID(t)
		junk.Admissions = append(junk.Admissions, Admit(stranger, newID(t).Public(), "j"+string(rune('a'+i%26)), uint64(900+i)))
		junk.Revocations = append(junk.Revocations, Revoke(stranger, a.Public()))
	}
	// offered one at a time, as gossip carries them
	for _, adm := range junk.Admissions {
		_, err := set.AddAdmission(adm)
		require.ErrorIs(t, err, ErrSuperseded)
	}
	for _, rev := range junk.Revocations {
		_, err := set.AddRevocation(rev)
		require.ErrorIs(t, err, ErrSuperseded)
	}
	// and in a state sync, which carries a peer's whole set
	res := set.Merge(junk)
	assert.Zero(t, res.Changed)
	assert.Equal(t, 200, res.Superseded)

	held := set.Records()
	assert.Empty(t, held.Admissions)
	assert.Empty(t, held.Revocations)
	assert.Empty(t, held.Checkpoints, "and the membership is not among them: it is the anchor")
	assert.Equal(t, 2, set.MemberCount())
	assert.True(t, set.Valid(a.Public()), "and none of it touched the membership")
}

// With confirmations asked for, one member's signature is no longer enough:
// the record is held and does nothing until another member agrees with it.
// This is the trade a cluster makes when one key should not be able to change
// the membership by itself.
func Test_Set_aRecordWaitsForItsConfirmations(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := NewSet()
	require.NoError(t, set.Adopt(Found(root, "root", "1", 1)))
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	require.Equal(t, 3, set.MemberCount(), "the founding membership asks for nobody to confirm it")
	require.Equal(t, 1, set.Confirmations())

	j := newID(t)
	adm := Admit(root, j.Public(), "j", 4)
	_, err := set.AddAdmission(adm)
	require.NoError(t, err, "the record is kept; it is what is waiting")
	_, proposed := set.Proposal().Holds(j.Public())
	assert.False(t, proposed, "but one member's signature does not admit anybody")

	waiting := set.Awaiting()
	require.Len(t, waiting, 1)
	assert.Equal(t, "admission", waiting[0].Kind)
	assert.Equal(t, "j", waiting[0].Name)
	assert.Equal(t, root.Public(), waiting[0].Signer)
	assert.Equal(t, 0, waiting[0].Have)
	assert.Equal(t, 1, waiting[0].Need)

	// the signer confirming its own record is not a second pair of eyes
	_, err = set.AddConfirmation(Confirm(root, adm.Digest()))
	require.NoError(t, err)
	_, proposed = set.Proposal().Holds(j.Public())
	assert.False(t, proposed, "the member that signed it cannot confirm it")

	// nor is somebody the cluster does not know
	_, err = set.AddConfirmation(Confirm(newID(t), adm.Digest()))
	assert.ErrorIs(t, err, ErrSuperseded)

	_, err = set.AddConfirmation(Confirm(a, adm.Digest()))
	require.NoError(t, err)
	_, proposed = set.Proposal().Holds(j.Public())
	assert.True(t, proposed, "and a second member's agreement admits it")
	assert.Empty(t, set.Awaiting(), "nothing is waiting any more")

	checkpoint(t, set, root)
	assert.True(t, set.Valid(j.Public()))
}

// A revocation waits the same way, so one key cannot take a member out either.
func Test_Set_aRevocationWaitsForItsConfirmations(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := NewSet()
	require.NoError(t, set.Adopt(Found(root, "root", "1", 1)))
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)

	rev := Revoke(root, a.Public())
	_, err := set.AddRevocation(rev)
	require.NoError(t, err)
	checkpoint(t, set, root)
	assert.True(t, set.Valid(a.Public()), "one member cannot take another out on its own")
	require.Len(t, set.Awaiting(), 1)

	_, err = set.AddConfirmation(Confirm(b, rev.Digest()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	assert.False(t, set.Valid(a.Public()), "with a second member's agreement it goes")
}

// The cluster asks for what it can supply. A setting larger than the membership
// would freeze a small cluster, so it is clamped to one short of it -- and the
// clamp reads the agreed membership, which every node computes the same way,
// rather than who happens to be reachable, which they would not.
func Test_Set_confirmationsAreClampedToTheMembership(t *testing.T) {
	root, a := newID(t), newID(t)
	set := NewSet()
	require.NoError(t, set.Adopt(Found(root, "root", "1", 5)))
	assert.Equal(t, 0, set.Confirmations(), "a cluster of one asks nobody")

	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	require.Equal(t, 2, set.MemberCount())
	assert.Equal(t, 1, set.Confirmations(), "a cluster of two asks the other one")

	// and it grows with the cluster: each new node needs one more agreement
	// than the last, until the setting itself is reached
	confirmers := []*Identity{a}
	for i := range 3 {
		id := newID(t)
		adm := Admit(root, id.Public(), string(rune('c'+i)), uint64(i+3))
		_, err := set.AddAdmission(adm)
		require.NoError(t, err)
		require.Equal(t, len(confirmers), set.Confirmations(), "round %d", i)
		for _, by := range confirmers {
			_, err = set.AddConfirmation(Confirm(by, adm.Digest()))
			require.NoError(t, err)
		}
		checkpoint(t, set, root)
		require.True(t, set.Valid(id.Public()), "round %d", i)
		confirmers = append(confirmers, id)
	}
	require.Equal(t, 5, set.MemberCount())
	assert.Equal(t, 4, set.Confirmations(), "and five asks four, which is all it has")

	// past that the setting is what binds, not the size
	sixth := Admit(root, newID(t).Public(), "f", 9)
	_, err := set.AddAdmission(sixth)
	require.NoError(t, err)
	for _, by := range confirmers[:3] {
		_, err = set.AddConfirmation(Confirm(by, sixth.Digest()))
		require.NoError(t, err)
	}
	_, proposed := set.Proposal().Holds(sixth.Identity)
	assert.False(t, proposed, "three of the four it asks for is not enough")
	_, err = set.AddConfirmation(Confirm(confirmers[3], sixth.Digest()))
	require.NoError(t, err)
	_, proposed = set.Proposal().Holds(sixth.Identity)
	assert.True(t, proposed, "and the fourth admits it")
}

// What a revocation would take out is what it takes out once confirmed, not
// what it does while it is waiting -- which is nothing. Asked the other way, an
// agent would refuse to sign any revocation in a cluster that asks for
// confirmations, since every one of them starts out doing nothing.
func Test_Set_WithdrawsAnswersForAConfirmedRecord(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := NewSet()
	require.NoError(t, set.Adopt(Found(root, "root", "1", 1)))
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	require.Equal(t, 1, set.Confirmations())

	gone := set.Withdraws(Revoke(root, a.Public()))
	require.Len(t, gone, 1, "the member it names goes, once somebody agrees")
	assert.Equal(t, "a", gone[0].Name)
}

// A trial counts its confirmations against the agreed membership, so that is
// where they have to come from. A revocation already signed and confirmed
// leaves the proposal a member short of that membership, and a trial supplied
// from the proposal then falls short of what it asks of itself: it answers that
// a revocation which works does nothing, and the agent refuses to sign it,
// telling the operator this node is no longer a member of its own cluster.
func Test_Set_WithdrawsAnswersWithARevocationAlreadyInFlight(t *testing.T) {
	root, x, y, z, j := newID(t), newID(t), newID(t), newID(t), newID(t)
	set := NewSet()
	require.NoError(t, set.Adopt(Found(root, "root", "1", 5))) // clamped to one short of the membership
	confirmBy := func(d Digest, ids ...*Identity) {
		t.Helper()
		for _, id := range ids {
			_, err := set.AddConfirmation(Confirm(id, d))
			require.NoError(t, err)
		}
	}
	admitted := func(admitter, id *Identity, name string, host uint64, by ...*Identity) {
		t.Helper()
		a := Admit(admitter, id.Public(), name, host)
		_, err := set.AddAdmission(a)
		require.NoError(t, err)
		confirmBy(a.Digest(), by...)
	}

	admitted(root, x, "x", 2) // one member so far, so nothing to confirm
	checkpoint(t, set, root)
	admitted(root, y, "y", 3, x)
	checkpoint(t, set, root)
	admitted(root, z, "z", 4, x, y)
	checkpoint(t, set, root)
	require.Equal(t, 4, set.MemberCount())
	require.Equal(t, 3, set.Confirmations())

	// x admits j, and the cluster has not agreed a membership holding it yet
	admitted(x, j, "j", 5, root, y, z)
	_, proposed := set.Proposal().Holds(j.Public())
	require.True(t, proposed, "j is proposed, through x's admission")

	// and a revocation of y is signed and confirmed, waiting to be agreed
	rev := Revoke(root, y.Public())
	_, err := set.AddRevocation(rev)
	require.NoError(t, err)
	confirmBy(rev.Digest(), x, y, z)
	_, stillY := set.Proposal().Holds(y.Public())
	require.False(t, stillY, "y is on its way out, so the proposal is a member short")

	gone := set.Withdraws(Revoke(root, x.Public()))
	require.Len(t, gone, 2, "revoking x takes x out, whatever else is in flight")
	assert.Equal(t, "j", gone[0].Name, "and j with it, since x is what admitted it")
	assert.Equal(t, "x", gone[1].Name)
}

// What was refused is counted out of what was judged, which is counted where
// the refusals are. The anchor a peer states is judged alongside the records it
// carries and is not one of them -- and it is the one a node behind its peer
// refuses -- so a count taken from the records alone reads as a refusal out of
// nothing at all.
func Test_Set_MergeFromCountsWhatItJudged(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	base, ok := set.Anchor()
	require.True(t, ok)

	// a membership nobody this node holds has attested to, stated as the
	// sender's own anchor: refused, and not one of the records it carries
	stranger := newID(t)
	far := Propose(stranger, base.Depth+1, base.Digest(), base.Quorum, 0,
		[]Member{{Identity: stranger.Public(), Name: "s", Host: 9}}, nil)

	res := set.MergeFrom(&far, Records{})
	assert.Equal(t, 1, res.Refused)
	assert.Equal(t, 1, res.Judged, "the anchor was judged, and it was all there was to judge")

	// and it counts across the kinds of record, not just the ones in the bag
	res = set.MergeFrom(&far, Records{Revocations: []Revocation{Revoke(root, a.Public())}})
	assert.Equal(t, 1, res.Refused, "the anchor again")
	assert.Equal(t, 1, res.Changed, "and a revocation this node takes")
	assert.Equal(t, 2, res.Judged)
}

// An attestation waiting for a membership that has not arrived is kept one per
// signer, which is what makes it bounded -- but only while the signer is one of
// the members. One from a member that has since gone waits for a membership
// that may never come and could not be counted if it did, so it goes with the
// member. One from a member still standing stays: the membership it is for
// comes back at the next state sync, and this is what holds the agreement
// meanwhile.
func Test_Set_pendingGoesWithTheMemberThatSignedIt(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	require.Equal(t, 3, set.MemberCount())

	// both attest to a membership this node has never been given
	absent := Digest{9, 9, 9}
	for _, id := range []*Identity{a, b} {
		ok, err := set.AddAttestation(absent, Attest(id, absent))
		require.NoError(t, err)
		require.True(t, ok, "kept until the membership it is for arrives")
	}
	require.Len(t, set.pending, 2)

	// a is revoked, and the cluster agrees a membership without it
	_, err := set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	require.False(t, set.Valid(a.Public()), "a is out")

	require.Len(t, set.pending, 1, "what a was waiting on goes with it")
	_, held := set.pending[b.Public()]
	assert.True(t, held, "and b is still a member, so what it signed is still worth holding")
}

// Two members admitting the same identity is a contest, and every node has to
// settle it the same way: one that picked the other record would give the
// identity a different name or slot and propose a membership the rest could
// never agree. The rule is the smaller admitter, and between two records from
// one admitter the smaller signature -- neither of which depends on the order
// they arrived in.
func Test_Set_oneIdentityAdmittedTwice(t *testing.T) {
	root, m1, m2, j := newID(t), newID(t), newID(t), newID(t)
	build := func(order ...Admission) Proposal {
		t.Helper()
		set := found(t, root, "1")
		admit(t, set, root, m1, "m1", 2)
		admit(t, set, root, m2, "m2", 3)
		checkpoint(t, set, root)
		require.Equal(t, 3, set.MemberCount())
		for _, a := range order {
			ok, err := set.AddAdmission(a)
			require.NoError(t, err)
			require.True(t, ok)
		}
		return set.Proposal()
	}

	// two admitters, each naming the joiner its own way
	byM1 := Admit(m1, j.Public(), "by-m1", 4)
	byM2 := Admit(m2, j.Public(), "by-m2", 5)
	want := "by-m1"
	if byIdentity(m2.Public(), m1.Public()) < 0 {
		want = "by-m2"
	}
	for _, order := range [][]Admission{{byM1, byM2}, {byM2, byM1}} {
		held, ok := build(order...).Holds(j.Public())
		require.True(t, ok)
		assert.Equal(t, want, held.Name, "the smaller admitter speaks for the identity, whichever arrived first")
	}

	// and one admitter that named it twice: the smaller signature wins
	first := Admit(m1, j.Public(), "first", 6)
	second := Admit(m1, j.Public(), "second", 7)
	wantSig := "first"
	if slices.Compare(second.Signature, first.Signature) < 0 {
		wantSig = "second"
	}
	for _, order := range [][]Admission{{first, second}, {second, first}} {
		held, ok := build(order...).Holds(j.Public())
		require.True(t, ok)
		assert.Equal(t, wantSig, held.Name, "the smaller signature settles it, whichever arrived first")
	}
}

// A sender's record bag cannot say how far back it is. A node stuck below
// quorum holds every checkpoint the cluster has produced since it stopped, so
// the deepest record it carries is the cluster's depth, not its own -- and a
// checkpoint whose depth was edited after signing carries any depth at all.
// The anchor it states is what it is judged by, and nothing else.
func Test_Set_stalenessIsJudgedByTheAnchorTheSenderStates(t *testing.T) {
	root, x := newID(t), newID(t)
	set := found(t, root, "1")
	old := Admit(root, x.Public(), "x", 2)
	_, err := set.AddAdmission(old)
	require.NoError(t, err)

	// what a peer that stopped here holds, and the membership it stopped on:
	// taken before the agreement, which is when this set lets go of the record
	behind := set.Records()
	behindAt, _ := set.Anchor()
	require.NotEmpty(t, behind.Admissions)

	checkpoint(t, set, root)
	require.True(t, set.Valid(x.Public()))

	// the cluster removes x and carries on until it has forgotten it
	_, err = set.AddRevocation(Revoke(root, x.Public()))
	require.NoError(t, err)
	checkpoint(t, set, root)
	for cur, _ := set.Anchor(); len(cur.Removed) > 0; cur, _ = set.Anchor() {
		checkpoint(t, set, root)
	}
	require.False(t, set.Revoked(x.Public()), "forgotten, so nothing refuses it by name")
	here, _ := set.Anchor()

	// the current membership among the peer's records does not make it current
	carrying := behind
	carrying.Checkpoints = append(slices.Clone(behind.Checkpoints), here)
	res := set.MergeFrom(&behindAt, carrying)
	assert.Equal(t, 1, res.Stale, "judged by the anchor it stands on, not the deepest record it carries")
	_, proposed := set.Proposal().Holds(x.Public())
	assert.False(t, proposed, "so nothing puts the forgotten identity back")

	// nor does a depth that was never signed for
	tampered := behindAt
	tampered.Depth = here.Depth
	require.Error(t, tampered.Validate(), "the edited depth cannot verify")
	res = set.MergeFrom(&tampered, behind)
	assert.Equal(t, 1, res.Stale, "an anchor that does not verify is not taken from at all")
	_, proposed = set.Proposal().Holds(x.Public())
	assert.False(t, proposed)
}

// The other side of stating the anchor: it is what a peer behind this one
// catches up from, since the records no longer carry it.
func Test_Set_MergeFrom_carriesTheAnchorToAPeerBehind(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)

	behind := found(t, root, "1")
	require.Equal(t, uint64(1), behind.Depth())
	require.False(t, behind.Valid(a.Public()))

	here, _ := set.Anchor()
	behind.MergeFrom(&here, set.Records())
	assert.Equal(t, set.Depth(), behind.Depth(), "the peer takes the membership its sender stands on")
	assert.True(t, behind.Valid(a.Public()))
}

// Holding a membership past its own is no proof a node is keeping up. One
// signature from a member it knows is enough for a membership to be worth
// keeping, but a quorum of them is needed to adopt it -- so where some of those
// members have left the cluster for good, the node stores every membership the
// cluster agrees and adopts none of them. Past Keep agreements behind, the
// cluster refuses its records whatever else is true, so it says so.
func Test_Set_strandedWhenTooFewOfTheMembersItKnowsAreLeft(t *testing.T) {
	a, b, c, p := newID(t), newID(t), newID(t), newID(t)
	members := []Member{
		{Identity: a.Public(), Name: "a", Host: 1},
		{Identity: b.Public(), Name: "b", Host: 2},
		{Identity: c.Public(), Name: "c", Host: 3},
		{Identity: p.Public(), Name: "p", Host: 4},
	}
	base := Propose(a, 5, Digest{}, QuorumMajority, 0, members, nil)
	for _, s := range []*Identity{b, c, p} {
		base.Attestations = append(base.Attestations, Attest(s, base.Digest()))
	}
	set := NewSet()
	require.NoError(t, set.Adopt(base))
	require.Equal(t, 3, set.Quorum().Size(set.MemberCount()), "three of the four it knows")

	// b and c leave for good; a carries on with nodes p has never heard of
	prev := base
	stranded := false
	for range Keep + 10 {
		next := []Member{{Identity: a.Public(), Name: "a", Host: 1}}
		for j := range 3 {
			s := newID(t)
			next = append(next, Member{Identity: s.Public(), Name: fmt.Sprintf("n%d", j), Host: uint64(10 + j)})
		}
		cp := Propose(a, prev.Depth+1, prev.Digest(), QuorumMajority, 0, next, nil)
		ok, err := set.AddCheckpoint(cp)
		require.NoError(t, err, "one signature it knows is enough to keep")
		require.True(t, ok)
		require.Equal(t, base.Depth, set.Depth(), "but never enough to adopt")
		if _, s := set.Stranded(); s {
			stranded = true
			assert.Greater(t, cp.Depth, base.Depth+Keep, "not before the cluster is out of reach")
			break
		}
		prev = cp
	}
	assert.True(t, stranded, "a node that can never catch up has to say so")

	seen, _ := set.Stranded()
	assert.Greater(t, seen-set.Depth(), uint64(Keep), "and says how far behind it is")
	assert.Equal(t, 4, set.MemberCount(), "while still serving the membership it is stuck on")
}

// A membership cannot name an identity as a member and as having gone. A node
// that took one would hold a member that is revoked at the same time: it serves
// as a peer, holding its name and slot, while 'cheesecloth revoke' refuses it
// as an identity already on its way out -- and the next membership drops the
// removal rather than the member, so nothing ever takes it out.
//
// Nothing honest states one. The proposal drops every member it holds from the
// list of the departed before stating either, so this is Validate's job: refuse
// the record rather than leave a node to act on a membership that contradicts
// itself.
func Test_Checkpoint_Validate_aMemberCannotAlsoBeRemoved(t *testing.T) {
	root, x := newID(t), newID(t)
	members := []Member{
		{Identity: root.Public(), Name: "root", Host: 1},
		{Identity: x.Public(), Name: "x", Host: 2},
	}

	both := Propose(root, 2, Digest{}, "1", 0, members, []Departure{{Identity: x.Public(), Depth: 1}})
	err := both.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "as a member and as removed")
	assert.Contains(t, err.Error(), x.Public().Short(), "and says which identity")

	// the same membership without the removal is well formed, so the test is
	// pinned to this rule rather than passing for some other reason
	clean := Propose(root, 2, Digest{}, "1", 0, members, nil)
	require.NoError(t, clean.Validate())

	// and it cannot be taken, which is what the check is for
	set := NewSet()
	assert.ErrorContains(t, set.Adopt(both), "as a member and as removed")
	assert.Equal(t, 0, set.MemberCount(), "so no membership was taken from it")
	_, err = set.AddCheckpoint(both)
	assert.ErrorContains(t, err, "as a member and as removed")
}

// A membership cannot state one identity twice. Quorum is sized over how many
// members the checkpoint states, while only distinct signers can attest to it,
// so two entries per identity ask for more attestations than the cluster has
// keys to give: the node that took such a membership agrees nothing again, and
// revoking is no way out, because that needs an agreement of its own.
//
// Adopt is the path that matters. It checks the record and the depth and
// nothing else, so a joiner takes whatever membership admitted it. One member,
// with no quorum behind it, would otherwise leave every node it enrolled stuck
// for good while the rest of the cluster carried on.
func Test_Checkpoint_Validate_aMemberCannotBeStatedTwice(t *testing.T) {
	root, x := newID(t), newID(t)
	members := []Member{
		{Identity: root.Public(), Name: "root", Host: 1},
		{Identity: x.Public(), Name: "x", Host: 2},
	}
	// every name and slot distinct, so the identity is the only thing repeated
	twice := []Member{
		{Identity: root.Public(), Name: "root", Host: 1},
		{Identity: root.Public(), Name: "root-again", Host: 3},
		{Identity: x.Public(), Name: "x", Host: 2},
		{Identity: x.Public(), Name: "x-again", Host: 4},
	}

	dup := Propose(root, 2, Digest{}, QuorumMajority, 0, twice, nil)
	err := dup.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "as a member twice")

	// the ordering rule does not catch it: members sort by identity, so the two
	// entries land side by side and the record is canonical
	assert.Equal(t, dup.Members, canonicalMembers(dup.Members))
	// which is also why the second entry is where it gives out, and whose
	// identity the error names
	assert.Contains(t, err.Error(), dup.Members[1].Identity.Short(), "and says which identity")

	// what taking it would cost: four entries need three attestations, and two
	// identities is all there is to sign
	assert.Greater(t, QuorumMajority.Size(len(twice)), 2, "asks for more attestations than there are keys")

	// the same membership without the repeats is well formed, so the test is
	// pinned to this rule rather than passing for some other reason
	clean := Propose(root, 2, Digest{}, QuorumMajority, 0, members, nil)
	require.NoError(t, clean.Validate())

	// and it comes in by neither door
	set := NewSet()
	assert.ErrorContains(t, set.Adopt(dup), "as a member twice")
	assert.Equal(t, 0, set.MemberCount(), "so no membership was taken from it")
	_, err = set.AddCheckpoint(dup)
	assert.ErrorContains(t, err, "as a member twice")
}

// A node the cluster has left behind is offered every membership the cluster
// agrees and can adopt none of them, so what it holds would grow with the
// cluster's every step. It keeps the deepest and lets the rest go: a peer
// states the membership it stands on at every state sync, so nothing it needs
// is gone for longer than a round.
func Test_Set_aNodeLeftBehindDoesNotHoardMemberships(t *testing.T) {
	a, b, c, p := newID(t), newID(t), newID(t), newID(t)
	members := []Member{
		{Identity: a.Public(), Name: "a", Host: 1}, {Identity: b.Public(), Name: "b", Host: 2},
		{Identity: c.Public(), Name: "c", Host: 3}, {Identity: p.Public(), Name: "p", Host: 4},
	}
	base := Propose(a, 5, Digest{}, QuorumMajority, 0, members, nil)
	for _, s := range []*Identity{b, c, p} {
		base.Attestations = append(base.Attestations, Attest(s, base.Digest()))
	}
	set := NewSet()
	require.NoError(t, set.Adopt(base))

	// b and c leave for good; a carries on with nodes p has never heard of, so
	// p keeps every membership it is offered and adopts none
	prev := base
	for i := range Keep + 20 {
		next := []Member{{Identity: a.Public(), Name: "a", Host: 1}}
		for j := range 3 {
			s := newID(t)
			next = append(next, Member{Identity: s.Public(), Name: fmt.Sprintf("n%d%d", i, j), Host: uint64(10 + j)})
		}
		cp := Propose(a, prev.Depth+1, prev.Digest(), QuorumMajority, 0, next, nil)
		_, err := set.AddCheckpoint(cp)
		require.NoError(t, err)
		prev = cp
	}
	require.Equal(t, base.Depth, set.Depth(), "it never advanced")
	_, stranded := set.Stranded()
	require.True(t, stranded)
	require.Greater(t, len(set.Records().Checkpoints), Keep,
		"gossip alone does not trim: a membership that moves nothing prunes nothing")

	// the state sync is where a set collects, and it is the tick every cluster
	// has: one round is enough to let go of what can never be used
	set.MergeFrom(nil, Records{})
	held := set.Records().Checkpoints
	require.Len(t, held, 2, "the deepest it was offered, and the one it could agree next")
	depths := []uint64{held[0].Depth, held[1].Depth}
	slices.Sort(depths)
	assert.Equal(t, []uint64{base.Depth + 1, prev.Depth}, depths,
		"everything between goes; the next one stays because a membership this node is "+
			"part of would be at that depth, and no claim about the cluster may discard it")

	// and it still catches up in one step once enough of the members it knows
	// attest to where the cluster is now
	current := prev
	for _, s := range []*Identity{b, c} {
		current.Attestations = append(current.Attestations, Attest(s, current.Digest()))
	}
	_, err := set.AddCheckpoint(current)
	require.NoError(t, err)
	assert.Equal(t, current.Depth, set.Depth(), "the membership the cluster is on now, in one step")
	_, stranded = set.Stranded()
	assert.False(t, stranded, "and it is no longer left behind")
}

// What one member says about where the cluster has got to must not throw away
// the membership this node is in the middle of agreeing. How far out of reach a
// node looks rests on the deepest membership it has been offered, and a single
// member can state one: the collection would then discard the agreement in
// flight, and the cluster would have to state it again at the next sync.
func Test_Set_aClaimAboutTheClusterKeepsTheNextMembership(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, root)
	anchor, ok := set.Anchor()
	require.True(t, ok)

	// the membership the cluster is agreeing now: root has stated it, and two of
	// the three members have to attest before it counts
	next := Propose(root, anchor.Depth+1, anchor.Digest(), QuorumMajority, 0, []Member{
		{Identity: root.Public(), Name: "root", Host: 1},
		{Identity: a.Public(), Name: "a", Host: 2},
	}, nil)
	_, err := set.AddCheckpoint(next)
	require.NoError(t, err)

	// b states one far enough ahead to put this node out of reach. Nobody else
	// has signed it, and b is a member, so it is kept and counted as evidence
	far := Propose(b, anchor.Depth+Keep+1, Digest{}, QuorumMajority, 0,
		[]Member{{Identity: b.Public(), Name: "b", Host: 3}}, nil)
	_, err = set.AddCheckpoint(far)
	require.NoError(t, err)
	_, stranded := set.Stranded()
	require.True(t, stranded, "on the face of it the cluster has gone out of reach")

	set.MergeFrom(nil, Records{}) // the sync, which is where the collection runs
	held := map[uint64]bool{}
	for _, c := range set.Records().Checkpoints {
		held[c.Depth] = true
	}
	assert.True(t, held[next.Depth], "the membership being agreed is still here")

	// so the agreement goes through on the next attestation, rather than waiting
	// for the cluster to state it again
	moved, err := set.AddAttestation(next.Digest(), Attest(a, next.Digest()))
	require.NoError(t, err)
	assert.True(t, moved)
	assert.Equal(t, next.Depth, set.Depth())
	assert.True(t, set.Valid(a.Public()))
	assert.False(t, set.Valid(b.Public()), "on the membership the cluster agreed, not the one b stated")
}

// A revocation is refused either because its subject is out already or because
// nothing here names it -- history, against a record that arrived before the
// admission it is about. Both are refused and both count as superseded, so the
// state sync offers them again; what differs is what the log tells an operator,
// and saying "a checkpoint has already accounted for this" of a record no
// checkpoint has ever seen sends them looking in the wrong place.
func Test_Set_aRefusedRevocationSaysWhichKindItIs(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)

	// a revocation that overtook the admission it is about
	early := newID(t)
	_, err := set.AddRevocation(Revoke(root, early.Public()))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSuperseded, "still counted as superseded, so a sync stays quiet")
	assert.ErrorIs(t, err, errUnknownSubject)
	assert.Contains(t, err.Error(), "nothing here names this identity")

	// and one whose subject the cluster really has accounted for
	_, err = set.AddRevocation(Revoke(root, a.Public()))
	require.NoError(t, err, "a is still a member, so this one is kept")
	checkpoint(t, set, root)
	require.False(t, set.Valid(a.Public()))

	_, err = set.AddRevocation(Revoke(root, a.Public()))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSuperseded)
	assert.NotErrorIs(t, err, errUnknownSubject, "the membership named it removed; that is history, not a stranger")
}
