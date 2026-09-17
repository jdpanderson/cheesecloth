package trust

import (
	"encoding/json"
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
	assert.NotEmpty(t, after.Checkpoints)
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

	ok, err := set.AddRevocation(Revoke(root, a.Public(), nil))
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

// A revocation names the nodes that go with its subject, and they go out
// entirely: identity, name and slot.
func Test_Set_revocationDisowns(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	admit(t, set, a, b, "b", 3)
	checkpoint(t, set, root)
	require.True(t, set.Valid(b.Public()))

	_, err := set.AddRevocation(Revoke(root, a.Public(), []PublicKey{b.Public()}))
	require.NoError(t, err)
	checkpoint(t, set, root)
	assert.False(t, set.Valid(a.Public()))
	assert.False(t, set.Valid(b.Public()), "named, so it goes too")

	// and the slots they held are free again
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
	_, err := set.AddRevocation(Revoke(root, a.Public(), nil))
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

	_, err := set.AddRevocation(Revoke(a, b.Public(), nil))
	require.NoError(t, err)
	_, err = set.AddRevocation(Revoke(b, a.Public(), nil))
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
	_, err := set.AddRevocation(Revoke(root, a.Public(), nil))
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

	_, err := set.AddRevocation(Revoke(root, a.Public(), nil))
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
		_, err := set.AddRevocation(Revoke(root, id.Public(), nil))
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
	admits, revokes := Admit(a, b.Public(), "b", 3), Revoke(a, root.Public(), nil)
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
// name every member as disowned and empty the cluster with one record.
func Test_Set_onlyMembersMayRevoke(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	require.Equal(t, 2, set.MemberCount())

	stranger := newID(t)
	_, err := set.AddRevocation(Revoke(stranger, stranger.Public(), []PublicKey{root.Public(), a.Public()}))
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
func Test_Set_aNewcomerCannotDisownItsWayOut(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)

	_, err := set.AddRevocation(Revoke(a, a.Public(), []PublicKey{root.Public()}))
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

	_, err := set.AddRevocation(Revoke(root, a.Public(), nil))
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
	_, err := set.AddRevocation(Revoke(root, x.Public(), nil))
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

	_, err = set.AddRevocation(Revoke(root, x.Public(), nil))
	require.NoError(t, err)
	checkpoint(t, set, root)
	require.Empty(t, set.Records().Admissions, "the admission is history here")

	peer.Merge(set.Records())
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
	// membership is agreed, which is when this set lets go of it
	behind := set.Records()
	require.NotEmpty(t, behind.Admissions)

	checkpoint(t, set, root)
	require.True(t, set.Valid(x.Public()))

	// a set only a little further on takes it, and refuses it on its own terms
	near := NewSet()
	anchor, _ := set.Anchor()
	require.NoError(t, near.Adopt(anchor))
	res := near.Merge(behind)
	assert.Zero(t, res.Stale, "near enough to walk here, so its records are judged")

	// meanwhile the cluster removes x and carries on until it has forgotten it
	_, err = set.AddRevocation(Revoke(root, x.Public(), nil))
	require.NoError(t, err)
	checkpoint(t, set, root)
	for cur, _ := set.Anchor(); len(cur.Removed) > 0; cur, _ = set.Anchor() {
		checkpoint(t, set, root)
	}
	require.False(t, set.Valid(x.Public()))
	require.False(t, set.Revoked(x.Public()), "x is forgotten, so nothing refuses its admission by name")

	res = set.Merge(behind)
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

	_, err := set.AddRevocation(Revoke(root, a.Public(), nil))
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

// A revocation may name any identity at all, and one naming a single member is
// taken by every node. Only what the cluster knows about is remembered as
// removed, or one record would put a thousand identities nobody has heard of
// into every checkpoint, state file and welcome, and refuse each of them
// enrolment for as long as they were named.
func Test_Set_aRevocationOnlyRemembersWhatTheClusterKnows(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, "1")
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, root)
	admit(t, set, root, b, "b", 3) // admitted, not yet agreed: the cluster knows of it

	strangers := make([]PublicKey, 0, 50)
	for range 50 {
		strangers = append(strangers, newID(t).Public())
	}
	_, err := set.AddRevocation(Revoke(root, a.Public(), canonicalKeys(append(strangers, b.Public()))))
	require.NoError(t, err)

	assert.Len(t, set.Proposal().Removed, 2, "the member and the joiner, and nobody else")
	checkpoint(t, set, root)
	assert.False(t, set.Valid(a.Public()), "the member it named goes")
	assert.True(t, set.Revoked(b.Public()), "so does the joiner, and it is remembered")
	for _, s := range strangers {
		require.False(t, set.Revoked(s), "an identity nobody ever admitted is not remembered")
	}

	// and the record itself is collected: the membership can never account for
	// an identity it has never heard of, so naming one is no reason to keep it
	assert.Empty(t, set.Records().Revocations)
	assert.False(t, set.Valid(a.Public()), "the member it named is still out")
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
		junk.Revocations = append(junk.Revocations, Revoke(stranger, a.Public(), nil))
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
	assert.Len(t, held.Checkpoints, 1, "the membership, and nothing else")
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

	rev := Revoke(root, a.Public(), nil)
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

	gone := set.Withdraws(Revoke(root, a.Public(), nil))
	require.Len(t, gone, 1, "the member it names goes, once somebody agrees")
	assert.Equal(t, "a", gone[0].Name)
}
