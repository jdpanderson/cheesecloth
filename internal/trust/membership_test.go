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
	checkpoint(t, set, root)

	before := set.Records()
	require.Len(t, before.Admissions, 2, "the founding membership needs no admission")
	assert.Positive(t, set.Trim(8), "the admissions the agreed membership accounts for go")

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
	h, err := set.Proposal().FreeHost(16)
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
	set.Trim(8)

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

	for i := range 20 {
		id := newID(t)
		admit(t, set, root, id, "n", 3)
		checkpoint(t, set, root)
		_, err := set.AddRevocation(Revoke(root, id.Public(), nil))
		require.NoError(t, err)
		checkpoint(t, set, root)
		set.Trim(4)
		require.True(t, set.Valid(keep.Public()), "round %d", i)
	}
	require.Greater(t, set.Depth(), uint64(20))
	assert.LessOrEqual(t, len(set.Records().Checkpoints), 6, "and the chain behind it is let go of")

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
	shallower := Propose(root, 1, Digest{}, QuorumMajority, []Member{{Identity: root.Public(), Name: "root", Host: 1}}, nil)
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

	// a has been admitted, but the cluster has agreed nothing yet
	_, err := set.AddAdmission(Admit(a, b.Public(), "b", 3))
	require.NoError(t, err)
	_, err = set.AddRevocation(Revoke(a, root.Public(), nil))
	require.NoError(t, err)
	p := set.Proposal()
	_, proposed := p.Holds(b.Public())
	assert.False(t, proposed, "a cannot admit until the cluster has agreed on a")
	_, still := p.Holds(root.Public())
	assert.True(t, still, "nor revoke")

	checkpoint(t, set, root)
	require.True(t, set.Valid(a.Public()))
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
	require.NoError(t, err, "the record is well formed, and the set keeps what it cannot yet judge")
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
	require.NoError(t, err)
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

	set.Trim(8)
	assert.True(t, set.Revoked(a.Public()), "the revocation is still held")
	_, proposed := set.Proposal().Holds(a.Public())
	assert.False(t, proposed, "and still proposes the membership without it")

	checkpoint(t, set, root, b) // which is agreed as soon as another attests too
	assert.False(t, set.Valid(a.Public()))
}
