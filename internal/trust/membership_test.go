package trust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Before any checkpoint the root alone is the membership, and a member it
// admits joins it.
func Test_Set_genesis(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	assert.True(t, set.Valid(root.Public()))
	assert.Equal(t, 1, set.MemberCount())
	assert.Equal(t, QuorumMajority, set.Quorum())

	admit(t, set, root, a, "a", 2)
	assert.True(t, set.Valid(a.Public()))
	m, ok := set.Lookup(a.Public())
	require.True(t, ok)
	assert.Equal(t, "a", m.Name)
	assert.Equal(t, uint64(2), m.Host)
}

// A checkpoint ratifies against the membership below it, and from then on the
// membership is read from the list rather than derived from the records.
func Test_Set_checkpointRatifiesAndIsRead(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)

	// the membership below is the root alone, so its own attestation ratifies
	checkpoint(t, set, nil, root)
	assert.Equal(t, uint64(1), set.Depth())
	base, ok := set.Base()
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
	checkpoint(t, set, nil, root)

	before := set.Records()
	require.Len(t, before.Admissions, 3)
	gone := set.Trim(4)
	assert.Equal(t, 2, gone, "the two admissions go; the root's own record is the anchor")

	after := set.Records()
	assert.Len(t, after.Admissions, 1)
	assert.Len(t, after.Checkpoints, 1)
	assert.Equal(t, 3, set.MemberCount(), "and everyone is still a member")
	assert.True(t, set.Valid(b.Public()))
}

// A revocation takes its subject out at once, whatever the checkpoints say:
// quorum ratifies what happened, it does not authorize it.
func Test_Set_revocationCountsWithoutACheckpoint(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, nil, root)

	ok, err := set.AddRevocation(Revoke(root, a.Public(), nil, t0.Add(time.Hour)))
	require.NoError(t, err)
	require.True(t, ok)
	assert.False(t, set.Valid(a.Public()), "out at once")
	assert.True(t, set.Valid(b.Public()))
	assert.Equal(t, 2, set.MemberCount())
}

// A revocation names the nodes that go with its subject, and they go out
// entirely: identity, name and slot.
func Test_Set_revocationDisowns(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, a, b, "b", 3)
	require.True(t, set.Valid(b.Public()))

	_, err := set.AddRevocation(Revoke(root, a.Public(), []PublicKey{b.Public()}, t0.Add(time.Hour)))
	require.NoError(t, err)
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
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)
	checkpoint(t, set, nil, root)

	old := Admit(root, a.Public(), "a", 2, t0.Add(time.Minute))
	_, err := set.AddRevocation(Revoke(root, a.Public(), nil, t0.Add(time.Hour)))
	require.NoError(t, err)
	checkpoint(t, set, []PublicKey{a.Public()}, root, b)
	require.False(t, set.Valid(a.Public()))
	set.Trim(4)

	_, err = set.AddAdmission(old)
	assert.ErrorIs(t, err, errSuperseded, "the record that first admitted it is history now")
	assert.False(t, set.Valid(a.Public()))
}

// Two members that revoke each other both go: each revocation is judged with
// the other held, and the guard makes neither count for its own signer.
func Test_Set_mutualRevocation(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	admit(t, set, root, b, "b", 3)

	_, err := set.AddRevocation(Revoke(a, b.Public(), nil, t0.Add(time.Hour)))
	require.NoError(t, err)
	_, err = set.AddRevocation(Revoke(b, a.Public(), nil, t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.False(t, set.Valid(a.Public()))
	assert.False(t, set.Valid(b.Public()))
	assert.True(t, set.Valid(root.Public()))
}

// A checkpoint ratifies against the membership below it, so removing one of two
// members needs the one being removed to attest. It will not, so a two-node
// cluster on majority never trims -- while revocation itself goes on working,
// because quorum ratifies rather than authorizes.
func Test_Set_twoNodeClusterNeverTrims(t *testing.T) {
	root, a := newID(t), newID(t)
	set := found(t, root, QuorumMajority)
	admit(t, set, root, a, "a", 2)
	checkpoint(t, set, nil, root)
	require.Equal(t, uint64(1), set.Depth())

	_, err := set.AddRevocation(Revoke(root, a.Public(), nil, t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.False(t, set.Valid(a.Public()), "the revocation counts regardless")

	checkpoint(t, set, []PublicKey{a.Public()}, root) // the root alone is not a majority of two
	assert.Equal(t, uint64(1), set.Depth(), "so nothing ratifies and nothing is trimmed")
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
