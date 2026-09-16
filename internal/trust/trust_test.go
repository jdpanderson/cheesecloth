package trust

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func newID(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	require.NoError(t, err)
	return id
}

// found creates a cluster rooted at root with the given quorum rule.
func found(t *testing.T, root *Identity, q QuorumRule) *Set {
	t.Helper()
	set := NewSet()
	require.NoError(t, set.Adopt(Found(root, "root", q)))
	return set
}

// admit puts id into set as name at slot host, vouched for by admitter.
func admit(t *testing.T, set *Set, admitter *Identity, id *Identity, name string, host uint64) Admission {
	t.Helper()
	a := Admit(admitter, id.Public(), name, host)
	ok, err := set.AddAdmission(a)
	require.NoError(t, err)
	require.True(t, ok)
	return a
}

// checkpoint proposes the set's current membership at the next depth and has
// each of signers attest to it.
func checkpoint(t *testing.T, set *Set, removed []PublicKey, signers ...*Identity) Checkpoint {
	t.Helper()
	var members []Member
	for _, m := range set.Members() {
		members = append(members, m)
	}
	prev := Digest{}
	if base, ok := set.Anchor(); ok {
		prev = base.Digest()
	}
	c := Propose(signers[0], set.Depth()+1, prev, set.Quorum(), members, removed)
	for _, s := range signers[1:] {
		c.Attestations = append(c.Attestations, Attest(s, c.Digest()))
	}
	_, err := set.AddCheckpoint(c)
	require.NoError(t, err)
	return c
}
