package trust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func newID(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	require.NoError(t, err)
	return id
}

// found creates a cluster rooted at root with the given quorum rule.
func found(t *testing.T, root *Identity, q QuorumRule) *Set {
	t.Helper()
	set := NewSet(root.Public())
	ok, err := set.AddAdmission(SelfAdmit(root, "root", q, t0))
	require.NoError(t, err)
	require.True(t, ok)
	return set
}

// admit puts id into set as name at slot host, vouched for by admitter.
func admit(t *testing.T, set *Set, admitter *Identity, id *Identity, name string, host uint64) Admission {
	t.Helper()
	a := Admit(admitter, id.Public(), name, host, t0.Add(time.Minute))
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
	if base, ok := set.Base(); ok {
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
