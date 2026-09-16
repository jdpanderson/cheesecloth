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

// admit signs an admission of id as name at slot host, vouched for by admitter.
// It proposes a membership holding id; it does not make id a member.
func admit(t *testing.T, set *Set, admitter *Identity, id *Identity, name string, host uint64) {
	t.Helper()
	ok, err := set.AddAdmission(Admit(admitter, id.Public(), name, host))
	require.NoError(t, err)
	require.True(t, ok)
}

// checkpoint states the membership the records propose, at the next depth, with
// each of signers attesting to it. Whether that agrees it is the set's to say.
func checkpoint(t *testing.T, set *Set, signers ...*Identity) {
	t.Helper()
	pr := set.Proposal()
	prev := Digest{}
	if base, ok := set.Anchor(); ok {
		prev = base.Digest()
	}
	c := Propose(signers[0], set.Depth()+1, prev, set.Quorum(), pr.Members, pr.Removed)
	for _, s := range signers[1:] {
		c.Attestations = append(c.Attestations, Attest(s, c.Digest()))
	}
	_, err := set.AddCheckpoint(c)
	require.NoError(t, err)
}
