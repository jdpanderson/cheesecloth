package trust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prune signs a prune the way the cluster does, for everything set offers.
func prune(t *testing.T, set *Set, pruner *Identity, now time.Time) Prune {
	t.Helper()
	ids := set.Prunable()
	require.NotEmpty(t, ids, "nothing to prune")
	return SignPrune(pruner, ids, set.NextSeq(pruner.Public()), now)
}

func addPrune(t *testing.T, set *Set, p Prune) bool {
	t.Helper()
	ok, err := set.AddPrune(p)
	require.NoError(t, err)
	return ok
}

func Test_Prune_Validate(t *testing.T) {
	root, a := newID(t), newID(t)
	p := SignPrune(root, []PublicKey{a.Public()}, 2, t0)
	require.NoError(t, p.Validate())

	for name, mutate := range map[string]func(*Prune){
		"issued":    func(x *Prune) { x.IssuedAt++ },
		"seq":       func(x *Prune) { x.Seq++ },
		"pruner":    func(x *Prune) { x.Pruner = a.Public() },
		"identity":  func(x *Prune) { x.Identities = []PublicKey{root.Public()} },
		"signature": func(x *Prune) { x.Signature[0] ^= 1 },
	} {
		x := p
		x.Signature = append([]byte(nil), p.Signature...)
		mutate(&x)
		assert.Error(t, x.Validate(), name)
	}

	x := p
	x.Seq = 0
	assert.ErrorContains(t, x.Validate(), "without a sequence number")
	x = p
	x.Identities = nil
	assert.ErrorContains(t, x.Validate(), "without any identities")
	x = SignPrune(root, []PublicKey{root.Public()}, 2, t0)
	assert.ErrorContains(t, x.Validate(), "names the node that signed it")
}

// the list is signed in one order, so the same record cannot be reshuffled
// into a second one saying the same thing.
func Test_SignPrune_sortsAndDeduplicates(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	p := SignPrune(root, []PublicKey{b.Public(), a.Public(), b.Public()}, 2, t0)
	require.NoError(t, p.Validate())
	assert.Len(t, p.Identities, 2)

	shuffled := p
	shuffled.Identities = []PublicKey{p.Identities[1], p.Identities[0]}
	assert.ErrorContains(t, shuffled.Validate(), "not sorted")
}

// the ordinary case: a member that leaves and admitted nobody takes its
// admission and its revocation with it.
func Test_Set_prunesARevokedLeaf(t *testing.T) {
	root, a, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, b, b.Public(), t0.Add(time.Hour))))

	assert.Equal(t, []PublicKey{b.Public()}, set.Prunable())
	before := set.Records()
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))

	after := set.Records()
	assert.Len(t, after.Admissions, len(before.Admissions)-1)
	assert.Empty(t, after.Revocations)
	assert.False(t, set.Valid(b.Public()))
	assert.True(t, set.Valid(a.Public()), "the rest of the cluster is untouched")
	assert.True(t, set.Valid(root.Public()))
}

// a revoked node that admitted somebody still standing cannot go: the chain
// to the root runs through the record it signed.
func Test_Set_keepsARevokedAdmitter(t *testing.T) {
	_, a, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, a, a.Public(), t0.Add(time.Hour))))

	require.False(t, set.Valid(a.Public()))
	require.True(t, set.Valid(b.Public()), "admitted while a was a member")
	assert.Empty(t, set.Prunable())
}

// a revoker is needed for as long as its victim is: dropping it would make
// the revocation stop counting and let the victim back in.
func Test_Set_keepsARevokerItsVictimNeeds(t *testing.T) {
	root, a, b, _, set := cluster(t)
	// a revokes b, then leaves itself. b is out, but only because a said so,
	// and b cannot go because c hangs off it.
	c := newID(t)
	require.NoError(t, addAdmission(set, admit(set, b, c.Public(), "c", 4, t0.Add(time.Hour))))
	require.NoError(t, addRevocation(set, revoke(set, a, b.Public(), t0.Add(2*time.Hour))))
	require.NoError(t, addRevocation(set, revoke(set, a, a.Public(), t0.Add(3*time.Hour))))

	require.False(t, set.Valid(a.Public()))
	require.False(t, set.Valid(b.Public()))
	require.True(t, set.Valid(c.Public()))
	assert.Empty(t, set.Prunable(), "b holds a, and c holds b")

	// once c goes too, the whole branch can
	require.NoError(t, addRevocation(set, revoke(set, root, c.Public(), t0.Add(4*time.Hour))))
	assert.ElementsMatch(t, []PublicKey{a.Public(), b.Public(), c.Public()}, set.Prunable())
}

func Test_Set_neverPrunesTheRoot(t *testing.T) {
	root, a, _, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, root, root.Public(), t0.Add(time.Hour))))
	require.False(t, set.Valid(root.Public()))
	assert.NotContains(t, set.Prunable(), root.Public())
	assert.NotContains(t, set.Prunable(), a.Public(), "admitted while the root was a member")
}

// every answer about a member is the same after a prune as before it: that is
// the whole claim pruning makes.
func Test_Set_pruningChangesNoAnswer(t *testing.T) {
	root, a, b, _, set := cluster(t)
	c, d := newID(t), newID(t)
	require.NoError(t, addAdmission(set, admit(set, a, c.Public(), "c", 4, t0.Add(time.Hour))))
	require.NoError(t, addAdmission(set, admit(set, a, d.Public(), "d", 5, t0.Add(2*time.Hour))))
	require.NoError(t, addRevocation(set, revoke(set, root, c.Public(), t0.Add(3*time.Hour))))
	require.NoError(t, addRevocation(set, revoke(set, d, d.Public(), t0.Add(4*time.Hour))))

	ids := []PublicKey{root.Public(), a.Public(), b.Public(), c.Public(), d.Public()}
	type answer struct {
		valid bool
		adm   Admission
		found bool
	}
	before := map[PublicKey]answer{}
	for _, id := range ids {
		adm, found := set.Lookup(id)
		before[id] = answer{set.Valid(id), adm, found}
	}
	freeBefore, err := set.FreeHost(255)
	require.NoError(t, err)

	require.ElementsMatch(t, []PublicKey{c.Public(), d.Public()}, set.Prunable())
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(5*time.Hour))))

	for _, id := range ids {
		was := before[id]
		assert.Equal(t, was.valid, set.Valid(id), "validity of %s", id.Short())
		if !was.valid {
			continue // a pruned identity keeps no record to look up
		}
		adm, found := set.Lookup(id)
		assert.Equal(t, was.found, found, "lookup of %s", id.Short())
		assert.Equal(t, was.adm, adm, "record for %s", id.Short())
	}
	for _, name := range []string{"root", "a", "b"} {
		_, ok := set.ByName(name)
		assert.True(t, ok, "member %s is still found by name", name)
	}
	free, err := set.FreeHost(255)
	require.NoError(t, err)
	assert.LessOrEqual(t, free, freeBefore, "a pruned slot is free again")
}

// the point of the tombstone: a peer that has not pruned yet re-offers the
// records at every push/pull, and they must not come back.
func Test_Set_prunedRecordsDoNotComeBack(t *testing.T) {
	root, _, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, b, b.Public(), t0.Add(time.Hour))))
	stale := set.Records()

	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))
	pruned := set.Records()

	assert.Zero(t, set.Merge(stale), "a stale peer's whole set changes nothing")
	assert.Equal(t, pruned, set.Records())
}

// a prune that arrives before the records it covers applies when they do,
// rather than being judged on what happened to be present when it landed.
func Test_Set_pruneAppliesWhenTheRecordsCatchUp(t *testing.T) {
	root, _, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, b, b.Public(), t0.Add(time.Hour))))
	p := prune(t, set, root, t0.Add(2*time.Hour))
	full := set.Records() // what a peer that has not pruned yet still offers
	require.True(t, addPrune(t, set, p))

	// a node that has only the root's own record so far
	fresh := NewSet(root.Public())
	for _, a := range full.Admissions {
		if a.Identity == root.Public() {
			require.NoError(t, addAdmission(fresh, a))
		}
	}
	require.True(t, addPrune(t, fresh, p), "held, though there is nothing to act on yet")

	fresh.Merge(full)
	assert.False(t, fresh.Valid(b.Public()))
	assert.Equal(t, set.Records(), fresh.Records(), "both nodes end up with the same set")
}

// a prune only ever removes what the node receiving it derives for itself.
func Test_Set_pruneOfAValidMemberIsIgnored(t *testing.T) {
	root, a, _, _, set := cluster(t)
	p := SignPrune(root, []PublicKey{a.Public()}, set.NextSeq(root.Public()), t0.Add(time.Hour))

	assert.True(t, addPrune(t, set, p), "the record is held")
	assert.True(t, set.Valid(a.Public()), "but it removes nothing")
	_, ok := set.Lookup(a.Public())
	assert.True(t, ok)
}

// a prune signed by a node that was not a member when it signed removes
// nothing, the same way an admission by one admits nobody.
func Test_Set_pruneByANonMemberIsIgnored(t *testing.T) {
	_, _, b, stranger, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, b, b.Public(), t0.Add(time.Hour))))

	addPrune(t, set, SignPrune(stranger, []PublicKey{b.Public()}, 1, t0.Add(2*time.Hour)))
	_, ok := set.Lookup(b.Public())
	assert.True(t, ok, "b's record is still there")
}

// the number a pruned record used is never handed out again, so a signer
// cannot be made to look as though it reused one.
func Test_Set_pruningDoesNotFreeASequenceNumber(t *testing.T) {
	root, _, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, root, b.Public(), t0.Add(time.Hour))))
	next := set.NextSeq(root.Public())

	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))
	assert.Greater(t, set.NextSeq(root.Public()), next, "the prune took the next one")
	assert.Equal(t, uint64(0), set.HighWater(b.Public()), "the pruned node is forgotten entirely")
}

func addAdmission(set *Set, a Admission) error {
	_, err := set.AddAdmission(a)
	return err
}

func addRevocation(set *Set, r Revocation) error {
	_, err := set.AddRevocation(r)
	return err
}
