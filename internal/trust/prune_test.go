package trust

import (
	"bytes"
	"strings"
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
// admission with it. Its revocation stays, which is what goes on saying it is
// out once the admission is not there to be judged.
func Test_Set_prunesARevokedLeaf(t *testing.T) {
	root, a, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, b, b.Public(), t0.Add(time.Hour))))

	assert.Equal(t, []PublicKey{b.Public()}, set.Prunable())
	before := set.Records()
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))

	after := set.Records()
	assert.Len(t, after.Admissions, len(before.Admissions)-1)
	assert.Equal(t, before.Revocations, after.Revocations, "the revocation is the evidence, so it stays")
	assert.Empty(t, set.Prunable(), "and it is not offered again, having nothing left to drop")
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

// a node that revoked another stays for good: the revocation it signed keeps
// its victim out, and stops counting without the chain that makes its signer a
// member. A node that revoked only itself is not held back this way.
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

	// once c goes too, the branch can, all but a, which revoked b
	require.NoError(t, addRevocation(set, revoke(set, root, c.Public(), t0.Add(4*time.Hour))))
	assert.ElementsMatch(t, []PublicKey{b.Public(), c.Public()}, set.Prunable())
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(5*time.Hour))))
	assert.False(t, set.Valid(b.Public()), "a's revocation of b outlives b's own records")
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

// A peer out of touch since before the revocation offers records that say the
// pruned node was a member and none that say it left. The node putting the two
// together may never have held the revocation and has no tombstone of its own,
// so the pruned set has to carry the answer with it.
func Test_Set_prunedIdentityStaysOutOnANodeThatMissedTheRevocation(t *testing.T) {
	root, _, b, _, set := cluster(t)
	stale := set.Records() // a peer that has heard nothing since

	require.NoError(t, addRevocation(set, revoke(set, b, b.Public(), t0.Add(time.Hour))))
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))
	require.False(t, set.Valid(b.Public()))

	fresh := NewSet(root.Public())
	fresh.Merge(set.Records())
	fresh.Merge(stale)
	assert.False(t, fresh.Valid(b.Public()), "the revocation went with the pruned set and still decides")
	_, found := fresh.Lookup(b.Public())
	assert.False(t, found, "and the admission the peer offered back was dropped again")
}

// the same, with the node that signed the prune revoked in the meantime. It
// cannot be pruned itself while a revocation it signed is holding somebody out,
// so there is always something left to judge its records by.
func Test_Set_prunedIdentityStaysOutOnceThePrunerIsRevoked(t *testing.T) {
	root, a, b, _, set := cluster(t)
	stale := set.Records()

	require.NoError(t, addRevocation(set, revoke(set, a, b.Public(), t0.Add(time.Hour))))
	require.True(t, addPrune(t, set, prune(t, set, a, t0.Add(2*time.Hour))))
	require.NoError(t, addRevocation(set, revoke(set, root, a.Public(), t0.Add(3*time.Hour))))
	require.False(t, set.Valid(a.Public()))
	require.NotContains(t, set.Prunable(), a.Public(), "a revoked b, so a stays")

	fresh := NewSet(root.Public())
	fresh.Merge(set.Records())
	fresh.Merge(stale)
	assert.False(t, fresh.Valid(b.Public()))
	assert.False(t, fresh.Valid(a.Public()))
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

// twoLeaves is a root with two members admitted directly by it, so neither
// depends on the other and each can be pruned on its own.
func twoLeaves(t *testing.T) (root, x, y *Identity, set *Set) {
	t.Helper()
	root, x, y = newID(t), newID(t), newID(t)
	set = NewSet(root.Public())
	for _, adm := range []Admission{
		SelfAdmit(root, "root", t0),
		Admit(root, x.Public(), "x", 2, 2, t0.Add(time.Minute)),
		Admit(root, y.Public(), "y", 3, 3, t0.Add(2*time.Minute)),
	} {
		require.NoError(t, addAdmission(set, adm))
	}
	return
}

// AddPrune turns a record away before it acts on it: one that does not verify,
// one no clock could have produced, and one already held, which must not be
// counted or applied twice.
func Test_Set_AddPrune_rejections(t *testing.T) {
	root, x, _, set := twoLeaves(t)
	require.NoError(t, addRevocation(set, revoke(set, root, x.Public(), t0.Add(time.Hour))))
	good := SignPrune(root, []PublicKey{x.Public()}, set.NextSeq(root.Public()), t0.Add(2*time.Hour))

	forged := good
	forged.Signature = append([]byte(nil), good.Signature...)
	forged.Signature[0] ^= 1
	_, err := set.AddPrune(forged)
	assert.ErrorContains(t, err, "signature does not verify")

	ancient := SignPrune(root, []PublicKey{x.Public()}, 9, time.Unix(0, 0))
	_, err = set.AddPrune(ancient)
	assert.ErrorContains(t, err, "dated before")

	require.True(t, addPrune(t, set, good))
	assert.False(t, addPrune(t, set, good), "a record already held is not applied twice")
	assert.Len(t, set.Records().Prunes, 1)
}

// A prune removes what it names and no more, even on a node that could derive
// more than the pruner did. That is what bounds a prune to one operator's
// decision at one moment rather than leaving a standing order.
func Test_Set_pruneRemovesOnlyWhatItNames(t *testing.T) {
	root, x, y, set := twoLeaves(t)
	// this node has seen both revocations; the pruner had seen only x's
	require.NoError(t, addRevocation(set, revoke(set, root, x.Public(), t0.Add(time.Hour))))
	require.NoError(t, addRevocation(set, revoke(set, root, y.Public(), t0.Add(time.Hour))))
	require.ElementsMatch(t, []PublicKey{x.Public(), y.Public()}, set.Prunable())

	p := SignPrune(root, []PublicKey{x.Public()}, set.NextSeq(root.Public()), t0.Add(2*time.Hour))
	require.True(t, addPrune(t, set, p))

	_, ok := set.Lookup(x.Public())
	assert.False(t, ok, "x was named, so its admissions went")
	_, ok = set.Lookup(y.Public())
	assert.True(t, ok, "y was prunable here, but the prune did not name it")
	assert.Equal(t, []PublicKey{y.Public()}, set.Prunable(), "and it is still on offer for the next one")
}

// Two prunes stand together: each removes what it names, and the set holds
// both in one order whatever order they arrived in.
func Test_Set_twoPrunesApplyAndOrderTheSame(t *testing.T) {
	root, x, y, set := twoLeaves(t)
	require.NoError(t, addRevocation(set, revoke(set, root, x.Public(), t0.Add(time.Hour))))
	require.NoError(t, addRevocation(set, revoke(set, root, y.Public(), t0.Add(time.Hour))))

	first := SignPrune(root, []PublicKey{x.Public()}, set.NextSeq(root.Public()), t0.Add(2*time.Hour))
	second := SignPrune(root, []PublicKey{y.Public()}, set.NextSeq(root.Public())+1, t0.Add(3*time.Hour))

	require.True(t, addPrune(t, set, first))
	assert.Equal(t, []PublicKey{y.Public()}, set.Prunable(), "the first took x alone")
	require.True(t, addPrune(t, set, second))
	assert.Empty(t, set.Prunable(), "between them they named everything")
	require.Len(t, set.Records().Prunes, 2)

	// a node given the two in the other order holds them the same way round
	other := NewSet(root.Public())
	other.Merge(Records{Admissions: set.Records().Admissions, Revocations: set.Records().Revocations})
	require.True(t, addPrune(t, other, second))
	require.True(t, addPrune(t, other, first))
	assert.Equal(t, set.Records().Prunes, other.Records().Prunes, "the prunes are ordered the same on both")
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
	assert.Equal(t, uint64(1), set.NextSeq(b.Public()), "the pruned node is forgotten entirely")
}

// An identity whose admissions have been withdrawn is no longer a member, and
// its records are worth no more than a revoked one's. This is what makes a
// compromised admitter recoverable: revoke it keeping only what is recognised,
// and the rest of what it signed can go.
func Test_Set_prunesWhatNoLongerReachesTheRoot(t *testing.T) {
	root, a, b, _, set := cluster(t)

	// the root revokes a, keeping nothing, so a's admission of b goes with it
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), set.NextSeq(root.Public()), nil, t0.Add(time.Hour))))
	require.False(t, set.Valid(b.Public()), "b no longer reaches the root")

	assert.Contains(t, set.Prunable(), b.Public(), "b is out and nothing runs through it")
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))
	_, held := set.Lookup(b.Public())
	assert.False(t, held, "b's admission is gone")
	assert.False(t, set.Valid(b.Public()), "and b is still no member")
}

// A node the revocation kept is still a member, so neither it nor the admitter
// it hangs from may be pruned.
func Test_Set_keepsWhatARevocationVouchedFor(t *testing.T) {
	root, a, b, _, set := cluster(t)
	kept, ok := set.Lookup(b.Public())
	require.True(t, ok)

	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), set.NextSeq(root.Public()),
		[][]byte{kept.Signature}, t0.Add(time.Hour))))
	require.True(t, set.Valid(b.Public()), "b was kept")

	prunable := set.Prunable()
	assert.NotContains(t, prunable, b.Public(), "b is still a member")
	assert.NotContains(t, prunable, a.Public(), "a's admission of b is what makes b one")
}

// A node that is merely unreachable now is offered, so an operator pruning
// from a node that is behind can drop records another node still needs. This
// is the trade the rule makes; it is why pruning is for a node in touch with
// the cluster.
func Test_Set_prunableFollowsThisNodesRecords(t *testing.T) {
	root, a, b, _, set := cluster(t)
	behind := NewSet(root.Public())
	for _, adm := range set.Records().Admissions {
		if adm.Identity != b.Public() { // this node never saw b's admission
			require.NoError(t, addAdmission(behind, adm))
		}
	}
	require.NoError(t, addRevocation(behind, Revoke(root, a.Public(), 3, nil, t0.Add(time.Hour))))
	assert.NotContains(t, behind.Prunable(), b.Public(), "it holds no record of b to offer")

	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, nil, t0.Add(time.Hour))))
	assert.Contains(t, set.Prunable(), b.Public(), "the node that has b's record offers it")
}

func addAdmission(set *Set, a Admission) error {
	_, err := set.AddAdmission(a)
	return err
}

func addRevocation(set *Set, r Revocation) error {
	_, err := set.AddRevocation(r)
	return err
}

// A peer that has not applied a prune yet re-offers what it removed. That is
// ordinary: the revocation that put the identity out is still held here, so
// both nodes already agree and nothing needs saying.
func Test_Set_refusingAPrunedRevokedIdentityIsQuiet(t *testing.T) {
	root, a, _, _, set := cluster(t)
	j := newID(t)

	adm := Admit(a, j.Public(), "j", 7, set.NextSeq(a.Public()), t0)
	_, err := set.AddAdmission(adm)
	require.NoError(t, err)
	_, err = set.AddRevocation(revoke(set, root, j.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	require.Equal(t, []PublicKey{j.Public()}, set.Prunable())
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))

	var log bytes.Buffer
	defer swapLogger(&log)()
	for range 3 {
		ok, aerr := set.AddAdmission(adm)
		require.NoError(t, aerr)
		assert.False(t, ok, "the record is refused")
	}
	assert.Empty(t, log.String(), "a pruned identity the records still revoke says nothing")
}

// An identity pruned because the records vouching for it were withdrawn is the
// other case: a member that still holds those records counts it as a member,
// and this node refuses them for as long as it runs. Said once, not once per
// state sync.
func Test_Set_refusingAPrunedUnrevokedIdentityIsReportedOnce(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, x := newID(t), newID(t)

	// c is admitted by the root; both a and c vouch for x
	_, err := set.AddAdmission(Admit(root, c.Public(), "c", 8, set.NextSeq(root.Public()), t0))
	require.NoError(t, err)
	xByA := Admit(a, x.Public(), "x", 9, set.NextSeq(a.Public()), t0)
	_, err = set.AddAdmission(xByA)
	require.NoError(t, err)
	xByC := Admit(c, x.Public(), "x", 9, set.NextSeq(c.Public()), t0)

	// this node never saw c's record, and a is revoked keeping nothing
	_, err = set.AddRevocation(Revoke(root, a.Public(), set.NextSeq(root.Public()), nil, t0.Add(time.Hour)))
	require.NoError(t, err)
	require.False(t, set.Valid(x.Public()), "x has nothing left vouching for it here")
	require.Contains(t, set.Prunable(), x.Public())
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(2*time.Hour))))

	var log bytes.Buffer
	defer swapLogger(&log)()
	for range 3 {
		ok, aerr := set.AddAdmission(xByC) // as a peer's state sync offers it, repeatedly
		require.NoError(t, aerr)
		assert.False(t, ok, "the record is refused")
	}
	assert.Equal(t, 1, strings.Count(log.String(), "refusing records for an identity this node pruned"),
		"reported once, however often the records come round again")
	assert.Contains(t, log.String(), x.Public().Short(), "and it names the identity")
	assert.Contains(t, log.String(), "restart this agent")
}
