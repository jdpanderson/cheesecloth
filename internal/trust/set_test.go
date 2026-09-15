package trust

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Set_validity(t *testing.T) {
	root, a, b, stranger, set := cluster(t)
	assert.True(t, set.Valid(root.Public()))
	assert.True(t, set.Valid(a.Public()))
	assert.True(t, set.Valid(b.Public()), "admitted by a valid non-root member")
	assert.False(t, set.Valid(stranger.Public()))

	// a stranger admitting itself is not a root
	_, err := set.AddAdmission(SelfAdmit(stranger, "x", t0))
	assert.ErrorIs(t, err, errUntrustedRoot)

	// a stranger's admission of someone else is stored (signature is fine) but confers nothing
	c := newID(t)
	ok, err := set.AddAdmission(admit(set, stranger, c.Public(), "c", 4, t0))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, set.Valid(c.Public()), "chain does not reach the root")

	// tampering breaks the signature
	adm := admit(set, root, c.Public(), "c", 4, t0)
	adm.Name = "evil"
	_, err = set.AddAdmission(adm)
	assert.ErrorContains(t, err, "signature")
	adm = admit(set, root, c.Public(), "c", 4, t0)
	adm.Host = 5
	_, err = set.AddAdmission(adm)
	assert.ErrorContains(t, err, "signature")
	adm = admit(set, root, c.Public(), "c", 0, t0)
	_, err = set.AddAdmission(adm)
	assert.ErrorContains(t, err, "overlay slot")
}

func Test_Set_revocation(t *testing.T) {
	t.Run("by a non-member has no effect", func(t *testing.T) {
		_, a, _, stranger, set := cluster(t)
		ok, err := set.AddRevocation(revoke(set, stranger, a.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err) // the signature is fine; the record is simply ineffective
		assert.True(t, ok)
		assert.True(t, set.Valid(a.Public()))
	})

	t.Run("by a member removes the target only", func(t *testing.T) {
		_, a, b, _, set := cluster(t)
		ok, err := set.AddRevocation(revoke(set, a, b.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.False(t, set.Valid(b.Public()))
		assert.True(t, set.Valid(a.Public()))
	})

	t.Run("does not cascade to earlier admissions", func(t *testing.T) {
		root, a, b, _, set := cluster(t)
		_, err := set.AddRevocation(revoke(set, root, a.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.False(t, set.Valid(a.Public()))
		assert.True(t, set.Valid(b.Public()), "b was admitted while a was still a member")

		c := newID(t)
		_, err = set.AddAdmission(admit(set, a, c.Public(), "c", 4, t0.Add(4*time.Minute)))
		require.NoError(t, err)
		assert.False(t, set.Valid(c.Public()), "admitted by a after a's revocation")
	})

	t.Run("by itself removes the leaving member", func(t *testing.T) {
		_, a, b, _, set := cluster(t)
		ok, err := set.AddRevocation(revoke(set, a, a.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.False(t, set.Valid(a.Public()), "a member may revoke itself")
		assert.True(t, set.Valid(b.Public()), "admitted by a while a was still a member")
	})

	t.Run("by a non-member on itself has no effect on anyone else", func(t *testing.T) {
		_, a, _, stranger, set := cluster(t)
		_, err := set.AddRevocation(revoke(set, stranger, stranger.Public(), t0))
		require.NoError(t, err)
		assert.False(t, set.Valid(stranger.Public()))
		assert.True(t, set.Valid(a.Public()))
	})

	t.Run("by a member removes the root like any other peer", func(t *testing.T) {
		root, a, b, _, set := cluster(t)
		ok, err := set.AddRevocation(revoke(set, a, root.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.False(t, set.Valid(root.Public()))
		assert.True(t, set.Valid(a.Public()), "the members the root admitted are unaffected")
		assert.True(t, set.Valid(b.Public()))
	})

	t.Run("by the root on itself removes the root", func(t *testing.T) {
		root, a, b, _, set := cluster(t)
		ok, err := set.AddRevocation(revoke(set, root, root.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.False(t, set.Valid(root.Public()), "the root may leave for good")
		assert.True(t, set.Valid(a.Public()))
		assert.True(t, set.Valid(b.Public()))

		// the cluster carries on: a admits c, and the departed root admits nobody
		c, d := newID(t), newID(t)
		_, err = set.AddAdmission(admit(set, a, c.Public(), "c", 4, t0.Add(10*time.Minute)))
		require.NoError(t, err)
		assert.True(t, set.Valid(c.Public()), "a member admitted after the root left")
		_, err = set.AddAdmission(admit(set, root, d.Public(), "d", 5, t0.Add(10*time.Minute)))
		require.NoError(t, err)
		assert.False(t, set.Valid(d.Public()), "admitted by the root after its revocation")
	})

	t.Run("by a non-member leaves the root alone", func(t *testing.T) {
		root, _, _, stranger, set := cluster(t)
		_, err := set.AddRevocation(revoke(set, stranger, root.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.True(t, set.Valid(root.Public()))
	})
}

func Test_Set_AddRevocation(t *testing.T) {
	root, a, b, stranger, set := cluster(t)
	rev := revoke(set, a, b.Public(), t0.Add(time.Hour))
	rev.IssuedAt++
	_, err := set.AddRevocation(rev)
	assert.ErrorContains(t, err, "signature")

	ok, err := set.AddRevocation(Revoke(a, b.Public(), set.NextSeq(a.Public()), 3, t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = set.AddRevocation(revoke(set, root, b.Public(), t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok, "a second revoker's record is kept beside the first")

	// every record a revoker signs is held, whatever mark it puts; which of
	// them decides is another question, see the test below
	ok, err = set.AddRevocation(Revoke(a, b.Public(), set.NextSeq(a.Public()), 5, t0.Add(3*time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok, "a revoker's later record is kept beside its earlier one")

	ok, err = set.AddRevocation(Revoke(a, b.Public(), set.NextSeq(a.Public()), 0, t0.Add(4*time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)

	// a stranger's revocation is stored but carries no weight
	ok, err = set.AddRevocation(revoke(set, stranger, a.Public(), t0))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, set.Valid(a.Public()))
}

func Test_Set_Merge_skipsBadRecords(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c := newID(t)
	good := admit(set, root, c.Public(), "c", 4, t0)
	bad := admit(set, root, c.Public(), "c", 5, t0)
	bad.Name = "tampered"
	badRev := revoke(set, a, a.Public(), t0)
	badRev.IssuedAt++ // the signature no longer covers the record
	res := set.Merge(Records{Admissions: []Admission{bad, good}, Revocations: []Revocation{badRev}})
	assert.Equal(t, 1, res.Changed)
	assert.Equal(t, 2, res.Refused, "and it says what it would not take")
	assert.ErrorContains(t, res.Reason, "signature", "with an example of why")
	assert.True(t, set.Valid(c.Public()))
	assert.True(t, set.Valid(a.Public()), "the tampered revocation was skipped")
}

func Test_Set_mergeAndRoundTrip(t *testing.T) {
	root, a, b, _, set := cluster(t)
	rs := set.Records()
	require.Len(t, rs.Admissions, 3)

	data, err := json.Marshal(rs)
	require.NoError(t, err)
	var back Records
	require.NoError(t, json.Unmarshal(data, &back))

	// merging into a fresh set in any order yields the same validity
	fresh := NewSet(root.Public())
	back.Admissions[0], back.Admissions[2] = back.Admissions[2], back.Admissions[0]
	assert.Equal(t, 3, fresh.Merge(back).Changed)
	assert.Equal(t, 0, fresh.Merge(back).Changed, "idempotent")
	for _, id := range []PublicKey{root.Public(), a.Public(), b.Public()} {
		assert.True(t, fresh.Valid(id))
	}

	// a set pinned to a different root trusts none of it
	other := NewSet(newID(t).Public())
	other.Merge(back)
	assert.False(t, other.Valid(a.Public()))
	assert.False(t, other.Valid(root.Public()))
}

// An admitter's latest record restates a member's name; the record that
// vouched for it stays alongside, and the ones in between are not kept.
func Test_Set_newerAdmissionReplaces(t *testing.T) {
	root, a, _, _, set := cluster(t) // root's 2nd record admitted a as "a"

	ok, err := set.AddAdmission(Admit(root, a.Public(), "a-mid", 2, 3, t0.Add(30*time.Minute)))
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = set.AddAdmission(Admit(root, a.Public(), "a-new", 2, 4, t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)
	got, _ := set.Lookup(a.Public())
	assert.Equal(t, "a-new", got.Name, "the admitter's latest record decides")

	var forA []Admission
	for _, adm := range set.Records().Admissions {
		if adm.Identity == a.Public() {
			forA = append(forA, adm)
		}
	}
	require.Len(t, forA, 3, "every record the admitter signed, so its sequence has no gap")
	assert.Equal(t, uint64(2), forA[0].Seq, "the record that vouched for a in the first place")
	assert.Equal(t, uint64(4), forA[2].Seq, "and its latest, which decides")
}

// Which of one admitter's own records states a member's name and slot is its
// counter's answer, not its clock's: a date that went backwards between the
// two does not put the superseded record back in charge.
func Test_Set_laterRecordDecidesByTheCounter(t *testing.T) {
	root, a, _, _, set := cluster(t) // root's 2nd record admitted a as "a"

	_, err := set.AddAdmission(Admit(root, a.Public(), "a-new", 2, 3, t0.Add(-time.Hour)))
	require.NoError(t, err)
	got, _ := set.Lookup(a.Public())
	assert.Equal(t, "a-new", got.Name, "the admitter's later record decides, backdated or not")

	// between admitters there is no shared counter, so the date decides there
	b := newID(t)
	_, err = set.AddAdmission(admit(set, root, b.Public(), "b", 5, t0))
	require.NoError(t, err)
	_, err = set.AddAdmission(admit(set, a, b.Public(), "b-by-a", 5, t0.Add(time.Hour)))
	require.NoError(t, err)
	got, _ = set.Lookup(b.Public())
	assert.Equal(t, "b-by-a", got.Name, "the later of the two admitters' claims")
}

// An admitter that has been revoked cannot take back the membership it
// vouched for: its earliest record stands, whatever it signs afterwards.
func Test_Set_revokedAdmitterCannotRetract(t *testing.T) {
	root, a, b, _, set := cluster(t)
	_, err := set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))
	require.True(t, set.Valid(b.Public()), "b was admitted while a was a member")

	_, err = set.AddAdmission(admit(set, a, b.Public(), "b", 3, t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.True(t, set.Valid(b.Public()), "a is no longer the one to say so")

	adm, ok := set.Lookup(b.Public())
	require.True(t, ok)
	assert.Equal(t, t0.Add(2*time.Minute).Unix(), adm.IssuedAt, "the record a signed while it was a member decides")
}

func Test_Set_ByName(t *testing.T) {
	root, a, _, _, set := cluster(t)
	got, ok := set.ByName("a")
	require.True(t, ok)
	assert.Equal(t, a.Public(), got.Identity)
	got, ok = set.ByName("root")
	require.True(t, ok, "the root's own record is not special")
	assert.Equal(t, root.Public(), got.Identity)
	_, ok = set.ByName("nobody")
	assert.False(t, ok)

	// two valid members with one name: ambiguous
	twin := newID(t)
	_, err := set.AddAdmission(admit(set, root, twin.Public(), "a", 9, t0))
	require.NoError(t, err)
	_, ok = set.ByName("a")
	assert.False(t, ok)

	// a revoked member's name no longer resolves
	_, err = set.AddRevocation(revoke(set, root, twin.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	got, ok = set.ByName("a")
	require.True(t, ok)
	assert.Equal(t, a.Public(), got.Identity)
}

func Test_Set_NameTaken(t *testing.T) {
	root, a, b, stranger, set := cluster(t)
	assert.True(t, set.NameTaken("a", PublicKey{}))
	assert.False(t, set.NameTaken("a", a.Public()), "a node may keep its own name")
	assert.False(t, set.NameTaken("nobody", PublicKey{}))
	assert.True(t, set.NameTaken("root", stranger.Public()))

	_, err := set.AddRevocation(revoke(set, root, b.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.False(t, set.NameTaken("b", PublicKey{}), "a revoked member's name is free")
}

func Test_Set_FreeHost(t *testing.T) {
	root, a, b, _, set := cluster(t) // slots 1, 2, 3
	h, err := set.FreeHost(10)
	require.NoError(t, err)
	assert.Equal(t, uint64(4), h)

	// gaps are filled first
	set2 := NewSet(root.Public())
	set2.Merge(Records{Admissions: []Admission{SelfAdmit(root, "root", t0), Admit(root, b.Public(), "b", 3, 2, t0)}})
	h, err = set2.FreeHost(10)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), h)

	// a revoked member's slot is reused only once nothing else is free
	_, err = set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	h, err = set.FreeHost(4)
	require.NoError(t, err)
	assert.Equal(t, uint64(4), h)
	h, err = set.FreeHost(3)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), h, "a's slot")

	_, err = set2.FreeHost(1)
	assert.ErrorIs(t, err, ErrOverlayFull)
}

// hostClash and nameClash ask Conflicts what it says about one identity, the
// way a caller checking a single node does.
func hostClash(s *Set, id PublicKey) (Admission, bool) { return clash(s, id, ContestedHost) }
func nameClash(s *Set, id PublicKey) (Admission, bool) { return clash(s, id, ContestedName) }

func clash(s *Set, id PublicKey, contested string) (Admission, bool) {
	c, held := s.Conflicts()[id]
	if !held || c.Contested != contested {
		return Admission{}, false
	}
	return c.Other, true
}

func Test_Set_Conflicts_host(t *testing.T) {
	root, a, b, _, set := cluster(t)
	_, clash := hostClash(set, a.Public())
	assert.False(t, clash)

	// two admitters hand out slot 4 at once: the earlier admission wins
	c, d := newID(t), newID(t)
	set.Merge(Records{Admissions: []Admission{
		admit(set, root, c.Public(), "c", 4, t0.Add(10*time.Minute)),
		admit(set, a, d.Public(), "d", 4, t0.Add(11*time.Minute)),
	}})
	_, clash = hostClash(set, c.Public())
	assert.False(t, clash)
	winner, clash := hostClash(set, d.Public())
	assert.True(t, clash)
	assert.Equal(t, "c", winner.Name)

	// revoking the winner frees the slot for the loser
	_, err := set.AddRevocation(revoke(set, root, c.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	_, clash = hostClash(set, d.Public())
	assert.False(t, clash)

	// same second: the smaller identity wins, and both sides agree
	e, f := newID(t), newID(t)
	set.Merge(Records{Admissions: []Admission{
		admit(set, root, e.Public(), "e", 5, t0),
		admit(set, b, f.Public(), "f", 5, t0),
	}})
	_, eLoses := hostClash(set, e.Public())
	_, fLoses := hostClash(set, f.Public())
	assert.NotEqual(t, eLoses, fLoses)
	eKey, fKey := e.Public(), f.Public()
	assert.Equal(t, bytes.Compare(eKey[:], fKey[:]) > 0, eLoses)

	// an unknown identity has nothing to conflict with
	_, clash = hostClash(set, newID(t).Public())
	assert.False(t, clash)
}

// A name is handed out twice the way a slot is, by two admitters enrolling at
// once, and the records settle it the same way.
func Test_Set_Conflicts_name(t *testing.T) {
	root, a, b, _, set := cluster(t)
	_, clash := nameClash(set, a.Public())
	assert.False(t, clash)

	// two admitters admit a "web1" at once: the earlier admission keeps it
	c, d := newID(t), newID(t)
	set.Merge(Records{Admissions: []Admission{
		admit(set, root, c.Public(), "web1", 4, t0.Add(10*time.Minute)),
		admit(set, a, d.Public(), "web1", 5, t0.Add(11*time.Minute)),
	}})
	_, clash = nameClash(set, c.Public())
	assert.False(t, clash)
	winner, clash := nameClash(set, d.Public())
	assert.True(t, clash)
	assert.Equal(t, c.Public(), winner.Identity)
	_, clash = hostClash(set, d.Public())
	assert.False(t, clash, "the two hold different slots; it is the name they contest")

	// revoking the winner frees the name for the loser
	_, err := set.AddRevocation(revoke(set, root, c.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	_, clash = nameClash(set, d.Public())
	assert.False(t, clash)

	// same second: the smaller identity wins, and both sides agree
	e, f := newID(t), newID(t)
	set.Merge(Records{Admissions: []Admission{
		admit(set, root, e.Public(), "web2", 6, t0),
		admit(set, b, f.Public(), "web2", 7, t0),
	}})
	_, eLoses := nameClash(set, e.Public())
	_, fLoses := nameClash(set, f.Public())
	assert.NotEqual(t, eLoses, fLoses)
	eKey, fKey := e.Public(), f.Public()
	assert.Equal(t, bytes.Compare(eKey[:], fKey[:]) > 0, eLoses)

	// an unknown identity has nothing to conflict with
	_, clash = nameClash(set, newID(t).Public())
	assert.False(t, clash)
}

// A member contesting both a slot and a name is reported for the slot: it has
// to be enrolled again either way, and one reason is enough to say so.
func Test_Set_Conflicts_reportsTheSlotFirst(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, d := newID(t), newID(t)
	set.Merge(Records{Admissions: []Admission{
		admit(set, root, c.Public(), "web1", 4, t0.Add(10*time.Minute)),
		admit(set, a, d.Public(), "web1", 4, t0.Add(11*time.Minute)),
	}})
	conflicts := set.Conflicts()
	assert.Equal(t, ContestedHost, conflicts[d.Public()].Contested)
	assert.NotContains(t, conflicts, c.Public(), "the earlier admission keeps both")
}

// Every member is answered for in one pass, so a caller with a whole
// membership to check asks once.
func Test_Set_Conflicts_answersForEveryMember(t *testing.T) {
	root, a, b, _, set := cluster(t)
	assert.Empty(t, set.Conflicts(), "a settled cluster has none")
	c := newID(t)
	set.Merge(Records{Admissions: []Admission{admit(set, a, c.Public(), "b", 9, t0.Add(time.Hour))}})
	conflicts := set.Conflicts()
	assert.Len(t, conflicts, 1)
	assert.Equal(t, b.Public(), conflicts[c.Public()].Other.Identity, "b was admitted earlier and keeps the name")
	_ = root
}

func Test_Set_validity_cycle(t *testing.T) {
	_, _, _, _, set := cluster(t)
	x, y := newID(t), newID(t)
	assert.Equal(t, 2, mergeChanged(set, Records{Admissions: []Admission{
		admit(set, x, y.Public(), "y", 7, t0),
		admit(set, y, x.Public(), "x", 8, t0),
	}}), "the records are well signed and kept")
	assert.False(t, set.Valid(x.Public()))
	assert.False(t, set.Valid(y.Public()))
}

func Test_Set_revocation_ofOwnAdmitter(t *testing.T) {
	_, a, b, _, set := cluster(t) // root admitted a, a admitted b
	rev := revoke(set, b, a.Public(), t0.Add(time.Hour))
	ok, err := set.AddRevocation(rev)
	require.NoError(t, err)
	require.True(t, ok)
	assert.False(t, set.Valid(a.Public()), "a member may revoke the member that admitted it")
	assert.True(t, set.Valid(b.Public()), "the revoker keeps the membership it was already granted")
}

func Test_Set_revocationsMergeAndRoundTrip(t *testing.T) {
	root, a, b, _, set := cluster(t)
	revB := revoke(set, root, b.Public(), t0.Add(time.Hour))
	assert.Equal(t, 1, set.Merge(Records{Revocations: []Revocation{revB}}).Changed)
	assert.Equal(t, 0, set.Merge(Records{Revocations: []Revocation{revB}}).Changed, "idempotent")
	revA := revoke(set, root, a.Public(), t0.Add(2*time.Hour))
	assert.Equal(t, 1, set.Merge(Records{Revocations: []Revocation{revA}}).Changed)

	rs := set.Records()
	require.Len(t, rs.Revocations, 2)
	assert.Less(t, bytes.Compare(rs.Revocations[0].Identity[:], rs.Revocations[1].Identity[:]), 0, "sorted by identity")
	assert.ElementsMatch(t, []Revocation{revA, revB}, rs.Revocations)
	fresh := NewSet(root.Public())
	fresh.Merge(rs)
	assert.False(t, fresh.Valid(a.Public()))
	assert.False(t, fresh.Valid(b.Public()))
}

// Validity is cached, so the answer must still change the moment a record does.
func Test_Set_Valid_cacheFollowsTheRecords(t *testing.T) {
	root, a, b, stranger, set := cluster(t)
	for range 2 { // the second answer comes from the cache
		assert.True(t, set.Valid(a.Public()))
		assert.True(t, set.Valid(b.Public()))
		assert.False(t, set.Valid(stranger.Public()))
	}

	_, err := set.AddRevocation(revoke(set, root, b.Public(), t0.Add(time.Minute)))
	require.NoError(t, err)
	assert.False(t, set.Valid(b.Public()), "the revocation is not hidden by the cached answer")
	assert.True(t, set.Valid(a.Public()))

	// an identity admitted after it was first asked about becomes valid
	c := newID(t)
	assert.False(t, set.Valid(c.Public()))
	_, err = set.AddAdmission(admit(set, root, c.Public(), "c", 5, t0))
	require.NoError(t, err)
	assert.True(t, set.Valid(c.Public()))
}

// Anything that can open a connection is asked about, so what a query holds
// must not grow with who asks. The view is derived from the records alone, so
// a stranger leaves nothing behind however often it is asked about.
func Test_Set_Valid_strangerHoldsNothing(t *testing.T) {
	_, a, _, stranger, set := cluster(t)
	assert.True(t, set.Valid(a.Public()))
	for range 100 {
		assert.False(t, set.Valid(newID(t).Public()))
	}
	assert.False(t, set.Valid(stranger.Public()))
	assert.Len(t, set.current().members, 3, "the root and the two it admitted, whoever else asked")
}

// The view is read without the lock; the race detector is the point of this.
func Test_Set_Valid_concurrentWithChanges(t *testing.T) {
	root, a, _, _, set := cluster(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				set.Valid(a.Public())
			}
		}()
	}
	for i := range 20 {
		other := newID(t)
		_, err := set.AddAdmission(admit(set, root, other.Public(), fmt.Sprintf("n%d", i), uint64(i+10), t0))
		require.NoError(t, err)
	}
	wg.Wait()
	assert.True(t, set.Valid(a.Public()))
}

// A record by an identity the cluster does not believe must not displace one
// it does: an identity that has been revoked keeps its own key, and signing a
// later admission for a member was once enough to take that member out.
func Test_Set_admissionByNonMemberDoesNotDisplace(t *testing.T) {
	root, a, b, stranger, set := cluster(t)

	for _, forger := range []*Identity{stranger, a} {
		if forger == a {
			_, err := set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
			require.NoError(t, err)
			require.False(t, set.Valid(a.Public()))
		}
		ok, err := set.AddAdmission(admit(set, forger, b.Public(), "b", 3, t0.Add(2*time.Hour)))
		require.NoError(t, err)
		assert.True(t, ok, "the record is stored: it may yet be vouched for")
		assert.True(t, set.Valid(b.Public()), "the member stays a member")

		adm, found := set.Lookup(b.Public())
		require.True(t, found)
		assert.Equal(t, a.Public(), adm.Admitter, "the record that decides b is still the one a signed while it was a member")
	}
}

// Nothing an identity signs may rename or renumber a member behind its
// admitter's back.
func Test_Set_effectiveRecordIgnoresUnvouchedRecords(t *testing.T) {
	root, _, b, stranger, set := cluster(t)
	_, err := set.AddAdmission(admit(set, stranger, b.Public(), "impostor", 9, t0.Add(time.Hour)))
	require.NoError(t, err)

	adm, ok := set.Lookup(b.Public())
	require.True(t, ok)
	assert.Equal(t, "b", adm.Name)
	assert.Equal(t, uint64(3), adm.Host)
	assert.False(t, set.NameTaken("impostor", root.Public()))

	byName, ok := set.ByName("b")
	require.True(t, ok)
	assert.Equal(t, b.Public(), byName.Identity)
}

// Two nodes holding the same records must reach the same answers, whatever
// order those records reached them.
// A peer hands over its whole record set at once, in no order of ours. Each
// signer's records go in in the order it signed them, and of one admitter's
// records the earliest and the latest are kept: the earliest is what vouched
// for the identity in the first place, so a revocation naming only that one
// still leaves the member in.
func Test_Set_recordsGoInInSequenceOrder(t *testing.T) {
	root, a, b := newID(t), newID(t), newID(t)
	set := NewSet(root.Public())

	early := Admit(a, b.Public(), "b", 3, 1, t0.Add(2*time.Minute))
	mid := Admit(a, newID(t).Public(), "mid", 5, 2, t0.Add(150*time.Second))
	late := Admit(a, b.Public(), "b", 3, 3, t0.Add(3*time.Minute))
	// offered newest first, and a's records ahead of the one that admitted a
	res := set.Merge(Records{Admissions: []Admission{
		late, mid, early,
		Admit(root, a.Public(), "a", 2, 2, t0.Add(time.Minute)),
		SelfAdmit(root, "root", t0),
	}})
	require.Zero(t, res.Refused)
	require.Zero(t, res.Deferred, "no record waited on one later in the list")
	require.True(t, set.Valid(b.Public()))

	// the root revokes a, keeping only the record that first vouched for b
	rev := Revoke(root, a.Public(), set.NextSeq(root.Public()), 1, t0.Add(4*time.Minute))
	_, err := set.AddRevocation(rev)
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))
	assert.True(t, set.Valid(b.Public()), "the revocation named the record that vouched for b")

	var mine []Admission
	for _, adm := range set.Records().Admissions {
		if adm.Identity == b.Public() {
			mine = append(mine, adm)
		}
	}
	require.Len(t, mine, 2, "both ends of a's records for b are kept")
	assert.Equal(t, uint64(1), mine[0].Seq)
	assert.Equal(t, uint64(3), mine[1].Seq)
}

func Test_Set_answersDoNotDependOnArrivalOrder(t *testing.T) {
	root, a, b, _, _ := cluster(t)
	c := newID(t)

	// b leaves, keeping nothing it signed, and then admits c anyway; the root
	// revokes it later, keeping everything it has seen b sign, c's admission
	// among it
	leave := Revoke(b, b.Public(), 1, 0, t0.Add(90*time.Second))
	admitC := Admit(b, c.Public(), "c", 4, 2, t0.Add(95*time.Second))
	records := []any{
		SelfAdmit(root, "root", t0),                             // root's 1st
		Admit(root, a.Public(), "a", 2, 2, t0.Add(time.Minute)), // root's 2nd
		Admit(a, b.Public(), "b", 3, 1, t0.Add(2*time.Minute)),  // a's 1st
		leave,
		admitC,
		Revoke(root, b.Public(), 3, 2, t0.Add(200*time.Second)),
	}

	answers := func(order []int) [4]bool {
		set := NewSet(root.Public())
		var rs Records
		for _, i := range order {
			switch rec := records[i].(type) {
			case Admission:
				rs.Admissions = append(rs.Admissions, rec)
			case Revocation:
				rs.Revocations = append(rs.Revocations, rec)
			}
		}
		res := set.Merge(rs)
		require.Zero(t, res.Refused)
		require.Zero(t, res.Deferred, "a whole set goes in whatever order it is offered in")
		return [4]bool{set.Valid(root.Public()), set.Valid(a.Public()), set.Valid(b.Public()), set.Valid(c.Public())}
	}

	forward := answers([]int{0, 1, 2, 3, 4, 5})
	assert.Equal(t, [4]bool{true, true, false, false}, forward, "b left of its own accord keeping nothing, so the root keeping c's admission for it counts for nothing")
	assert.Equal(t, forward, answers([]int{5, 4, 3, 2, 1, 0}), "reversed")
	assert.Equal(t, forward, answers([]int{5, 0, 3, 1, 4, 2}), "interleaved")
}

// A revoked node keeps its key, so it can still sign. What its revoker kept,
// not the timestamp, is what stops it: a record the revocation does not name
// carries nothing, however far back it is dated.
func Test_Set_revokedAdmitterCannotBackdate(t *testing.T) {
	root, a, b, _, set := cluster(t) // a's 1st record admitted b
	_, err := set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))
	assert.True(t, set.Valid(b.Public()), "admitted by a's 1st record, which the revocation keeps")

	c := newID(t)
	ok, err := set.AddAdmission(Admit(a, c.Public(), "c", 4, 2, t0.Add(-time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok, "the record is stored: nothing about it is malformed")
	assert.False(t, set.Valid(c.Public()), "not kept, so a was not a member when it signed")
}

// The numbers a signer has used are its own to choose, so one that left gaps
// below a mark on its sequence could sign into them after the mark was made.
// Taking a signer's records in order is what settles it: there are no gaps,
// every number up to its head is spent, and nothing is put at one again.
func Test_Set_aSignerLeavesNoGapsToFill(t *testing.T) {
	root, a, _, _, set := cluster(t) // a's 1st record admitted b
	c, mole := newID(t), newID(t)

	// a cannot jump ahead, which is what would leave the numbers below free
	_, err := set.AddAdmission(Admit(a, c.Public(), "c", 4, 100, t0.Add(time.Minute)))
	require.ErrorIs(t, err, ErrAhead)
	require.False(t, set.Valid(c.Public()))

	_, err = set.AddAdmission(Admit(a, c.Public(), "c", 4, 2, t0.Add(time.Minute)))
	require.NoError(t, err)
	require.True(t, set.Valid(c.Public()))

	_, err = set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))
	require.True(t, set.Valid(c.Public()), "what a signed while it was a member still stands")

	// every number a has reached is spent, so it can put nothing below its head
	for _, seq := range []uint64{1, 2} {
		_, err = set.AddAdmission(Admit(a, mole.Public(), "mole", 5, seq, t0.Add(2*time.Hour)))
		assert.ErrorIs(t, err, errSpent, "seq %d", seq)
	}
	assert.False(t, set.Valid(mole.Public()))
}

// A signer's number is spent once. A second, different record at it is refused
// rather than kept beside the first: taking a signer's records in order is what
// lets a mark on its sequence say where its records stop, and two records at
// one number would leave that ambiguous. Its key has been used outside its
// agent either way, which is reported.
func Test_Set_aSecondRecordAtOneNumberIsRefused(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, d, e := newID(t), newID(t), newID(t)

	first := Admit(a, c.Public(), "c", 4, 2, t0)
	ok, err := set.AddAdmission(first)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = set.AddAdmission(Admit(a, d.Public(), "d", 5, 2, t0)) // a's 2nd, again
	assert.ErrorIs(t, err, errSpent, "a number is spent once")
	assert.True(t, set.Valid(c.Public()), "the record that took the number stands")
	assert.False(t, set.Valid(d.Public()), "the one behind it is not held at all")

	ok, err = set.AddAdmission(first)
	require.NoError(t, err)
	assert.False(t, ok, "the same record arriving again changes nothing")
	assert.Equal(t, uint64(3), set.NextSeq(a.Public()), "a number is not handed out twice")

	// once a is out, what it signed before still stands and what it signs now does not
	_, err = set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, set.Valid(c.Public()), "kept by the revocation")

	_, err = set.AddAdmission(Admit(a, e.Public(), "e", 6, 3, t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.False(t, set.Valid(e.Public()), "signed after a was out, at a number nobody had used")
}

// Only the first record at one of a signer's numbers is taken, so which one a
// set carries them in must not decide it. They are ordered by signature, so two
// nodes offered the same set keep the same record and answer alike.
func Test_Set_twoRecordsAtOneNumberDoNotDependOnArrivalOrder(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, d := newID(t), newID(t)
	records := Records{Admissions: []Admission{Admit(a, c.Public(), "c", 4, 2, t0), Admit(a, d.Public(), "d", 5, 2, t0)}}
	reversed := Records{Admissions: []Admission{records.Admissions[1], records.Admissions[0]}}

	forwards, backwards := NewSet(root.Public()), NewSet(root.Public())
	for _, pair := range []struct {
		set *Set
		rs  Records
	}{{forwards, records}, {backwards, reversed}} {
		pair.set.Merge(set.Records())
		assert.Equal(t, 1, pair.set.Merge(pair.rs).Changed, "one of the two takes the number")
	}

	assert.Equal(t, forwards.Records(), backwards.Records())
	for _, id := range []PublicKey{c.Public(), d.Public()} {
		assert.Equal(t, forwards.Valid(id), backwards.Valid(id), id.Short())
	}
}

// Records comes out in one order however often it is asked for, so the state
// file and what goes to a peer do not churn. Of one revoker's two records at
// one number every node keeps the same one, so the order does not depend on
// which arrived first either.
func Test_Set_recordOrderIsStable(t *testing.T) {
	root, _, _, _, set := cluster(t)
	var signed []Revocation
	for seq := uint64(3); seq < 40; seq++ {
		victim := newID(t).Public()
		for _, at := range []time.Duration{time.Hour, 2 * time.Hour} { // two records, one number
			signed = append(signed, Revoke(root, victim, seq, 0, t0.Add(at)))
		}
	}
	set.Merge(Records{Revocations: signed})
	require.Len(t, set.Records().Revocations, 37, "one revoker keeps one record per identity it revokes")

	first := set.Records()
	for range 100 {
		assert.Equal(t, first, set.Records())
	}

	// a node told them the other way round settles on the same records
	reversed := Records{Admissions: first.Admissions, Revocations: slices.Clone(signed)}
	slices.Reverse(reversed.Revocations)
	fresh := NewSet(root.Public())
	fresh.Merge(reversed)
	assert.Equal(t, first, fresh.Records())
}

// A revocation cannot be undone by its signer putting another record at the
// number it took: that number is spent, so the second record is refused.
func Test_Set_laterRecordAtOneNumberDoesNotUndoARevocation(t *testing.T) {
	root, a, _, _, set := cluster(t)
	rev := revoke(set, root, a.Public(), t0.Add(time.Hour))
	_, err := set.AddRevocation(rev)
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))

	_, err = set.AddAdmission(Admit(root, newID(t).Public(), "junk", 9, rev.Seq, t0.Add(2*time.Hour)))
	assert.ErrorIs(t, err, errSpent)
	assert.False(t, set.Valid(a.Public()), "the revocation stands")
}

// A signer's next number is one past everything it has been seen to sign, so a
// node that restarts from its records does not reuse one.
func Test_Set_NextSeq(t *testing.T) {
	root, a, _, stranger, set := cluster(t)
	assert.Equal(t, uint64(3), set.NextSeq(root.Public()), "past the self-admission and one admission")
	assert.Equal(t, uint64(2), set.NextSeq(a.Public()))
	assert.Equal(t, uint64(1), set.NextSeq(stranger.Public()), "a signer with no records starts at 1")

	for _, seq := range []uint64{3, 4} {
		_, err := set.AddAdmission(Admit(root, a.Public(), "a", 2, seq, t0.Add(time.Hour)))
		require.NoError(t, err)
	}
	assert.Equal(t, uint64(5), set.NextSeq(root.Public()))

	fresh := NewSet(root.Public())
	fresh.Merge(set.Records())
	assert.Equal(t, uint64(5), fresh.NextSeq(root.Public()), "and survives a round trip through the records")
}

// The records a node holds need not say how far a signer's counter reached:
// one that advanced it may have been dropped, or may never have arrived. The
// signer persists the number itself and reads it back, rather than signing at
// one it has already used; a node that did otherwise would put two different
// records at one of its numbers and report the cluster compromised.
func Test_Set_NextSeq_survivesARestartWithoutTheRecord(t *testing.T) {
	root, a, b, c := newID(t), newID(t), newID(t), newID(t)
	set := NewSet(root.Public())
	admissions := []Admission{
		SelfAdmit(root, "root", t0),
		Admit(root, a.Public(), "a", 2, 2, t0),
		Admit(a, b.Public(), "b", 3, 1, t0),
		Admit(a, c.Public(), "c", 4, 2, t0), // a's highest
	}
	for _, adm := range admissions {
		_, err := set.AddAdmission(adm)
		require.NoError(t, err)
	}
	require.Equal(t, uint64(3), set.NextSeq(a.Public()), "a has spent 1 and 2")

	signers := set.SignerStates()
	fresh := NewSet(root.Public())
	fresh.Merge(Records{Admissions: admissions[:3]}) // without the record that took a's second number
	assert.Equal(t, uint64(2), fresh.NextSeq(a.Public()), "the records alone no longer say a reached 2")
	fresh.RestoreSigners(signers)
	assert.Equal(t, uint64(3), fresh.NextSeq(a.Public()), "the number persisted beside them says so")

	fresh.RestoreSigners(map[PublicKey]SignerState{a.Public(): {Head: 1}})
	assert.Equal(t, uint64(3), fresh.NextSeq(a.Public()), "a head is never lowered")
}

// A record no clock could honestly have produced is kept out of a set that
// never forgets. The bounds are wide: policing skew is the warning's job.
func Test_Set_checkClock(t *testing.T) {
	root, a, _, _, set := cluster(t)
	set.now = func() time.Time { return t0 }

	_, err := set.AddAdmission(Admit(root, newID(t).Public(), "ancient", 8, 3, time.Unix(epoch-1, 0)))
	assert.ErrorContains(t, err, "dated before 2020-01-01")

	_, err = set.AddAdmission(Admit(root, newID(t).Public(), "ahead", 9, 3, t0.Add(ahead+time.Minute)))
	assert.ErrorContains(t, err, "in the future")
	_, err = set.AddRevocation(Revoke(a, root.Public(), 2, 0, t0.Add(ahead+time.Minute)))
	assert.ErrorContains(t, err, "in the future")
	assert.True(t, set.Valid(root.Public()), "a revocation that was refused revokes nobody")

	// skewed but plausible: kept, and the operator is told
	var log bytes.Buffer
	defer swapLogger(&log)()
	ok, err := set.AddAdmission(Admit(root, newID(t).Public(), "skewed", 10, 3, t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, log.String(), "clocks are synchronised")

	log.Reset()
	_, err = set.AddAdmission(Admit(root, newID(t).Public(), "close", 11, 4, t0.Add(time.Minute)))
	require.NoError(t, err)
	assert.Empty(t, log.String(), "ordinary skew is not worth a line")
}

// The floor under a signer's next record is the newest date on what it has
// already signed, whether or not that record was kept.
func Test_Set_LastSigned(t *testing.T) {
	root, a, _, stranger, set := cluster(t)
	assert.Equal(t, t0.Add(time.Minute).Unix(), set.LastSigned(root.Public()))
	assert.Equal(t, t0.Add(2*time.Minute).Unix(), set.LastSigned(a.Public()))
	assert.Zero(t, set.LastSigned(stranger.Public()))

	// the newest date the signer has been seen to sign at, not the newest record
	for _, seq := range []uint64{3, 4} {
		hours := time.Duration(10-seq) * time.Hour // the later record is the older date
		_, err := set.AddAdmission(Admit(root, a.Public(), "a", 2, seq, t0.Add(hours)))
		require.NoError(t, err)
	}
	assert.Equal(t, t0.Add(7*time.Hour).Unix(), set.LastSigned(root.Public()))
}

// A node's agent takes its next number from NextSeq and holds the cluster's
// lock from reading it to storing the record, so it cannot use one twice. Two
// different records at one number say the key was used somewhere else.
func Test_Set_reportsASequenceNumberUsedTwice(t *testing.T) {
	root, _, _, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	first := Admit(root, newID(t).Public(), "one", 10, 3, t0)
	second := Admit(root, newID(t).Public(), "two", 11, 3, t0) // same number, other record
	require.NoError(t, addAdmission(set, first))
	assert.Empty(t, log.String(), "the first record at a number is ordinary")

	assert.ErrorIs(t, addAdmission(set, second), errSpent)
	assert.Contains(t, log.String(), "two different records at one of its own sequence numbers")
	assert.Contains(t, log.String(), "rebuild it")
	assert.Contains(t, log.String(), root.Public().Short())

	assert.True(t, set.Valid(first.Identity), "the record that took the number stands")
	assert.False(t, set.Valid(second.Identity), "the one behind it is not held")
}

// A peer re-offers the whole set at every push/pull, so the report has to be
// about the number rather than about each time the record arrives.
func Test_Set_reportsASequenceNumberUsedTwiceOnlyOnce(t *testing.T) {
	root, _, _, _, set := cluster(t)
	first := Admit(root, newID(t).Public(), "one", 10, 3, t0)
	second := Admit(root, newID(t).Public(), "two", 11, 3, t0)
	require.NoError(t, addAdmission(set, first))
	require.ErrorIs(t, addAdmission(set, second), errSpent)

	var log bytes.Buffer
	defer swapLogger(&log)()
	for range 3 {
		require.NoError(t, addAdmission(set, first))
		require.ErrorIs(t, addAdmission(set, second), errSpent)
	}
	assert.Empty(t, log.String(), "the same two records arriving again say nothing new")
}

// Every kind of record advances the one counter, so a number reused across
// kinds is caught as well.
func Test_Set_reportsANumberReusedAcrossRecordKinds(t *testing.T) {
	root, _, b, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	require.NoError(t, addAdmission(set, Admit(root, newID(t).Public(), "one", 10, 3, t0)))
	assert.ErrorIs(t, addRevocation(set, Revoke(root, b.Public(), 3, 0, t0)), errSpent)
	assert.Contains(t, log.String(), "two different records at one of its own sequence numbers")
}

// A revoker keeps what it had seen its subject sign, so a node that has seen
// more loses the difference. That is the safe direction, but it means the
// cluster was changed from a node that was behind.
func Test_Set_reportsARevocationThatWithdrawsAdmissions(t *testing.T) {
	root, a, _, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	// the revoker had not seen a sign anything, so its cut is at nothing
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 0, t0.Add(time.Hour))))
	assert.Contains(t, log.String(), "cuts its subject's records off below")
	assert.Contains(t, log.String(), "admissions=1")
}

// A cut below a revocation its subject signed says that subject was already out
// when it signed, so the node it revoked was never validly revoked and is a
// member again. What the operator is told names both ways that happens.
func Test_Set_reportsACutBelowARevocationItsSubjectSigned(t *testing.T) {
	root, a, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, Revoke(a, b.Public(), 2, 0, t0.Add(time.Hour))))
	require.False(t, set.Valid(b.Public()))

	// the root cuts a off after its admission of b but before its revocation of
	// it, which is what a revoker that had not seen the revocation would sign
	var log bytes.Buffer
	defer swapLogger(&log)()
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3,
		1, t0.Add(2*time.Hour))))
	assert.Contains(t, log.String(), "never counted")
	assert.Contains(t, log.String(), "nodes it revoked are members again")
	assert.Contains(t, log.String(), "had not caught up")
	assert.Contains(t, log.String(), "revocations=1")
	assert.True(t, set.Valid(b.Public()), "and it says so because b really is back")
}

// The ordinary case is quiet: the revoker had seen everything this node has.
func Test_Set_saysNothingWhenARevocationKeepsWhatWeHave(t *testing.T) {
	root, a, _, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	require.NoError(t, addRevocation(set, revoke(set, root, a.Public(), t0.Add(time.Hour))))
	assert.Empty(t, log.String())
}

// A node revoking itself keeps what it signed and must not be reported for
// failing to keep the record it is signing now.
func Test_Set_saysNothingWhenANodeRevokesItself(t *testing.T) {
	_, a, _, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	require.NoError(t, addRevocation(set, revoke(set, a, a.Public(), t0.Add(time.Hour))))
	assert.Empty(t, log.String())
}

// A revocation counts only while its signer is judged to have been a member
// when it signed, so revoking the revoker without keeping the revocation
// withdraws it and its subject is a member again.
//
// This is not an oversight, and permanence cannot simply be bolted on: a
// record missing from a keep list was either signed after the revocation, which
// must not count, or signed before and never seen by the revoker, which should.
// The records cannot tell those apart, so honouring the second would honour the
// first, and Test_Set_aRevokedNodeCannotRevoke is what that costs.
func Test_Set_aRevocationLastsOnlyWhileItsSignerIsJudgedAMember(t *testing.T) {
	root, a, b, _, set := cluster(t)

	require.NoError(t, addRevocation(set, Revoke(a, b.Public(), 2, 0, t0.Add(time.Hour))))
	require.False(t, set.Valid(b.Public()), "a put b out")

	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3,
		1, t0.Add(2*time.Hour))))
	assert.False(t, set.Valid(a.Public()), "a is out")
	assert.True(t, set.Valid(b.Public()), "and b is back, because nothing keeps a's revocation of it")
}

// The other side of the same rule, and the reason it is the way it is: a node
// that has been revoked keeps its key, and nothing it signs afterwards counts.
func Test_Set_aRevokedNodeCannotRevoke(t *testing.T) {
	root, a, b, _, set := cluster(t)
	require.NoError(t, addRevocation(set, revoke(set, root, a.Public(), t0.Add(time.Hour))))
	require.False(t, set.Valid(a.Public()))
	require.True(t, set.Valid(b.Public()))

	// a, still holding its key, tries to take an innocent member out
	require.NoError(t, addRevocation(set, Revoke(a, b.Public(), 2, 0, t0.Add(2*time.Hour))))
	assert.True(t, set.Valid(b.Public()), "what a signs after it is out counts for nothing")
}

// Whatever the rule decides, it decides from the records alone, so two nodes
// holding the same ones agree however they arrived.
func Test_Set_theSameRecordsDecideTheSameInAnyOrder(t *testing.T) {
	root, a, b, _, set := cluster(t)
	records := set.Records()
	records.Revocations = []Revocation{
		Revoke(a, b.Public(), 2, 0, t0.Add(time.Hour)),
		Revoke(root, a.Public(), 3, 1, t0.Add(2*time.Hour)),
	}

	forwards := NewSet(root.Public())
	forwards.Merge(records)
	backwards := NewSet(root.Public())
	slices.Reverse(records.Admissions)
	slices.Reverse(records.Revocations)
	backwards.Merge(records)

	for _, id := range []PublicKey{root.Public(), a.Public(), b.Public()} {
		assert.Equal(t, forwards.Valid(id), backwards.Valid(id), id.Short())
	}
}

// The count a destructive change is measured against: what the records make
// members, not what the node can reach.
func Test_Set_MemberCount(t *testing.T) {
	root, _, b, _, set := cluster(t)
	assert.Equal(t, 3, set.MemberCount(), "root, a and b")

	require.NoError(t, addRevocation(set, revoke(set, root, b.Public(), t0.Add(time.Hour))))
	assert.Equal(t, 2, set.MemberCount(), "a revoked node is no member")

	require.NoError(t, addAdmission(set, admit(set, root, newID(t).Public(), "c", 4, t0.Add(2*time.Hour))))
	assert.Equal(t, 3, set.MemberCount())
}

// mergeChanged is Merge for the tests that only care how many records landed.
func mergeChanged(s *Set, rs Records) int { return s.Merge(rs).Changed }

// A record the set already holds is taken as read rather than checked again,
// which is what keeps a state sync from verifying the whole membership every
// time a peer offers it. Only an identical record counts as held: one that
// borrows a held record's signature still goes through the checks.
func Test_Set_takesAHeldRecordAsRead(t *testing.T) {
	root, a, _, _, set := cluster(t)
	adm, held := set.Lookup(a.Public())
	require.True(t, held)

	ok, err := set.AddAdmission(adm)
	require.NoError(t, err)
	assert.False(t, ok, "a record already held changes nothing")

	renamed := adm
	renamed.Name = "elsewhere"
	ok, err = set.AddAdmission(renamed)
	assert.Error(t, err, "the signature does not cover this name")
	assert.False(t, ok)
	after, _ := set.Lookup(a.Public())
	assert.Equal(t, "a", after.Name, "and the held record stands")

	rev := revoke(set, root, a.Public(), t0.Add(time.Hour))
	ok, err = set.AddRevocation(rev)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = set.AddRevocation(rev)
	require.NoError(t, err)
	assert.False(t, ok, "a revocation already held changes nothing")

	wider := rev
	wider.UpTo++
	_, err = set.AddRevocation(wider)
	assert.Error(t, err, "the signature does not cover another cut")
}

// The view is one set of answers rather than two. Every member holds the
// record that makes it one, so no identity is a member of a cluster that
// cannot say what it is called. A revocation that withdraws the chain its own
// signer stands on is where the two would come apart if membership were asked
// twice: chain(b) reached through that revocation's own walk stands, while
// nothing vouches for b from the outside.
func Test_Set_theViewAgreesWithItself(t *testing.T) {
	root, a, b, _, set := cluster(t)
	// b, which a admitted, revokes a and keeps none of its records — the
	// admission b itself stands on included
	require.NoError(t, addRevocation(set, Revoke(b, a.Public(), 1, 0, t0.Add(time.Hour))))

	v := set.current()
	require.NotEmpty(t, v.members)
	for id := range v.members {
		_, named := v.effective[id]
		assert.True(t, named, "%s is a member with no record naming it", id.Short())
	}
	for _, id := range []PublicKey{root.Public(), a.Public(), b.Public()} {
		if !set.Valid(id) {
			continue
		}
		_, ok := set.Lookup(id)
		assert.True(t, ok, "%s is a member, so a record names it", id.Short())
	}
}

// A revoker cannot weaken a revocation it has already issued by signing another
// that keeps more: of the marks it has put on one identity, the lowest is the
// one that counts. The record that decides nothing is still held, because the
// number it took is spent either way and a number with no record at it is a gap
// in the revoker's sequence that no node given the set could step over.
func Test_Set_aRevokerCannotRaiseACutItHasMade(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c := newID(t)
	require.NoError(t, addAdmission(set, Admit(a, c.Public(), "c", 9, 2, t0.Add(time.Hour))))
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 1, t0.Add(2*time.Hour))))
	require.False(t, set.Valid(c.Public()), "a admitted c above the mark")

	ok, err := set.AddRevocation(Revoke(root, a.Public(), 4, 2, t0.Add(3*time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok, "the record is held")
	assert.Equal(t, uint64(1), cutOn(set, a.Public()), "but the lower mark still decides")
	assert.False(t, set.Valid(c.Public()))

	// and what the revoker signed is a run of its numbers, so a node given the
	// records takes every one of them
	fresh := NewSet(root.Public())
	assert.Zero(t, fresh.Merge(set.Records()).Deferred)
	assert.Equal(t, set.Records(), fresh.Records())
}

// The state file is loaded by what it says rather than by re-deriving the
// order its records went in. A file that has a number with no record at it —
// left by a sweep, or by a version that dropped one — would otherwise lose
// everything above it: those records wait for one that is never coming, and the
// restored heads then refuse them for good.
func Test_Set_Restore_takesWhatFollowsAGap(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, d := newID(t), newID(t)
	require.NoError(t, addAdmission(set, Admit(a, c.Public(), "c", 9, 2, t0.Add(time.Hour))))
	require.NoError(t, addAdmission(set, Admit(a, d.Public(), "d", 10, 3, t0.Add(2*time.Hour))))

	// whatever left it out, a's second record is not in the file
	rs := set.Records()
	rs.Admissions = slices.DeleteFunc(rs.Admissions, func(x Admission) bool {
		return x.Admitter == a.Public() && x.Seq == 2
	})

	fresh := NewSet(root.Public())
	res := fresh.Restore(rs, set.SignerStates())
	assert.Zero(t, res.Deferred)
	assert.Zero(t, res.Refused)
	assert.True(t, fresh.Valid(d.Public()), "the record above the gap is held")
	assert.False(t, fresh.Valid(c.Public()), "and the one the file left out is not")
	assert.Equal(t, uint64(4), fresh.NextSeq(a.Public()), "every number a spent is still spent")

	// which is what merging the same records, as a peer's set is merged, loses
	merged := NewSet(root.Public())
	assert.Equal(t, 1, merged.Merge(rs).Deferred)
	assert.False(t, merged.Valid(d.Public()))
}

// A record the file cannot vouch for is skipped, not trusted for having been
// written by this node: the signatures are checked as they are on the wire.
func Test_Set_Restore_checksWhatItLoads(t *testing.T) {
	root, a, _, stranger, set := cluster(t)
	rs := set.Records()
	tampered := rs.Admissions[0]
	tampered.Name = "evil"
	rs.Admissions = append(rs.Admissions, tampered, SelfAdmit(stranger, "x", t0))

	fresh := NewSet(root.Public())
	res := fresh.Restore(rs, set.SignerStates())
	assert.Equal(t, 2, res.Refused)
	assert.True(t, fresh.Valid(a.Public()), "what verifies is loaded")
	assert.False(t, fresh.Valid(stranger.Public()), "a self-signed record is the pinned root's alone")
}

// Two copies of one record can be on their way into the set at once:
// memberlist delivers a broadcast and a push/pull state sync on different
// goroutines, and both carry the records the other does. Neither copy may be
// taken for a second record at a number its signer has already used.
func Test_Set_theSameRecordArrivingTwiceAtOnce(t *testing.T) {
	_, a, _, _, set := cluster(t)
	var records []Admission
	for i := range 100 {
		records = append(records, Admit(a, newID(t).Public(), nameOf(i), uint64(i+10), uint64(i+2), t0.Add(time.Hour)))
	}
	leaving := Revoke(a, a.Public(), uint64(len(records))+2, 1, t0.Add(2*time.Hour))

	var wg sync.WaitGroup
	failed := make(chan error, 8)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, adm := range records {
				if _, err := set.AddAdmission(adm); err != nil {
					select {
					case failed <- err:
					default:
					}
				}
			}
			if _, err := set.AddRevocation(leaving); err != nil {
				select {
				case failed <- err:
				default:
				}
			}
		}()
	}
	wg.Wait()
	close(failed)
	for err := range failed {
		t.Errorf("a record the set already holds was refused: %v", err)
	}
	assert.Len(t, set.Records().Admissions, len(records)+3, "each record went in once")
}
