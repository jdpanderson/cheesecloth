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

	ok, err := set.AddRevocation(revoke(set, a, b.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = set.AddRevocation(revoke(set, root, b.Public(), t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok, "a second revoker's record is kept beside the first")

	// one revoker's later record does not weaken the one it already issued
	ok, err = set.AddRevocation(revoke(set, a, b.Public(), t0.Add(3*time.Hour)))
	require.NoError(t, err)
	assert.False(t, ok, "a revoker's earliest record stands")

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

	ok, err := set.AddAdmission(Admit(root, a.Public(), "a-new", 2, 4, t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)
	got, _ := set.Lookup(a.Public())
	assert.Equal(t, "a-new", got.Name, "the admitter's latest record decides")

	// one signed between the two is neither end, so it changes nothing
	ok, err = set.AddAdmission(Admit(root, a.Public(), "a-mid", 2, 3, t0.Add(30*time.Minute)))
	require.NoError(t, err)
	assert.False(t, ok, "two are kept however many the admitter signs")
	got, _ = set.Lookup(a.Public())
	assert.Equal(t, "a-new", got.Name)

	var forA []Admission
	for _, adm := range set.Records().Admissions {
		if adm.Identity == a.Public() {
			forA = append(forA, adm)
		}
	}
	require.Len(t, forA, 2)
	assert.Equal(t, uint64(2), forA[0].Seq, "the record that vouched for a in the first place")
	assert.Equal(t, uint64(4), forA[1].Seq)
}

// Which of one admitter's own records states a member's name and slot is its
// counter's answer, not its clock's: a date that went backwards between the
// two does not put the superseded record back in charge.
func Test_Set_laterRecordDecidesByTheCounter(t *testing.T) {
	root, a, _, _, set := cluster(t) // root's 2nd record admitted a as "a"

	_, err := set.AddAdmission(Admit(root, a.Public(), "a-new", 2, 4, t0.Add(-time.Hour)))
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
// A peer can hand over an admitter's earlier record after a later one has
// already arrived. The earliest is what vouched for the identity in the first
// place, so it is kept rather than dropped as old news, and a revocation that
// names only that one still leaves the member in.
func Test_Set_earlierRecordArrivingLateIsKept(t *testing.T) {
	root, a := newID(t), newID(t)
	b := newID(t)
	set := NewSet(root.Public())
	for _, adm := range []Admission{
		SelfAdmit(root, "root", t0),
		Admit(root, a.Public(), "a", 2, 2, t0.Add(time.Minute)),
	} {
		_, err := set.AddAdmission(adm)
		require.NoError(t, err)
	}

	// a admitted b twice; this node has heard only the later record
	early := Admit(a, b.Public(), "b", 3, 1, t0.Add(2*time.Minute))
	late := Admit(a, b.Public(), "b", 3, 7, t0.Add(3*time.Minute))
	_, err := set.AddAdmission(late)
	require.NoError(t, err)

	// the root revokes a, and its own view holds only what it has seen
	rev := Revoke(root, a.Public(), set.NextSeq(root.Public()), [][]byte{early.Signature}, t0.Add(4*time.Minute))
	_, err = set.AddRevocation(rev)
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))
	require.False(t, set.Valid(b.Public()), "the only record this node holds is not one the revocation kept")

	// the earlier record arrives from a peer
	changed, err := set.AddAdmission(early)
	require.NoError(t, err)
	assert.True(t, changed, "an admitter's earliest record is kept, however late it arrives")
	assert.True(t, set.Valid(b.Public()), "the revocation named that record, so it still vouches for b")

	held := set.Records().Admissions
	var mine []Admission
	for _, adm := range held {
		if adm.Identity == b.Public() {
			mine = append(mine, adm)
		}
	}
	require.Len(t, mine, 2, "both ends of a's records for b are kept")
	assert.Equal(t, uint64(1), mine[0].Seq)
	assert.Equal(t, uint64(7), mine[1].Seq)
}

func Test_Set_answersDoNotDependOnArrivalOrder(t *testing.T) {
	root, a, b, _, _ := cluster(t)
	c := newID(t)

	// b leaves, keeping nothing it signed, and then admits c anyway; the root
	// revokes it later, keeping everything it has seen b sign, c's admission
	// among it
	leave := Revoke(b, b.Public(), 1, nil, t0.Add(90*time.Second))
	admitC := Admit(b, c.Public(), "c", 4, 2, t0.Add(95*time.Second))
	records := []any{
		SelfAdmit(root, "root", t0),                             // root's 1st
		Admit(root, a.Public(), "a", 2, 2, t0.Add(time.Minute)), // root's 2nd
		Admit(a, b.Public(), "b", 3, 1, t0.Add(2*time.Minute)),  // a's 1st
		leave,
		admitC,
		Revoke(root, b.Public(), 3, [][]byte{leave.Signature, admitC.Signature}, t0.Add(200*time.Second)),
	}

	answers := func(order []int) [4]bool {
		set := NewSet(root.Public())
		for _, i := range order {
			var err error
			switch rec := records[i].(type) {
			case Admission:
				_, err = set.AddAdmission(rec)
			case Revocation:
				_, err = set.AddRevocation(rec)
			}
			require.NoError(t, err)
		}
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

// The numbers a signer has used are its own to choose, so one that leaves gaps
// under its revocation must not be able to sign into them afterwards. Naming
// the records rather than a range of numbers is what settles it.
func Test_Set_revokedAdmitterCannotFillAnUnusedNumber(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, mole := newID(t), newID(t)

	// a signs its 2nd record at 100, leaving 2 to 99 unused
	_, err := set.AddAdmission(Admit(a, c.Public(), "c", 4, 100, t0.Add(time.Minute)))
	require.NoError(t, err)
	require.True(t, set.Valid(c.Public()))

	_, err = set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))
	require.True(t, set.Valid(c.Public()), "what a signed while it was a member still stands")

	// a now signs into a number it never used, below everything it did use
	ok, err := set.AddAdmission(Admit(a, mole.Public(), "mole", 5, 50, t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok, "the record is stored: nothing about it is malformed")
	assert.False(t, set.Valid(mole.Public()), "a was out when it signed, whatever number it used")
}

// A signer's counter orders its records; it decides nothing about them on its
// own. Two records at one number are two records, and each stands or falls on
// whether its signer was a member, which is what its revoker kept.
func Test_Set_twoRecordsAtOneNumberAreTwoRecords(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, d, e := newID(t), newID(t), newID(t)

	first := Admit(a, c.Public(), "c", 4, 2, t0)
	ok, err := set.AddAdmission(first)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = set.AddAdmission(Admit(a, d.Public(), "d", 5, 2, t0)) // a's 2nd, again
	require.NoError(t, err)
	assert.True(t, ok, "the second record is stored and passed on like any other")
	assert.True(t, set.Valid(c.Public()), "both were signed by a member, so both stand")
	assert.True(t, set.Valid(d.Public()))

	ok, err = set.AddAdmission(first)
	require.NoError(t, err)
	assert.False(t, ok, "the same record arriving again changes nothing")
	assert.Equal(t, uint64(3), set.NextSeq(a.Public()), "a number is not handed out twice")

	// once a is out, what it signed before still stands and what it signs now does not
	_, err = set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, set.Valid(c.Public()), "kept by the revocation")
	assert.True(t, set.Valid(d.Public()), "and so is the one that shared its number")

	ok, err = set.AddAdmission(Admit(a, e.Public(), "e", 6, 2, t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, set.Valid(e.Public()), "signed at the same number, but after a was out")
}

// Two records at one number reach two nodes in either order, and they answer
// alike and hold the same records.
func Test_Set_twoRecordsAtOneNumberDoNotDependOnArrivalOrder(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, d := newID(t), newID(t)
	records := Records{Admissions: []Admission{Admit(a, c.Public(), "c", 4, 2, t0), Admit(a, d.Public(), "d", 5, 2, t0)}}
	records.Revocations = []Revocation{Revoke(root, a.Public(), set.NextSeq(root.Public()),
		[][]byte{records.Admissions[0].Signature}, t0.Add(time.Hour))} // only the first was seen
	reversed := Records{
		Admissions:  []Admission{records.Admissions[1], records.Admissions[0]},
		Revocations: records.Revocations,
	}

	forwards, backwards := NewSet(root.Public()), NewSet(root.Public())
	for _, pair := range []struct {
		set *Set
		rs  Records
	}{{forwards, records}, {backwards, reversed}} {
		pair.set.Merge(set.Records())
		pair.set.Merge(pair.rs)
	}

	assert.Equal(t, forwards.Records(), backwards.Records())
	assert.True(t, forwards.Valid(c.Public()), "kept by the revocation")
	assert.False(t, forwards.Valid(d.Public()), "not kept, so its number does not save it")
	for _, id := range []PublicKey{c.Public(), d.Public()} {
		assert.Equal(t, forwards.Valid(id), backwards.Valid(id))
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
			signed = append(signed, Revoke(root, victim, seq, nil, t0.Add(at)))
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

// A revocation is not undone by its signer signing at the number it took: both
// records are the revoker's own, so whichever is the one at that number, it
// signed the revocation.
func Test_Set_laterRecordAtOneNumberDoesNotUndoARevocation(t *testing.T) {
	root, a, _, _, set := cluster(t)
	rev := revoke(set, root, a.Public(), t0.Add(time.Hour))
	_, err := set.AddRevocation(rev)
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))

	_, err = set.AddAdmission(Admit(root, newID(t).Public(), "junk", 9, rev.Seq, t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.False(t, set.Valid(a.Public()), "the root is still a member, so its revocation stands")
}

// A signer's next number is one past everything it has been seen to sign, so a
// node that restarts from its records does not reuse one.
func Test_Set_NextSeq(t *testing.T) {
	root, a, _, stranger, set := cluster(t)
	assert.Equal(t, uint64(3), set.NextSeq(root.Public()), "past the self-admission and one admission")
	assert.Equal(t, uint64(2), set.NextSeq(a.Public()))
	assert.Equal(t, uint64(1), set.NextSeq(stranger.Public()), "a signer with no records starts at 1")

	// a number stays used even when keepEnds does not keep the record using it
	for _, seq := range []uint64{9, 5} {
		_, err := set.AddAdmission(Admit(root, a.Public(), "a", 2, seq, t0.Add(time.Hour)))
		require.NoError(t, err)
	}
	assert.Equal(t, uint64(10), set.NextSeq(root.Public()))

	fresh := NewSet(root.Public())
	fresh.Merge(set.Records())
	assert.Equal(t, uint64(10), fresh.NextSeq(root.Public()), "and survives a round trip through the records")
}

// A prune takes the record that last advanced an admitter's counter, so the
// records it leaves do not say how far that counter reached. The admitter
// persists the number itself and reads it back, rather than signing at one it
// has already used; a node that never restarted would see two different
// records at one of its numbers and report the cluster compromised.
func Test_Set_NextSeq_survivesAPruneAndRestart(t *testing.T) {
	root, a, b, c := newID(t), newID(t), newID(t), newID(t)
	set := NewSet(root.Public())
	for _, adm := range []Admission{
		SelfAdmit(root, "root", t0),
		Admit(root, a.Public(), "a", 2, 2, t0),
		Admit(a, b.Public(), "b", 3, 1, t0),
		Admit(a, c.Public(), "c", 4, 2, t0), // a's highest, and the one the prune takes
	} {
		_, err := set.AddAdmission(adm)
		require.NoError(t, err)
	}
	_, err := set.AddRevocation(Revoke(root, c.Public(), set.NextSeq(root.Public()), set.SignedBy(c.Public()), t0))
	require.NoError(t, err)
	require.Equal(t, []PublicKey{c.Public()}, set.Prunable())
	_, err = set.AddPrune(SignPrune(root, set.Prunable(), set.NextSeq(root.Public()), t0))
	require.NoError(t, err)
	require.Equal(t, uint64(3), set.NextSeq(a.Public()), "a has spent 1 and 2")

	records, spent := set.Records(), set.HighWater(a.Public())
	fresh := NewSet(root.Public())
	fresh.Merge(records)
	assert.Equal(t, uint64(2), fresh.NextSeq(a.Public()), "the records alone no longer say a reached 2")
	fresh.Spent(a.Public(), spent)
	assert.Equal(t, uint64(3), fresh.NextSeq(a.Public()), "the number a persisted says so")

	fresh.Spent(a.Public(), 1)
	assert.Equal(t, uint64(3), fresh.NextSeq(a.Public()), "a counter is never lowered")
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
	_, err = set.AddRevocation(Revoke(a, root.Public(), 2, nil, t0.Add(ahead+time.Minute)))
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

	// a record that keepEnds drops still counts
	for _, seq := range []uint64{9, 5} {
		_, err := set.AddAdmission(Admit(root, a.Public(), "a", 2, seq, t0.Add(time.Duration(seq)*time.Hour)))
		require.NoError(t, err)
	}
	assert.Equal(t, t0.Add(9*time.Hour).Unix(), set.LastSigned(root.Public()))
}

// A node's agent takes its next number from NextSeq and holds the cluster's
// lock from reading it to storing the record, so it cannot use one twice. Two
// different records at one number say the key was used somewhere else.
func Test_Set_reportsASequenceNumberUsedTwice(t *testing.T) {
	root, _, _, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	first := Admit(root, newID(t).Public(), "one", 10, 7, t0)
	second := Admit(root, newID(t).Public(), "two", 11, 7, t0) // same number, other record
	require.NoError(t, addAdmission(set, first))
	assert.Empty(t, log.String(), "the first record at a number is ordinary")

	require.NoError(t, addAdmission(set, second))
	assert.Contains(t, log.String(), "two different records at one of its own sequence numbers")
	assert.Contains(t, log.String(), "rebuild it")
	assert.Contains(t, log.String(), root.Public().Short())

	// both records still stand: they cannot be told apart, so nothing is refused
	assert.True(t, set.Valid(first.Identity))
	assert.True(t, set.Valid(second.Identity))
}

// A peer re-offers the whole set at every push/pull, so the report has to be
// about the number rather than about each time the record arrives.
func Test_Set_reportsASequenceNumberUsedTwiceOnlyOnce(t *testing.T) {
	root, _, _, _, set := cluster(t)
	first := Admit(root, newID(t).Public(), "one", 10, 7, t0)
	second := Admit(root, newID(t).Public(), "two", 11, 7, t0)
	require.NoError(t, addAdmission(set, first))
	require.NoError(t, addAdmission(set, second))

	var log bytes.Buffer
	defer swapLogger(&log)()
	for range 3 {
		require.NoError(t, addAdmission(set, first))
		require.NoError(t, addAdmission(set, second))
	}
	assert.Empty(t, log.String(), "the same two records arriving again say nothing new")
}

// Every kind of record advances the one counter, so a number reused across
// kinds is caught as well.
func Test_Set_reportsANumberReusedAcrossRecordKinds(t *testing.T) {
	root, _, b, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	require.NoError(t, addAdmission(set, Admit(root, newID(t).Public(), "one", 10, 8, t0)))
	require.NoError(t, addRevocation(set, Revoke(root, b.Public(), 8, nil, t0)))
	assert.Contains(t, log.String(), "two different records at one of its own sequence numbers")
}

// A revoker keeps what it had seen its subject sign, so a node that has seen
// more loses the difference. That is the safe direction, but it means the
// cluster was changed from a node that was behind.
func Test_Set_reportsARevocationThatWithdrawsAdmissions(t *testing.T) {
	root, a, _, _, set := cluster(t)
	var log bytes.Buffer
	defer swapLogger(&log)()

	// the revoker had not seen a's admission of b, so its keep list is empty
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, nil, t0.Add(time.Hour))))
	assert.Contains(t, log.String(), "does not keep every record")
	assert.Contains(t, log.String(), "admissions=1")
}

// Withdrawing a revocation puts its subject back, which is the one that is
// worth an error rather than a warning.
func Test_Set_reportsARevocationThatWithdrawsRevocations(t *testing.T) {
	root, a, b, _, set := cluster(t)
	admOfB, ok := set.Lookup(b.Public())
	require.True(t, ok)
	require.NoError(t, addRevocation(set, Revoke(a, b.Public(), 2, nil, t0.Add(time.Hour))))
	require.False(t, set.Valid(b.Public()))

	// the root revokes a, keeping a's admission of b but not a's revocation of
	// it, which is what a revoker that had not seen the revocation would sign
	var log bytes.Buffer
	defer swapLogger(&log)()
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3,
		[][]byte{admOfB.Signature}, t0.Add(2*time.Hour))))
	assert.Contains(t, log.String(), "are members again")
	assert.Contains(t, log.String(), "treat it as compromised and rebuild it")
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
	admOfB, ok := set.Lookup(b.Public())
	require.True(t, ok)

	require.NoError(t, addRevocation(set, Revoke(a, b.Public(), 2, nil, t0.Add(time.Hour))))
	require.False(t, set.Valid(b.Public()), "a put b out")

	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3,
		[][]byte{admOfB.Signature}, t0.Add(2*time.Hour))))
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
	require.NoError(t, addRevocation(set, Revoke(a, b.Public(), 9, nil, t0.Add(2*time.Hour))))
	assert.True(t, set.Valid(b.Public()), "what a signs after it is out counts for nothing")
}

// Whatever the rule decides, it decides from the records alone, so two nodes
// holding the same ones agree however they arrived.
func Test_Set_theSameRecordsDecideTheSameInAnyOrder(t *testing.T) {
	root, a, b, _, set := cluster(t)
	admOfB, ok := set.Lookup(b.Public())
	require.True(t, ok)
	records := set.Records()
	records.Revocations = []Revocation{
		Revoke(a, b.Public(), 2, nil, t0.Add(time.Hour)),
		Revoke(root, a.Public(), 3, [][]byte{admOfB.Signature}, t0.Add(2*time.Hour)),
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

// Pruning acts on this node's records, and a revocation it acted on can later
// be withdrawn. A node that pruned meanwhile cannot take the records back, so
// it answers differently from one that did not. This is the hazard behind
// pruning from a node that is in touch with the cluster.
func Test_Set_pruningWhileASubjectIsOutCanDiverge(t *testing.T) {
	root, a, b, _, set := cluster(t)
	admOfB, ok := set.Lookup(b.Public())
	require.True(t, ok)
	outOfB := Revoke(a, b.Public(), 2, nil, t0.Add(time.Hour))
	// past the number the prune below takes, so the root does not look as
	// though it used one twice
	ofA := Revoke(root, a.Public(), 9, [][]byte{admOfB.Signature}, t0.Add(2*time.Hour))

	kept := NewSet(root.Public()) // never pruned
	kept.Merge(set.Records())
	require.NoError(t, addRevocation(kept, outOfB))

	require.NoError(t, addRevocation(set, outOfB))
	require.Contains(t, set.Prunable(), b.Public())
	require.True(t, addPrune(t, set, prune(t, set, root, t0.Add(90*time.Minute))))

	for _, s := range []*Set{set, kept} {
		require.NoError(t, addRevocation(s, ofA))
	}
	assert.True(t, kept.Valid(b.Public()), "the node that kept the records has b back")
	assert.False(t, set.Valid(b.Public()), "the node that pruned cannot, and disagrees")
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
	wider.Keeps = nil
	_, err = set.AddRevocation(wider)
	assert.Error(t, err, "the signature does not cover an empty keeps list")

	p := SignPrune(root, []PublicKey{a.Public()}, set.NextSeq(root.Public()), t0.Add(2*time.Hour))
	ok, err = set.AddPrune(p)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = set.AddPrune(p)
	require.NoError(t, err)
	assert.False(t, ok, "a prune already held changes nothing")

	other := p
	other.Identities = []PublicKey{root.Public()}
	_, err = set.AddPrune(other)
	assert.Error(t, err, "the signature does not cover these identities")
}
