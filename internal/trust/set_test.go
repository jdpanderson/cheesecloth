package trust

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	n := set.Merge(Records{Admissions: []Admission{bad, good}, Revocations: []Revocation{badRev}})
	assert.Equal(t, 1, n)
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
	assert.Equal(t, 3, fresh.Merge(back))
	assert.Equal(t, 0, fresh.Merge(back), "idempotent")
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

func Test_Set_HostConflict(t *testing.T) {
	root, a, b, _, set := cluster(t)
	_, clash := set.HostConflict(a.Public())
	assert.False(t, clash)

	// two admitters hand out slot 4 at once: the earlier admission wins
	c, d := newID(t), newID(t)
	set.Merge(Records{Admissions: []Admission{
		admit(set, root, c.Public(), "c", 4, t0.Add(10*time.Minute)),
		admit(set, a, d.Public(), "d", 4, t0.Add(11*time.Minute)),
	}})
	_, clash = set.HostConflict(c.Public())
	assert.False(t, clash)
	winner, clash := set.HostConflict(d.Public())
	assert.True(t, clash)
	assert.Equal(t, "c", winner.Name)

	// revoking the winner frees the slot for the loser
	_, err := set.AddRevocation(revoke(set, root, c.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	_, clash = set.HostConflict(d.Public())
	assert.False(t, clash)

	// same second: the smaller identity wins, and both sides agree
	e, f := newID(t), newID(t)
	set.Merge(Records{Admissions: []Admission{
		admit(set, root, e.Public(), "e", 5, t0),
		admit(set, b, f.Public(), "f", 5, t0),
	}})
	_, eLoses := set.HostConflict(e.Public())
	_, fLoses := set.HostConflict(f.Public())
	assert.NotEqual(t, eLoses, fLoses)
	eKey, fKey := e.Public(), f.Public()
	assert.Equal(t, bytes.Compare(eKey[:], fKey[:]) > 0, eLoses)

	// an unknown identity has nothing to conflict with
	_, clash = set.HostConflict(newID(t).Public())
	assert.False(t, clash)
}

// Two identities that admit each other, with no path to the root, are both
// invalid, and deciding so terminates.
func Test_Set_validity_cycle(t *testing.T) {
	_, _, _, _, set := cluster(t)
	x, y := newID(t), newID(t)
	assert.Equal(t, 2, set.Merge(Records{Admissions: []Admission{
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
	assert.Equal(t, 1, set.Merge(Records{Revocations: []Revocation{revB}}))
	assert.Equal(t, 0, set.Merge(Records{Revocations: []Revocation{revB}}), "idempotent")
	revA := revoke(set, root, a.Public(), t0.Add(2*time.Hour))
	assert.Equal(t, 1, set.Merge(Records{Revocations: []Revocation{revA}}))

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

// Anything that can open a connection is asked about, so only members are
// cached: an unknown identity is decided in one lookup anyway.
func Test_Set_Valid_cachesMembersOnly(t *testing.T) {
	_, a, _, stranger, set := cluster(t)
	assert.True(t, set.Valid(a.Public()))
	assert.False(t, set.Valid(stranger.Public()))

	cached := 0
	set.members.Load().Range(func(any, any) bool { cached++; return true })
	assert.Equal(t, 1, cached, "only the member was kept")
}

// The cache is read without the lock; the race detector is the point of this.
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
func Test_Set_answersDoNotDependOnArrivalOrder(t *testing.T) {
	root, a, b, _, _ := cluster(t)
	c := newID(t)

	records := []any{
		SelfAdmit(root, "root", t0),                             // root's 1st
		Admit(root, a.Public(), "a", 2, 2, t0.Add(time.Minute)), // root's 2nd
		Admit(a, b.Public(), "b", 3, 1, t0.Add(2*time.Minute)),  // a's 1st
		// b leaves, admitting nothing it signed afterwards, and then admits c
		// anyway; the root revokes it later against everything it has seen
		Revoke(b, b.Public(), 1, 0, t0.Add(90*time.Second)),
		Admit(b, c.Public(), "c", 4, 2, t0.Add(95*time.Second)),
		Revoke(root, b.Public(), 3, 2, t0.Add(200*time.Second)),
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
	assert.Equal(t, [4]bool{true, true, false, false}, forward, "b left of its own accord, so what it signed past its own mark counts for nothing")
	assert.Equal(t, forward, answers([]int{5, 4, 3, 2, 1, 0}), "reversed")
	assert.Equal(t, forward, answers([]int{5, 0, 3, 1, 4, 2}), "interleaved")
}

// A revoked node keeps its key, so it can still sign. The mark, not the
// timestamp, is what stops it: whatever it signs past the number its revoker
// had seen carries nothing, however far back the record is dated.
func Test_Set_revokedAdmitterCannotBackdate(t *testing.T) {
	root, a, b, _, set := cluster(t) // a's 1st record admitted b
	_, err := set.AddRevocation(revoke(set, root, a.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	require.False(t, set.Valid(a.Public()))
	assert.True(t, set.Valid(b.Public()), "admitted by a's 1st record, which the mark covers")

	c := newID(t)
	ok, err := set.AddAdmission(Admit(a, c.Public(), "c", 4, 2, t0.Add(-time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok, "the record is stored: nothing about it is malformed")
	assert.False(t, set.Valid(c.Public()), "past the mark, so a was not a member when it signed")
}

// Two different records at one number are both ignored: an honest signer never
// reuses one, and there is no safe way to choose between them.
func Test_Set_reusedSequenceVoidsBoth(t *testing.T) {
	_, a, _, _, set := cluster(t)
	c, d := newID(t), newID(t)

	first := Admit(a, c.Public(), "c", 4, 2, t0)
	ok, err := set.AddAdmission(first)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, set.Valid(c.Public()))

	ok, err = set.AddAdmission(Admit(a, d.Public(), "d", 5, 2, t0)) // a's 2nd, again
	require.NoError(t, err)
	assert.True(t, ok, "the clash changes the answers, so it counts as a change")
	assert.False(t, set.Valid(c.Public()), "the record that was already there stops counting")
	assert.False(t, set.Valid(d.Public()), "and so does the one that clashed with it")

	ok, err = set.AddAdmission(first)
	require.NoError(t, err)
	assert.False(t, ok, "the same record arriving again is not a clash")
	assert.Equal(t, uint64(3), set.NextSeq(a.Public()), "a poisoned number is not handed out again")
}

// A signer's next number is one past everything it has been seen to sign, so a
// node that restarts from its records does not reuse one.
func Test_Set_NextSeq(t *testing.T) {
	root, a, _, stranger, set := cluster(t)
	assert.Equal(t, uint64(2), set.HighWater(root.Public()), "the self-admission and one admission")
	assert.Equal(t, uint64(3), set.NextSeq(root.Public()))
	assert.Equal(t, uint64(2), set.NextSeq(a.Public()))
	assert.Zero(t, set.HighWater(stranger.Public()))
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

// A record no clock could honestly have produced is kept out of a set that
// never forgets. The bounds are wide: policing skew is the warning's job.
func Test_Set_checkClock(t *testing.T) {
	root, a, _, _, set := cluster(t)
	set.now = func() time.Time { return t0 }

	_, err := set.AddAdmission(Admit(root, newID(t).Public(), "ancient", 8, 3, time.Unix(epoch-1, 0)))
	assert.ErrorContains(t, err, "dated before 2020-01-01")

	_, err = set.AddAdmission(Admit(root, newID(t).Public(), "ahead", 9, 3, t0.Add(ahead+time.Minute)))
	assert.ErrorContains(t, err, "in the future")
	_, err = set.AddRevocation(Revoke(a, root.Public(), 2, 2, t0.Add(ahead+time.Minute)))
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
