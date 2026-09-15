package trust

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// records is how many the set holds, of both kinds.
func records(s *Set) int {
	rs := s.Records()
	return len(rs.Admissions) + len(rs.Revocations)
}

// A member that went wrong is undone by a cut below where it did: everything it
// signed above the cut goes, on every node that holds the revocation, and the
// identities it minted are left with nothing naming them.
func Test_Set_Sweep_dropsWhatACutWithdrew(t *testing.T) {
	root, a, _, _, set := cluster(t)
	var minted []PublicKey
	for i := range 20 {
		id := newID(t)
		minted = append(minted, id.Public())
		_, err := set.AddAdmission(admit(set, a, id.Public(), nameOf(i), uint64(i+10), t0.Add(time.Hour)))
		require.NoError(t, err)
	}
	require.True(t, set.Valid(minted[0]))

	before := records(set)
	// a was trusted as far as its first record, which admitted b
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 1, t0.Add(2*time.Hour))))
	for _, id := range minted {
		require.False(t, set.Valid(id), "nothing a signed above the cut stands")
	}

	assert.Equal(t, 20, set.Sweep(), "one per record above the cut")
	assert.Equal(t, before-20+1, records(set), "the revocation is the one record added")
	assert.Zero(t, set.Sweep(), "and there is nothing left to do")
}

func nameOf(i int) string { return string(rune('a'+i%26)) + "x" }

// Sweeping changes no answer about any member: what it drops stood for nobody.
func Test_Set_Sweep_changesNoAnswer(t *testing.T) {
	root, a, b, _, set := cluster(t)
	c := newID(t)
	_, err := set.AddAdmission(admit(set, a, c.Public(), "c", 9, t0.Add(time.Hour)))
	require.NoError(t, err)
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 1, t0.Add(2*time.Hour))))

	was := map[PublicKey]bool{}
	for _, id := range []PublicKey{root.Public(), a.Public(), b.Public(), c.Public()} {
		was[id] = set.Valid(id)
	}
	require.Positive(t, set.Sweep())
	for id, valid := range was {
		assert.Equal(t, valid, set.Valid(id), id.Short())
	}
}

// A node given the swept set reaches the same answers as one that never swept.
func Test_Set_Sweep_leavesASetThatDecidesTheSame(t *testing.T) {
	root, a, b, _, set := cluster(t)
	c := newID(t)
	_, err := set.AddAdmission(admit(set, a, c.Public(), "c", 9, t0.Add(time.Hour)))
	require.NoError(t, err)
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 1, t0.Add(2*time.Hour))))
	require.Positive(t, set.Sweep())

	fresh := NewSet(root.Public())
	require.Zero(t, fresh.Merge(set.Records()).Deferred, "the swept set has no gap in it")
	for _, id := range []PublicKey{root.Public(), a.Public(), b.Public(), c.Public()} {
		assert.Equal(t, set.Valid(id), fresh.Valid(id), id.Short())
	}
}

// The sweep is reversible. A revocation shown to have been signed by a node
// that was already out stops counting, the cut it set rises, and the records it
// withdrew have to stand again — so a peer that never swept can hand them back.
func Test_Set_Sweep_takesBackWhatACutThatRoseWithdrew(t *testing.T) {
	root, a, b, _, set := cluster(t)
	c := newID(t)
	admOfC := admit(set, a, c.Public(), "c", 9, t0.Add(time.Hour))
	_, err := set.AddAdmission(admOfC)
	require.NoError(t, err)

	// b, which a admitted, revokes a and cuts it below its admission of c
	require.NoError(t, addRevocation(set, Revoke(b, a.Public(), 1, 1, t0.Add(2*time.Hour))))
	require.False(t, set.Valid(c.Public()), "a's second record is above the cut")
	require.Equal(t, 1, set.Sweep())
	_, held := set.Lookup(c.Public())
	require.False(t, held, "and is gone")

	// the root now cuts b below the revocation it signed, so that revocation
	// never counted and a was never validly revoked
	require.NoError(t, addRevocation(set, Revoke(root, b.Public(), 3, 0, t0.Add(3*time.Hour))))
	assert.True(t, set.Valid(a.Public()), "a was never validly revoked")

	// a peer that never swept offers the record back, and it is taken
	ok, err := set.AddAdmission(admOfC)
	require.NoError(t, err)
	assert.True(t, ok, "the record this node swept comes back")
	assert.True(t, set.Valid(c.Public()), "and c is a member again")
}

// Only the record that was there may come back. Anything else at a swept number
// is a second record at one of the signer's numbers, and is refused as one.
func Test_Set_Sweep_refusesSomethingElseAtASweptNumber(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c, mole := newID(t), newID(t)
	_, err := set.AddAdmission(admit(set, a, c.Public(), "c", 9, t0.Add(time.Hour)))
	require.NoError(t, err)
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 1, t0.Add(2*time.Hour))))
	require.Equal(t, 1, set.Sweep())

	forged := Admit(a, mole.Public(), "mole", 10, 2, t0.Add(4*time.Hour))
	_, err = set.AddAdmission(forged)
	assert.ErrorIs(t, err, errSpent, "the number is spent, whatever this node dropped from it")
	assert.False(t, set.Valid(mole.Public()))
}

// What a node cut off when it left can never stand again, so nothing is kept
// about it: a self-revocation counts whatever else is held.
func Test_Set_Sweep_keepsNothingAboveANodesOwnDeparture(t *testing.T) {
	_, a, _, _, set := cluster(t)
	c := newID(t)
	strays := Admit(a, c.Public(), "c", 9, 3, t0.Add(time.Hour))

	// a leaves keeping its first record, then its key signs another
	require.NoError(t, addRevocation(set, Revoke(a, a.Public(), 2, 1, t0.Add(2*time.Hour))))
	_, err := set.AddAdmission(strays)
	require.NoError(t, err)
	require.False(t, set.Valid(c.Public()), "signed after a cut itself off")

	require.Equal(t, 1, set.Sweep())
	set.mu.RLock()
	_, kept := set.signers[a.Public()].dropped[3]
	set.mu.RUnlock()
	assert.False(t, kept, "a node's own departure cannot be undone, so nothing is kept")

	_, err = set.AddAdmission(strays)
	assert.ErrorIs(t, err, errSpent, "and the record cannot come back")
}

// A node's own departure is the one record a cut does not reach: dropping it
// would let the node back in.
func Test_Set_Sweep_keepsANodesOwnDeparture(t *testing.T) {
	_, a, _, _, set := cluster(t)
	require.NoError(t, addRevocation(set, Revoke(a, a.Public(), 2, 1, t0.Add(time.Hour))))
	require.False(t, set.Valid(a.Public()))
	set.Sweep()
	assert.False(t, set.Valid(a.Public()), "the record that says it left is still held")
}

// What a sweep kept has to survive a restart, or the records it dropped could
// never come back and a number it spent would be free again.
func Test_Set_Sweep_survivesARestart(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c := newID(t)
	admOfC := admit(set, a, c.Public(), "c", 9, t0.Add(time.Hour))
	_, err := set.AddAdmission(admOfC)
	require.NoError(t, err)
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 1, t0.Add(2*time.Hour))))
	require.Equal(t, 1, set.Sweep())

	fresh := NewSet(root.Public())
	fresh.Restore(set.Records(), set.SignerStates())
	assert.Equal(t, uint64(3), fresh.NextSeq(a.Public()), "the number a spent is still spent")

	// the cut still withdraws the record, so a peer offering it back changes
	// nothing; what the sweep kept is what would take it back if the cut rose
	_, err = fresh.AddAdmission(admOfC)
	assert.ErrorIs(t, err, ErrWithdrawn)
	fresh.mu.RLock()
	_, kept := fresh.signers[a.Public()].dropped[2]
	fresh.mu.RUnlock()
	assert.True(t, kept, "and what it takes to take the record back survived too")
}

// A peer that has not swept offers a record this node dropped in every state
// sync, once a minute for ever. Taking it back while its signer's cut still
// withdraws it would add a record that stands for nobody, throw the answers
// away to derive them again, and sweep it out at the next save, every time. It
// is refused quietly instead: nothing is wrong with the record or the peer.
func Test_Set_Sweep_doesNotTakeBackWhatTheCutStillWithdraws(t *testing.T) {
	root, a, b, _, set := cluster(t)
	c := newID(t)
	admOfC := admit(set, a, c.Public(), "c", 9, t0.Add(time.Hour))
	require.NoError(t, addAdmission(set, admOfC))
	// b, which a admitted, cuts a off below its admission of c
	require.NoError(t, addRevocation(set, Revoke(b, a.Public(), 1, 1, t0.Add(2*time.Hour))))
	require.Equal(t, 1, set.Sweep())

	res := set.Merge(Records{Admissions: []Admission{admOfC}})
	assert.Zero(t, res.Changed)
	assert.Zero(t, res.Refused, "the peer is not sending anything wrong")
	assert.Equal(t, 1, res.Withdrawn)
	assert.Zero(t, set.Sweep(), "and there is nothing to sweep again")

	// the root now cuts b below the revocation it signed, so that revocation
	// never counted, the cut on a rises, and the record is taken back
	require.NoError(t, addRevocation(set, Revoke(root, b.Public(), 3, 0, t0.Add(3*time.Hour))))
	res = set.Merge(Records{Admissions: []Admission{admOfC}})
	assert.Equal(t, 1, res.Changed)
	assert.Zero(t, res.Withdrawn)
	assert.True(t, set.Valid(c.Public()), "and c is a member again")
}

// A revocation can withdraw the chain its own signer stands on. Then the
// records above the cut are what somebody's membership rests on: judged from
// outside the revocation counts and they are withdrawn, judged from within its
// own walk the revoker is a member and they stand. Dropping them would change
// who is a member, so the sweep keeps them and says why.
func Test_Set_Sweep_keepsRecordsThatStillDecideSomething(t *testing.T) {
	for _, tc := range []struct {
		name string
		rev  func(root, a, b *Identity) Revocation
	}{
		// b cuts off a, which admitted b, keeping nothing
		{"its own admitter", func(_, a, b *Identity) Revocation {
			return Revoke(b, a.Public(), 1, 0, t0.Add(time.Hour))
		}},
		// a cuts off the root, which admitted a, keeping nothing
		{"the root", func(root, a, _ *Identity) Revocation {
			return Revoke(a, root.Public(), 2, 0, t0.Add(time.Hour))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, a, b, _, set := cluster(t)
			var buf bytes.Buffer
			defer swapLogger(&buf)()
			require.NoError(t, addRevocation(set, tc.rev(root, a, b)))

			ids := []PublicKey{root.Public(), a.Public(), b.Public()}
			was := map[PublicKey]bool{}
			for _, id := range ids {
				was[id] = set.Valid(id)
			}

			assert.Zero(t, set.Sweep(), "no record may go")
			for _, id := range ids {
				assert.Equal(t, was[id], set.Valid(id), id.Short())
			}
			assert.Contains(t, buf.String(), "withdraws the chain its own signer stands on")

			// and a node given the records answers the same way this one does
			fresh := NewSet(root.Public())
			require.Zero(t, fresh.Merge(set.Records()).Deferred)
			for _, id := range ids {
				assert.Equal(t, was[id], fresh.Valid(id), "on a fresh set: "+id.Short())
			}
		})
	}
}

// The records a sweep keeps are kept until a record settles which answer
// stands, and the sweep runs before every write of the state file. So the line
// that says so goes out at this node's rate rather than at every record
// change, with the count of the sweeps it stands for.
func Test_Set_Sweep_reportsWhatItKeepsAtThisNodesRate(t *testing.T) {
	_, a, b, _, set := cluster(t)
	var buf bytes.Buffer
	defer swapLogger(&buf)()
	// b cuts off a, which admitted b: the records above the cut hold b up
	require.NoError(t, addRevocation(set, Revoke(b, a.Public(), 1, 0, t0.Add(time.Hour))))

	const kept = "withdraws the chain its own signer stands on"
	for range 9 {
		require.Zero(t, set.Sweep())
	}
	assert.Equal(t, 1, strings.Count(buf.String(), kept), "one line, not one per sweep")
	assert.Contains(t, buf.String(), "count=1")

	require.Zero(t, set.Sweep())
	assert.Equal(t, 2, strings.Count(buf.String(), kept), "and one saying how many it has held up")
	assert.Contains(t, buf.String(), "count=10")
}

// A node's own departure is the one record a cut never reaches, so a foreign
// cut below it must not take the records in between: they are what a set given
// these records steps over to reach the departure. The shape is a node that
// left keeping everything it signed, revoked afterwards by a member that had
// not seen all of it.
func Test_Set_Sweep_keepsWhatALowerCutWouldStrandADepartureAbove(t *testing.T) {
	root, a, b, _, set := cluster(t)
	c := newID(t)
	require.NoError(t, addAdmission(set, Admit(a, c.Public(), "c", 9, 2, t0.Add(time.Hour))))
	// a leaves, keeping every record it signed, this one included
	require.NoError(t, addRevocation(set, Revoke(a, a.Public(), 3, 3, t0.Add(2*time.Hour))))
	// the root had only seen a's first record, and cuts it off there
	require.NoError(t, addRevocation(set, Revoke(root, a.Public(), 3, 1, t0.Add(3*time.Hour))))

	ids := []PublicKey{root.Public(), a.Public(), b.Public(), c.Public()}
	was := map[PublicKey]bool{}
	for _, id := range ids {
		was[id] = set.Valid(id)
	}
	require.False(t, was[c.Public()], "c's admission is above the root's cut")

	assert.Zero(t, set.Sweep(), "the records under a's own mark stay")
	for _, id := range ids {
		assert.Equal(t, was[id], set.Valid(id), id.Short())
	}

	// a node given the records takes all of them, the departure included
	fresh := NewSet(root.Public())
	require.Zero(t, fresh.Merge(set.Records()).Deferred, "no gap for a fresh set to step over")
	for _, id := range ids {
		assert.Equal(t, was[id], fresh.Valid(id), "on a fresh set: "+id.Short())
	}

	// and so does a restart, which restores the heads over the same records
	restart := NewSet(root.Public())
	restart.Merge(set.Records())
	restart.RestoreSigners(set.SignerStates())
	assert.Equal(t, set.Records(), restart.Records(), "a restart holds what the sweep left")
	assert.False(t, restart.Valid(a.Public()), "the record that says a left is still held")
}
