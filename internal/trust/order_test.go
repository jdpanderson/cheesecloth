package trust

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A record broadcast on its own can arrive before ones its signer signed
// earlier. It is held rather than refused, and the state sync that carries the
// whole set puts it in.
func Test_Set_aRecordAheadOfItsSignerIsTakenAtTheNextSync(t *testing.T) {
	_, a, _, _, set := cluster(t)
	c, d := newID(t), newID(t)
	second := Admit(a, c.Public(), "c", 4, 2, t0.Add(time.Hour))
	third := Admit(a, d.Public(), "d", 5, 3, t0.Add(2*time.Hour))

	// the broadcast of a's third record reaches this node first
	_, err := set.AddAdmission(third)
	require.ErrorIs(t, err, ErrAhead)
	assert.False(t, set.Valid(d.Public()))

	// the peer's whole set carries both, and both go in
	res := set.Merge(Records{Admissions: []Admission{third, second}})
	assert.Equal(t, 2, res.Changed)
	assert.Zero(t, res.Deferred)
	assert.True(t, set.Valid(c.Public()))
	assert.True(t, set.Valid(d.Public()))
}

// Two nodes given the same records must hold the same records and answer the
// same, whichever order the set puts them in.
func Test_Set_mergeDoesNotDependOnTheOrderOfTheSet(t *testing.T) {
	root, a, b, _, seed := cluster(t)
	c := newID(t)
	rs := seed.Records()
	rs.Admissions = append(rs.Admissions, Admit(a, c.Public(), "c", 4, 2, t0.Add(time.Hour)))
	rs.Revocations = append(rs.Revocations, Revoke(root, b.Public(), 3, nil, t0.Add(2*time.Hour)))

	first := NewSet(root.Public())
	require.Zero(t, first.Merge(rs).Deferred)

	for i := range len(rs.Admissions) {
		shuffled := Records{
			Admissions:  slices.Clone(rs.Admissions),
			Revocations: slices.Clone(rs.Revocations),
		}
		// a different rotation each time, so no two runs see the same order
		rotate := i + 1
		shuffled.Admissions = append(shuffled.Admissions[rotate:], shuffled.Admissions[:rotate]...)
		slices.Reverse(shuffled.Revocations)

		other := NewSet(root.Public())
		require.Zero(t, other.Merge(shuffled).Deferred, "rotation %d", i)
		assert.Equal(t, first.Records(), other.Records(), "rotation %d", i)
		for _, id := range []PublicKey{root.Public(), a.Public(), b.Public(), c.Public()} {
			assert.Equal(t, first.Valid(id), other.Valid(id), "rotation %d, %s", i, id.Short())
		}
	}
}
