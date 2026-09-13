package trust

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func newID(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	require.NoError(t, err)
	return id
}

// cluster builds root -> a -> b, and an unrelated stranger.
func cluster(t *testing.T) (root, a, b, stranger *Identity, set *Set) {
	t.Helper()
	root, a, b, stranger = newID(t), newID(t), newID(t), newID(t)
	set = NewSet(root.Public())
	for _, adm := range []Admission{
		SelfAdmit(root, "root", t0), // root's 1st
		Admit(root, a.Public(), "a", 2, 2, t0.Add(time.Minute)),
		Admit(a, b.Public(), "b", 3, 1, t0.Add(2*time.Minute)), // a's 1st
	} {
		ok, err := set.AddAdmission(adm)
		require.NoError(t, err)
		require.True(t, ok)
	}
	return
}

// admit and revoke sign the way the cluster does: with the next number the set
// has for the signer, and keeping everything it has seen the subject sign.
// Tests that turn on a particular number or a particular kept record call Admit
// or Revoke directly.
func admit(set *Set, admitter *Identity, id PublicKey, name string, host uint64, now time.Time) Admission {
	return Admit(admitter, id, name, host, set.NextSeq(admitter.Public()), now)
}

func revoke(set *Set, revoker *Identity, id PublicKey, now time.Time) Revocation {
	return Revoke(revoker, id, set.NextSeq(revoker.Public()), set.SignedBy(id), now)
}

// swapLogger sends the default logger to buf until the returned func restores it.
func swapLogger(buf *bytes.Buffer) func() {
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	return func() { slog.SetDefault(old) }
}
