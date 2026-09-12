//go:build unix

package etchosts

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unix file modes and owners; Windows has neither in this form.

func TestEtcHosts_WriteEntries_preservesMode(t *testing.T) {
	p := writeTempHosts(t, "", 0o640)
	eh := &EtcHosts{Path: p}
	require.NoError(t, eh.WriteEntries(map[string][]string{"10.0.0.1": {"a"}}))

	info, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestEtcHosts_WriteEntries_preservesOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership needs root")
	}
	p := writeTempHosts(t, "", 0o644)
	const nobody = 65534
	if err := os.Chown(p, nobody, nobody); err != nil {
		// root inside a user namespace, where only one id is mapped
		t.Skipf("cannot give the file away to %d: %v", nobody, err)
	}
	eh := &EtcHosts{Path: p}
	require.NoError(t, eh.WriteEntries(map[string][]string{"10.0.0.1": {"a"}}))

	info, err := os.Stat(p)
	require.NoError(t, err)
	st := info.Sys().(*syscall.Stat_t)
	assert.EqualValues(t, nobody, st.Uid)
	assert.EqualValues(t, nobody, st.Gid)
}
