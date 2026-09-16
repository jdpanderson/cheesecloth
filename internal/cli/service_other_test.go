//go:build !windows

package cli

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ServiceCmd_other(t *testing.T) {
	c := &CLI{}
	k, err := Parser(c, filepath.Join(t.TempDir(), "absent.yaml"), "1.2.3")
	require.NoError(t, err)
	for _, sub := range []string{"install", "uninstall"} {
		ktx, err := k.Parse([]string{"service", sub})
		require.NoError(t, err)
		err = ktx.Run()
		require.ErrorIs(t, err, errNoServiceManager)
		assert.Contains(t, err.Error(), "dist/")
	}
}
