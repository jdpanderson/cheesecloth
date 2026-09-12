package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The agent's Run takes a context and a notifier, which nothing on the command
// line provides: run binds them, and without that the command cannot be
// called at all.
func Test_run_bindsTheContextAndNotifier(t *testing.T) {
	dir := t.TempDir()
	c := &CLI{}
	k, err := Parser(c, filepath.Join(dir, "absent.yaml"), "1.2.3", nil)
	require.NoError(t, err)
	ktx, err := k.Parse([]string{"--interface", "wg1"})
	require.NoError(t, err)
	require.Equal(t, "agent", ktx.Command())
	c.Agent.stateDir = dir // nothing else of the machine is touched: this node idles

	ctx, cancel := context.WithCancel(context.Background())
	n := &recordingNotifier{}
	errc := make(chan error, 1)
	go func() { errc <- run(ktx, ctx, n) }()

	require.Eventually(t, func() bool { return n.ready.Load() }, 5*time.Second, 10*time.Millisecond,
		"the notifier reached the command")
	cancel()
	require.NoError(t, waitErr(t, errc), "the context reached the command, which stopped with it")
	assert.True(t, n.stopping.Load())
}
