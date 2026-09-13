package cli

import (
	"errors"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PruneCmd_Run(t *testing.T) {
	agent := &fakeAgent{pruned: control.PruneResult{
		Identities: []trust.PublicKey{key(1), key(2)}, Before: 10, After: 6,
	}}
	cmd := &PruneCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}}
	stdout, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Equal(t, key(1).String()+"\n"+key(2).String()+"\n", stdout)
	assert.Equal(t, "pruned 2 identities: 6 records, down from 10\n", stderr)
	assert.False(t, agent.dryRun)
}

func Test_PruneCmd_Run_dryRun(t *testing.T) {
	agent := &fakeAgent{pruned: control.PruneResult{Identities: []trust.PublicKey{key(1)}, Before: 10, After: 10}}
	cmd := &PruneCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}, DryRun: true}
	stdout, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Equal(t, key(1).String()+"\n", stdout)
	assert.Contains(t, stderr, "would be pruned")
	assert.True(t, agent.dryRun)
}

func Test_PruneCmd_Run_nothingToDo(t *testing.T) {
	cmd := &PruneCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, &fakeAgent{})}}
	stdout, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "nothing to prune")
}

func Test_PruneCmd_Run_error(t *testing.T) {
	cmd := &PruneCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, &fakeAgent{err: errors.New("clock is behind")})}}
	_, _, err := captureOutput(t, cmd.Run)
	assert.ErrorContains(t, err, "clock is behind")
}
