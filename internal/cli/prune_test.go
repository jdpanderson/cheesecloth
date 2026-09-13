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

// A prune acts on the records the agent holds, so one run from a node that
// cannot see the cluster can drop records the rest still needs.
func Test_PruneCmd_Run_warnsWhenTheAgentIsOutOfTouch(t *testing.T) {
	agent := &fakeAgent{pruned: control.PruneResult{
		Identities: []trust.PublicKey{key(1)}, Before: 10, After: 8, Seen: 2, Members: 7,
	}}
	cmd := &PruneCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "can reach 2 of 7 members")
	assert.Contains(t, stderr, "pruned 1 identities")
}

// Nothing to prune is still worth the warning: a node out of touch is the
// reason it may be seeing nothing to do.
func Test_PruneCmd_Run_warnsEvenWithNothingToPrune(t *testing.T) {
	agent := &fakeAgent{pruned: control.PruneResult{Seen: 1, Members: 4}}
	cmd := &PruneCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "can reach 1 of 4 members")
	assert.Contains(t, stderr, "nothing to prune")
}

func Test_PruneCmd_Run_quietWhenTheAgentSeesEverything(t *testing.T) {
	agent := &fakeAgent{pruned: control.PruneResult{
		Identities: []trust.PublicKey{key(1)}, Before: 10, After: 8, Seen: 4, Members: 4,
	}}
	cmd := &PruneCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.NotContains(t, stderr, "can reach")
}
