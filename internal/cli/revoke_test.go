package cli

import (
	"errors"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RevokeCmd_Run(t *testing.T) {
	agent := &fakeAgent{}
	cmd := &RevokeCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}, Target: "node2"}
	stdout, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Equal(t, "revoked node2 ("+key(1).String()+")\n", stderr)
	assert.Equal(t, "node2", agent.target)

	agent.err = errors.New("no such member")
	_, _, err = captureOutput(t, cmd.Run)
	assert.ErrorContains(t, err, "no such member")
}

// The nodes a revocation takes out along with its subject are named: the
// operator asked for some of them by disowning them, and the mark took the
// rest, so all of them are printed and none of them can come back.
func Test_RevokeCmd_Run_disown(t *testing.T) {
	agent := &fakeAgent{revoked: control.RevokeResult{
		Identity:  key(1),
		Withdrawn: []control.Member{{Identity: key(2), Name: "node3"}, {Identity: key(3), Name: "node4"}},
	}}
	cmd := &RevokeCmd{
		controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)},
		Target:       "node2",
		Disown:       []string{"node3"},
	}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Equal(t, []string{"node3"}, agent.disown)
	assert.Contains(t, stderr, "revoked node2 ("+key(1).String()+")\n")
	assert.Contains(t, stderr, "2 node(s) it admitted are withdrawn with it and have to enrol again:")
	assert.Contains(t, stderr, "  node3 ("+key(2).String()+")\n")
	assert.Contains(t, stderr, "  node4 ("+key(3).String()+")\n")
}

// Disowning everything needs no names: the flag alone reaches the agent.
func Test_RevokeCmd_Run_disownAll(t *testing.T) {
	agent := &fakeAgent{}
	cmd := &RevokeCmd{
		controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)},
		Target:       "node2",
		DisownAll:    true,
	}
	_, _, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.True(t, agent.all)
	assert.Empty(t, agent.disown)
}
