package cli

import (
	"errors"
	"testing"

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
