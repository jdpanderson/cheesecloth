package cli

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeHosts records the entries a leave writes.
type fakeHosts struct{ writes []map[string][]string }

func (f *fakeHosts) WriteEntries(m map[string][]string) error {
	f.writes = append(f.writes, m)
	return nil
}

func Test_LeaveCmd_Run(t *testing.T) {
	agent := &fakeAgent{}
	cmd := &LeaveCmd{controlFlags: controlFlags{interfaceFlag: interfaceFlag{Interface: "wg1"}, ControlSocket: listenFakeAgent(t, agent)}}
	stdout, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "left the cluster: revoked "+key(1).String()+", 3 member(s) told")
	assert.Contains(t, stderr, "its state for wg1 is gone")
	assert.NotContains(t, stderr, "still trusts")
	assert.False(t, agent.force)

	cmd.Force = true
	_, _, err = captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.True(t, agent.force, "the agent is told to leave even if it cannot revoke")
}

// A node that could not tell the cluster is still a member to every peer, so
// the operator is given the identity to revoke from a member.
func Test_LeaveCmd_Run_notRevoked(t *testing.T) {
	agent := &fakeAgent{left: control.LeaveResult{Identity: key(1)}}
	cmd := &LeaveCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}, Force: true}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "left the cluster without revoking "+key(1).String())
	assert.Contains(t, stderr, "cheesecloth revoke "+key(1).String())
}

// The cluster took this node out before it asked to leave, so there is nothing
// to tell it -- and nothing for the operator to go and revoke on a member.
func Test_LeaveCmd_Run_alreadyOut(t *testing.T) {
	agent := &fakeAgent{left: control.LeaveResult{Identity: key(1), AlreadyOut: true}}
	cmd := &LeaveCmd{controlFlags: controlFlags{interfaceFlag: interfaceFlag{Interface: "wg1"}, ControlSocket: listenFakeAgent(t, agent)}}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "had already taken "+key(1).String()+" out")
	assert.Contains(t, stderr, "its state for wg1 is gone")
	assert.NotContains(t, stderr, "still trusts", "so it is not told to revoke a node that is already revoked")
}

func Test_LeaveCmd_Run_agentRefuses(t *testing.T) {
	agent := &fakeAgent{err: errors.New("signing the revocation failed")}
	cmd := &LeaveCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}}
	_, _, err := captureOutput(t, cmd.Run)
	assert.ErrorContains(t, err, "signing the revocation failed")
	assert.ErrorContains(t, err, "--force leaves without telling the cluster")
}

func Test_LeaveCmd_Run_noAgent(t *testing.T) {
	dir := t.TempDir()
	_, err := cluster.Load(dir, "wg1")
	require.NoError(t, err)
	identity, ok := cluster.LocalIdentity(dir, "wg1")
	require.True(t, ok)
	hosts := &fakeHosts{}
	cmd := &LeaveCmd{
		controlFlags: controlFlags{interfaceFlag: interfaceFlag{Interface: "wg1"}, ControlSocket: filepath.Join(t.TempDir(), "absent.sock")},
		stateDir:     dir, hosts: hosts,
	}

	_, _, err = captureOutput(t, cmd.Run)
	assert.ErrorIs(t, err, control.ErrNoAgent)
	assert.ErrorContains(t, err, "--force")
	assert.FileExists(t, filepath.Join(dir, "wg1.json"), "nothing removed without --force")

	cmd.Force = true
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "removed this node's state for wg1")
	assert.Contains(t, stderr, "cheesecloth revoke "+identity.String())
	assert.NoFileExists(t, filepath.Join(dir, "wg1.json"))
	assert.Equal(t, []map[string][]string{{}}, hosts.writes, "this interface's hosts entries are gone")

	// and again, with nothing left to remove
	_, stderr, err = captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "no state for wg1")
}

// --force is "take this node out without telling the cluster", so an agent
// that answered and could not do it is no more a reason to stop than one that
// did not answer at all. An agent that is a member of nothing refuses, and
// this is the command that gets such a node back to a state it can enrol from.
func Test_LeaveCmd_Run_forcedPastAnAgentThatRefuses(t *testing.T) {
	dir := t.TempDir()
	_, err := cluster.Load(dir, "wg1")
	require.NoError(t, err)
	agent := &fakeAgent{err: errors.New("this node is not a member of any cluster")}
	hosts := &fakeHosts{}
	cmd := &LeaveCmd{
		controlFlags: controlFlags{interfaceFlag: interfaceFlag{Interface: "wg1"},
			ControlSocket: listenFakeAgent(t, agent)},
		stateDir: dir, hosts: hosts, Force: true,
	}

	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "this node is not a member of any cluster", "the operator is told why")
	assert.Contains(t, stderr, "leaving anyway")
	assert.Contains(t, stderr, "removed this node's state for wg1")
	assert.NoFileExists(t, filepath.Join(dir, "wg1.json"))
}
