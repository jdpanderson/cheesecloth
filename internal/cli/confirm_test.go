package cli

import (
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The listing names the signer of each record, and says "this node" for the
// ones this node signed: those are the rows it cannot act on, and the operator
// reads that before trying rather than after being told it worked.
func Test_ConfirmCmd_Run_lists(t *testing.T) {
	agent := &fakeAgent{pending: []control.PendingRecord{
		{Record: "9f3a1c2e00", Kind: "admission", Identity: key(2), Name: "theirs",
			Signer: key(3), Have: 0, Need: 1, Waiting: true},
		{Record: "aa11bb22cc", Kind: "revocation", Identity: key(4), Name: "mine",
			Signer: key(5), Have: 1, Need: 2, Waiting: true, SignedHere: true},
	}}
	cmd := &ConfirmCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}}
	stdout, _, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)

	assert.Contains(t, stdout, "SIGNED BY")
	assert.Contains(t, stdout, "9f3a1c2e")
	assert.Contains(t, stdout, "0 of 1")
	assert.Contains(t, stdout, key(3).Short(), "a record another member signed names it")
	assert.Contains(t, stdout, "this node", "and one this node signed says so")
	assert.NotContains(t, stdout, key(5).Short(), "rather than naming this node by its fingerprint")
}

// Nothing waiting is said plainly rather than as an empty table.
func Test_ConfirmCmd_Run_listsNothing(t *testing.T) {
	agent := &fakeAgent{}
	cmd := &ConfirmCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}}
	stdout, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "nothing is waiting to be confirmed")
	assert.Empty(t, stdout)
}

// Confirming reports the count the cluster came back with. It is not one more
// than the record had: this node's may have been the last one needed, and
// another member's may have arrived while this one was being signed.
func Test_ConfirmCmd_Run_reportsTheCountItWasGiven(t *testing.T) {
	agent := &fakeAgent{pending: []control.PendingRecord{
		{Record: "9f3a1c2e00", Kind: "admission", Identity: key(2), Name: "web3",
			Signer: key(3), Have: 2, Need: 3, Waiting: true},
	}}
	cmd := &ConfirmCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}, Target: "web3"}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Equal(t, "web3", agent.confirmed)
	assert.Contains(t, stderr, "confirmed the admission of web3")
	assert.Contains(t, stderr, "it now has 2 of the 3 it needs")
}

// A record the cluster is no longer holding is reported as such: a count would
// read as though it were still waiting for something.
func Test_ConfirmCmd_Run_saysWhenTheRecordIsNoLongerHeld(t *testing.T) {
	agent := &fakeAgent{pending: []control.PendingRecord{
		{Record: "9f3a1c2e00", Kind: "revocation", Identity: key(2), Name: "web3",
			Signer: key(3), Have: 1, Need: 1, Waiting: false},
	}}
	cmd := &ConfirmCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}, Target: "web3"}
	_, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stderr, "the cluster is no longer holding it")
	assert.NotContains(t, stderr, "it needs")
}

// The agent's refusal of a record this node signed reaches the operator.
func Test_ConfirmCmd_Run_refusal(t *testing.T) {
	agent := &fakeAgent{err: assert.AnError}
	cmd := &ConfirmCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}, Target: "web3"}
	_, _, err := captureOutput(t, cmd.Run)
	assert.Error(t, err)
}
