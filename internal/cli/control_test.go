package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_controlFlags_socket(t *testing.T) {
	f := controlFlags{interfaceFlag: interfaceFlag{Interface: "wg1"}}
	assert.Equal(t, control.DefaultSocket("wg1"), f.socket())
	f.ControlSocket = "/tmp/x.sock"
	assert.Equal(t, "/tmp/x.sock", f.socket())
}

// fakeMembership stands in for the cluster behind the control socket.
type fakeMembership struct {
	id            *trust.Identity
	set           *trust.Set
	revoked       []trust.PublicKey
	revokeErr     error
	revokedSelf   bool
	revokeSelfErr error
	pruneDry      bool
	pruned        cluster.PruneResult
	pruneErr      error
}

func (f *fakeMembership) Prune(dry bool) (cluster.PruneResult, error) {
	f.pruneDry = dry
	return f.pruned, f.pruneErr
}

func newFakeMembership(t *testing.T) (*fakeMembership, *trust.Identity) {
	t.Helper()
	root, err := trust.NewIdentity()
	require.NoError(t, err)
	member, err := trust.NewIdentity()
	require.NoError(t, err)
	set := trust.NewSet(root.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(root, "root", time.Now()),
		trust.Admit(root, member.Public(), "member", 2, 2, time.Now()),
	}})
	return &fakeMembership{id: root, set: set}, member
}

func (f *fakeMembership) Invite(ttl time.Duration, uses int) (string, error) {
	return "token-" + ttl.String(), nil
}
func (f *fakeMembership) Revoke(id trust.PublicKey) error {
	f.revoked = append(f.revoked, id)
	return f.revokeErr
}
func (f *fakeMembership) RevokeSelf() (int, error) {
	if f.revokeSelfErr != nil {
		return 0, f.revokeSelfErr
	}
	f.revokedSelf = true
	return 3, nil
}
func (f *fakeMembership) Trust() *trust.Set         { return f.set }
func (f *fakeMembership) Identity() trust.PublicKey { return f.id.Public() }

func Test_agentControl(t *testing.T) {
	m, member := newFakeMembership(t)
	ctl := agentControl{cluster: m}

	tok, err := ctl.Invite(5*time.Minute, 1)
	require.NoError(t, err)
	assert.Equal(t, "token-5m0s", tok)

	got, err := ctl.Revoke("member")
	require.NoError(t, err)
	assert.Equal(t, member.Public().String(), got, "resolved by name")

	got, err = ctl.Revoke(member.Public().String())
	require.NoError(t, err)
	assert.Equal(t, member.Public().String(), got, "given as an identity")
	assert.Equal(t, []trust.PublicKey{member.Public(), member.Public()}, m.revoked)

	_, err = ctl.Revoke("nobody")
	assert.ErrorContains(t, err, `no member named "nobody"`)
	_, err = ctl.Revoke("root")
	assert.ErrorContains(t, err, "refusing to revoke this node itself")
	_, err = ctl.Revoke(m.Identity().String())
	assert.ErrorContains(t, err, "refusing")

	m.revokeErr = errors.New("boom")
	_, err = ctl.Revoke("member")
	assert.ErrorContains(t, err, "boom")
}

// leaveControl is an agentControl whose agent stops when it is told to and
// reports that it has torn everything down.
func leaveControl(m membership) (agentControl, *leaving, chan struct{}) {
	stopped := make(chan struct{})
	l := &leaving{done: make(chan struct{})}
	l.stop = func() {
		close(stopped)
		close(l.done) // the agent has left the cluster, downed the interface and forgotten its state
	}
	return agentControl{cluster: m, leaving: l}, l, stopped
}

func Test_agentControl_Leave(t *testing.T) {
	m, _ := newFakeMembership(t)
	ctl, l, stopped := leaveControl(m)

	left, err := ctl.Leave(false)
	require.NoError(t, err)
	assert.Equal(t, m.Identity().String(), left.Identity)
	assert.True(t, left.Revoked)
	assert.Equal(t, 3, left.Notified)
	assert.True(t, m.revokedSelf)
	assert.True(t, l.requested.Load(), "the agent forgets its state on the way out")
	<-stopped
}

// A node that cannot revoke itself stays where it is unless the operator insists.
func Test_agentControl_Leave_cannotRevoke(t *testing.T) {
	m, _ := newFakeMembership(t)
	m.revokeSelfErr = errors.New("signing the revocation failed")
	ctl, l, stopped := leaveControl(m)

	_, err := ctl.Leave(false)
	assert.ErrorContains(t, err, "signing the revocation failed")
	assert.False(t, l.requested.Load())
	select {
	case <-stopped:
		t.Fatal("the agent was stopped by a leave it refused")
	default:
	}

	left, err := ctl.Leave(true)
	require.NoError(t, err)
	assert.Equal(t, m.Identity().String(), left.Identity, "the operator needs it to revoke this node from a member")
	assert.False(t, left.Revoked)
	assert.Zero(t, left.Notified)
	assert.True(t, l.requested.Load())
	<-stopped
}
