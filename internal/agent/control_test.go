package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMembership stands in for the cluster behind the control socket.
type fakeMembership struct {
	id            *trust.Identity
	set           *trust.Set
	revoked       []trust.PublicKey
	marks         []uint64 // where each revocation marked its subject's sequence
	withdrawn     []trust.Admission
	revokeErr     error
	revokedSelf   bool
	revokeSelfErr error
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
func (f *fakeMembership) Revoke(id trust.PublicKey, upTo uint64) ([]trust.Admission, error) {
	f.revoked = append(f.revoked, id)
	f.marks = append(f.marks, upTo)
	return f.withdrawn, f.revokeErr
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

func Test_controlHandler(t *testing.T) {
	m, member := newFakeMembership(t)
	ctl := controlHandler{cluster: m}

	tok, err := ctl.Invite(5*time.Minute, 1)
	require.NoError(t, err)
	assert.Equal(t, "token-5m0s", tok)

	got, err := ctl.Revoke("member", nil)
	require.NoError(t, err)
	assert.Equal(t, member.Public(), got.Identity, "resolved by name")

	got, err = ctl.Revoke(member.Public().String(), nil)
	require.NoError(t, err)
	assert.Equal(t, member.Public(), got.Identity, "given as an identity")
	assert.Equal(t, []trust.PublicKey{member.Public(), member.Public()}, m.revoked)
	assert.Equal(t, []uint64{0, 0}, m.marks, "where this node has seen the member sign, which is nowhere")

	_, err = ctl.Revoke("nobody", nil)
	assert.ErrorContains(t, err, `no member named "nobody"`)
	_, err = ctl.Revoke("root", nil)
	assert.ErrorContains(t, err, "refusing to revoke this node itself")
	_, err = ctl.Revoke(m.Identity().String(), nil)
	assert.ErrorContains(t, err, "refusing")

	m.revokeErr = errors.New("boom")
	_, err = ctl.Revoke("member", nil)
	assert.ErrorContains(t, err, "boom")
}

// leaveControl is an controlHandler whose agent stops when it is told to and
// reports that it has torn everything down.
func leaveControl(m membership) (controlHandler, *leaving, chan struct{}) {
	stopped := make(chan struct{})
	l := &leaving{done: make(chan struct{})}
	l.stop = func() {
		close(stopped)
		close(l.done) // the agent has left the cluster, downed the interface and forgotten its state
	}
	return controlHandler{cluster: m, leaving: l}, l, stopped
}

func Test_controlHandler_Leave(t *testing.T) {
	m, _ := newFakeMembership(t)
	ctl, l, stopped := leaveControl(m)

	left, err := ctl.Leave(false)
	require.NoError(t, err)
	assert.Equal(t, m.Identity(), left.Identity)
	assert.True(t, left.Revoked)
	assert.Equal(t, 3, left.Notified)
	assert.True(t, m.revokedSelf)
	assert.True(t, l.requested.Load(), "the agent forgets its state on the way out")
	<-stopped
}

// A node that cannot revoke itself stays where it is unless the operator insists.
func Test_controlHandler_Leave_cannotRevoke(t *testing.T) {
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
	assert.Equal(t, m.Identity(), left.Identity, "the operator needs it to revoke this node from a member")
	assert.False(t, left.Revoked)
	assert.Zero(t, left.Notified)
	assert.True(t, l.requested.Load())
	<-stopped
}

// A second revocation of one identity keeps only what this node has seen, so
// it can take out members the first one left alone, and it costs a record the
// cluster never gets back.
func Test_controlHandler_Revoke_refusesANodeThatIsAlreadyOut(t *testing.T) {
	m, member := newFakeMembership(t)
	ctl := controlHandler{cluster: m}

	_, err := m.set.AddRevocation(trust.Revoke(m.id, member.Public(), 3, 0, time.Now()))
	require.NoError(t, err)

	_, err = ctl.Revoke(member.Public().String(), nil)
	assert.ErrorContains(t, err, "is not a member")
	assert.ErrorContains(t, err, "revoked already")
	assert.Empty(t, m.revoked, "and nothing was signed")
}

// An identity nobody ever admitted is refused the same way, rather than
// costing a revocation of something that was never in.
func Test_controlHandler_Revoke_refusesAStranger(t *testing.T) {
	m, _ := newFakeMembership(t)
	stranger, err := trust.NewIdentity()
	require.NoError(t, err)

	_, err = controlHandler{cluster: m}.Revoke(stranger.Public().String(), nil)
	assert.ErrorContains(t, err, "was never admitted")
	assert.Empty(t, m.revoked)
}

// The operator names nodes rather than sequence numbers: the agent marks the
// subject's sequence below the first record that admitted one of them, so that
// node and everything the subject signed afterwards are withdrawn.
func Test_controlHandler_Revoke_disown(t *testing.T) {
	m, member := newFakeMembership(t)
	x, err := trust.NewIdentity()
	require.NoError(t, err)
	y, err := trust.NewIdentity()
	require.NoError(t, err)
	// member admits x as its first record and y as its second
	for i, id := range []*trust.Identity{x, y} {
		_, err = m.set.AddAdmission(trust.Admit(member, id.Public(), []string{"x", "y"}[i], uint64(3+i), uint64(1+i), time.Now()))
		require.NoError(t, err)
	}
	m.withdrawn = []trust.Admission{{Identity: y.Public(), Name: "y"}}
	ctl := controlHandler{cluster: m}

	res, err := ctl.Revoke("member", []string{"y"})
	require.NoError(t, err)
	assert.Equal(t, member.Public(), res.Identity)
	assert.Equal(t, []uint64{1}, m.marks, "below the record that admitted y, so x stands")
	assert.Equal(t, []control.Member{{Identity: y.Public(), Name: "y"}}, res.Withdrawn,
		"and the operator is told what went with it")

	// the lowest of several decides, and an identity does as well as a name
	_, err = ctl.Revoke("member", []string{"y", x.Public().String()})
	require.NoError(t, err)
	assert.Equal(t, uint64(0), m.marks[1], "below the record that admitted x, so neither stands")

	// a node the subject did not admit says so rather than marking anywhere
	_, err = ctl.Revoke("member", []string{"root"})
	assert.ErrorContains(t, err, "did not admit")
	_, err = ctl.Revoke("member", []string{"nobody"})
	assert.ErrorContains(t, err, `no member named "nobody"`)
	assert.Len(t, m.revoked, 2, "and neither cost a record")
}
