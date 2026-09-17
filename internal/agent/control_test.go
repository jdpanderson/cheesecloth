package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMembership stands in for the cluster behind the control socket.
type fakeMembership struct {
	awaiting        []trust.Awaiting
	afterConfirm    []trust.Awaiting // what the cluster is holding once Confirm has run
	confirmedRecord trust.Digest
	confirmErr      error
	id              *trust.Identity
	set             *trust.Set
	revoked         []trust.PublicKey
	withdrawn       []trust.Member
	revokeErr       error
	revokedSelf     bool
	revokeSelfErr   error
}

func newFakeMembership(t *testing.T) (*fakeMembership, *trust.Identity) {
	t.Helper()
	root, err := trust.NewIdentity()
	require.NoError(t, err)
	member, err := trust.NewIdentity()
	require.NoError(t, err)
	// the cluster has agreed on both of them, so member's own records count
	set := trust.NewSet()
	founding := trust.Found(root, "root", trust.QuorumMajority, 0)
	agreed := trust.Propose(root, 2, founding.Digest(), trust.QuorumMajority, 0, []trust.Member{
		{Identity: root.Public(), Name: "root", Host: 1},
		{Identity: member.Public(), Name: "member", Host: 2},
	}, nil)
	require.NoError(t, set.Adopt(agreed))
	return &fakeMembership{id: root, set: set}, member
}

func (f *fakeMembership) Invite(ttl time.Duration) (string, error) {
	return "token-" + ttl.String(), nil
}
func (f *fakeMembership) Revoke(id trust.PublicKey) ([]trust.Member, error) {
	f.revoked = append(f.revoked, id)
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

	tok, err := ctl.Invite(5 * time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "token-5m0s", tok)

	got, err := ctl.Revoke("member")
	require.NoError(t, err)
	assert.Equal(t, member.Public(), got.Identity, "resolved by name")

	got, err = ctl.Revoke(member.Public().String())
	require.NoError(t, err)
	assert.Equal(t, member.Public(), got.Identity, "given as an identity")
	assert.Equal(t, []trust.PublicKey{member.Public(), member.Public()}, m.revoked)
	assert.Empty(t, got.Withdrawn, "and nothing else goes with it")

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

	_, err := m.set.AddRevocation(trust.Revoke(m.id, member.Public()))
	require.NoError(t, err)

	_, err = ctl.Revoke(member.Public().String())
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

	_, err = controlHandler{cluster: m}.Revoke(stranger.Public().String())
	assert.ErrorContains(t, err, "was never admitted")
	assert.Empty(t, m.revoked)
}

func (f *fakeMembership) Awaiting() []trust.Awaiting { return f.awaiting }

func (f *fakeMembership) Confirm(record trust.Digest) error {
	f.confirmedRecord = record
	if f.confirmErr != nil {
		return f.confirmErr
	}
	if f.afterConfirm != nil {
		f.awaiting = f.afterConfirm
	}
	return nil
}

// The agent reports what the record has after the confirmation rather than one
// more than it had: another member's may have arrived while this one was being
// signed, and the count the operator reads has to be the cluster's.
func Test_controlHandler_Confirm_reportsWhatTheRecordHasNow(t *testing.T) {
	m, member := newFakeMembership(t)
	rec := trust.Digest{1}
	m.awaiting = []trust.Awaiting{{
		Record: rec, Kind: "admission", Identity: member.Public(), Name: "j",
		Signer: member.Public(), Have: 0, Need: 2,
	}}
	// by the time it is confirmed, two have arrived
	m.afterConfirm = []trust.Awaiting{{
		Record: rec, Kind: "admission", Identity: member.Public(), Name: "j",
		Signer: member.Public(), Have: 2, Need: 2,
	}}

	got, err := controlHandler{cluster: m}.Confirm("j")
	require.NoError(t, err)
	assert.Equal(t, rec, m.confirmedRecord)
	assert.True(t, got.Waiting)
	assert.Equal(t, 2, got.Have, "read back, not counted up from what it had")
}

// A record that is no longer held once it is confirmed is reported as such,
// rather than as a count that would imply it is still waiting.
func Test_controlHandler_Confirm_saysWhenNothingIsHoldingItAnyMore(t *testing.T) {
	m, member := newFakeMembership(t)
	rec := trust.Digest{2}
	m.awaiting = []trust.Awaiting{{
		Record: rec, Kind: "revocation", Identity: member.Public(), Name: "j",
		Signer: member.Public(), Have: 0, Need: 1,
	}}
	m.afterConfirm = []trust.Awaiting{} // it had what it needed and took effect

	got, err := controlHandler{cluster: m}.Confirm("j")
	require.NoError(t, err)
	assert.False(t, got.Waiting)
	assert.Equal(t, "j", got.Name)
}

// The listing says which records this node signed, since those are the ones it
// cannot confirm: the operator sees that before trying rather than after.
func Test_controlHandler_Pending_marksWhatThisNodeSigned(t *testing.T) {
	m, member := newFakeMembership(t)
	m.awaiting = []trust.Awaiting{
		{Record: trust.Digest{1}, Kind: "admission", Name: "mine", Signer: m.Identity(), Need: 1},
		{Record: trust.Digest{2}, Kind: "admission", Name: "theirs", Signer: member.Public(), Need: 1},
	}
	got, err := controlHandler{cluster: m}.Pending()
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.True(t, got[0].SignedHere, "signed here, so this node cannot confirm it")
	assert.False(t, got[1].SignedHere)
	assert.True(t, got[0].Waiting)
}
