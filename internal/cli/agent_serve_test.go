package cli

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/wg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fakeMachine stands in for everything serve builds: it hands out the fakes
// the agent loop is already tested with, remembers what they were configured
// with, and can fail any step of the wiring.
type fakeMachine struct {
	cl    *fakeCluster
	wg    *fakeWG
	hosts *fakeHosts
	ctl   *fakeCtl

	name      string
	nameErr   error
	wgErr     error
	clErr     error
	listenErr error

	wgCfg    wg.Config
	clCfg    cluster.Config
	socket   string
	listened chan control.Handler // the handler the control socket was given
}

func newFakeMachine(t *testing.T) *fakeMachine {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return &fakeMachine{
		cl:       &fakeCluster{ch: make(chan []overlay.Node)},
		wg:       &fakeWG{pub: key.PublicKey().String()},
		hosts:    &fakeHosts{},
		ctl:      &fakeCtl{},
		name:     "testhost",
		listened: make(chan control.Handler, 1),
	}
}

func (m *fakeMachine) deps() agentDeps {
	return agentDeps{
		hostname: func() (string, error) { return m.name, m.nameErr },
		newWG: func(cfg wg.Config) (wgDevice, error) {
			m.wgCfg = cfg
			return m.wg, m.wgErr
		},
		newCluster: func(cfg cluster.Config) (agentCluster, error) {
			m.clCfg = cfg
			return m.cl, m.clErr
		},
		newHosts: func(string) hostsWriter { return m.hosts },
		listen: func(socket string, h control.Handler) (controlServer, error) {
			m.socket = socket
			if m.listenErr != nil {
				return nil, m.listenErr
			}
			m.listened <- h
			return m.ctl, nil
		},
	}
}

// fakeCtl is the control socket, which the agent only closes.
type fakeCtl struct{ closed atomic.Bool }

func (c *fakeCtl) Close() { c.closed.Store(true) }

// serveCmd is an agent with a state directory of its own, configured to start
// a new cluster so that serve gets past bootstrap without a member to enrol
// with.
func serveCmd(t *testing.T) (*AgentCmd, string) {
	t.Helper()
	dir := t.TempDir()
	a := validCmd()
	a.Interface, a.stateDir = "wg1", dir
	a.BindAddr = netip.MustParseAddr("127.0.0.1") // a specific address needs no interface list
	a.ControlSocket = filepath.Join(dir, "ctl.sock")
	return &a, dir
}

// runServe starts serve and returns the channel it reports on.
func runServe(t *testing.T, a *AgentCmd, m *fakeMachine) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- a.serve(ctx, notify.None{}, m.deps()) }()
	return cancel, errc
}

// waitHandler is the control handler once serve has opened the socket, which
// is also how a test knows the wiring is done.
func waitHandler(t *testing.T, m *fakeMachine) control.Handler {
	t.Helper()
	select {
	case h := <-m.listened:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("the control socket was never opened")
		return nil
	}
}

// waitJoin waits for the agent to have tried to join the gossip ring.
func waitJoin(t *testing.T, m *fakeMachine) {
	t.Helper()
	require.Eventually(t, func() bool { return m.cl.attempts.Load() > 0 }, 5*time.Second, 10*time.Millisecond,
		"the cluster was never joined")
}

// The node has an overlay network and no state, so it starts a cluster: the
// slot it assigns itself, its wireguard key and its settings all have to reach
// the pieces that are built from them.
func Test_AgentCmd_serve_wiresEverythingUp(t *testing.T) {
	a, dir := serveCmd(t)
	a.WireguardPort, a.ClusterPort, a.Join = 51821, 7947, []string{"member:7947"}
	m := newFakeMachine(t)
	cancel, errc := runServe(t, a, m)
	waitHandler(t, m)

	assert.Equal(t, "wg1", m.wgCfg.Interface)
	assert.Equal(t, 51821, m.wgCfg.Port)
	assert.Equal(t, 1420, m.wgCfg.MTU)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), m.wgCfg.OverlayAddr, "the root takes the first address")

	assert.Equal(t, dir, m.clCfg.StateDir)
	assert.Equal(t, "wg1", m.clCfg.StateName)
	assert.Equal(t, 7947, m.clCfg.BindPort)
	assert.Equal(t, netip.MustParseAddr("127.0.0.1"), m.clCfg.AdvertiseAddr)
	require.NotNil(t, m.clCfg.LocalNode)
	assert.Equal(t, "testhost", m.clCfg.LocalNode.Name, "the host's name identifies it in the cluster")
	assert.Equal(t, m.wg.pub, m.clCfg.LocalNode.PubKey, "peers are told the key wireguard just generated")
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), m.clCfg.LocalNode.OverlayAddr)
	assert.Equal(t, filepath.Join(dir, "ctl.sock"), m.socket)
	waitJoin(t, m)
	assert.Equal(t, []string{"member:7947"}, m.cl.joined(), "joined at the members --join names")

	m.cl.ch <- []overlay.Node{verifiedNode(t, "peer", "192.0.2.1", "10.0.0.2")}

	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Len(t, m.wg.ups, 1, "the membership reached wireguard")
	assert.True(t, m.cl.left)
	assert.True(t, m.ctl.closed.Load(), "the control socket is closed on the way out")
	assert.FileExists(t, filepath.Join(dir, "wg1.json"), "an ordinary stop keeps the state")
}

// A leave asked for through the control socket stops the agent and deletes the
// state, and the operator waiting on the socket is told only once that is done.
func Test_AgentCmd_serve_leaveForgetsTheCluster(t *testing.T) {
	a, dir := serveCmd(t)
	m := newFakeMachine(t)
	_, errc := runServe(t, a, m)
	h := waitHandler(t, m)

	left := make(chan control.LeaveResult, 1)
	go func() {
		res, err := h.Leave(false)
		assert.NoError(t, err)
		left <- res
	}()

	require.NoError(t, waitErr(t, errc))
	assert.NoFileExists(t, filepath.Join(dir, "wg1.json"), "a node that left keeps nothing")
	select {
	case res := <-left:
		assert.True(t, res.Revoked, "the node revoked itself before it went")
	case <-time.After(5 * time.Second):
		t.Fatal("the leave request was never answered")
	}
}

// A cluster that cannot be joined is retried rather than given up on, until
// the agent is stopped; stopping that way is not a failure.
func Test_AgentCmd_serve_retriesTheJoin(t *testing.T) {
	a, dir := serveCmd(t)
	m := newFakeMachine(t)
	m.cl.joinErr = errors.New("no route to member")
	cancel, errc := runServe(t, a, m)
	waitHandler(t, m)

	waitJoin(t, m)
	cancel()
	require.NoError(t, waitErr(t, errc), "being stopped mid-join is not an error")
	assert.True(t, m.cl.left, "the cluster is left rather than abandoned mid-join")
	assert.FileExists(t, filepath.Join(dir, "wg1.json"), "the state is kept for the next start")
}

// Whatever the agent cannot build, it reports rather than carrying on with
// half an interface.
func Test_AgentCmd_serve_reportsWiringFailures(t *testing.T) {
	tests := []struct {
		name    string
		broken  func(*AgentCmd, *fakeMachine)
		wantErr string
		// wantDown is set where the interface already exists by the time the
		// step fails: asking for it is what creates it, so a failure from
		// there on must not leave one behind that no agent is driving.
		wantDown bool
	}{
		{"no hostname", func(_ *AgentCmd, m *fakeMachine) { m.nameErr = errors.New("boom") }, "getting hostname", false},
		{
			"the settled overlay network does not hold",
			func(a *AgentCmd, _ *fakeMachine) { a.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")} },
			"overlaps the overlay network",
			false,
		},
		{"no wireguard", func(_ *AgentCmd, m *fakeMachine) { m.wgErr = errors.New("no module") }, "instantiating wireguard controller", false},
		{"no cluster", func(_ *AgentCmd, m *fakeMachine) { m.clErr = errors.New("port taken") }, "creating cluster", true},
		{"no control socket", func(_ *AgentCmd, m *fakeMachine) { m.listenErr = errors.New("in use") }, "in use", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := serveCmd(t)
			m := newFakeMachine(t)
			tt.broken(a, m)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := a.serve(ctx, notify.None{}, m.deps())
			assert.ErrorContains(t, err, tt.wantErr)
			if tt.wantDown {
				assert.Equal(t, 1, m.wg.downs, "the interface a failed start created is removed")
			} else {
				assert.Zero(t, m.wg.downs)
			}
		})
	}
}

// A control socket that cannot be opened leaves the agent with a cluster it
// has joined and no way to be told to leave, so it leaves it there and then.
func Test_AgentCmd_serve_listenFailureLeavesTheCluster(t *testing.T) {
	a, _ := serveCmd(t)
	m := newFakeMachine(t)
	m.listenErr = errors.New("in use")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.Error(t, a.serve(ctx, notify.None{}, m.deps()))
	assert.True(t, m.cl.left)
}
