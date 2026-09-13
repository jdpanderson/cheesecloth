package cli

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

// validCmd returns an AgentCmd with the flag defaults that Validate requires.
func validCmd() AgentCmd {
	return AgentCmd{settings: settings{OverlayNet: testOverlay, MTU: 1420, BindAddr: netip.IPv4Unspecified()}}
}

// The name a host asks for is the first label of its hostname, lowercased,
// which is the form a cluster's names take. A hostname that cannot be made
// into one stops the node rather than being fixed up silently.
func Test_nodeName(t *testing.T) {
	for _, tt := range []struct{ hostname, want string }{
		{"web1", "web1"},
		{"WEB1", "web1"},
		{"web1.example.com", "web1"},
		{"Web1.Example.COM", "web1"},
	} {
		got, err := nodeName(tt.hostname)
		require.NoError(t, err, tt.hostname)
		assert.Equal(t, tt.want, got)
	}

	for _, hostname := range []string{"", ".", "-web1", "web_1", "192", "a b"} {
		_, err := nodeName(hostname)
		assert.ErrorContains(t, err, "cannot be named in a cluster", "hostname %q", hostname)
	}
}

func Test_AgentCmd_Validate_errors(t *testing.T) {
	tests := []struct {
		name    string
		cmd     AgentCmd
		wantErr string
	}{
		{
			"overlay too small",
			AgentCmd{settings: settings{OverlayNet: netip.MustParsePrefix("10.0.0.0/31"), MTU: 1420}},
			"no room for two nodes",
		},
		{
			"allowed ips inside the overlay",
			AgentCmd{settings: settings{OverlayNet: testOverlay, MTU: 1420, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.5.0.0/16")}}},
			"overlaps the overlay network",
		},
		{
			"mtu too small",
			AgentCmd{settings: settings{OverlayNet: testOverlay, MTU: 500}},
			"unsupported MTU",
		},
		{
			"keepalive not whole seconds",
			AgentCmd{settings: settings{OverlayNet: testOverlay, MTU: 1420, PersistentKeepalive: 1500 * time.Millisecond}},
			"unsupported persistent keepalive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func Test_masked(t *testing.T) {
	got := masked([]netip.Prefix{netip.MustParsePrefix("192.168.7.9/24"), netip.MustParsePrefix("fd00::1/64")})
	assert.Equal(t, "192.168.7.0/24", got[0].String())
	assert.Equal(t, "fd00::/64", got[1].String())
	assert.Empty(t, masked(nil))
}

func Test_AgentCmd_Validate_joinKey(t *testing.T) {
	cmd := validCmd()
	cmd.JoinKey = "token"
	assert.ErrorContains(t, cmd.Validate(), "needs --join")
	cmd.Join = []string{"member"}
	require.NoError(t, cmd.Validate())
}

func Test_AgentCmd_enrolAddrs(t *testing.T) {
	cmd := AgentCmd{settings: settings{ClusterPort: 7946,
		Join: []string{"member", "10.0.0.1:1234", "fd00::1", "[fd00::1]", "[fd00::2]:99"}}}
	assert.Equal(t, []string{"member:7946", "10.0.0.1:1234", "[fd00::1]:7946", "[fd00::1]:7946", "[fd00::2]:99"},
		cmd.enrolAddrs(), "an address already in brackets is not bracketed twice")
}

func Test_AgentCmd_bootstrap(t *testing.T) {
	newBoot := func() *cluster.Bootstrap {
		id, err := trust.NewIdentity()
		require.NoError(t, err)
		return &cluster.Bootstrap{Identity: id}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// not a member and nothing configured: left unenrolled, so the agent idles
	idle := newBoot()
	addrs, err := (&AgentCmd{}).bootstrap(ctx, idle, "h")
	require.NoError(t, err)
	assert.Empty(t, addrs)
	assert.False(t, idle.Enrolled())

	// an overlay network with no state to go with it: root of a new cluster,
	// joining whatever --join names
	boot := newBoot()
	addrs, err = (&AgentCmd{settings: settings{OverlayNet: DefaultOverlayNet, Join: []string{"x"}}}).bootstrap(ctx, boot, "h")
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, addrs)
	assert.True(t, boot.Enrolled())
	assert.Equal(t, boot.Identity.Public(), boot.Root)
	require.Len(t, boot.Records.Admissions, 1)
	assert.Equal(t, "h", boot.Records.Admissions[0].Name)

	// already enrolled: the join key is ignored, --join is used as given
	addrs, err = (&AgentCmd{settings: settings{Join: []string{"a", "b"}}, JoinKey: "stale"}).bootstrap(ctx, boot, "h")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, addrs)

	// --join-key with no reachable member fails
	_, err = (&AgentCmd{settings: settings{ClusterPort: 1, Join: []string{"127.0.0.1"}}, JoinKey: "token"}).bootstrap(ctx, newBoot(), "h")
	assert.ErrorContains(t, err, "enrolling with 127.0.0.1:1")

	// enrolling wins over an overlay network the config file happens to set
	_, err = (&AgentCmd{settings: settings{ClusterPort: 1, Join: []string{"127.0.0.1"}, OverlayNet: DefaultOverlayNet}, JoinKey: "token"}).
		bootstrap(ctx, newBoot(), "h")
	assert.ErrorContains(t, err, "enrolling with 127.0.0.1:1", "the join key is tried, not ignored for an init")
}

// A node with nothing to act on keeps its identity and waits, rather than
// exiting and leaving the service manager to restart it in a loop. Nothing
// that needs privileges is touched: no wireguard interface, no control socket.
func Test_AgentCmd_Run_idles(t *testing.T) {
	dir := t.TempDir()
	a := validCmd()
	a.Interface, a.stateDir, a.OverlayNet = "wg1", dir, netip.Prefix{}
	n := &recordingNotifier{}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- a.Run(ctx, n) }()

	require.Eventually(t, func() bool { return n.ready.Load() }, time.Second, 10*time.Millisecond,
		"the service manager is told the agent is up")
	assert.FileExists(t, filepath.Join(dir, "wg1.json"), "the identity is still generated and kept")
	assert.NoFileExists(t, socketFor("wg1", ""), "no control socket without a cluster to control")

	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.True(t, n.stopping.Load())
}

// recordingNotifier is a service manager that remembers what it was told.
type recordingNotifier struct{ ready, stopping atomic.Bool }

func (n *recordingNotifier) Ready(string) error  { n.ready.Store(true); return nil }
func (n *recordingNotifier) Status(string) error { return nil }
func (n *recordingNotifier) Stopping() error     { n.stopping.Store(true); return nil }

func Test_AgentCmd_enrol_unreachable(t *testing.T) {
	joiner, err := trust.NewIdentity()
	require.NoError(t, err)
	cmd := AgentCmd{settings: settings{ClusterPort: 1, Join: []string{"127.0.0.1", "127.0.0.1:2"}}, JoinKey: "token"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _, err = cmd.enrol(ctx, joiner, "j")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enrolling with 127.0.0.1:2", "the last member tried is reported")
}

// The command line, then the config file (kong has merged the two by now),
// then what the cluster says, then the default for a new cluster.
func Test_AgentCmd_settleOverlayNet(t *testing.T) {
	clusterNet := netip.MustParsePrefix("10.42.0.0/16")
	tests := []struct {
		name          string
		given, ofNode netip.Prefix
		want          netip.Prefix
	}{
		{"given here", netip.MustParsePrefix("10.9.0.0/16"), netip.Prefix{}, netip.MustParsePrefix("10.9.0.0/16")},
		{"from the cluster", netip.Prefix{}, clusterNet, clusterNet},
		{"the default for a new cluster", netip.Prefix{}, netip.Prefix{}, DefaultOverlayNet},
		{"given here, and the cluster agrees", clusterNet, clusterNet, clusterNet},
		{"given here, and the cluster does not", netip.MustParsePrefix("10.9.0.0/16"), clusterNet, netip.MustParsePrefix("10.9.0.0/16")},
		{"host bits are cleared", netip.MustParsePrefix("10.9.0.5/16"), netip.Prefix{}, netip.MustParsePrefix("10.9.0.0/16")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validCmd()
			a.OverlayNet = tt.given
			require.NoError(t, a.settleOverlayNet(tt.ofNode))
			assert.Equal(t, tt.want, a.OverlayNet)
		})
	}
}

// A network that comes from the cluster is checked like one given here.
func Test_AgentCmd_settleOverlayNet_checksTheResult(t *testing.T) {
	unset := func(routes ...netip.Prefix) AgentCmd {
		a := validCmd()
		a.OverlayNet, a.AllowedIPs = netip.Prefix{}, routes
		return a
	}
	route := netip.MustParsePrefix("10.1.0.0/16")

	a := unset(route)
	assert.ErrorContains(t, a.settleOverlayNet(netip.Prefix{}), "overlaps the overlay network 10.0.0.0/8", "the default")
	a = unset(route)
	assert.ErrorContains(t, a.settleOverlayNet(netip.MustParsePrefix("10.1.0.0/24")), "overlaps the overlay network", "the cluster's")
	a = unset()
	assert.ErrorContains(t, a.settleOverlayNet(netip.MustParsePrefix("10.0.0.0/31")), "no room for two nodes")
}

// Nothing to check until the cluster has been asked.
func Test_AgentCmd_Validate_overlayNetUnset(t *testing.T) {
	a := validCmd()
	a.OverlayNet = netip.Prefix{}
	a.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	assert.NoError(t, a.Validate())
}

// The state file is deleted only when the agent stopped because it left the
// cluster; an ordinary stop keeps everything for the next start.
func Test_AgentCmd_forget(t *testing.T) {
	dir := t.TempDir()
	a := validCmd()
	a.Interface, a.stateDir = "wg1", dir
	_, err := cluster.Load(dir, "wg1")
	require.NoError(t, err)
	statePath := filepath.Join(dir, "wg1.json")
	require.FileExists(t, statePath)

	l := &leaving{done: make(chan struct{})}
	require.NoError(t, a.forget(l))
	assert.FileExists(t, statePath)

	l.requested.Store(true)
	require.NoError(t, a.forget(l))
	assert.NoFileExists(t, statePath)
}
