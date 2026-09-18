package agent

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

// validAgent is an agent with the settings the flag defaults would give it.
func validAgent() agent {
	return agent{Config: Config{Interface: "wgcloth", OverlayNet: testOverlay, MTU: 1420, WireguardPort: 51820,
		BindAddr: netip.IPv4Unspecified()}}
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

func Test_masked(t *testing.T) {
	got := masked([]netip.Prefix{netip.MustParsePrefix("192.168.7.9/24"), netip.MustParsePrefix("fd00::1/64")})
	assert.Equal(t, "192.168.7.0/24", got[0].String())
	assert.Equal(t, "fd00::/64", got[1].String())
	assert.Empty(t, masked(nil))
}

func Test_agent_enrolAddrs(t *testing.T) {
	cmd := agent{Config: Config{ClusterPort: 7946,
		Join: []string{"member", "10.0.0.1:1234", "fd00::1", "[fd00::1]", "[fd00::2]:99"}}}
	assert.Equal(t, []string{"member:7946", "10.0.0.1:1234", "[fd00::1]:7946", "[fd00::1]:7946", "[fd00::2]:99"},
		cmd.enrolAddrs(), "an address already in brackets is not bracketed twice")
}

func Test_agent_bootstrap(t *testing.T) {
	newBoot := func() *cluster.Bootstrap {
		id, err := trust.NewIdentity()
		require.NoError(t, err)
		return &cluster.Bootstrap{Identity: id}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// not a member and nothing configured: left unenrolled, so the agent idles
	idle := newBoot()
	addrs, err := (&agent{}).bootstrap(ctx, idle, "h")
	require.NoError(t, err)
	assert.Empty(t, addrs)
	assert.False(t, idle.Enrolled())

	// an overlay network with no state to go with it: root of a new cluster,
	// joining whatever --join names
	boot := newBoot()
	addrs, err = (&agent{Config: Config{OverlayNet: netip.MustParsePrefix("10.0.0.9/8"), Join: []string{"x"}}}).bootstrap(ctx, boot, "h")
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, addrs)
	assert.True(t, boot.Enrolled())
	assert.Equal(t, testOverlay, boot.OverlayNet, "the cluster's network, as a welcome would have stated it")
	require.NotNil(t, boot.Anchor, "a node that founds a cluster starts from its own membership")
	require.Len(t, boot.Anchor.Members, 1)
	assert.Equal(t, "h", boot.Anchor.Members[0].Name)

	// already enrolled: the join key is ignored, --join is used as given
	addrs, err = (&agent{Config: Config{Join: []string{"a", "b"}, JoinKey: "stale"}}).bootstrap(ctx, boot, "h")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, addrs)

	// --join-key with no reachable member fails
	_, err = (&agent{Config: Config{ClusterPort: 1, Join: []string{"127.0.0.1"}, JoinKey: "token"}}).bootstrap(ctx, newBoot(), "h")
	assert.ErrorContains(t, err, "enrolling with 127.0.0.1:1")

	// enrolling wins over an overlay network the config file happens to set
	_, err = (&agent{Config: Config{ClusterPort: 1, Join: []string{"127.0.0.1"}, OverlayNet: testOverlay, JoinKey: "token"}}).
		bootstrap(ctx, newBoot(), "h")
	assert.ErrorContains(t, err, "enrolling with 127.0.0.1:1", "the join key is tried, not ignored for an init")
}

// A node with nothing to act on keeps its identity and waits, rather than
// exiting and leaving the service manager to restart it in a loop. No
// wireguard interface is touched; the control socket is opened where it can be,
// so that an operator asking the agent something is answered rather than told
// nothing is listening (see Test_serve_idleAnswersTheControlSocket).
func Test_Run_idles(t *testing.T) {
	dir := t.TempDir()
	a := validAgent()
	a.Interface, a.StateDir, a.OverlayNet = "wg1", dir, netip.Prefix{}
	n := &recordingNotifier{}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, a.Config, n) }()

	require.Eventually(t, func() bool { return n.ready.Load() }, time.Second, 10*time.Millisecond,
		"the service manager is told the agent is up")
	assert.FileExists(t, filepath.Join(dir, "wg1.json"), "the identity is still generated and kept")
	assert.NoFileExists(t, filepath.Join(dir, "wg1.sock"), "and no interface is configured")

	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.True(t, n.stopping.Load())
}

// recordingNotifier is a service manager that remembers what it was told.
type recordingNotifier struct{ ready, stopping atomic.Bool }

func (n *recordingNotifier) Ready(string) error  { n.ready.Store(true); return nil }
func (n *recordingNotifier) Status(string) error { return nil }
func (n *recordingNotifier) Stopping() error     { n.stopping.Store(true); return nil }

func Test_agent_enrol_unreachable(t *testing.T) {
	joiner, err := trust.NewIdentity()
	require.NoError(t, err)
	cmd := agent{Config: Config{ClusterPort: 1, Join: []string{"127.0.0.1", "127.0.0.1:2"}, JoinKey: "token"}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _, err = cmd.enrol(ctx, joiner, "j")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enrolling with 127.0.0.1:2", "the last member tried is reported")
}

// The command line, then the config file (kong has merged the two by now),
// then what the cluster says, which every member's bootstrap knows.
func Test_agent_settleOverlayNet(t *testing.T) {
	clusterNet := netip.MustParsePrefix("10.42.0.0/16")
	tests := []struct {
		name          string
		given, ofNode netip.Prefix
		want          netip.Prefix
	}{
		{"from the cluster", netip.Prefix{}, clusterNet, clusterNet},
		{"given here, and the cluster agrees", clusterNet, clusterNet, clusterNet},
		{"given here, and the cluster does not", netip.MustParsePrefix("10.9.0.0/16"), clusterNet, netip.MustParsePrefix("10.9.0.0/16")},
		{"host bits are cleared", netip.MustParsePrefix("10.9.0.5/16"), clusterNet, netip.MustParsePrefix("10.9.0.0/16")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validAgent()
			a.OverlayNet = tt.given
			require.NoError(t, a.settleOverlayNet(tt.ofNode))
			assert.Equal(t, tt.want, a.OverlayNet)
		})
	}
}

// A network that comes from the cluster is checked like one given here.
func Test_agent_settleOverlayNet_checksTheResult(t *testing.T) {
	unset := func(routes ...netip.Prefix) agent {
		a := validAgent()
		a.OverlayNet, a.AllowedIPs = netip.Prefix{}, routes
		return a
	}
	route := netip.MustParsePrefix("10.1.0.0/16")

	a := unset(route)
	assert.ErrorContains(t, a.settleOverlayNet(netip.MustParsePrefix("10.1.0.0/24")), "overlaps the overlay network 10.1.0.0/24")
	a = unset()
	assert.ErrorContains(t, a.settleOverlayNet(netip.MustParsePrefix("10.0.0.0/31")), "no room for two nodes")
}

// The state file is deleted only when the agent stopped because it left the
// cluster; an ordinary stop keeps everything for the next start.
func Test_agent_forget(t *testing.T) {
	dir := t.TempDir()
	a := validAgent()
	a.Interface, a.StateDir = "wg1", dir
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

// Check holds a configuration to what the agent can run with, whichever
// command is holding it.
func Test_Config_Check(t *testing.T) {
	valid := validAgent().Config
	require.NoError(t, valid.Check())

	tests := []struct {
		name    string
		broken  func(*Config)
		wantErr string
	}{
		{"no interface", func(c *Config) { c.Interface = "" }, "no interface name"},
		{"interface too long", func(c *Config) { c.Interface = "wg0123456789abc" + "d" }, "the most is 15"},
		{"interface with a path separator", func(c *Config) { c.Interface = "../secrets" }, "is not one"},
		{"interface with a newline", func(c *Config) { c.Interface = "wg0\nevil" }, "is not one"},
		{"interface starting with a dot", func(c *Config) { c.Interface = ".wg0" }, "is not one"},
		{"interface with a space", func(c *Config) { c.Interface = "wg 0" }, "is not one"},
		{"join key without a member to join", func(c *Config) { c.JoinKey = "token" }, "needs --join"},
		{"overlay too small", func(c *Config) { c.OverlayNet = netip.MustParsePrefix("10.0.0.0/31") }, "no room for two nodes"},
		{"allowed ips inside the overlay", func(c *Config) { c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.5.0.0/16")} }, "overlaps the overlay network"},
		{"mtu too small", func(c *Config) { c.MTU = 500 }, "unsupported MTU"},
		{"mtu too large", func(c *Config) { c.MTU = 65536 }, "unsupported MTU"},
		{"no wireguard port", func(c *Config) { c.WireguardPort = 0 }, "unsupported wireguard port"},
		{"wireguard port past a port", func(c *Config) { c.WireguardPort = 65536 }, "unsupported wireguard port"},
		{"negative cluster port", func(c *Config) { c.ClusterPort = -1 }, "unsupported cluster port"},
		{"cluster port past a port", func(c *Config) { c.ClusterPort = 65536 }, "unsupported cluster port"},
		{"keepalive not whole seconds", func(c *Config) { c.PersistentKeepalive = 1500 * time.Millisecond }, "unsupported persistent keepalive"},
		{"sync interval too short", func(c *Config) { c.SyncInterval = time.Second }, "unsupported sync interval"},
		{"sync interval too long", func(c *Config) { c.SyncInterval = 2 * time.Hour }, "unsupported sync interval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid
			tt.broken(&c)
			assert.ErrorContains(t, c.Check(), tt.wantErr)
		})
	}

	// the names an interface actually goes by, which must all keep working
	for _, name := range []string{"wgcloth", "wg0", "wg-mesh", "wg_mesh", "eth0.100", "utun3", "0"} {
		c := valid
		c.Interface = name
		assert.NoError(t, c.Check(), name)
	}

	// zero is a cluster port, unlike a wireguard port: it asks for a free one
	c0 := valid
	c0.ClusterPort = 0
	assert.NoError(t, c0.Check())

	// nothing to check of the overlay network until the cluster has been asked
	c := valid
	c.OverlayNet, c.AllowedIPs = netip.Prefix{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	assert.NoError(t, c.Check())
	c.JoinKey, c.Join = "token", []string{"member"}
	assert.NoError(t, c.Check())
}

// freeUDPPort is a loopback port nothing is listening on, so a test can know
// where the cluster it starts will be before it starts it.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := c.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, c.Close())
	return port
}

// rootClusterAt starts a one-node cluster on port, ready to enrol others.
func rootClusterAt(t *testing.T, dir string, port int) *cluster.Cluster {
	t.Helper()
	b, err := cluster.Load(dir, "root")
	require.NoError(t, err)
	b.InitRoot("root", testOverlay, trust.QuorumMajority, 0)
	adm, err := b.Assigned()
	require.NoError(t, err)
	addr, ok := overlay.Addr(testOverlay, adm.Host)
	require.True(t, ok)
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	node := &overlay.Node{Name: "root"}
	node.OverlayAddr, node.PubKey = addr, key.PublicKey().String()

	loopback := netip.MustParseAddr("127.0.0.1")
	c, err := cluster.New(cluster.Config{
		StateDir: dir, StateName: "root", BindAddr: loopback, AdvertiseAddr: loopback, BindPort: port,
		OverlayNet: testOverlay, LocalNode: node, Boot: b, Memberlist: memberlist.DefaultLocalConfig,
	})
	require.NoError(t, err)
	return c
}

// An enrolment reaches the disk as soon as it has happened, before anything
// that could fail has run. By the time bootstrap returns the invitation is
// spent and the cluster has agreed a membership holding this node, so an
// enrolment kept only in memory would cost a second invitation every time the
// interface could not be created -- and leave the cluster holding a member
// that never came up.
func Test_agent_bootstrap_keepsTheEnrolment(t *testing.T) {
	dir := t.TempDir()
	port := freeUDPPort(t)
	root := rootClusterAt(t, dir, port)
	defer root.Leave()
	token, err := root.Invite(time.Minute)
	require.NoError(t, err)

	a := validAgent()
	a.Interface, a.StateDir, a.OverlayNet = "wg1", dir, netip.Prefix{}
	a.Join, a.JoinKey = []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}, token

	boot, err := cluster.Load(dir, "wg1")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = a.bootstrap(ctx, boot, "joiner")
	require.NoError(t, err)

	// nothing else has run: no address settled, no interface, no cluster
	held, err := cluster.Load(dir, "wg1")
	require.NoError(t, err)
	assert.True(t, held.Enrolled(), "the enrolment is kept before anything else can fail")
	assert.Equal(t, boot.Identity.Public(), held.Identity.Public())
	assert.True(t, held.Set().Valid(held.Identity.Public()), "and holds a membership this node is a member of")
	assert.Equal(t, testOverlay, held.OverlayNet, "with the network the cluster stated")
}
