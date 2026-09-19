//go:build linux

package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// requirePrivilegedEnv makes the tests in this file fail rather than skip when
// what they need is missing. CI sets it for the run that is meant to be
// privileged, so that a run which quietly stops being privileged — a changed
// runner image, a dropped sudo — fails instead of passing with everything
// skipped, which is indistinguishable from passing for real.
const requirePrivilegedEnv = "CHEESECLOTH_REQUIRE_PRIVILEGED"

// skipUnlessRequired skips the test, or fails it where these tests are
// required to run.
func skipUnlessRequired(t *testing.T, format string, args ...any) {
	t.Helper()
	reason := fmt.Sprintf(format, args...)
	if os.Getenv(requirePrivilegedEnv) != "" {
		t.Fatalf("%s (this run is required to be privileged: %s is set)", reason, requirePrivilegedEnv)
	}
	t.Skip(reason)
}

// enterTestNetns runs the rest of the test in a fresh network namespace.
// Skips without CAP_NET_ADMIN; `unshare -r go test ./...` or root provides it.
func enterTestNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	require.NoError(t, err)
	ns, err := netns.New()
	if errors.Is(err, os.ErrPermission) {
		runtime.UnlockOSThread()
		skipUnlessRequired(t, "needs CAP_NET_ADMIN (run under `unshare -r` or as root)")
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = ns.Close()
		_ = orig.Close()
		runtime.UnlockOSThread()
	})
}

func Test_New(t *testing.T) {
	enterTestNetns(t)
	s, err := New(testConfig())
	require.NoError(t, err)
	assert.Equal(t, s.privKey.PublicKey(), s.pubKey)
	assert.True(t, netip.MustParsePrefix("10.99.0.0/16").Contains(s.overlayAddr))
}

func Test_State_SetUpInterface_and_Down(t *testing.T) {
	enterTestNetns(t)
	s, err := New(testConfig())
	require.NoError(t, err)

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	p1.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}
	p2 := testPeer(t, "p2", "192.0.2.2", "10.99.0.2")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))

	link, err := netlink.LinkByName("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, "wireguard", link.Type())
	assert.Equal(t, 1400, link.Attrs().MTU)
	assert.NotZero(t, link.Attrs().Flags&net.FlagUp)

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	assert.Equal(t, s.overlayAddr.String()+"/32", addrs[0].IPNet.String())

	dev, err := s.client.Device("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, s.pubKey, dev.PublicKey)
	assert.Equal(t, 51820, dev.ListenPort)
	require.Len(t, dev.Peers, 2)
	assert.Equal(t, "192.0.2.1:51820", dev.Peers[0].Endpoint.String())
	require.Len(t, dev.Peers[0].AllowedIPs, 2)
	assert.Equal(t, "10.99.0.1/32", dev.Peers[0].AllowedIPs[0].String())
	assert.Equal(t, "192.168.7.0/24", dev.Peers[0].AllowedIPs[1].String())
	assert.Equal(t, 25*time.Second, dev.Peers[0].PersistentKeepaliveInterval)

	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	assert.Len(t, routes, 3, "two peer addresses and one advertised network")

	report, err := Status("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, s.pubKey.String(), report.PublicKey)
	assert.Equal(t, []netip.Prefix{netip.PrefixFrom(s.overlayAddr, 32)}, report.Addrs)
	require.Len(t, report.Peers, 2)
	assert.Equal(t, 25*time.Second, report.Peers[0].PersistentKeepalive)

	// idempotent: link and routes already exist
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))

	// peers and their routes are replaced, not accumulated
	require.NoError(t, s.SetUpInterface([]overlay.Node{p2}))
	dev, err = s.client.Device("wgtest0")
	require.NoError(t, err)
	assert.Len(t, dev.Peers, 1)
	routes, err = netlink.RouteList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, "10.99.0.2/32", routes[0].Dst.String())

	require.NoError(t, s.DownInterface())
	_, err = netlink.LinkByName("wgtest0")
	assert.Error(t, err)

	require.NoError(t, s.DownInterface(), "down on a missing device is a no-op")
}

func Test_netlinkLinker_idempotent(t *testing.T) {
	enterTestNetns(t)
	link := netlinkLinker{}
	name, err := kernelDevice{}.Create("wgtest1", 0)
	require.NoError(t, err)
	assert.Equal(t, "wgtest1", name)
	_, err = kernelDevice{}.Create("wgtest1", 0)
	require.NoError(t, err, "creating an existing interface is fine")
	require.NoError(t, link.Up(name))

	dst := netip.MustParsePrefix("192.0.2.0/24")
	require.NoError(t, link.AddRoute(name, dst))
	require.NoError(t, link.AddRoute(name, dst), "adding an existing route is fine")
	routes, err := link.Routes(name)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{dst}, routes)
	require.NoError(t, link.DelRoute(name, dst))
	require.NoError(t, link.DelRoute(name, dst), "removing a missing route is fine")
	routes, err = link.Routes(name)
	require.NoError(t, err)
	assert.Empty(t, routes)

	osName, _, err := lookup("wgtest1")
	require.NoError(t, err)
	assert.Equal(t, "wgtest1", osName)
	require.NoError(t, kernelDevice{}.Delete(name))
	require.NoError(t, kernelDevice{}.Delete(name), "deleting a missing interface is fine")
	_, _, err = lookup("wgtest1")
	assert.Error(t, err)
}

func Test_State_SetUpInterface_badPeerKey(t *testing.T) {
	enterTestNetns(t)
	s, err := New(testConfig())
	require.NoError(t, err)
	defer func() { _ = s.DownInterface() }()

	bad := testPeer(t, "bad", "192.0.2.1", "10.99.0.1")
	bad.PubKey = "not a key"
	err = s.SetUpInterface([]overlay.Node{bad})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "converting received node information")
}

// needTun skips where the tun device is missing (a container started without it).
func needTun(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		skipUnlessRequired(t, "no /dev/net/tun")
	}
}

// needUAPIDir skips where the directory wg(8) looks in for control sockets
// cannot be made. A user namespace gives CAP_NET_ADMIN but no write access to
// /var/run, so `unshare -r` runs everything here except this.
func needUAPIDir(t *testing.T) {
	t.Helper()
	const dir = "/var/run/wireguard"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		skipUnlessRequired(t, "cannot create %s (run as root rather than under `unshare -r`): %v", dir, err)
	}
}

func Test_State_userspace(t *testing.T) {
	enterTestNetns(t)
	needTun(t)
	needUAPIDir(t)
	cfg := testConfig()
	cfg.Interface, cfg.Userspace = "wgtest2", true
	s, err := New(cfg)
	require.NoError(t, err)
	assert.Equal(t, "userspace", s.dev.Kind())

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}))
	link, err := netlink.LinkByName("wgtest2")
	require.NoError(t, err)
	assert.Equal(t, "tuntap", link.Type())
	assert.Equal(t, 1400, link.Attrs().MTU)
	assert.NotZero(t, link.Attrs().Flags&net.FlagUp)

	// wgctrl reaches the device through its control socket like any other
	dev, err := s.client.Device("wgtest2")
	require.NoError(t, err)
	assert.Equal(t, s.pubKey, dev.PublicKey)
	assert.Equal(t, 51820, dev.ListenPort)
	require.Len(t, dev.Peers, 1)
	assert.Equal(t, "192.0.2.1:51820", dev.Peers[0].Endpoint.String())
	report, err := Status("wgtest2")
	require.NoError(t, err)
	assert.Equal(t, s.pubKey.String(), report.PublicKey)
	assert.Equal(t, []netip.Prefix{netip.PrefixFrom(s.overlayAddr, 32)}, report.Addrs)

	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}), "idempotent: the running device is kept")
	require.NoError(t, s.DownInterface())
	_, err = netlink.LinkByName("wgtest2")
	assert.Error(t, err, "the tun interface went with the device")
	_, err = os.Stat("/var/run/wireguard/wgtest2.sock")
	assert.True(t, os.IsNotExist(err), "the control socket is gone")
	require.NoError(t, s.DownInterface(), "down on a stopped device is a no-op")

	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}), "and it can come back")
	require.NoError(t, s.DownInterface())
}

// An interface a stopped agent left behind is removed by name alone.
func Test_Remove_kernelInterface(t *testing.T) {
	enterTestNetns(t)
	if _, err := (kernelDevice{}).Create("wgtest4", 1420); err != nil {
		skipUnlessRequired(t, "no kernel wireguard here: %v", err)
	}
	require.NoError(t, Remove("wgtest4"))
	_, err := netlink.LinkByName("wgtest4")
	assert.Error(t, err, "the interface is gone")
}

func Test_platform_kernelFirst(t *testing.T) {
	enterTestNetns(t)
	cfg := testConfig()
	cfg.Interface = "wgtest3"
	dev, _, err := platform(cfg)
	if err != nil {
		skipUnlessRequired(t, "no kernel wireguard here either: %v", err)
	}
	defer func() { _ = dev.Delete("wgtest3") }()
	assert.Equal(t, "kernel", dev.Kind(), "the module is preferred whenever the kernel has it")
	_, err = netlink.LinkByName("wgtest3")
	assert.NoError(t, err, "the probe left the interface in place for SetUpInterface")
}

// Restating the interface leaves the device holding exactly what the cluster
// names: the peers it still names updated where they stand, the ones it no
// longer names removed. Against the real kernel, since whether a peer is
// updated or taken out and put back is the kernel's to decide, and a peer put
// back loses the session it had.
func Test_State_SetUpInterface_reconcilesAgainstTheKernel(t *testing.T) {
	enterTestNetns(t)
	s, err := New(testConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.DownInterface() })

	keys := func() []string {
		t.Helper()
		dev, derr := s.client.Device("wgtest0")
		require.NoError(t, derr)
		out := make([]string, 0, len(dev.Peers))
		for _, p := range dev.Peers {
			out = append(out, p.PublicKey.String())
		}
		return out
	}

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	p2 := testPeer(t, "p2", "192.0.2.2", "10.99.0.2")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))
	require.ElementsMatch(t, []string{p1.PubKey, p2.PubKey}, keys())

	// p2 goes and p3 arrives: the device ends up naming p1 and p3 and nothing else
	p3 := testPeer(t, "p3", "192.0.2.3", "10.99.0.3")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p3}))
	assert.ElementsMatch(t, []string{p1.PubKey, p3.PubKey}, keys())

	// and a membership of nobody empties it
	require.NoError(t, s.SetUpInterface(nil))
	assert.Empty(t, keys())
}
