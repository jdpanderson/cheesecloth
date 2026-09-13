//go:build darwin

package wg

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The ioctl request numbers encode their argument's size; the structs must
// be laid out exactly as the kernel's.
func Test_darwin_structSizes(t *testing.T) {
	assert.Equal(t, uintptr(32), unsafe.Sizeof(ifreq{}), "struct ifreq")
	assert.Equal(t, uintptr(unix.SIOCSIFFLAGS>>16&0x1fff), unsafe.Sizeof(ifreq{}))
	assert.Equal(t, uintptr(64), unsafe.Sizeof(ifAliasReq{}), "struct ifaliasreq")
	assert.Equal(t, uintptr(unix.SIOCAIFADDR>>16&0x1fff), unsafe.Sizeof(ifAliasReq{}))
	assert.Equal(t, uintptr(128), unsafe.Sizeof(in6AliasReq{}), "struct in6_aliasreq")
	assert.Equal(t, uintptr(siocAIFADDRIn6>>16&0x1fff), unsafe.Sizeof(in6AliasReq{}))
}

func Test_darwin_ifName(t *testing.T) {
	name, err := ifName("utun7")
	require.NoError(t, err)
	assert.Equal(t, "utun7", string(name[:5]))
	assert.Zero(t, name[5], "NUL terminated")
	_, err = ifName("an-interface-name")
	assert.Error(t, err, "sixteen bytes including the terminator")
}

func Test_darwin_sockaddrs(t *testing.T) {
	sa := sockaddr4(netip.MustParseAddr("10.0.0.2"))
	assert.Equal(t, uint8(16), sa.Len)
	assert.Equal(t, uint8(unix.AF_INET), sa.Family)
	assert.Equal(t, [4]byte{10, 0, 0, 2}, sa.Addr)
	assert.Equal(t, "255.255.255.255", mask4(netip.MustParsePrefix("10.0.0.2/32")).String())
	assert.Equal(t, "255.255.0.0", mask4(netip.MustParsePrefix("10.0.0.0/16")).String())

	sa6 := sockaddr6(netip.MustParseAddr("fd00::2"))
	assert.Equal(t, uint8(28), sa6.Len)
	assert.Equal(t, uint8(unix.AF_INET6), sa6.Family)
	assert.Equal(t, "ffff:ffff:ffff:ffff::", mask6(netip.MustParsePrefix("fd00::/64")).String())
}

// A route message marshals into what the kernel parses back into the same
// route: the destination, its mask, the interface as gateway.
func Test_darwin_routeMessage_roundTrip(t *testing.T) {
	for _, dst := range []string{"10.99.0.1/32", "192.168.7.0/24", "fd00::2/128", "fd00:7::/64"} {
		p := netip.MustParsePrefix(dst)
		m := routeMessage(unix.RTM_ADD, 7, p)
		b, err := m.Marshal()
		require.NoError(t, err)
		msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		got := msgs[0].(*route.RouteMessage)
		assert.Equal(t, unix.RTM_ADD, got.Type)
		assert.Equal(t, 7, got.Index)
		assert.Equal(t, unix.RTF_UP|unix.RTF_STATIC, got.Flags)
		gw, ok := got.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		require.True(t, ok, "the gateway is the interface itself")
		assert.Equal(t, 7, gw.Index)
		back, ok := destination(got)
		require.True(t, ok, dst)
		assert.Equal(t, p, back)
	}
	assert.NotEqual(t, routeMessage(unix.RTM_ADD, 1, netip.MustParsePrefix("10.0.0.1/32")).Seq,
		routeMessage(unix.RTM_DELETE, 1, netip.MustParsePrefix("10.0.0.1/32")).Seq, "every message has its own sequence number")
}

func Test_darwin_destination(t *testing.T) {
	host := &route.RouteMessage{Flags: unix.RTF_HOST, Addrs: []route.Addr{&route.Inet4Addr{IP: [4]byte{10, 0, 0, 9}}}}
	p, ok := destination(host)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.9/32", p.String(), "a host route has no mask")

	_, ok = destination(&route.RouteMessage{})
	assert.False(t, ok, "no destination")
	_, ok = destination(&route.RouteMessage{Addrs: []route.Addr{&route.LinkAddr{Index: 1}}})
	assert.False(t, ok, "not an IP destination")
}

func Test_darwin_staticRoutes(t *testing.T) {
	ours := routeMessage(unix.RTM_ADD, 7, netip.MustParsePrefix("10.99.0.1/32"))
	other := routeMessage(unix.RTM_ADD, 8, netip.MustParsePrefix("10.99.0.2/32"))
	kernel := routeMessage(unix.RTM_ADD, 7, netip.MustParsePrefix("10.99.0.100/32"))
	kernel.Flags = unix.RTF_UP | unix.RTF_HOST
	linkLocal := routeMessage(unix.RTM_ADD, 7, netip.MustParsePrefix("fe80::/64"))
	multicast := routeMessage(unix.RTM_ADD, 7, netip.MustParsePrefix("ff02::/32"))
	got := staticRoutes([]route.Message{ours, other, kernel, linkLocal, multicast}, 7)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32")}, got,
		"only static routes through the interface, and not the link-local and multicast ones")
}

// The read side works without privileges against the live system.
func Test_darwin_bsdLinker_reads(t *testing.T) {
	link := bsdLinker{}
	addrs, err := link.Addrs("lo0")
	require.NoError(t, err)
	assert.Contains(t, addrs, netip.MustParsePrefix("127.0.0.1/8"))
	_, err = link.Routes("lo0")
	require.NoError(t, err)

	_, err = link.Addrs("nonexistent0")
	assert.Error(t, err)
	_, err = link.Routes("nonexistent0")
	assert.Error(t, err)
	assert.Error(t, link.AddRoute("nonexistent0", netip.MustParsePrefix("10.99.0.1/32")))
}

// The whole thing, for real: needs root for the utun. `sudo go test -run Live ./internal/wg`.
func Test_darwin_Live(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun interface needs root")
	}
	cfg := testConfig()
	cfg.Interface = "wgtest0"
	s, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = s.DownInterface() }()
	assert.Equal(t, "userspace", s.dev.Kind())

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	p1.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}
	p2 := testPeer(t, "p2", "192.0.2.2", "10.99.0.2")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))
	osName := s.osName
	assert.Contains(t, osName, "utun")

	ifi, err := net.InterfaceByName(osName)
	require.NoError(t, err)
	assert.Equal(t, 1400, ifi.MTU)
	assert.NotZero(t, ifi.Flags&net.FlagUp)
	link := bsdLinker{}
	addrs, err := link.Addrs(osName)
	require.NoError(t, err)
	assert.Contains(t, addrs, netip.MustParsePrefix("10.99.0.100/32"))
	routes, err := link.Routes(osName)
	require.NoError(t, err)
	assert.ElementsMatch(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32"), netip.MustParsePrefix("192.168.7.0/24"), netip.MustParsePrefix("10.99.0.2/32")}, routes)

	// the running interface is found by the agent's name, with its peers
	report, err := Status("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, s.pubKey.String(), report.PublicKey)
	assert.Equal(t, 51820, report.ListenPort)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.100/32")}, report.Addrs)
	require.Len(t, report.Peers, 2)
	assert.Equal(t, 25*time.Second, report.Peers[0].PersistentKeepalive)

	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}), "idempotent")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p2}))
	routes, err = link.Routes(osName)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")}, routes, "p1's routes went with it")

	require.NoError(t, s.DownInterface())
	_, err = net.InterfaceByName(osName)
	assert.Error(t, err, "the utun went with the device")
	_, _, err = lookup("wgtest0")
	assert.Error(t, err, "and so did the name record")
	require.NoError(t, s.DownInterface(), "down on a stopped device is a no-op")
}
