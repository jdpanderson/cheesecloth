package agent

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAddrs(t *testing.T, cidrs ...string) []net.Addr {
	t.Helper()
	addrs := make([]net.Addr, 0, len(cidrs))
	for _, c := range cidrs { // like iface.Addrs(): host IP with the interface mask
		ip, n, err := net.ParseCIDR(c)
		require.NoError(t, err)
		addrs = append(addrs, &net.IPNet{IP: ip, Mask: n.Mask})
	}
	return addrs
}

func Test_pickAdvertiseAddr(t *testing.T) {
	v4 := netip.IPv4Unspecified()
	v6 := netip.IPv6Unspecified()
	mixed := testAddrs(t,
		"fe80::1/64",      // IPv6 link-local: never
		"169.254.1.2/16",  // IPv4 link-local: never
		"192.168.7.7/24",  // private IPv4
		"100.64.0.9/10",   // shared address space: private
		"fd00::7/64",      // IPv6 ULA: private
		"198.51.100.7/24", // public IPv4
		"2001:db8::7/64",  // public IPv6
	)

	got, ok := pickAdvertiseAddr(v4, mixed)
	require.True(t, ok)
	assert.Equal(t, "198.51.100.7", got.String(), "public IPv4 wins over private")

	got, ok = pickAdvertiseAddr(v6, mixed)
	require.True(t, ok)
	assert.Equal(t, "2001:db8::7", got.String(), "public IPv6 wins over ULA")

	got, ok = pickAdvertiseAddr(v4, testAddrs(t, "fe80::1/64", "169.254.1.2/16", "10.1.2.3/24"))
	require.True(t, ok)
	assert.Equal(t, "10.1.2.3", got.String(), "private is fine when nothing public exists")

	got, ok = pickAdvertiseAddr(v6, testAddrs(t, "fe80::1/64", "fd00::7/64"))
	require.True(t, ok)
	assert.Equal(t, "fd00::7", got.String())

	_, ok = pickAdvertiseAddr(v6, testAddrs(t, "192.168.7.7/24", "fe80::1/64"))
	assert.False(t, ok, "no usable IPv6")

	_, ok = pickAdvertiseAddr(v4, testAddrs(t, "169.254.1.2/16", "127.0.0.1/8"))
	assert.False(t, ok, "link-local and loopback never qualify")
}

func Test_firstAddr_unmaps(t *testing.T) {
	mapped := &net.IPNet{IP: net.ParseIP("198.51.100.7"), Mask: net.CIDRMask(120, 128)} // 16-byte form of a v4 address
	got, ok := firstAddr([]net.Addr{mapped, &net.IPAddr{IP: net.ParseIP("203.0.113.1")}}, func(netip.Addr) bool { return true })
	require.True(t, ok)
	assert.True(t, got.Is4())
	assert.Equal(t, "198.51.100.7", got.String())
}

func Test_firstAddr_skipsWhatIsNotAnIP(t *testing.T) {
	addrs := []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, // not an interface address
		&net.IPNet{IP: net.IP{1, 2, 3}},                     // malformed
		&net.IPAddr{IP: net.ParseIP("203.0.113.1")},
	}
	got, ok := firstAddr(addrs, func(netip.Addr) bool { return true })
	require.True(t, ok)
	assert.Equal(t, "203.0.113.1", got.String())
	_, ok = firstAddr(addrs[:2], func(netip.Addr) bool { return true })
	assert.False(t, ok)
}

func Test_agent_advertiseAddr(t *testing.T) {
	cmd := validAgent()
	cmd.BindAddr = netip.MustParseAddr("192.0.2.1")
	got, err := cmd.advertiseAddr()
	require.NoError(t, err)
	assert.Equal(t, cmd.BindAddr, got, "a specific bind address is advertised as is")

	var skipped string
	cmd.addrs = func(skip string) []net.Addr {
		skipped = skip
		return testAddrs(t, "fe80::1/64", "10.1.2.3/24", "fd00::7/64")
	}

	cmd.Interface = "wg7"
	cmd.BindAddr = netip.IPv4Unspecified()
	got, err = cmd.advertiseAddr()
	require.NoError(t, err)
	assert.Equal(t, "10.1.2.3", got.String())
	assert.Equal(t, "wg7", skipped, "the overlay interface's own addresses are left out")

	cmd.BindAddr = netip.IPv6Unspecified()
	got, err = cmd.advertiseAddr()
	require.NoError(t, err)
	assert.Equal(t, "fd00::7", got.String())

	cmd.addrs = func(string) []net.Addr { return testAddrs(t, "fe80::1/64") }
	_, err = cmd.advertiseAddr()
	assert.ErrorContains(t, err, "no IPv6 address found")
	cmd.BindAddr = netip.IPv4Unspecified()
	_, err = cmd.advertiseAddr()
	assert.ErrorContains(t, err, "no IPv4 address found")
}

func Test_upInterfaceAddrs(t *testing.T) {
	// only loopback is certain to exist; it is excluded, so the result may be empty but must not include it
	for _, a := range upInterfaceAddrs("") {
		ip, ok := a.(*net.IPNet)
		require.True(t, ok)
		assert.False(t, ip.IP.IsLoopback(), "%s", a)
	}
}
