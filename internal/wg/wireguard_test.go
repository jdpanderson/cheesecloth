package wg

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testConfig uses a non-default MTU so the test proves it is applied.
func testConfig() Config {
	return Config{
		Interface: "wgtest0", Port: 51820,
		OverlayAddr: netip.MustParseAddr("10.99.0.100"), MTU: 1400, PersistentKeepalive: 25 * time.Second,
	}
}

func testPeer(t *testing.T, name, addr, overlayAddr string) overlay.Node {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	n := overlay.Node{Name: name, Addr: netip.MustParseAddr(addr)}
	n.OverlayAddr = netip.MustParseAddr(overlayAddr)
	n.PubKey = key.PublicKey().String()
	return n
}

func Test_hostPrefix(t *testing.T) {
	assert.Equal(t, "10.0.0.1/32", hostPrefix(netip.MustParseAddr("10.0.0.1")).String())
	assert.Equal(t, "2001:db8::1/128", hostPrefix(netip.MustParseAddr("2001:db8::1")).String())
	assert.Equal(t, "10.0.0.1/32", prefixToIPNet(hostPrefix(netip.MustParseAddr("10.0.0.1"))).String())
}

func Test_State_nodesToPeerConfigs(t *testing.T) {
	key1 := wgtypes.Key{1}.String()
	key2 := wgtypes.Key{2}.String()

	n1 := overlay.Node{Name: "n1", Addr: netip.MustParseAddr("192.0.2.1")}
	n1.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n1.PubKey = key1
	n2 := overlay.Node{Name: "n2", Addr: netip.MustParseAddr("2001:db8::2")}
	n2.OverlayAddr = netip.MustParseAddr("fd00::2")
	n2.PubKey = key2

	s := &State{port: 51820}
	cfgs, err := s.nodesToPeerConfigs([]overlay.Node{n1, n2})
	require.NoError(t, err)
	require.Len(t, cfgs, 2)

	assert.Equal(t, key1, cfgs[0].PublicKey.String())
	assert.True(t, cfgs[0].ReplaceAllowedIPs)
	require.NotNil(t, cfgs[0].PersistentKeepaliveInterval, "stated even where it is off; see statesWhatIsTurnedOff")
	assert.Zero(t, *cfgs[0].PersistentKeepaliveInterval, "keepalive off by default")
	assert.Equal(t, "192.0.2.1:51820", cfgs[0].Endpoint.String())
	assert.Equal(t, "10.0.0.1/32", cfgs[0].AllowedIPs[0].String())

	assert.Equal(t, key2, cfgs[1].PublicKey.String())
	assert.Equal(t, "[2001:db8::2]:51820", cfgs[1].Endpoint.String())
	assert.Equal(t, "fd00::2/128", cfgs[1].AllowedIPs[0].String())
}

func Test_State_nodesToPeerConfigs_keepalive(t *testing.T) {
	n := overlay.Node{Name: "n", Addr: netip.MustParseAddr("192.0.2.1")}
	n.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n.PubKey = wgtypes.Key{1}.String()

	s := &State{port: 51820, keepalive: 25 * time.Second}
	cfgs, err := s.nodesToPeerConfigs([]overlay.Node{n})
	require.NoError(t, err)
	require.NotNil(t, cfgs[0].PersistentKeepaliveInterval)
	assert.Equal(t, 25*time.Second, *cfgs[0].PersistentKeepaliveInterval)
}

func Test_State_nodesToPeerConfigs_badKey(t *testing.T) {
	n := overlay.Node{Name: "n", Addr: netip.MustParseAddr("192.0.2.1")}
	n.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n.PubKey = "not a key"

	_, err := (&State{}).nodesToPeerConfigs([]overlay.Node{n})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing wireguard key")
}

func Test_State_nodesToPeerConfigs_empty(t *testing.T) {
	cfgs, err := (&State{}).nodesToPeerConfigs(nil)
	require.NoError(t, err)
	assert.Empty(t, cfgs)
}

// Asking the kernel whether it has wireguard is what creates the interface, so
// a failure after that removes it rather than leaving one behind that no agent
// is driving.
func Test_newDeviceState_removesTheInterfaceItCreated(t *testing.T) {
	dev := &fakeDevice{}
	broken := errors.New("no netlink")
	newClient = func() (wgClient, error) { return nil, broken }
	t.Cleanup(func() { newClient = func() (wgClient, error) { return wgctrl.New() } })

	_, err := newDeviceState(Config{Interface: "wgtest0"}, dev, &fakeLinker{})
	require.ErrorIs(t, err, broken)
	assert.Equal(t, []string{"Delete"}, dev.calls, "the interface does not outlive the failure")

	// an interface that cannot be removed is reported and not retried
	dev = &fakeDevice{errs: map[string]error{"Delete": errors.New("busy")}}
	_, err = newDeviceState(Config{Interface: "wgtest0"}, dev, &fakeLinker{})
	require.ErrorIs(t, err, broken)
	assert.Equal(t, []string{"Delete"}, dev.calls)

	// and a device that is built keeps its interface
	newClient = func() (wgClient, error) { return &fakeWG{}, nil }
	dev = &fakeDevice{}
	s, err := newDeviceState(Config{Interface: "wgtest0"}, dev, &fakeLinker{})
	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Empty(t, dev.calls)
}
