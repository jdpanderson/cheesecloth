package wg

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fakeDevice records device calls; errs injects an error per method name.
type fakeDevice struct {
	errs   map[string]error
	calls  []string
	osName string // what Create reports; the requested name when empty
	mtu    int
}

func (f *fakeDevice) call(name string) error {
	f.calls = append(f.calls, name)
	return f.errs[name]
}

func (f *fakeDevice) Kind() string { return "fake" }

func (f *fakeDevice) Create(name string, mtu int) (string, error) {
	if err := f.call("Create"); err != nil {
		return "", err
	}
	f.mtu = mtu
	if f.osName != "" {
		return f.osName, nil
	}
	return name, nil
}

func (f *fakeDevice) Delete(string) error { return f.call("Delete") }

// fakeLinker records linker calls and keeps the state they set.
type fakeLinker struct {
	errs      map[string]error
	routeErrs map[netip.Prefix]error // per destination, as a kernel refuses one route and not another
	calls     []string
	iface     string // the interface name every call was made with
	addr      netip.Prefix
	mtu       int
	up        bool
	addrs     []netip.Prefix
	routes    []netip.Prefix
}

func (f *fakeLinker) call(name, iface string) error {
	f.calls = append(f.calls, name)
	f.iface = iface
	return f.errs[name]
}

func (f *fakeLinker) SetAddr(iface string, addr netip.Prefix) error {
	f.addr = addr
	return f.call("SetAddr", iface)
}
func (f *fakeLinker) SetMTU(iface string, mtu int) error { f.mtu = mtu; return f.call("SetMTU", iface) }
func (f *fakeLinker) Up(iface string) error              { f.up = true; return f.call("Up", iface) }
func (f *fakeLinker) Addrs(iface string) ([]netip.Prefix, error) {
	if err := f.call("Addrs", iface); err != nil {
		return nil, err
	}
	return f.addrs, nil
}
func (f *fakeLinker) Routes(iface string) ([]netip.Prefix, error) {
	if err := f.call("Routes", iface); err != nil {
		return nil, err
	}
	return slices.Clone(f.routes), nil
}
func (f *fakeLinker) AddRoute(iface string, dst netip.Prefix) error {
	if err := f.call("AddRoute", iface); err != nil {
		return err
	}
	if err := f.routeErrs[dst]; err != nil {
		return err
	}
	if !slices.Contains(f.routes, dst) {
		f.routes = append(f.routes, dst)
	}
	return nil
}
func (f *fakeLinker) DelRoute(iface string, dst netip.Prefix) error {
	if err := f.call("DelRoute", iface); err != nil {
		return err
	}
	if err := f.routeErrs[dst]; err != nil {
		return err
	}
	f.routes = slices.DeleteFunc(f.routes, func(p netip.Prefix) bool { return p == dst })
	return nil
}

type fakeWG struct {
	cfgErr    error
	cfg       *wgtypes.Config
	device    *wgtypes.Device // returned by Device when set
	deviceErr error
}

func (f *fakeWG) Device(string) (*wgtypes.Device, error) {
	if f.deviceErr != nil {
		return nil, f.deviceErr
	}
	if f.device != nil {
		return f.device, nil
	}
	return &wgtypes.Device{}, nil
}
func (f *fakeWG) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	f.cfg = &cfg
	return f.cfgErr
}

func newFakeState(t *testing.T, dev *fakeDevice, link *fakeLinker, wgc *fakeWG) *State {
	t.Helper()
	s, err := newState(testConfig(), wgc, dev, link)
	require.NoError(t, err)
	return s
}

func Test_State_SetUpInterface_fake(t *testing.T) {
	dev := &fakeDevice{}
	link := &fakeLinker{}
	wgc := &fakeWG{}
	s := newFakeState(t, dev, link, wgc)

	// what peers are told this node's wireguard key is, which is the public
	// half of the one the device is configured with below
	assert.Equal(t, s.pubKey.String(), s.PublicKey())

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}))

	assert.Equal(t, []string{"Create"}, dev.calls)
	assert.Equal(t, 1400, dev.mtu)
	assert.Equal(t, []string{"SetAddr", "SetMTU", "Up", "AddRoute", "Routes"}, link.calls)
	assert.Equal(t, "wgtest0", link.iface)
	assert.Equal(t, netip.MustParsePrefix("10.99.0.100/32"), link.addr)
	assert.Equal(t, 1400, link.mtu)
	assert.True(t, link.up)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32")}, link.routes)
	require.NotNil(t, wgc.cfg)
	assert.True(t, wgc.cfg.ReplacePeers)
	assert.Equal(t, 51820, *wgc.cfg.ListenPort)
	assert.Len(t, wgc.cfg.Peers, 1)
}

func Test_State_SetUpInterface_fake_osName(t *testing.T) {
	// the operating system may name the interface itself (macOS: utunN); the
	// stack is driven by that name, wireguard by the agent's
	dev := &fakeDevice{osName: "utun7"}
	link := &fakeLinker{}
	s := newFakeState(t, dev, link, &fakeWG{})
	require.NoError(t, s.SetUpInterface(nil))
	assert.Equal(t, "utun7", link.iface)
	assert.Equal(t, "utun7", s.osName)
	require.NoError(t, s.DownInterface())
	assert.Empty(t, s.osName)
}

func Test_State_SetUpInterface_fake_removesStaleRoutes(t *testing.T) {
	link := &fakeLinker{}
	s := newFakeState(t, &fakeDevice{}, link, &fakeWG{})
	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	p2 := testPeer(t, "p2", "192.0.2.2", "10.99.0.2")

	p1.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}

	// leftovers on the interface from a previous run, and the kernel's route to our own address
	own := hostPrefix(s.overlayAddr)
	link.routes = []netip.Prefix{netip.MustParsePrefix("192.0.2.9/32"), netip.MustParsePrefix("10.99.0.0/24"), own}

	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))
	want := []netip.Prefix{own, netip.MustParsePrefix("10.99.0.1/32"), netip.MustParsePrefix("192.168.7.0/24"), netip.MustParsePrefix("10.99.0.2/32")}
	assert.ElementsMatch(t, want, link.routes, "routes nobody advertises are removed, our own address stays")

	link.calls = nil
	require.NoError(t, s.SetUpInterface([]overlay.Node{p2}))
	assert.Contains(t, link.calls, "DelRoute")
	assert.ElementsMatch(t, []netip.Prefix{own, netip.MustParsePrefix("10.99.0.2/32")}, link.routes, "p1's address and network went with it")

	// a route that cannot be removed is left in place and logged, rather than
	// costing the interface every route it did manage to set
	link.errs = map[string]error{"DelRoute": errors.New("boom")}
	logged := captureLog(t)
	require.NoError(t, s.SetUpInterface(nil))
	assert.Contains(t, link.routes, netip.MustParsePrefix("10.99.0.2/32"), "the route nobody claims is still there")
	assert.Contains(t, logged.String(), "could not remove a route no peer claims")
}

// The kernel refuses one route: the peers whose routes it took keep working,
// and the operator is told which destination is not reachable.
func Test_State_SetUpInterface_fake_keepsGoingPastARefusedRoute(t *testing.T) {
	clash := netip.MustParsePrefix("192.168.7.0/24")
	link := &fakeLinker{routeErrs: map[netip.Prefix]error{clash: errors.New("file exists")}}
	wgc := &fakeWG{}
	s := newFakeState(t, &fakeDevice{}, link, wgc)

	bad := testPeer(t, "bad", "192.0.2.1", "10.99.0.1")
	bad.AllowedIPs = []netip.Prefix{clash}
	good := testPeer(t, "good", "192.0.2.2", "10.99.0.2")

	logged := captureLog(t)
	require.NoError(t, s.SetUpInterface([]overlay.Node{bad, good}), "one refused route is not a failed interface")

	assert.ElementsMatch(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32"), netip.MustParsePrefix("10.99.0.2/32")},
		link.routes, "every other route went in, the refused one did not")
	require.NotNil(t, wgc.cfg)
	assert.Len(t, wgc.cfg.Peers, 2, "both peers are still configured in wireguard")
	assert.True(t, link.up)

	out := logged.String()
	assert.Contains(t, out, "could not add route")
	assert.Contains(t, out, "192.168.7.0/24")
	assert.Contains(t, out, "bad", "the node advertising it is named")
}

// Routes that cannot even be listed leave the interface up: reconciliation is
// what is lost, not connectivity.
func Test_State_SetUpInterface_fake_routeListFailure(t *testing.T) {
	link := &fakeLinker{errs: map[string]error{"Routes": errors.New("boom")}}
	s := newFakeState(t, &fakeDevice{}, link, &fakeWG{})

	logged := captureLog(t)
	require.NoError(t, s.SetUpInterface([]overlay.Node{testPeer(t, "p1", "192.0.2.1", "10.99.0.1")}))
	assert.True(t, link.up)
	assert.Contains(t, logged.String(), "could not list the routes")
}

// captureLog sends the default logger to a buffer for the rest of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return buf
}

func Test_State_SetUpInterface_fake_errors(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name     string
		devErrs  map[string]error
		linkErrs map[string]error
		cfgErr   error
		wantMsg  string
	}{
		{"create", map[string]error{"Create": boom}, nil, nil, "creating interface"},
		{"configure device", nil, nil, boom, "setting wireguard configuration"},
		{"set addr", nil, map[string]error{"SetAddr": boom}, nil, "setting address"},
		{"mtu", nil, map[string]error{"SetMTU": boom}, nil, "setting MTU"},
		{"up", nil, map[string]error{"Up": boom}, nil, "enabling interface"},
		// route failures are logged rather than returned: see the tests above
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeState(t, &fakeDevice{errs: tt.devErrs}, &fakeLinker{errs: tt.linkErrs}, &fakeWG{cfgErr: tt.cfgErr})
			err := s.SetUpInterface([]overlay.Node{testPeer(t, "p1", "192.0.2.1", "10.99.0.1")})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantMsg)
			assert.ErrorIs(t, err, boom)
		})
	}
}

func Test_State_DownInterface_fake(t *testing.T) {
	dev := &fakeDevice{}
	s := newFakeState(t, dev, &fakeLinker{}, &fakeWG{})
	require.NoError(t, s.DownInterface())
	assert.Equal(t, []string{"Delete"}, dev.calls)

	boom := errors.New("boom")
	s = newFakeState(t, &fakeDevice{errs: map[string]error{"Delete": boom}}, &fakeLinker{}, &fakeWG{})
	err := s.DownInterface()
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "removing interface")
}

// Restating the interface reconciles its peers rather than replacing them: a
// replacement takes every peer out and puts it back, which costs each one its
// session and a fresh handshake, and this runs on every membership snapshot
// rather than only when the membership changes. The first statement is the
// exception, since the interface may be one another agent left behind.
func Test_State_SetUpInterface_reconcilesAfterTheFirstStatement(t *testing.T) {
	dev, link, wgc := &fakeDevice{}, &fakeLinker{}, &fakeWG{}
	s := newFakeState(t, dev, link, wgc)
	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")

	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}))
	require.NotNil(t, wgc.cfg)
	assert.True(t, wgc.cfg.ReplacePeers, "the first statement does not reason about what was there")
	kept := wgc.cfg.Peers[0].PublicKey

	// the device now holds that peer, and one the cluster no longer names
	gone := wgtypes.Key{9}
	wgc.device = &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: kept}, {PublicKey: gone}}}
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}))

	assert.False(t, wgc.cfg.ReplacePeers, "the statements after it reconcile")
	require.Len(t, wgc.cfg.Peers, 2)
	assert.Equal(t, kept, wgc.cfg.Peers[0].PublicKey)
	assert.False(t, wgc.cfg.Peers[0].Remove, "the peer the cluster still names is stated where it stands")
	assert.Equal(t, gone, wgc.cfg.Peers[1].PublicKey)
	assert.True(t, wgc.cfg.Peers[1].Remove, "and the one it does not is named for removal")
}

// A device that cannot be read is one there is nothing to reconcile against,
// and a statement that failed leaves one whose contents are not known. Both
// are stated whole instead.
func Test_State_SetUpInterface_replacesWhereTheDeviceIsInDoubt(t *testing.T) {
	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")

	wgc := &fakeWG{}
	s := newFakeState(t, &fakeDevice{}, &fakeLinker{}, wgc)
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}))
	wgc.deviceErr = errors.New("cannot read the device")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1}))
	assert.True(t, wgc.cfg.ReplacePeers, "a device that cannot be read is stated whole")

	wgc2 := &fakeWG{}
	s2 := newFakeState(t, &fakeDevice{}, &fakeLinker{}, wgc2)
	require.NoError(t, s2.SetUpInterface([]overlay.Node{p1}))
	wgc2.cfgErr = errors.New("boom")
	require.Error(t, s2.SetUpInterface([]overlay.Node{p1}))
	wgc2.cfgErr = nil
	require.NoError(t, s2.SetUpInterface([]overlay.Node{p1}))
	assert.True(t, wgc2.cfg.ReplacePeers, "and so is one left by a statement that failed")
}

// Every attribute is stated, the ones that are off included: a nil field means
// "leave what is there" once the peers are reconciled rather than replaced, so
// a keepalive turned off by leaving the field out would go on applying.
func Test_State_nodesToPeerConfigs_statesWhatIsTurnedOff(t *testing.T) {
	n := testPeer(t, "n", "192.0.2.1", "10.0.0.1")
	cfgs, err := (&State{port: 51820}).nodesToPeerConfigs([]overlay.Node{n})
	require.NoError(t, err)
	require.NotNil(t, cfgs[0].PersistentKeepaliveInterval, "a nil keepalive would leave whatever was set")
	assert.Zero(t, *cfgs[0].PersistentKeepaliveInterval)
	require.NotNil(t, cfgs[0].PresharedKey, "and nothing here sets one, so it is cleared rather than left")
	assert.Equal(t, wgtypes.Key{}, *cfgs[0].PresharedKey)
}
