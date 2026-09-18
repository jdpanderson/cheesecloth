package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeCluster struct {
	ch   chan []overlay.Node
	left bool

	// the join and the control socket are driven from other goroutines
	joinErr  error
	joinMu   sync.Mutex
	joinedAt []string
	attempts atomic.Int32
	revoked  atomic.Bool
	stranded atomic.Bool
}

func (f *fakeCluster) Members() <-chan []overlay.Node { return f.ch }
func (f *fakeCluster) Stranded() bool                 { return f.stranded.Load() }
func (f *fakeCluster) Awaiting() []trust.Awaiting     { return nil }
func (f *fakeCluster) Confirm(trust.Digest) error     { return nil }
func (f *fakeCluster) Leave()                         { f.left = true }

func (f *fakeCluster) Join(addrs []string) error {
	f.joinMu.Lock()
	f.joinedAt = append(f.joinedAt, addrs...)
	f.joinMu.Unlock()
	f.attempts.Add(1)
	return f.joinErr
}

// joined is the addresses the agent has tried to join at.
func (f *fakeCluster) joined() []string {
	f.joinMu.Lock()
	defer f.joinMu.Unlock()
	return slices.Clone(f.joinedAt)
}

// The rest is what the control socket asks of a cluster.
func (f *fakeCluster) Invite(time.Duration) (string, error)           { return "token", nil }
func (f *fakeCluster) Revoke(trust.PublicKey) ([]trust.Member, error) { return nil, nil }
func (f *fakeCluster) RevokeSelf() (int, error)                       { f.revoked.Store(true); return 0, nil }
func (f *fakeCluster) Trust() *trust.Set                              { return trust.NewSet() }
func (f *fakeCluster) Identity() trust.PublicKey                      { return trust.PublicKey{} }

type fakeWG struct {
	mu             sync.Mutex
	upErr, downErr error
	ups            [][]overlay.Node
	downs          int
	pub            string
	// calls is signalled on each SetUpInterface, so a test watching for the
	// loop to state a snapshot again waits on it rather than on the clock.
	calls chan struct{}
}

func (f *fakeWG) PublicKey() string { return f.pub }

func (f *fakeWG) SetUpInterface(nodes []overlay.Node) error {
	f.mu.Lock()
	f.ups = append(f.ups, nodes)
	err := f.upErr
	f.mu.Unlock()
	if f.calls != nil {
		select {
		case f.calls <- struct{}{}:
		default:
		}
	}
	return err
}

func (f *fakeWG) DownInterface() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downs++
	return f.downErr
}

// setUpErr is what the interface says from the next snapshot on.
func (f *fakeWG) setUpErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upErr = err
}

type fakeHosts struct {
	writes []map[string][]string
	err    error
}

func (f *fakeHosts) WriteEntries(m map[string][]string) error {
	f.writes = append(f.writes, m)
	return f.err
}

// verifiedNode is a node as the cluster hands it over: metadata decoded and checked.
func verifiedNode(t *testing.T, name, addr, overlayAddr string, routes ...string) overlay.Node {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	n := overlay.Node{Name: name, Addr: netip.MustParseAddr(addr)}
	n.OverlayAddr = netip.MustParseAddr(overlayAddr)
	n.PubKey = key.PublicKey().String()
	for _, r := range routes {
		n.AllowedIPs = append(n.AllowedIPs, netip.MustParsePrefix(r))
	}
	return n
}

// runLoop runs the agent loop with the given notifier, or none.
func runLoop(t *testing.T, a *agent, cl *fakeCluster, wg *fakeWG, hosts *fakeHosts, notifiers ...notify.Notifier) (context.CancelFunc, <-chan error) {
	t.Helper()
	var n notify.Notifier = notify.None{}
	if len(notifiers) > 0 {
		n = notifiers[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- a.loop(ctx, cl.ch, cl, wg, hosts, n) }()
	return cancel, errc
}

func waitErr(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not return")
		return nil
	}
}

func Test_agent_loop_appliesAndTearsDown(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{}
	hosts := &fakeHosts{}
	cancel, errc := runLoop(t, &agent{Config: Config{OverlayNet: testOverlay}}, cl, wg, hosts)

	cl.ch <- []overlay.Node{verifiedNode(t, "good", "192.0.2.1", "10.0.0.1")}

	cancel()
	require.NoError(t, waitErr(t, errc))

	require.Len(t, wg.ups, 1)
	require.Len(t, wg.ups[0], 1)
	assert.Equal(t, "good", wg.ups[0][0].Name)
	require.Len(t, hosts.writes, 2)
	assert.Equal(t, map[string][]string{"10.0.0.1": {"good"}}, hosts.writes[0])
	assert.Empty(t, hosts.writes[1], "hosts entries cleared on shutdown")
	assert.True(t, cl.left)
	assert.Equal(t, 1, wg.downs)
}

func Test_agent_apply_allowedIPs(t *testing.T) {
	wg := &fakeWG{}
	a := &agent{Config: Config{OverlayNet: testOverlay, NoEtcHosts: true}}
	// z is listed first but b wins the shared network by name; the overlay-net prefix is dropped
	z := verifiedNode(t, "z", "192.0.2.1", "10.0.0.1", "192.168.7.0/24", "10.9.0.0/16", "172.16.0.0/12")
	b := verifiedNode(t, "b", "192.0.2.2", "10.0.0.2", "192.168.7.0/24")
	_, err := a.apply([]overlay.Node{z, b}, wg, &fakeHosts{})
	require.NoError(t, err)

	require.Len(t, wg.ups, 1)
	require.Len(t, wg.ups[0], 2)
	assert.Equal(t, "b", wg.ups[0][0].Name)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}, wg.ups[0][0].AllowedIPs)
	assert.Equal(t, "z", wg.ups[0][1].Name)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}, wg.ups[0][1].AllowedIPs)
}

// The snapshot's route slices belong to the cluster, which persists them;
// filtering must not touch their backing arrays.
func Test_agent_apply_leavesInputRoutesAlone(t *testing.T) {
	a := &agent{Config: Config{OverlayNet: testOverlay, NoEtcHosts: true}}
	z := verifiedNode(t, "z", "192.0.2.1", "10.0.0.1", "10.9.0.0/16", "192.168.7.0/24", "172.16.0.0/12")
	shared := z.AllowedIPs
	before := slices.Clone(shared)

	_, err := a.apply([]overlay.Node{z}, &fakeWG{}, &fakeHosts{})
	require.NoError(t, err)

	assert.Equal(t, before, shared, "the caller's slice is unchanged")
}

func Test_agent_loop_noEtcHosts(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{}
	hosts := &fakeHosts{}
	cancel, errc := runLoop(t, &agent{Config: Config{OverlayNet: testOverlay, NoEtcHosts: true}}, cl, wg, hosts)

	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Empty(t, hosts.writes)
}

// An interface that will not take a snapshot keeps the one it last took:
// removing it would cost every peer their tunnel over a fault that may be in
// one of them, and leave nothing to route over until the membership next
// changed.
func Test_agent_loop_setupFailureKeepsTheInterface(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{upErr: errors.New("boom")}
	a := &agent{Config: Config{OverlayNet: testOverlay, NoEtcHosts: true}, every: time.Hour}
	cancel, errc := runLoop(t, a, cl, wg, &fakeHosts{})

	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Equal(t, 1, wg.downs, "removed at shutdown and not before")
}

// A snapshot the interface would not take is stated again until it does, and
// the service manager's line says so meanwhile: nothing else would state it,
// since a membership that does not change produces no further snapshots.
func Test_agent_loop_statesARefusedSnapshotUntilItIsTaken(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{upErr: errors.New("boom"), calls: make(chan struct{}, 64)}
	n := &statusNotifier{}
	a := &agent{Config: Config{OverlayNet: testOverlay, NoEtcHosts: true}, every: time.Millisecond}
	cancel, errc := runLoop(t, a, cl, wg, &fakeHosts{}, n)

	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	for range 3 { // the first statement and two more of the same snapshot
		select {
		case <-wg.calls:
		case <-time.After(5 * time.Second):
			t.Fatal("the snapshot was not stated again")
		}
	}
	assert.Contains(t, n.last(), "could not be configured", "the operator is told where to look")

	wg.setUpErr(nil) // whatever the interface objected to is mended
	require.Eventually(t, func() bool { return n.last() == "1 peers" }, 5*time.Second, time.Millisecond,
		"the line goes back to a plain count once the interface takes it")

	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Equal(t, 1, wg.downs, "removed at shutdown and not before")
}

// Nothing closes the membership channel but the cluster being left, which the
// loop does itself, so this is a way out that should not happen. It still hands
// the interface back: serve stops tearing it down once the loop is running, so
// a way out that skipped the teardown would leave the device behind.
func Test_agent_loop_closedChannel(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg, hosts := &fakeWG{}, &fakeHosts{}
	_, errc := runLoop(t, &agent{}, cl, wg, hosts)
	close(cl.ch)
	err := waitErr(t, errc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel closed")
	assert.Equal(t, 1, wg.downs, "the interface is not left behind")
	assert.True(t, cl.left, "and the cluster is left")
	require.Len(t, hosts.writes, 1)
	assert.Empty(t, hosts.writes[0], "and the hosts entries are cleared")
}

// failingNotifier is a service manager that cannot be reached.
type failingNotifier struct{}

func (failingNotifier) Ready(string) error  { return errors.New("notify boom") }
func (failingNotifier) Status(string) error { return errors.New("notify boom") }
func (failingNotifier) Stopping() error     { return errors.New("notify boom") }

// Failures to write hosts entries, to down the interface after a failed setup,
// or to reach the service manager are logged and the loop carries on; only a
// failure to down the interface at shutdown is an error, since the interface
// is left behind.
func Test_agent_loop_toleratesFailures(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{upErr: errors.New("up boom"), downErr: errors.New("down boom")}
	hosts := &fakeHosts{err: errors.New("hosts boom")}
	cancel, errc := runLoop(t, &agent{Config: Config{OverlayNet: testOverlay}}, cl, wg, hosts, failingNotifier{})

	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	cl.ch <- nil // still running after every failure
	cancel()
	err := waitErr(t, errc)
	assert.ErrorContains(t, err, "downing interface")
	assert.Len(t, wg.ups, 2)
	assert.Len(t, hosts.writes, 3, "two snapshots and the clearing at shutdown")
	assert.True(t, cl.left)
}

// statusNotifier keeps the status lines the loop reports.
type statusNotifier struct {
	mu    sync.Mutex
	lines []string
}

func (r *statusNotifier) Ready(s string) error  { return r.note(s) }
func (r *statusNotifier) Status(s string) error { return r.note(s) }
func (r *statusNotifier) Stopping() error       { return nil }

func (r *statusNotifier) note(s string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, s)
	return nil
}

func (r *statusNotifier) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) == 0 {
		return ""
	}
	return r.lines[len(r.lines)-1]
}

// A node that cannot catch up with its cluster says so where an operator looks
// first. The log says it too, but the service manager's line is what
// 'systemctl status' shows without being asked.
func Test_loop_saysWhenTheClusterIsOutOfReach(t *testing.T) {
	cl, wg, hosts := &fakeCluster{ch: make(chan []overlay.Node)}, &fakeWG{}, &fakeHosts{}
	n := &statusNotifier{}
	cancel, errc := runLoop(t, &agent{Config: Config{OverlayNet: testOverlay}}, cl, wg, hosts, n)
	defer func() { cancel(); <-errc }()

	cl.ch <- nil
	require.Eventually(t, func() bool { return n.last() == "0 peers" }, time.Second, 10*time.Millisecond)

	cl.stranded.Store(true)
	cl.ch <- nil
	require.Eventually(t, func() bool { return strings.Contains(n.last(), "cannot verify") },
		time.Second, 10*time.Millisecond, "the status says what is wrong and where to read about it")
	assert.Contains(t, n.last(), "see the log")
}
