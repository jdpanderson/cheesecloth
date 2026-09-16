package cluster

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

// testNodeFor builds the local node for b at the overlay address its admission assigns.
func testNodeFor(t *testing.T, name string, b *Bootstrap) *overlay.Node {
	t.Helper()
	adm, err := b.Assigned()
	require.NoError(t, err)
	addr, ok := overlay.Addr(testOverlay, adm.Host)
	require.True(t, ok)
	node := &overlay.Node{Name: name}
	node.OverlayAddr = addr
	node.PubKey = testKey
	return node
}

// loopback is where every test node binds, each on a port of its own (BindPort 0).
var loopback = netip.MustParseAddr("127.0.0.1")

// fastMemberlist is the local-network memberlist profile, for quick failure detection in tests.
func fastMemberlist(c *Config) { c.Memberlist = memberlist.DefaultLocalConfig }

// rootCluster starts a new cluster whose root is this node, with state under dir.
func rootCluster(t *testing.T, dir, name string, opts ...func(*Config)) *Cluster {
	t.Helper()
	b, err := Load(dir, name)
	require.NoError(t, err)
	b.InitRoot(name, testOverlay, trust.QuorumMajority)
	cfg := Config{
		StateDir: dir, StateName: name, BindAddr: loopback, AdvertiseAddr: loopback, OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, name, b), Boot: b,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	return c
}

// gossipAddr is the ip:port a cluster's peers reach it at.
func gossipAddr(c *Cluster) string { return c.enrolSrv.GossipAddr }

// enrolCluster enrols a new node with member and joins it to the gossip ring.
func enrolCluster(t *testing.T, dir string, member *Cluster, name string, opts ...func(*Config)) *Cluster {
	t.Helper()
	token, err := member.Invite(time.Minute, 1)
	require.NoError(t, err)
	b, err := Load(dir, name)
	require.NoError(t, err)
	w, memberID, err := Enrol(context.Background(), gossipAddr(member), token, b.Identity, name)
	require.NoError(t, err)
	require.Equal(t, member.Identity(), memberID)
	b.Enrol(w.Root, w.Records, w.OverlayNet)
	cfg := Config{
		StateDir: dir, StateName: name, BindAddr: loopback, AdvertiseAddr: loopback, OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, name, b), Boot: b,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, c.Join([]string{w.GossipAddr}))
	return c
}

// Peers are remembered by address alone; a restarted node rejoins them on the
// cluster port, which is the one it was started with, not memberlist's default.
// The local profile matters here: a node that left is normally let back in as
// soon as it refutes the death gossiped at it, but a lost packet leaves it
// waiting for the dead record to be reaped, which the WAN profile puts a
// minute away and this one fifteen seconds.
func Test_Cluster_Join_rememberedPeers(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()

	// b shares a's port on another loopback address, as real nodes share the cluster port
	other := secondLoopback(t)
	samePort := func(cfg *Config) { cfg.BindAddr, cfg.AdvertiseAddr, cfg.BindPort = other, other, a.port }
	b := enrolCluster(t, dir, a, "b", samePort, fastMemberlist)
	waitMembers(t, b.Members(), 1) // a is now remembered
	waitMembers(t, chA, 1)
	b.Leave()
	waitMembers(t, chA, 0)

	// b restarts from its state: no addresses given, only the remembered a
	boot, err := Load(dir, "b")
	require.NoError(t, err)
	require.Len(t, boot.Peers, 1)
	require.True(t, boot.Set().Valid(boot.Identity.Public()), "and it still knows it is a member")
	cfg := Config{StateDir: dir, StateName: "b", OverlayNet: testOverlay, LocalNode: testNodeFor(t, "b", boot), Boot: boot}
	samePort(&cfg)
	fastMemberlist(&cfg)
	b, err = New(cfg)
	require.NoError(t, err)
	defer b.Leave()
	// Wait for the first snapshot before joining: it means the watch has run,
	// and with it anything it does to the peers the join is about to use.
	require.Empty(t, waitMembers(t, b.Members(), 0))
	require.NoError(t, b.Join(nil))
	assert.Equal(t, "b", waitMembers(t, chA, 1)[0].Name)
}

// The cluster keeps the network it allocates addresses in, for the root and
// for a node the welcome told, so neither needs a setting of its own to
// restart.
func Test_Cluster_persistsOverlayNet(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	defer b.Leave()

	for _, name := range []string{"a", "b"} {
		boot, err := Load(dir, name)
		require.NoError(t, err)
		assert.Equal(t, testOverlay, boot.OverlayNet, "%s", name)
	}
}

// A member listening on its own port is remembered with it, so a restart
// reaches it there rather than on the port this node happens to use.
// The local profile is for the same reason as in the test above: a node that
// left has to outlive its own dead record when the refute goes astray.
func Test_Cluster_Join_rememberedPeers_ownPort(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist) // BindPort 0: a and b end up on different ports
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	require.NotEqual(t, a.port, b.port, "the test needs two ports")
	waitMembers(t, b.Members(), 1)
	waitMembers(t, chA, 1)
	b.Leave()
	waitMembers(t, chA, 0)

	boot, err := Load(dir, "b")
	require.NoError(t, err)
	require.Len(t, boot.Peers, 1)
	assert.Equal(t, uint16(a.port), boot.Peers[0].Port, "a's own port was remembered")

	// b restarts from its state alone, on a port of its own again
	b, err = New(Config{StateDir: dir, StateName: "b", BindAddr: loopback, AdvertiseAddr: loopback,
		OverlayNet: testOverlay, LocalNode: testNodeFor(t, "b", boot), Boot: boot,
		Memberlist: memberlist.DefaultLocalConfig})
	require.NoError(t, err)
	defer b.Leave()
	require.Empty(t, waitMembers(t, b.Members(), 0), "the watch has run, as in the test above")
	require.NoError(t, b.Join(nil))
	assert.Equal(t, "b", waitMembers(t, chA, 1)[0].Name)
}

// secondLoopback is a loopback address other than 127.0.0.1. Linux answers to
// all of 127.0.0.0/8; macOS configures only 127.0.0.1 unless an alias is added
// (ifconfig lo0 alias 127.0.0.2), so the test skips there.
func secondLoopback(t *testing.T) netip.Addr {
	t.Helper()
	addr := netip.MustParseAddr("127.0.0.2")
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: addr.AsSlice()})
	if err != nil {
		t.Skipf("no second loopback address: %v", err)
	}
	_ = l.Close()
	return addr
}

func waitMembers(t *testing.T, ch <-chan []overlay.Node, want int) []overlay.Node {
	t.Helper()
	// Long enough for the slowest way a membership settles under the local
	// profile: a dead record reaped after fifteen seconds, then the state sync
	// fifteen seconds after that.
	deadline := time.After(60 * time.Second)
	for {
		select {
		case nodes := <-ch:
			if len(nodes) == want {
				return nodes
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %d members", want)
		}
	}
}

func drain(ch <-chan []overlay.Node) {
	go func() {
		for range ch {
		}
	}()
}

func Test_Cluster_enrolJoinLeave(t *testing.T) {
	dir := useTempStatePaths(t)

	a := rootCluster(t, dir, "a")
	defer a.Leave()
	chA := a.Members()

	b := enrolCluster(t, dir, a, "b")
	drain(b.Members())

	members := waitMembers(t, chA, 1)
	assert.Equal(t, "b", members[0].Name)
	assert.Equal(t, "10.0.0.2", members[0].OverlayAddr.String())
	assert.Equal(t, testKey, members[0].PubKey)
	assert.Equal(t, b.Identity(), members[0].Identity)
	assert.True(t, a.Trust().Valid(b.Identity()))
	assert.True(t, b.Trust().Valid(a.Identity()))

	b.Leave()
	waitMembers(t, chA, 0)

	// both persisted enough to restart unattended
	for _, name := range []string{"a", "b"} {
		st, err := loadState(statePath(dir, name))
		require.NoError(t, err, name)
		require.NotNil(t, st.Root, name)
		assert.Equal(t, a.Identity(), *st.Root, name)
		held, lerr := Load(dir, name)
		require.NoError(t, lerr, name)
		assert.True(t, held.Set().Valid(a.Identity()), name)
		assert.True(t, held.Set().Valid(b.Identity()), name)
	}
	boot, err := Load(dir, "b")
	require.NoError(t, err)
	assert.True(t, boot.Enrolled())
	assert.Equal(t, b.Identity(), boot.Identity.Public())
}

func Test_Cluster_rejectsUnenrolled(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	// a node rooted elsewhere knows a's address and identity but is not a member of a's cluster
	c := rootCluster(t, dir, "c")
	defer c.Leave()
	err := c.Join([]string{gossipAddr(a)})
	require.Error(t, err)
	assert.Equal(t, 1, a.ml.Load().NumMembers(), "a must not have admitted c")
}

func Test_Cluster_revocation(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	defer b.Leave()
	chB := b.Members()
	waitMembers(t, chA, 1)
	waitMembers(t, chB, 1)

	_, err := a.Revoke(b.Identity(), nil)
	require.NoError(t, err)
	waitMembers(t, chA, 0)
	assert.False(t, a.Trust().Valid(b.Identity()))
	// a no longer talks to b at all, so b sees a fail and loses its peer
	waitMembers(t, chB, 0)
}

// Once the cluster has agreed a membership, a node stands on that list rather
// than on the record that admitted it, so revoking the node that enrolled it no
// longer takes it out. That is what a checkpoint is worth here: before one, b
// is a member only through a.
func Test_Cluster_Revoke_doesNotUnseatAnAgreedMember(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	defer b.Leave()
	waitMembers(t, a.Members(), 1)
	waitMembers(t, b.Members(), 1)

	// both nodes state the membership, so it is agreed rather than derived
	require.Eventually(t, func() bool {
		a.attest()
		b.attest()
		return b.Trust().Depth() > 0
	}, 5*time.Second, 50*time.Millisecond, "the two of them agree what the membership is")

	withdrawn, err := b.Revoke(a.Identity(), nil)
	require.NoError(t, err)
	assert.Empty(t, withdrawn, "a admitted b, but b stands on the agreed membership now")
	assert.False(t, b.Trust().Valid(a.Identity()))
	assert.True(t, b.Trust().Valid(b.Identity()))
}

// A leaving node revokes itself and hands the record to the members directly,
// so the cluster stops trusting it even though it stops straight afterwards.
func Test_Cluster_RevokeSelf(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	defer b.Leave()
	waitMembers(t, chA, 1)
	waitMembers(t, b.Members(), 1)

	told, err := b.RevokeSelf()
	require.NoError(t, err)
	assert.Equal(t, 1, told)
	assert.False(t, b.Trust().Valid(b.Identity()))
	waitMembers(t, chA, 0)
	assert.False(t, a.Trust().Valid(b.Identity()), "a was handed the revocation")
}

// The root anchors every admission, so it cannot revoke itself.
func Test_Cluster_RevokeSelf_root(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	_, err := a.RevokeSelf()
	require.NoError(t, err, "the root may leave its own cluster")
	assert.False(t, a.Trust().Valid(a.Identity()))
}

func Test_Cluster_recordsSpreadTransitively(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	defer b.Leave()
	chB := b.Members()
	waitMembers(t, chA, 1)
	waitMembers(t, chB, 1)

	// c is enrolled by b, not by the root, and joins via b; a must still accept it
	c := enrolCluster(t, dir, b, "c", fastMemberlist)
	defer c.Leave()
	drain(c.Members())
	members := waitMembers(t, chA, 2)
	names := []string{members[0].Name, members[1].Name}
	assert.ElementsMatch(t, []string{"b", "c"}, names)
	assert.True(t, a.Trust().Valid(c.Identity()))
}

func Test_New_badBindAddr(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a", testOverlay, trust.QuorumMajority)
	bad := netip.MustParseAddr("192.0.2.1") // TEST-NET, not a local address
	_, err = New(Config{StateDir: dir, StateName: "a", BindAddr: bad, AdvertiseAddr: bad, BindPort: 0, OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, "a", b), Boot: b})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gossip transport")
}

// The local node must claim the overlay address its admission assigns, and
// that address must fit the overlay net; both are checked before anything binds.
func Test_New_overlayAddressMismatch(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a", testOverlay, trust.QuorumMajority)
	node := testNodeFor(t, "a", b)
	node.OverlayAddr = netip.MustParseAddr("10.0.0.9")
	_, err = New(Config{StateDir: dir, StateName: "a", BindAddr: loopback, AdvertiseAddr: loopback, OverlayNet: testOverlay, LocalNode: node, Boot: b})
	assert.ErrorContains(t, err, "is not the assigned 10.0.0.1")

	_, err = New(Config{StateDir: dir, StateName: "a", BindAddr: loopback, AdvertiseAddr: loopback, OverlayNet: netip.MustParsePrefix("10.0.0.0/31"), LocalNode: testNodeFor(t, "a", b), Boot: b})
	assert.ErrorContains(t, err, "does not fit")
}

// memberlist refusing the configuration is reported, and the transport it was
// handed is shut down: the same port binds again at once.
func Test_New_badAdvertiseAddr(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a", testOverlay, trust.QuorumMajority)
	_, err = New(Config{StateDir: dir, StateName: "a", BindAddr: loopback, OverlayNet: testOverlay, LocalNode: testNodeFor(t, "a", b), Boot: b})
	assert.ErrorContains(t, err, "creating memberlist")
}

func Test_New_notAMember(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.Root = testIdentity(t).Public() // pinned to a root that never admitted us
	_, err = New(Config{StateDir: dir, StateName: "a", OverlayNet: testOverlay, LocalNode: &overlay.Node{Name: "a"}, Boot: b})
	assert.ErrorContains(t, err, "not a member")
	_, err = New(Config{StateDir: dir, StateName: "a", LocalNode: &overlay.Node{Name: "a"}})
	assert.ErrorContains(t, err, "bootstrap, local node and overlay network are required")
	_, err = New(Config{StateDir: dir, StateName: "a", LocalNode: &overlay.Node{Name: "a"}, Boot: b})
	assert.ErrorContains(t, err, "overlay network are required", "every cluster allocates addresses somewhere")
}

func Test_Cluster_Leave_closesMembers(t *testing.T) {
	dir := useTempStatePaths(t)
	c := rootCluster(t, dir, "a")
	ch := c.Members()
	second := c.Members()
	for _, sub := range []<-chan []overlay.Node{ch, second} {
		select {
		case peers := <-sub:
			assert.Empty(t, peers, "every subscriber gets a first snapshot")
		case <-time.After(5 * time.Second):
			t.Fatal("no first snapshot")
		}
	}
	// second stops reading; every change from here on lands in its one slot
	c.signalChanged()
	require.Eventually(t, func() bool { return len(second) == 1 }, 5*time.Second, 10*time.Millisecond, "snapshot buffered")
	c.signalChanged()
	c.signalChanged()

	c.Leave()
	c.Leave() // idempotent

	// what is still buffered is delivered, then every subscriber's channel is closed
	received := map[<-chan []overlay.Node]int{}
	for _, sub := range []<-chan []overlay.Node{ch, second} {
		deadline := time.After(5 * time.Second)
		for closed := false; !closed; {
			select {
			case _, ok := <-sub:
				closed = !ok
				if ok {
					received[sub]++
				}
			case <-deadline:
				t.Fatal("Members channel not closed after Leave")
			}
		}
	}
	assert.Equal(t, 1, received[second], "a subscriber that fell behind gets the latest snapshot, not every one")

	// a subscriber that arrives after Leave is not left waiting
	_, ok := <-c.Members()
	assert.False(t, ok, "Members after Leave is a closed channel")
}

func Test_Cluster_detectsFailedNode(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	drain(b.Members())
	waitMembers(t, chA, 1)

	// crash b without leaving; a must eventually mark it dead
	require.NoError(t, b.ml.Load().Shutdown())
	close(b.done)
	b.routines.Wait()
	waitMembers(t, chA, 0)
}

// Enrol against nothing fails with the address in the error.
func Test_Enrol_unreachable(t *testing.T) {
	id := testIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := Enrol(ctx, "not an address", "token", id, "j")
	assert.Error(t, err)
	_, _, err = Enrol(ctx, "127.0.0.1:1", "token", id, "j")
	assert.ErrorContains(t, err, "connecting to 127.0.0.1:1")
}

// The whole of enrolment and gossip works over IPv6.
func Test_Cluster_ipv6(t *testing.T) {
	v6 := netip.MustParseAddr("::1")
	if l, err := net.ListenUDP("udp", &net.UDPAddr{IP: v6.AsSlice()}); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	} else {
		_ = l.Close()
	}
	onV6 := func(cfg *Config) { cfg.BindAddr, cfg.AdvertiseAddr = v6, v6 }
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", onV6)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", onV6)
	defer b.Leave()
	drain(b.Members())
	members := waitMembers(t, chA, 1)
	assert.Equal(t, "b", members[0].Name)
	assert.Equal(t, v6, members[0].Addr)
}

// A node that has restarted but not yet joined anybody must not write its
// remembered peers away: they are the only way back, and an agent stopped in
// that window would come up with nothing to try.
func Test_Cluster_keepsRememberedPeersUntilItHasSome(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	waitMembers(t, b.Members(), 1)
	b.Leave()

	boot, err := Load(dir, "b")
	require.NoError(t, err)
	require.Len(t, boot.Peers, 1)

	// b restarts and does not join: the first snapshot is empty, and the state
	// it saves must still name a
	b, err = New(Config{StateDir: dir, StateName: "b", BindAddr: loopback, AdvertiseAddr: loopback,
		OverlayNet: testOverlay, LocalNode: testNodeFor(t, "b", boot), Boot: boot,
		Memberlist: memberlist.DefaultLocalConfig})
	require.NoError(t, err)
	defer b.Leave()
	require.Empty(t, waitMembers(t, b.Members(), 0), "not joined: no peers yet")

	again, err := Load(dir, "b")
	require.NoError(t, err)
	assert.Len(t, again.Peers, 1, "the peer it remembers is still on disk")
}

// Once a node has seen the membership, an empty one is recorded: a cluster
// that has shrunk to this node alone starts up without chasing what has gone.
func Test_Cluster_forgetsPeersOnceItHasSeenSome(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	waitMembers(t, chA, 1)
	b.Leave()
	waitMembers(t, chA, 0)

	boot, err := Load(dir, "a")
	require.NoError(t, err)
	assert.Empty(t, boot.Peers, "b left, and a is alone again")
}
