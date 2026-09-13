package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests of the memberlist delegate on a one-node cluster; the gossip
// paths between nodes are covered by the integration tests.

func recordJSON(t *testing.T, m recordMsg) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

// drainBroadcasts empties the transmit queue, which hands out each record a few times.
func drainBroadcasts(c *Cluster) {
	for i := 0; i < 20 && len(c.GetBroadcasts(0, 1<<16)) > 0; i++ {
	}
}

func Test_Cluster_NotifyMsg(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	a.NotifyMsg([]byte("garbage")) // ignored
	a.NotifyMsg([]byte("{}"))      // neither record kind: ignored

	j := testIdentity(t)
	adm := trust.Admit(a.id, j.Public(), "j", 2, a.set.NextSeq(a.Identity()), time.Now())
	tampered := adm
	tampered.Name = "x"
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &tampered}))
	assert.False(t, a.Trust().Valid(j.Public()), "a record with a bad signature is rejected")

	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.True(t, a.Trust().Valid(j.Public()))
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16), "a record that changed the set is re-broadcast")
	drainBroadcasts(a)
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.Empty(t, a.GetBroadcasts(0, 1<<16), "a record already known is not")

	rootRev := trust.Revoke(j, a.Identity(), 1, a.set.SignedBy(a.Identity()), time.Now().Add(time.Minute)) // after j's own admission
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rootRev}))
	assert.False(t, a.Trust().Valid(a.Identity()), "a member may revoke the root, which is a peer like any other")
	assert.True(t, a.Trust().Valid(j.Public()), "the revoker keeps its own membership")

	// the root is out, so what it signs that its revocation did not keep
	// carries no weight, however the record is dated
	rev := trust.Revoke(a.id, j.Public(), a.set.NextSeq(a.Identity()), a.set.SignedBy(j.Public()), time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rev}))
	assert.True(t, a.Trust().Valid(j.Public()), "a revoked member cannot revoke the member that revoked it")
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16), "the record is new, so it still spreads")
}

func Test_Cluster_state_pushPull(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	var rs trust.Records
	require.NoError(t, json.Unmarshal(a.LocalState(true), &rs))
	require.Len(t, rs.Admissions, 1)
	assert.Equal(t, a.Identity(), rs.Admissions[0].Identity)

	a.MergeRemoteState([]byte("garbage"), false) // ignored
	k := testIdentity(t)
	adm := trust.Admit(a.id, k.Public(), "k", 3, a.set.NextSeq(a.Identity()), time.Now())
	remote, err := json.Marshal(trust.Records{Admissions: []trust.Admission{adm}})
	require.NoError(t, err)
	a.MergeRemoteState(remote, false)
	assert.True(t, a.Trust().Valid(k.Public()))
	a.MergeRemoteState(remote, false) // nothing new: no save, no signal

	// The merged record is persisted by the watch loop rather than here, so a
	// burst of records costs one write instead of one each.
	require.Eventually(t, func() bool {
		b, lerr := Load(dir, "a")
		return lerr == nil && len(b.Records.Admissions) == 2
	}, 5*time.Second, 10*time.Millisecond, "the watch loop persists what was merged")
}

func Test_Cluster_NodeMeta_and_Conflict(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()

	assert.Nil(t, a.NodeMeta(1), "metadata that does not fit is not sent")
	assert.NotEmpty(t, a.NodeMeta(memberlist.MetaMaxSize))
	a.NotifyConflict(&memberlist.Node{Name: "a"}, &memberlist.Node{Name: "a"}) // only logs
}

func Test_Cluster_Join(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()

	require.NoError(t, a.Join(nil), "nothing to join and nothing remembered: a cluster of one")
	err := a.Join([]string{"127.0.0.1:1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "joining cluster")
}

func Test_WithPort(t *testing.T) {
	got := WithPort([]string{"10.0.0.1", "10.0.0.1:1", "fd00::1", "[fd00::1]", "[fd00::1]:1", "host", "host:2"}, 7947)
	assert.Equal(t, []string{"10.0.0.1:7947", "10.0.0.1:1", "[fd00::1]:7947", "[fd00::1]:7947", "[fd00::1]:1", "host:7947", "host:2"}, got)
	assert.Empty(t, WithPort(nil, 1))
}

func Test_recordBroadcast(t *testing.T) {
	b := recordBroadcast{name: "adm:x", msg: []byte("m")}
	assert.Equal(t, "adm:x", b.Name())
	assert.Equal(t, []byte("m"), b.Message())
	assert.False(t, b.Invalidates(recordBroadcast{name: "adm:x"}), "the queue de-duplicates by name; records never invalidate each other")
	b.Finished()
}

func Test_Cluster_admit_refusesTakenName(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()

	j := testIdentity(t)
	_, _, err := a.admit(j.Public(), "a")
	assert.ErrorContains(t, err, `named "a" already exists`)
	adm, _, err := a.admit(j.Public(), "j")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), adm.Host)
	// the same identity may enrol again under its name
	again, _, err := a.admit(j.Public(), "j")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), again.Host, "its slot is reused")
	k := testIdentity(t)
	_, _, err = a.admit(k.Public(), "j")
	assert.ErrorContains(t, err, "already exists")
}

// The root is revoked like any other member, by itself or by a peer.
func Test_Cluster_Revoke_root(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	require.NoError(t, a.Revoke(a.Identity()))
	assert.False(t, a.Trust().Valid(a.Identity()))
}

// Everything this node signs is serialised, so two records of its own never
// take one sequence number, which would void both of them.
func Test_Cluster_signsOneRecordAtATime(t *testing.T) {
	t.Run("two revocations at once", func(t *testing.T) {
		dir := useTempStatePaths(t)
		a := rootCluster(t, dir, "a")
		defer a.Leave()
		x, y := testIdentity(t), testIdentity(t)
		for name, id := range map[string]trust.PublicKey{"x": x.Public(), "y": y.Public()} {
			_, _, err := a.admit(id, name)
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, id := range []trust.PublicKey{x.Public(), y.Public()} {
			wg.Add(1)
			go func() { defer wg.Done(); errs[i] = a.Revoke(id) }()
		}
		wg.Wait()

		require.NoError(t, errors.Join(errs...))
		assert.False(t, a.Trust().Valid(x.Public()), "the first revocation took effect")
		assert.False(t, a.Trust().Valid(y.Public()), "and so did the second")
	})

	t.Run("a revocation while a node enrols", func(t *testing.T) {
		dir := useTempStatePaths(t)
		a := rootCluster(t, dir, "a")
		defer a.Leave()
		x := testIdentity(t)
		_, _, err := a.admit(x.Public(), "x")
		require.NoError(t, err)

		j := testIdentity(t)
		var wg sync.WaitGroup
		var admitErr, revokeErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, _, admitErr = a.admit(j.Public(), "j") }()
		go func() { defer wg.Done(); revokeErr = a.Revoke(x.Public()) }()
		wg.Wait()

		require.NoError(t, errors.Join(admitErr, revokeErr))
		assert.True(t, a.Trust().Valid(j.Public()), "the joiner was admitted for good")
		assert.False(t, a.Trust().Valid(x.Public()), "and the revocation still took effect")
	})
}

// A node the cluster no longer trusts cannot revoke anyone, and is told so
// rather than left believing it removed a member.
func Test_Cluster_Revoke_byARevokedNode(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x := testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)
	require.NoError(t, a.Revoke(a.Identity()))

	assert.ErrorContains(t, a.Revoke(x.Public()), "has no effect")
	assert.True(t, a.Trust().Valid(x.Public()))
}

// A node that advertises more networks than its metadata can hold does not
// start: it would join the ring, and every peer would ignore it for metadata
// it could not read.
func Test_New_refusesMetadataThatDoesNotFit(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a")
	node := &overlay.Node{Name: "a"}
	node.OverlayAddr, node.PubKey = netip.MustParseAddr("10.0.0.1"), testKey
	for i := range 40 {
		node.AllowedIPs = append(node.AllowedIPs, netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, byte(i), 0}), 24))
	}
	cfg := Config{StateDir: dir, StateName: "a", BindAddr: loopback, AdvertiseAddr: loopback,
		OverlayNet: testOverlay, LocalNode: node, Boot: b}

	_, err = New(cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not fit node metadata")
	assert.ErrorContains(t, err, "40 advertised networks")

	// and the same node within the limit starts and gossips what it advertises
	node.AllowedIPs = node.AllowedIPs[:10]
	c, err := New(cfg)
	require.NoError(t, err)
	defer c.Leave()
	assert.NotEmpty(t, c.NodeMeta(memberlist.MetaMaxSize))
}

// A cluster whose overlay net is full refuses the next joiner, naming the net.
func Test_Cluster_admit_overlayFull(t *testing.T) {
	dir := useTempStatePaths(t)
	small := netip.MustParsePrefix("10.0.0.0/30") // slots 1 and 2
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a")
	node := &overlay.Node{Name: "a"}
	node.OverlayAddr, node.PubKey = netip.MustParseAddr("10.0.0.1"), testKey
	a, err := New(Config{StateDir: dir, StateName: "a", BindAddr: loopback, AdvertiseAddr: loopback, OverlayNet: small, LocalNode: node, Boot: b})
	require.NoError(t, err)
	defer a.Leave()

	j, k := testIdentity(t), testIdentity(t)
	adm, _, err := a.admit(j.Public(), "j")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), adm.Host)
	_, _, err = a.admit(k.Public(), "k")
	require.ErrorIs(t, err, trust.ErrOverlayFull)
	assert.ErrorContains(t, err, "10.0.0.0/30")
}

// The rejoin tests run on the local profile so that they finish in seconds.
// This is the guard on the one the agent actually runs with: a node that left
// and came straight back is normally readmitted as soon as it refutes the
// death gossiped at it, and only if that packet is lost does it wait for its
// own dead record to be reaped, which is GossipToTheDeadTime away. Changing
// the profile changes that worst case, and the documentation that goes with
// it, so it is not something to do by accident.
func Test_profile_rejoinWindow(t *testing.T) {
	wan := profile(Config{})()
	assert.Equal(t, 60*time.Second, wan.GossipToTheDeadTime,
		"a node that leaves and restarts can be kept out this long if its refute is lost")
	assert.Equal(t, 5*time.Second, wan.ProbeInterval, "the WAN profile, not the LAN or local one")

	local := profile(Config{Memberlist: memberlist.DefaultLocalConfig})()
	assert.Equal(t, 15*time.Second, local.GossipToTheDeadTime, "what the rejoin tests wait for instead")
}

// A node whose clock is behind what it already signed refuses to sign rather
// than backdate: the date is what the signer asserts, so the clock is what has
// to be fixed.
func Test_Cluster_signingTime_refusesABackwardClock(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	_, err := a.signingTime()
	require.NoError(t, err)

	// as if the clock had jumped back an hour after this record was signed
	ahead := trust.Admit(a.id, testIdentity(t).Public(), "j", 2,
		a.set.NextSeq(a.Identity()), time.Now().Add(time.Hour))
	_, err = a.set.AddAdmission(ahead)
	require.NoError(t, err)

	_, err = a.signingTime()
	assert.ErrorContains(t, err, "behind the last record it signed")
	assert.ErrorContains(t, a.Revoke(testIdentity(t).Public()), "behind the last record it signed")
	_, _, err = a.admit(testIdentity(t).Public(), "k")
	assert.ErrorContains(t, err, "behind the last record it signed")
}

func Test_Cluster_Prune(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	// a member that enrols and is then revoked leaves two records behind
	j := testIdentity(t)
	adm := trust.Admit(a.id, j.Public(), "j", 2, a.set.NextSeq(a.Identity()), time.Now())
	_, err := a.set.AddAdmission(adm)
	require.NoError(t, err)
	require.NoError(t, a.Revoke(j.Public()))
	drainBroadcasts(a)

	dry, err := a.Prune(true)
	require.NoError(t, err)
	assert.Equal(t, []trust.PublicKey{j.Public()}, dry.Identities)
	assert.Equal(t, dry.Before, dry.After, "a dry run removes nothing")
	assert.Empty(t, a.GetBroadcasts(0, 1<<16), "and signs nothing")

	res, err := a.Prune(false)
	require.NoError(t, err)
	assert.Equal(t, []trust.PublicKey{j.Public()}, res.Identities)
	// one admission goes, the revocation stays and the prune itself is a
	// record, so pruning a single node leaves the count where it was: a prune
	// pays for itself from the second identity on
	assert.Equal(t, res.Before, res.After)
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16), "the prune goes out to the members")

	_, ok := a.Trust().Lookup(j.Public())
	assert.False(t, ok, "j's records are gone")
	assert.True(t, a.Trust().Valid(a.Identity()), "the root is untouched")

	none, err := a.Prune(false)
	require.NoError(t, err)
	assert.Empty(t, none.Identities, "nothing left to prune")
}

// One prune record covers however many identities go at once, so the count
// falls by one less than the number of admissions dropped.
func Test_Cluster_Prune_severalIdentitiesAtOnce(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	for host := uint64(2); host < 6; host++ {
		j := testIdentity(t)
		adm := trust.Admit(a.id, j.Public(), fmt.Sprintf("j%d", host), host, a.set.NextSeq(a.Identity()), time.Now())
		_, err := a.set.AddAdmission(adm)
		require.NoError(t, err)
		require.NoError(t, a.Revoke(j.Public()))
	}
	drainBroadcasts(a)

	res, err := a.Prune(false)
	require.NoError(t, err)
	assert.Len(t, res.Identities, 4)
	assert.Equal(t, res.Before-3, res.After, "four admissions go, one prune record arrives")
}

func Test_Cluster_NotifyMsg_prune(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	j := testIdentity(t)
	adm := trust.Admit(a.id, j.Public(), "j", 2, a.set.NextSeq(a.Identity()), time.Now())
	_, err := a.set.AddAdmission(adm)
	require.NoError(t, err)
	require.NoError(t, a.Revoke(j.Public()))
	drainBroadcasts(a)

	// a prune signed by a member the cluster no longer trusts removes nothing
	stranger := testIdentity(t)
	p := trust.SignPrune(stranger, []trust.PublicKey{j.Public()}, 1, time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Prune: &p}))
	_, ok := a.Trust().Lookup(j.Public())
	assert.True(t, ok, "j's records are still there")

	tampered := p
	tampered.Seq++
	a.NotifyMsg(recordJSON(t, recordMsg{Prune: &tampered}))
	_, ok = a.Trust().Lookup(j.Public())
	assert.True(t, ok, "a record with a bad signature is rejected")

	// one signed by the root does
	good := trust.SignPrune(a.id, []trust.PublicKey{j.Public()}, a.set.NextSeq(a.Identity()), time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Prune: &good}))
	_, ok = a.Trust().Lookup(j.Public())
	assert.False(t, ok)
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16), "and is passed on")
}

// A prune reports how much of the cluster the node could see while it decided,
// so the operator running it knows whether to trust the answer.
func Test_Cluster_Prune_reportsWhatThisNodeCanSee(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	res, err := a.Prune(true)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Seen, "a cluster of one sees itself")
	assert.Equal(t, 1, res.Members)

	// two members admitted but never reachable: this node is plainly behind
	var log bytes.Buffer
	restore := swapLogger(&log)
	for i, name := range []string{"j", "k"} {
		j := testIdentity(t)
		adm := trust.Admit(a.id, j.Public(), name, uint64(i+2), a.set.NextSeq(a.Identity()), time.Now())
		_, err := a.set.AddAdmission(adm)
		require.NoError(t, err)
	}
	res, err = a.Prune(true)
	restore()
	require.NoError(t, err)
	assert.Equal(t, 1, res.Seen)
	assert.Equal(t, 3, res.Members, "the records hold three members")
	assert.Contains(t, log.String(), "can reach only some of the cluster")
}

// swapLogger sends the default logger to buf until the returned func restores it.
func swapLogger(buf *bytes.Buffer) func() {
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	return func() { slog.SetDefault(old) }
}
