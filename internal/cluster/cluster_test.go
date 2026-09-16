package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
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
	adm := trust.Admit(a.id, j.Public(), "j", 2, time.Now())
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

	rootRev := trust.Revoke(j, a.Identity(), nil, time.Now().Add(time.Minute)) // after j's own admission
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rootRev}))
	assert.False(t, a.Trust().Valid(a.Identity()), "a member may revoke the root, which is a peer like any other")
	assert.True(t, a.Trust().Valid(j.Public()), "the revoker keeps its own membership")

	// the root is out, so what it signs that its revocation did not keep
	// carries no weight, however the record is dated
	rev := trust.Revoke(a.id, j.Public(), nil, time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rev}))
	assert.True(t, a.Trust().Valid(j.Public()), "a revoked member cannot revoke the member that revoked it")
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16), "the record is new, so it still spreads")
}

// A record is taken on its signature alone, so a member can hand this node one
// signed by a key the cluster knows nothing about. It changes no answer here,
// and what is logged says so: without that check, anyone who can generate a key
// could have every node in the cluster report that the root had been revoked.
func Test_Cluster_NotifyMsg_saysWhatARecordDidRatherThanWhatItSays(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(old)

	stranger := testIdentity(t)
	rev := trust.Revoke(stranger, a.Identity(), nil, time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rev}))
	require.True(t, a.Trust().Valid(a.Identity()), "the stranger is no member, so its record puts nobody out")
	assert.Empty(t, log.String(), "and nothing claims the root was revoked")

	adm := trust.Admit(stranger, testIdentity(t).Public(), "ghost", 9, time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.False(t, a.Trust().Valid(adm.Identity), "the same holds of an admission it signs")

	// a revocation that does put a member out is still reported
	j := testIdentity(t)
	_, _, err := a.admit(j.Public(), "j")
	require.NoError(t, err)
	out := trust.Revoke(a.id, j.Public(), nil, time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &out}))
	require.False(t, a.Trust().Valid(j.Public()))
	assert.Contains(t, log.String(), "node revoked")
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
	adm := trust.Admit(a.id, k.Public(), "k", 3, time.Now())
	remote, err := json.Marshal(trust.Records{Admissions: []trust.Admission{adm}})
	require.NoError(t, err)
	a.MergeRemoteState(remote, false)
	assert.True(t, a.Trust().Valid(k.Public()))
	a.MergeRemoteState(remote, false) // nothing new: no save, no signal

	// What was merged is persisted by the watch loop rather than here, so a
	// burst of records costs one write instead of one each. A cluster of one
	// agrees with itself, so the watch also states the membership and trims
	// what led to it: the record is gone and the checkpoint carries the answer.
	require.Eventually(t, func() bool {
		b, lerr := Load(dir, "a")
		return lerr == nil && b.Set().Valid(k.Public())
	}, 5*time.Second, 10*time.Millisecond, "the watch loop persists what was merged")
	boot, err := Load(dir, "a")
	require.NoError(t, err)
	assert.NotEmpty(t, boot.Records.Checkpoints, "and states it as a checkpoint")
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

// Nothing admits a revoked identity back, so signing for one would spend a
// number, leave the cluster carrying the record for good, and send the joiner
// away believing itself admitted while every peer refused it. It is refused at
// the door instead, and the name it held is free for the node's next identity.
func Test_Cluster_admit_refusesARevokedIdentity(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()

	j := testIdentity(t)
	_, _, err := a.admit(j.Public(), "j")
	require.NoError(t, err)
	_, err = a.Revoke(j.Public(), nil)
	require.NoError(t, err)

	records := len(a.set.Records().Admissions)
	_, _, err = a.admit(j.Public(), "j")
	assert.ErrorContains(t, err, "has been revoked")
	assert.ErrorContains(t, err, "needs a fresh")
	assert.Len(t, a.set.Records().Admissions, records, "and no record entered the set")

	// the name it went by is nobody's now, so the host comes back under it
	fresh := testIdentity(t)
	adm, _, err := a.admit(fresh.Public(), "j")
	require.NoError(t, err)
	assert.True(t, a.Trust().Valid(fresh.Public()))
	assert.Equal(t, "j", adm.Name)
}

// The root is revoked like any other member, by itself or by a peer.
func Test_Cluster_Revoke_root(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	_, err := a.Revoke(a.Identity(), nil)
	require.NoError(t, err)
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
			go func() { defer wg.Done(); _, errs[i] = a.Revoke(id, nil) }()
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
		go func() { defer wg.Done(); _, revokeErr = a.Revoke(x.Public(), nil) }()
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
	_, err = a.Revoke(a.Identity(), nil)
	require.NoError(t, err)

	// nothing is signed for it: the record would spend a number, reach every
	// peer and do nothing, and the cluster never gets a record back
	seq := 0
	_, err = a.Revoke(x.Public(), nil)
	assert.ErrorContains(t, err, "has no effect")
	assert.True(t, a.Trust().Valid(x.Public()))
	assert.Equal(t, seq, "and no number was spent")
	for _, r := range a.set.Records().Revocations {
		assert.NotEqual(t, x.Public(), r.Identity, "and no record of it entered the set")
	}
}

// A mark keeping everything the subject signed takes out the subject alone.
// What a lower one would take out is worked out from the records and handed
// back before the record is signed, since nothing puts those members back.
func Test_Cluster_Revoke_saysWhatAMarkWithdraws(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x := testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)
	y := testIdentity(t)
	_, err = a.set.AddAdmission(trust.Admit(x, y.Public(), "y", 3, time.Now()))
	require.NoError(t, err)
	require.True(t, a.Trust().Valid(y.Public()))

	// keeping what x signed takes x alone, and y keeps its place
	withdrawn, err := a.Revoke(x.Public(), nil)
	require.NoError(t, err)
	assert.Empty(t, withdrawn)
	assert.False(t, a.Trust().Valid(x.Public()))
	assert.True(t, a.Trust().Valid(y.Public()), "y was admitted while x was still a member")
}

// A node the operator names to go with the subject keeps its place if somebody
// else admitted it too, because no mark on the subject's sequence reaches the
// other admitter's record. Signing anyway would leave the operator a revocation
// they cannot take back and a node they asked to remove still in the cluster,
// so nothing is signed and they are told which node it is.
func Test_Cluster_Revoke_refusesAMarkThatLeavesADisownedNodeStanding(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x := testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)
	y := testIdentity(t)
	_, err = a.set.AddAdmission(trust.Admit(x, y.Public(), "y", 3, time.Now()))
	require.NoError(t, err)
	// the root vouches for y as well, which no mark on x's sequence reaches
	_, err = a.set.AddAdmission(trust.Admit(a.id, y.Public(), "y", 3, time.Now()))
	require.NoError(t, err)

	seq := 0
	_, err = a.Revoke(x.Public(), []trust.PublicKey{y.Public()})
	assert.ErrorContains(t, err, "would not withdraw y")
	assert.ErrorContains(t, err, "Nothing is signed")
	assert.True(t, a.Trust().Valid(x.Public()), "so the subject is still a member too")
	assert.True(t, a.Trust().Valid(y.Public()))
	assert.Equal(t, seq, "and no number was spent")

	// the same mark without naming y is the operator's to make: y stays, and
	// they are not claiming otherwise
	withdrawn, err := a.Revoke(x.Public(), nil)
	require.NoError(t, err)
	assert.Empty(t, withdrawn)
	assert.False(t, a.Trust().Valid(x.Public()))
	assert.True(t, a.Trust().Valid(y.Public()))
}

// Every node named has to go, not just the first, and the message names each
// one that would not.
func Test_Cluster_Revoke_namesEveryDisownedNodeThatWouldStand(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x := testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)
	var disown []trust.PublicKey
	for i, name := range []string{"y", "z"} {
		other := testIdentity(t)
		// x admits it, and the root admits it too, so no mark on x reaches it
		_, err = a.set.AddAdmission(trust.Admit(x, other.Public(), name, uint64(3+i), time.Now()))
		require.NoError(t, err)
		_, err = a.set.AddAdmission(trust.Admit(a.id, other.Public(), name, uint64(3+i), time.Now()))
		require.NoError(t, err)
		disown = append(disown, other.Public())
	}

	_, err = a.Revoke(x.Public(), disown)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "y")
	assert.Contains(t, err.Error(), "z")
	assert.Contains(t, err.Error(), "each of those", "and the message reads for more than one")
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
		time.Now().Add(time.Hour))
	_, err = a.set.AddAdmission(ahead)
	require.NoError(t, err)

	_, err = a.signingTime()
	assert.ErrorContains(t, err, "behind the last record it signed")
	_, err = a.Revoke(testIdentity(t).Public(), nil)
	assert.ErrorContains(t, err, "behind the last record it signed")
	_, _, err = a.admit(testIdentity(t).Public(), "k")
	assert.ErrorContains(t, err, "behind the last record it signed")
}

// A node that advertises more networks than its metadata can hold does not
// start: it would join the ring, and every peer would ignore it for metadata
// it could not read.
func Test_New_refusesMetadataThatDoesNotFit(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a", testOverlay, trust.QuorumMajority)
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
	b.InitRoot("a", testOverlay, trust.QuorumMajority)
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

// swapLogger sends the default logger to buf until the returned func restores it.
func swapLogger(buf *bytes.Buffer) func() {
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	return func() { slog.SetDefault(old) }
}

// A hand-out that could not reach every member names the ones it missed, so the
// operator knows which to look at rather than being given a count.
func Test_Cluster_reportHandOut_namesTheMembersThatMissedIt(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()

	var log bytes.Buffer
	defer swapLogger(&log)()

	a.reportHandOut("revocation", 3, nil)
	assert.Empty(t, log.String(), "a hand-out everyone took says nothing")

	a.reportHandOut("revocation", 3, []string{"c", "b"})
	assert.Contains(t, log.String(), "could not hand the revocation to every member")
	assert.Contains(t, log.String(), "next full state sync")
	assert.Contains(t, log.String(), `missed="[c b]"`, "the members are named")
	assert.Contains(t, log.String(), "told=3")
}

// A node that is stopping will not sync again, so it says so rather than
// promising the record will arrive on its own.
func Test_Cluster_reportHandOut_whenStopping(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	a.Leave()

	var log bytes.Buffer
	defer swapLogger(&log)()

	a.reportHandOut("revocation", 0, []string{"b"})
	assert.Contains(t, log.String(), "stopped before the revocation reached every member")
	assert.Contains(t, log.String(), "run the same command on another member")
}

// Leave closes done under the lock track takes, so a hand-out starting as the
// cluster goes down either joins the wait group before the wait or not at all.
func Test_Cluster_distribute_afterLeaveStartsNothing(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	a.Leave()

	rev := trust.Revoke(a.id, testIdentity(t).Public(), nil, time.Now())

	assert.False(t, a.track(), "nothing is added to the wait group once Leave has waited")
	a.distribute(recordMsg{Revocation: &rev}) // must not panic on the wait group
}

// The size the queue can carry is what memberlist leaves after its own framing.
func Test_maxBroadcast(t *testing.T) {
	assert.Equal(t, 1095, maxBroadcast)
	assert.Less(t, maxBroadcast, maxDatagram)
}

// A record a peer pushes in its state sync is refused the same way one it
// broadcasts is, and now says so: the state sync carries the whole set, so a
// peer offering a bad record offers it again every minute.
func Test_Cluster_MergeRemoteState_reportsWhatItWillNotTake(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()

	var log bytes.Buffer
	defer swapLogger(&log)()

	forged := trust.Admit(testIdentity(t), testIdentity(t).Public(), "j", 2, time.Now())
	forged.Signature[0] ^= 1
	state, err := json.Marshal(trust.Records{Admissions: []trust.Admission{forged}})
	require.NoError(t, err)

	a.MergeRemoteState(state, false)
	assert.Contains(t, log.String(), "will not take", "a forged record in a state sync is reported")
	assert.Contains(t, log.String(), "refused=1")
	assert.Contains(t, log.String(), "signature")

	// re-offered at every sync, it is counted rather than written out each time
	for range 20 {
		a.MergeRemoteState(state, false)
	}
	assert.Less(t, strings.Count(log.String(), "will not take"), 4, "counted, not one line each")
}

// A state sync this node takes in full says nothing: the ordinary case is quiet.
func Test_Cluster_MergeRemoteState_quietWhenEverythingVerifies(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()

	var log bytes.Buffer
	defer swapLogger(&log)()

	state, err := json.Marshal(a.Trust().Records())
	require.NoError(t, err)
	a.MergeRemoteState(state, false)
	assert.Empty(t, log.String())
}

// memberlist hands its event delegate a pointer into its own table of nodes
// and goes on writing through it, so what the cluster keeps has to be a copy
// taken while the delegate call is running. Writing through the node
// afterwards must change nothing the cluster holds.
func Test_Cluster_noteMember_copiesTheNode(t *testing.T) {
	c := &Cluster{events: make(chan memberEvent, 4), members: map[string]member{}}
	meta := []byte("first")
	n := &memberlist.Node{Name: "a", Addr: net.IP{192, 0, 2, 7}, Port: 7946, Meta: meta}
	c.noteMember(memberlist.NodeJoin, n)

	// memberlist replaces a node's metadata with a fresh slice rather than
	// writing over the old one, so the copy is tested both ways
	n.Addr, n.Port = net.IP{198, 51, 100, 9}, 9999
	meta[0] = 'X'
	n.Meta = []byte("second")
	held := c.currentMembers()["a"]
	assert.Equal(t, "192.0.2.7", held.addr.String())
	assert.Equal(t, uint16(7946), held.port)
	assert.Equal(t, []byte("first"), held.meta)

	// and the cluster's own map is not the one a caller walks
	current := c.currentMembers()
	delete(current, "a")
	assert.Contains(t, c.currentMembers(), "a")

	c.noteMember(memberlist.NodeUpdate, n)
	held = c.currentMembers()["a"]
	assert.Equal(t, []byte("second"), held.meta, "an update replaces what is held")

	c.noteMember(memberlist.NodeLeave, n)
	assert.NotContains(t, c.currentMembers(), "a", "a node that left is dropped")

	assert.Len(t, c.events, 3, "each change is passed on to be logged")
}
