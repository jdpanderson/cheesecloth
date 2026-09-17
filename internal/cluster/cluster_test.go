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

// agree states c's current membership and has each of signers attest to it, so
// that a test with identities no agent is running can reach the quorum a real
// cluster reaches by itself. The agent attests on its own as the membership
// changes, so this retries until one of the two ratifies.
func agree(t *testing.T, c *Cluster, signers ...*trust.Identity) {
	t.Helper()
	require.Eventually(t, func() bool { return propose(t, c, signers...) },
		5*time.Second, 20*time.Millisecond, "the membership is agreed")
}

// propose is one attempt at agree, which races the agent's own attestation.
func propose(t *testing.T, c *Cluster, signers ...*trust.Identity) bool {
	t.Helper()
	base, founded := c.set.Anchor()
	if !founded {
		return false
	}
	pr := c.set.Proposal()
	cp := trust.Propose(c.id, c.set.Depth()+1, base.Digest(), c.set.Quorum(), base.Confirmations, pr.Members, pr.Removed)
	for _, s := range signers {
		cp.Attestations = append(cp.Attestations, trust.Attest(s, cp.Digest()))
	}
	depth := c.set.Depth()
	if _, err := c.set.AddCheckpoint(cp); err != nil {
		return false
	}
	return c.set.Depth() > depth
}

// settle states the membership a set's records propose and has each of signers
// attest to it, so that a set built by hand reaches the agreement a running
// cluster reaches by itself. Nothing a record says takes effect before that.
func settle(t *testing.T, set *trust.Set, signers ...*trust.Identity) {
	t.Helper()
	base, ok := set.Anchor()
	require.True(t, ok, "a set with no membership has nothing to agree against")
	p := set.Proposal()
	cp := trust.Propose(signers[0], base.Depth+1, base.Digest(), base.Quorum, base.Confirmations, p.Members, p.Removed)
	for _, s := range signers[1:] {
		cp.Attestations = append(cp.Attestations, trust.Attest(s, cp.Digest()))
	}
	_, err := set.AddCheckpoint(cp)
	require.NoError(t, err)
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
	adm := trust.Admit(a.id, j.Public(), "j", 2)
	tampered := adm
	tampered.Name = "x"
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &tampered}))
	assert.False(t, a.Trust().Valid(j.Public()), "a record with a bad signature is rejected")

	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16), "a record that changed the set is re-broadcast")
	drainBroadcasts(a)
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.Empty(t, a.GetBroadcasts(0, 1<<16), "a record already known is not")

	// an admission is a proposal: the joiner is a member once the cluster has
	// agreed a membership holding it, and not before
	agree(t, a, j)
	assert.True(t, a.Trust().Valid(j.Public()))

	rootRev := trust.Revoke(j, a.Identity(), nil)
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rootRev}))
	agree(t, a, j)
	assert.False(t, a.Trust().Valid(a.Identity()), "a member may revoke the root, which is a peer like any other")
	assert.True(t, a.Trust().Valid(j.Public()), "the revoker keeps its own membership")

	// the root is out, so nothing it signs afterwards carries any weight
	rev := trust.Revoke(a.id, j.Public(), nil)
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rev}))
	assert.True(t, a.Trust().Valid(j.Public()), "a revoked member cannot revoke the member that revoked it")
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
	rev := trust.Revoke(stranger, a.Identity(), nil)
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rev}))
	require.True(t, a.Trust().Valid(a.Identity()), "the stranger is no member, so its record puts nobody out")
	assert.Empty(t, log.String(), "and nothing claims the root was revoked")

	adm := trust.Admit(stranger, testIdentity(t).Public(), "ghost", 9)
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.False(t, a.Trust().Valid(adm.Identity), "the same holds of an admission it signs")

	// a revocation that does take a member out of the membership the records
	// propose is still reported, before anything has agreed it
	j := testIdentity(t)
	_, _, err := a.admit(j.Public(), "j")
	require.NoError(t, err)
	out := trust.Revoke(a.id, j.Public(), nil)
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &out}))
	_, proposed := a.Trust().Proposal().Holds(j.Public())
	require.False(t, proposed)
	assert.Contains(t, log.String(), "node revoked")
}

func Test_Cluster_state_pushPull(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	var rs trust.Records
	require.NoError(t, json.Unmarshal(a.LocalState(true), &rs))
	require.Len(t, rs.Checkpoints, 1, "the membership goes out as what the cluster agreed, not as who admitted whom")
	require.Len(t, rs.Checkpoints[0].Members, 1)
	assert.Equal(t, a.Identity(), rs.Checkpoints[0].Members[0].Identity)

	a.MergeRemoteState([]byte("garbage"), false) // ignored
	k := testIdentity(t)
	adm := trust.Admit(a.id, k.Public(), "k", 3)
	remote, err := json.Marshal(trust.Records{Admissions: []trust.Admission{adm}})
	require.NoError(t, err)
	a.MergeRemoteState(remote, false)
	agree(t, a, k)
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

	_, _, err = a.admit(j.Public(), "j")
	assert.ErrorContains(t, err, "has been revoked")
	assert.ErrorContains(t, err, "needs a fresh")
	// the refusal comes before anything is signed, so nothing was spent on it
	_, proposed := a.Trust().Proposal().Holds(j.Public())
	assert.False(t, proposed, "and nothing proposes it as a member")

	// the name it went by is nobody's now, so the host comes back under it
	agree(t, a, j) // the cluster agrees the membership without it
	require.False(t, a.Trust().Valid(j.Public()))
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
	x := testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)

	_, err = a.Revoke(a.Identity(), nil)
	require.NoError(t, err)
	agree(t, a, x)
	assert.False(t, a.Trust().Valid(a.Identity()))
	assert.True(t, a.Trust().Valid(x.Public()), "and the member it admitted keeps its place")
}

// Everything this node signs is serialised, so two records of its own never
// contradict each other. The cluster agrees on its own here, so that what is
// being tested is the signing rather than the quorum.
func Test_Cluster_signsOneRecordAtATime(t *testing.T) {
	t.Run("two revocations at once", func(t *testing.T) {
		dir := useTempStatePaths(t)
		a := soloCluster(t, dir, "a")
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
		agree(t, a)
		assert.False(t, a.Trust().Valid(x.Public()), "the first revocation took effect")
		assert.False(t, a.Trust().Valid(y.Public()), "and so did the second")
	})

	t.Run("a revocation while a node enrols", func(t *testing.T) {
		dir := useTempStatePaths(t)
		a := soloCluster(t, dir, "a")
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
		agree(t, a)
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

	// nothing is signed for it: the record would reach every peer and do
	// nothing, and the cluster never gets a record back
	_, err = a.Revoke(x.Public(), nil)
	assert.ErrorContains(t, err, "has no effect")
	for _, r := range a.set.Records().Revocations {
		assert.NotEqual(t, x.Public(), r.Identity, "and no record of it entered the set")
	}
}

// A revocation takes its subject out and nobody else: the nodes it admitted
// were invited on purpose, and removing them is the operator's decision rather
// than an automatic consequence.
func Test_Cluster_Revoke_takesTheSubjectAlone(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x, y := testIdentity(t), testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)

	_, err = a.set.AddAdmission(trust.Admit(x, y.Public(), "y", 3))
	require.NoError(t, err)

	// only a membership the cluster has agreed on can change the membership,
	// which Test_Set_onlyAgreedMembersMayAdmit pins down without an agent
	// racing to agree it; here both are agreed before anything is revoked
	agree(t, a, x)
	require.True(t, a.Trust().Valid(y.Public()), "what x signed counts once x is agreed")
	agree(t, a, x, y)
	require.True(t, a.Trust().Valid(y.Public()))

	withdrawn, err := a.Revoke(x.Public(), nil)
	require.NoError(t, err)
	assert.Empty(t, withdrawn)
	agree(t, a, y)
	assert.False(t, a.Trust().Valid(x.Public()))
	assert.True(t, a.Trust().Valid(y.Public()), "the agreed membership names y in its own right")
}

// A revocation names the nodes that go with its subject, and they go out
// entirely. Naming reaches a node whatever else vouches for it, because the
// record says who goes rather than describing where to stop.
func Test_Cluster_Revoke_disownsByName(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x := testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)
	y := testIdentity(t)
	_, err = a.set.AddAdmission(trust.Admit(x, y.Public(), "y", 3))
	require.NoError(t, err)
	// the root vouches for y as well; naming it still takes it out
	_, err = a.set.AddAdmission(trust.Admit(a.id, y.Public(), "y", 3))
	require.NoError(t, err)
	agree(t, a, x, y)
	require.True(t, a.Trust().Valid(y.Public()))

	withdrawn, err := a.Revoke(x.Public(), []trust.PublicKey{y.Public()})
	require.NoError(t, err)
	agree(t, a, x) // an honest node attests to its own removal
	assert.False(t, a.Trust().Valid(x.Public()))
	assert.False(t, a.Trust().Valid(y.Public()), "named, so it goes")
	require.Len(t, withdrawn, 1)
	assert.Equal(t, "y", withdrawn[0].Name, "and the operator is told it went")

	// the slots they held are free again, since nothing records that they held them
	h, err := a.set.FreeHost(16)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), h)
}

// A node that advertises more networks than its metadata can hold does not
// start: it would join the ring, and every peer would ignore it for metadata
// it could not read.
func Test_New_refusesMetadataThatDoesNotFit(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a", testOverlay, trust.QuorumMajority, 0)
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
	b.InitRoot("a", testOverlay, trust.QuorumMajority, 0)
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

	rev := trust.Revoke(a.id, testIdentity(t).Public(), nil)

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

	forged := trust.Admit(testIdentity(t), testIdentity(t).Public(), "j", 2)
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

// A node whose cluster has moved out of reach says so where an operator will
// see it, and keeps saying it: the condition does not mend itself.
func Test_Cluster_saysWhenItIsTooFarBehind(t *testing.T) {
	dir := useTempStatePaths(t)
	a := soloCluster(t, dir, "a")
	defer a.Leave()
	require.False(t, a.Stranded())

	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(old)

	other := testIdentity(t)
	far := trust.Propose(other, a.Trust().Depth()+trust.Keep+2, trust.Digest{}, trust.QuorumMajority, 0,
		[]trust.Member{{Identity: other.Public(), Name: "o", Host: 1}}, nil)
	a.NotifyMsg(recordJSON(t, recordMsg{Checkpoint: &far}))

	assert.True(t, a.Stranded(), "the cluster is further on than anything this node could walk to")
	a.reportStranded()
	assert.Contains(t, log.String(), "none of its members signed")
	assert.Contains(t, log.String(), "check 'cheesecloth status' on another member",
		"and the line says what to do before anything is removed")
}

// Every member signs the same membership, so once one of them has stated it the
// rest have nothing to add but a signature. Restating it would put one record
// on the wire once per node, and a membership too large for a datagram goes to
// each peer over a stream -- so every node restating it is a stream from each
// of them to each of the others.
func Test_Cluster_attest_agreesRatherThanRestatingTheMembership(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x, y := testIdentity(t), testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)
	_, err = a.set.AddAdmission(trust.Admit(a.id, y.Public(), "y", 3))
	require.NoError(t, err)
	agree(t, a, x)
	require.Equal(t, 3, a.Trust().MemberCount(), "so a majority is two of the three")

	t.Run("the first to state a membership sends it", func(t *testing.T) {
		z := testIdentity(t)
		_, err := a.set.AddAdmission(trust.Admit(a.id, z.Public(), "z", 4))
		require.NoError(t, err)
		drainBroadcasts(a)

		a.attest()
		sent := lastRecord(t, a)
		require.NotNil(t, sent.Checkpoint, "nobody else has it yet")
		assert.Nil(t, sent.Agreement)
	})

	t.Run("a node that already holds it sends only its signature", func(t *testing.T) {
		w := testIdentity(t)
		_, err := a.set.AddAdmission(trust.Admit(a.id, w.Public(), "w", 5))
		require.NoError(t, err)

		// x states the membership first; one of three does not agree it. It
		// goes into the set rather than through NotifyMsg, which would wake the
		// agent's own attesting and leave the test racing it.
		p := a.Trust().Proposal()
		base, ok := a.Trust().Anchor()
		require.True(t, ok)
		stated := trust.Propose(x, p.Depth, base.Digest(), base.Quorum, 0, p.Members, p.Removed)
		_, err = a.set.AddCheckpoint(stated)
		require.NoError(t, err)
		require.False(t, a.Trust().Valid(w.Public()))
		drainBroadcasts(a)

		a.attest()
		sent := lastRecord(t, a)
		require.Nil(t, sent.Checkpoint, "the membership is already going round")
		require.NotNil(t, sent.Agreement)
		assert.Equal(t, stated.Digest(), sent.Agreement.Digest)
		assert.Equal(t, a.Identity(), sent.Agreement.By.Signer)
		assert.True(t, a.Trust().Valid(w.Public()), "and the two signatures agree it")
	})
}

// lastRecord is the record a node most recently put on the gossip queue. It
// allows for the agent's own attesting having queued one first.
func lastRecord(t *testing.T, c *Cluster) recordMsg {
	t.Helper()
	var m recordMsg
	require.Eventually(t, func() bool {
		msgs := c.GetBroadcasts(0, 1<<16)
		if len(msgs) == 0 {
			return false
		}
		return json.Unmarshal(msgs[len(msgs)-1], &m) == nil
	}, 2*time.Second, 10*time.Millisecond, "nothing was queued")
	return m
}

// The records that led to a membership are let go of wherever the cluster
// agreed it, not only on the node whose signature completed the quorum. Every
// other node's anchor moves inside the set, so it has nothing to state and
// would otherwise return with the spent records still in hand -- for the life
// of the cluster, since the next membership leaves them just as spent.
func Test_Cluster_attest_discardsWhatTheClusterAgreedElsewhere(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	x := testIdentity(t)
	_, _, err := a.admit(x.Public(), "x")
	require.NoError(t, err)

	z := testIdentity(t)
	_, err = a.set.AddAdmission(trust.Admit(a.id, z.Public(), "z", 3))
	require.NoError(t, err)

	// the cluster agrees it without this node stating anything, as it does when
	// a peer's attestation is the one that completes the quorum
	agree(t, a, x)
	require.True(t, a.Trust().Valid(z.Public()))

	_, signed := a.attest()
	assert.False(t, signed, "there is nothing left for this node to state")
	assert.Empty(t, a.Trust().Records().Admissions, "and the records it accounts for are let go of")
}

// Where a cluster asks for confirmations, a record this node signs does nothing
// until another member agrees with it, and the agent is what an operator
// confirms through.
func Test_Cluster_confirm(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	b.InitRoot("a", testOverlay, "1", 1)
	cfg := Config{StateDir: dir, StateName: "a", BindAddr: loopback, AdvertiseAddr: loopback,
		OverlayNet: testOverlay, LocalNode: testNodeFor(t, "a", b), Boot: b}
	a, err := New(cfg)
	require.NoError(t, err)
	defer a.Leave()

	// a second member, which the founding membership needed nobody to confirm
	x := testIdentity(t)
	_, _, err = a.admit(x.Public(), "x")
	require.NoError(t, err)
	require.Equal(t, 2, a.Trust().MemberCount())
	require.Equal(t, 1, a.Trust().Confirmations(), "and from here one other member has to agree")

	// a record it signs itself now waits
	j := testIdentity(t)
	adm := trust.Admit(a.id, j.Public(), "j", 3)
	_, err = a.set.AddAdmission(adm)
	require.NoError(t, err)
	waiting := a.Awaiting()
	require.Len(t, waiting, 1)
	assert.Equal(t, "j", waiting[0].Name)
	assert.Equal(t, 0, waiting[0].Have)
	assert.Equal(t, 1, waiting[0].Need)

	// this node confirming its own record is not a second pair of eyes
	require.NoError(t, a.Confirm(adm.Digest()))
	_, proposed := a.Trust().Proposal().Holds(j.Public())
	assert.False(t, proposed)
	require.Len(t, a.Awaiting(), 1, "so it is still waiting")

	// the other member's does it
	_, err = a.set.AddConfirmation(trust.Confirm(x, adm.Digest()))
	require.NoError(t, err)
	_, proposed = a.Trust().Proposal().Holds(j.Public())
	assert.True(t, proposed)
	assert.Empty(t, a.Awaiting())
}
