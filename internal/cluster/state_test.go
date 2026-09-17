package cluster

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useTempStatePaths is a fresh state directory for the test.
func useTempStatePaths(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func testIdentity(t *testing.T) *trust.Identity {
	t.Helper()
	id, err := trust.NewIdentity()
	require.NoError(t, err)
	return id
}

func Test_state_save_load(t *testing.T) {
	dir := useTempStatePaths(t)
	id := testIdentity(t)
	s := &state{
		Seed:    id.Seed(),
		Records: trust.Records{Checkpoints: []trust.Checkpoint{trust.Found(id, "root", trust.QuorumMajority, 0)}},
		Peers:   []overlay.Node{{Name: "node", Addr: netip.MustParseAddr("10.0.0.2")}},
	}
	require.NoError(t, s.save(statePath(dir, "test")))
	got, err := loadState(statePath(dir, "test"))
	require.NoError(t, err)
	assert.Equal(t, s, got)
}

func Test_Forget(t *testing.T) {
	dir := useTempStatePaths(t)
	_, err := Load(dir, "test")
	require.NoError(t, err)
	require.FileExists(t, statePath(dir, "test"))
	require.NoError(t, Forget(dir, "test"))
	assert.NoFileExists(t, statePath(dir, "test"))
	assert.NoError(t, Forget(dir, "test"), "nothing to forget is not an error")

	require.NoError(t, os.Mkdir(statePath(dir, "dir"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(statePath(dir, "dir"), "f"), nil, 0o600))
	assert.ErrorContains(t, Forget(dir, "dir"), "removing state")
}

func Test_state_save_unwritableDir(t *testing.T) {
	dir := useTempStatePaths(t)
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	assert.Error(t, (&state{}).save(statePath(blocker, "test")), "a file where the directory should be")
	// Which failure it is depends on the system: unix reports a file in a
	// path as not a directory, windows as a path that is not there, which
	// looks like a fresh node until the identity cannot be written either.
	_, err := Load(blocker, "test")
	assert.Error(t, err, "a file where the directory should be")
}

// Nothing to read, and nowhere to write the identity that would replace it.
func Test_Load_reportsUnwritableIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not stop a write on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	readonly := filepath.Join(useTempStatePaths(t), "readonly")
	require.NoError(t, os.Mkdir(readonly, 0o500))
	_, err := Load(readonly, "test")
	assert.ErrorContains(t, err, "saving new identity")
}

func Test_loadState_missingOrBroken(t *testing.T) {
	dir := useTempStatePaths(t)
	got, err := loadState(statePath(dir, "test"))
	require.NoError(t, err)
	assert.Equal(t, &state{}, got, "no file is a fresh start")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), []byte("{not json"), 0o600))
	_, err = loadState(statePath(dir, "test"))
	assert.ErrorContains(t, err, "decoding state")
	require.NoError(t, os.Mkdir(statePath(dir, "dir"), 0o700))
	_, err = loadState(statePath(dir, "dir"))
	assert.ErrorContains(t, err, "reading state")
}

// A state file whose seed is not one is refused, not replaced.
func Test_Load_refusesBadSeed(t *testing.T) {
	dir := useTempStatePaths(t)
	require.NoError(t, (&state{Seed: []byte("short")}).save(statePath(dir, "a")))
	_, err := Load(dir, "a")
	assert.ErrorContains(t, err, "loading identity")
}

// A damaged state file must not be replaced by a new identity: that would
// silently drop the node out of its cluster.
func Test_Load_refusesBrokenState(t *testing.T) {
	dir := useTempStatePaths(t)
	path := filepath.Join(dir, "test.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
	_, err := Load(dir, "test")
	require.Error(t, err)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "{not json", string(content), "the file is left for the operator")

	assert.Empty(t, KnownNodes(dir, "test"))
	_, ok := LocalIdentity(dir, "test")
	assert.False(t, ok)

	// Forgetting the state is the explicit way to start over.
	require.NoError(t, Forget(dir, "test"))
	b, err := Load(dir, "test")
	require.NoError(t, err)
	assert.False(t, b.Enrolled())
}

// A member's state always names the cluster's overlay network: it was settled
// when the node enrolled or started the cluster. One with a root and no
// network is damaged, and is refused like any other damage.
func Test_Load_refusesAMemberWithoutAnOverlayNetwork(t *testing.T) {
	dir := useTempStatePaths(t)
	id := testIdentity(t)
	founding := trust.Found(id, "test", trust.QuorumMajority, 0)
	require.NoError(t, (&state{Seed: id.Seed(), Anchor: &founding}).save(statePath(dir, "test")))
	_, err := Load(dir, "test")
	assert.ErrorContains(t, err, "no overlay network")
}

func Test_Load_createsAndKeepsIdentity(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "test")
	require.NoError(t, err)
	assert.False(t, b.Enrolled())
	assert.FileExists(t, filepath.Join(dir, "test.json"), "identity persisted right away")

	again, err := Load(dir, "test")
	require.NoError(t, err)
	assert.Equal(t, b.Identity.Public(), again.Identity.Public(), "same identity on restart")

	require.NoError(t, Forget(dir, "test"))
	fresh, err := Load(dir, "test")
	require.NoError(t, err)
	assert.NotEqual(t, b.Identity.Public(), fresh.Identity.Public(), "a forgotten node starts over")
}

func Test_Bootstrap_initAndEnrol(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "test")
	require.NoError(t, err)
	b.InitRoot("root", testOverlay, trust.QuorumMajority, 0)
	assert.True(t, b.Enrolled())
	require.NotNil(t, b.Anchor, "it starts from its own membership")
	assert.True(t, b.Set().Valid(b.Identity.Public()))

	other := testIdentity(t)
	j, err := Load(dir, "joiner")
	require.NoError(t, err)
	// what a welcome carries: the membership the cluster agreed on, which names
	// the joiner -- nothing is a member until one does
	founding := trust.Found(other, "o", trust.QuorumMajority, 0)
	adm := trust.Admit(other, j.Identity.Public(), "joiner", 7)
	agreed := trust.Propose(other, founding.Depth+1, founding.Digest(), founding.Quorum, 0, []trust.Member{
		{Identity: other.Public(), Name: "o", Host: 1},
		{Identity: j.Identity.Public(), Name: "joiner", Host: 7},
	}, nil)
	records := trust.Records{Admissions: []trust.Admission{adm}}
	j.Enrol(records, netip.MustParsePrefix("10.42.0.0/16"), &agreed)
	assert.True(t, j.Enrolled())
	assert.Equal(t, netip.MustParsePrefix("10.42.0.0/16"), j.OverlayNet, "the cluster's, as the member stated it")
	adm2, err := j.Assigned()
	require.NoError(t, err)
	assert.Equal(t, uint64(7), adm2.Host)
	assert.Equal(t, adm.Name, adm2.Name, "the name the cluster admitted this node under")
}

func Test_KnownNodes(t *testing.T) {
	dir := useTempStatePaths(t)
	assert.Empty(t, KnownNodes(dir, "test"))

	good := overlay.Node{Name: "good", Addr: netip.MustParseAddr("192.0.2.1")}
	good.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	good.PubKey = "pk"
	require.NoError(t, (&state{Peers: []overlay.Node{good}}).save(statePath(dir, "test")))

	got := KnownNodes(dir, "test")
	require.Len(t, got, 1)
	assert.Equal(t, good, got[0], "persisted with its metadata")

	require.NoError(t, os.WriteFile(statePath(dir, "broken"), []byte("{"), 0o600))
	assert.Empty(t, KnownNodes(dir, "broken"), "an unusable state file yields no peers")
}

// What a command that only reports settings reads, without creating state of
// its own the way Load would.
func Test_KnownOverlayNet(t *testing.T) {
	dir := useTempStatePaths(t)
	_, ok := KnownOverlayNet(dir, "none")
	assert.False(t, ok, "a node that has never run knows no network")
	assert.NoFileExists(t, statePath(dir, "none"), "asking creates nothing")

	require.NoError(t, (&state{}).save(statePath(dir, "fresh")))
	_, ok = KnownOverlayNet(dir, "fresh")
	assert.False(t, ok, "a node that is not in a cluster has not been told one")

	net := netip.MustParsePrefix("10.42.0.0/16")
	require.NoError(t, (&state{OverlayNet: net}).save(statePath(dir, "member")))
	got, ok := KnownOverlayNet(dir, "member")
	require.True(t, ok)
	assert.Equal(t, net, got)

	require.NoError(t, os.WriteFile(statePath(dir, "broken"), []byte("{"), 0o600))
	_, ok = KnownOverlayNet(dir, "broken")
	assert.False(t, ok, "an unusable state file says nothing")
}

func Test_LocalIdentity(t *testing.T) {
	dir := useTempStatePaths(t)
	_, ok := LocalIdentity(dir, "none")
	assert.False(t, ok)

	b, err := Load(dir, "a")
	require.NoError(t, err)
	id, ok := LocalIdentity(dir, "a")
	require.True(t, ok)
	assert.Equal(t, b.Identity.Public(), id)

	require.NoError(t, (&state{Seed: []byte("short")}).save(statePath(dir, "broken")))
	_, ok = LocalIdentity(dir, "broken")
	assert.False(t, ok)
}

func Test_Bootstrap_Assigned_withoutAdmission(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a")
	require.NoError(t, err)
	_, err = b.Assigned()
	assert.ErrorContains(t, err, "is not a member of the cluster it holds records for")
}

// A reader must never see a half-written state file.
func Test_state_save_atomic(t *testing.T) {
	dir := useTempStatePaths(t)
	id := testIdentity(t)
	st := &state{Seed: id.Seed(), Records: trust.Records{Checkpoints: []trust.Checkpoint{trust.Found(id, "root", trust.QuorumMajority, 0)}}}
	require.NoError(t, st.save(statePath(dir, "a")))

	// the writer reports through the channel: a test must not fail from another goroutine
	saved := make(chan error, 1)
	go func() {
		for i := 0; i < 200; i++ {
			st.Peers = append(st.Peers, overlay.Node{Name: fmt.Sprintf("n%d", i), Addr: netip.MustParseAddr("10.0.0.2")})
			if err := st.save(statePath(dir, "a")); err != nil {
				saved <- err
				return
			}
		}
		saved <- nil
	}()
	for {
		select {
		case err := <-saved:
			require.NoError(t, err)
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Len(t, entries, 1, "no temp files left behind")
			return
		default:
			got, err := loadState(statePath(dir, "a"))
			require.NoError(t, err, "torn read")
			assert.Equal(t, id.Seed(), got.Seed)
		}
	}
}
