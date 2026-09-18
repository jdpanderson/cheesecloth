package cli

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/wg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StatusCmd_Run(t *testing.T) {
	report, _, _ := statusFixture()
	status := func(iface string) (*wg.Report, error) {
		if iface != "wgcloth" {
			return nil, errors.New("no such device")
		}
		return report, nil
	}

	// no cluster state for this interface: peers are shown by key
	cmd := &StatusCmd{interfaceFlag: interfaceFlag{Interface: "wgcloth"}, status: status, stateDir: t.TempDir()}
	stdout, _, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stdout, "interface: wgcloth\n")
	assert.Contains(t, stdout, "peers:     2\n")
	assert.Contains(t, stdout, "KEYB")

	cmd.JSON = true
	stdout, _, err = captureOutput(t, cmd.Run)
	require.NoError(t, err)
	var got struct {
		Interface string `json:"interface"`
		Peers     []struct {
			PublicKey string `json:"publicKey"`
		} `json:"peers"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	assert.Equal(t, "wgcloth", got.Interface)
	assert.Len(t, got.Peers, 2)

	_, _, err = captureOutput(t, (&StatusCmd{interfaceFlag: interfaceFlag{Interface: "absent0"}, status: status, stateDir: t.TempDir()}).Run)
	assert.ErrorContains(t, err, "no such device")
}

// With the agent's state on disk, peers are named and the local identity is shown.
func Test_StatusCmd_Run_namesPeersFromState(t *testing.T) {
	report, _, _ := statusFixture()
	dir := t.TempDir()
	boot, err := cluster.Load(dir, "wgcloth") // writes the identity
	require.NoError(t, err)

	// add the peer the agent would have remembered, under the state file's "peers" key
	path := filepath.Join(dir, "wgcloth.json")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var st map[string]any
	require.NoError(t, json.Unmarshal(content, &st))
	b := overlay.Node{Name: "b", Addr: netip.MustParseAddr("192.0.2.2")}
	b.PubKey, b.OverlayAddr, b.Identity = "KEYB", netip.MustParseAddr("10.0.0.2"), identityB
	st["peers"] = []overlay.Node{b}
	content, err = json.Marshal(st)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, content, 0o600))

	cmd := &StatusCmd{interfaceFlag: interfaceFlag{Interface: "wgcloth"}, status: func(string) (*wg.Report, error) { return report, nil }, stateDir: dir}
	stdout, _, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stdout, "identity:  "+boot.Identity.Public().String()+"\n")
	assert.Regexp(t, `\nb\s+`+identityB.Short()+`\s+10\.0\.0\.2\s+192\.0\.2\.2:51820`, stdout, "the peer is named from the state")
	assert.Contains(t, stdout, "KEYUNKNOWN12...", "a peer the state does not know is shown by key")

	cmd.JSON = true
	stdout, _, err = captureOutput(t, cmd.Run)
	require.NoError(t, err)
	var got struct {
		Identity string `json:"identity"`
		Peers    []struct {
			Name     string `json:"name"`
			Identity string `json:"identity"`
		} `json:"peers"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	assert.Equal(t, boot.Identity.Public().String(), got.Identity)
	require.Len(t, got.Peers, 2)
	assert.Equal(t, "b", got.Peers[0].Name)
	assert.Equal(t, identityB.String(), got.Peers[0].Identity)
}

// Without seams the command asks wireguard itself, which has no such interface.
func Test_StatusCmd_Run_real(t *testing.T) {
	_, _, err := captureOutput(t, (&StatusCmd{interfaceFlag: interfaceFlag{Interface: "wg-absent0"}}).Run)
	assert.Error(t, err)
}
