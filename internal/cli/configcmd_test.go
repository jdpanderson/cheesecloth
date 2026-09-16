package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runConfig parses args and runs the config command with its state kept in
// stateDir, returning what it printed.
func runConfig(t *testing.T, configPath, stateDir string, args ...string) (string, string, error) {
	t.Helper()
	c, err := parse(t, configPath, args...)
	require.NoError(t, err)
	c.Settings.stateDir = stateDir
	return captureOutput(t, func() error { return c.Settings.Run(c) })
}

// writeState puts a state file for iface in dir holding only the overlay
// network, which is all the config command reads back.
func writeState(t *testing.T, dir, iface, overlayNet string) {
	t.Helper()
	body := `{"seed":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","overlayNet":"` + overlayNet + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, iface+".json"), []byte(body), 0o600))
}

func Test_ConfigCmd_dumpsOneInterface(t *testing.T) {
	path := writeConfig(t, "interface: wg7\nmtu: 1380\ncluster-port: 17946\n")

	// the command line applies on top of the file
	stdout, _, err := runConfig(t, path, t.TempDir(), "config", "--mtu", "9000")
	require.NoError(t, err)
	assert.Equal(t, "interface: wg7\ncluster-port: 17946\nmtu: 9000\n", stdout)
}

func Test_ConfigCmd_dumpTakesOverlayNetFromState(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, "wg7", "10.42.0.0/16")
	path := writeConfig(t, "interface: wg7\nmtu: 1380\n")

	stdout, _, err := runConfig(t, path, dir, "config")
	require.NoError(t, err)
	assert.Contains(t, stdout, "overlay-net: 10.42.0.0/16", "what the cluster told this node")

	// an overlay network given here wins, as it does for the agent
	stdout, _, err = runConfig(t, path, dir, "config", "--overlay-net", "10.9.0.0/16")
	require.NoError(t, err)
	assert.Contains(t, stdout, "overlay-net: 10.9.0.0/16")
}

func Test_ConfigCmd_initRefusesAFileThatExists(t *testing.T) {
	path := writeConfig(t, "interface: wg7\nmtu: 1380\n")
	_, _, err := runConfig(t, path, t.TempDir(), "config", "--init", "--mtu", "9000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Contains(t, err.Error(), "cheesecloth config")

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "interface: wg7\nmtu: 1380\n", string(after), "the file is left alone")
}

func Test_ConfigCmd_dumpsDefaultInterfaceWithoutAFile(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, DefaultInterface, "10.42.0.0/16")

	stdout, _, err := runConfig(t, filepath.Join(t.TempDir(), "absent.yaml"), dir, "config")
	require.NoError(t, err)
	assert.Equal(t, "overlay-net: 10.42.0.0/16\n", stdout)
}

func Test_ConfigCmd_dumpsOnlyWhatDiffersFromTheDefaults(t *testing.T) {
	stdout, _, err := runConfig(t, filepath.Join(t.TempDir(), "absent.yaml"), t.TempDir(),
		"config", "--mtu", "1420", "--cluster-port", "7946", "--log-level", "warn")
	require.NoError(t, err)
	assert.Equal(t, "{}\n", stdout, "nothing is worth writing down")

	stdout, _, err = runConfig(t, filepath.Join(t.TempDir(), "absent.yaml"), t.TempDir(),
		"config", "--log-level", "debug", "--no-etc-hosts", "--join", "a.example.net")
	require.NoError(t, err)
	assert.Contains(t, stdout, "join:\n  - a.example.net")
	assert.Contains(t, stdout, "no-etc-hosts: true")
	assert.Contains(t, stdout, "log-level: debug")
}

func Test_ConfigCmd_initWritesAFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.yaml")
	_, stderr, err := runConfig(t, path, t.TempDir(), "config", "--init", "--overlay-net", "10.42.0.0/24")
	require.NoError(t, err)
	assert.Contains(t, stderr, "wrote ")

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "overlay-net: 10.42.0.0/24\n", string(written))

	// and the agent reads back what was written
	c, err := parse(t, path, "agent")
	require.NoError(t, err)
	assert.Equal(t, "10.42.0.0/24", c.Agent.OverlayNet.String())
	assert.Equal(t, DefaultInterface, c.Agent.Interface)
}
