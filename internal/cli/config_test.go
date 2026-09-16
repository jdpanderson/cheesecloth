package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// parse runs the real parser with configPath as the default config file.
func parse(t *testing.T, configPath string, args ...string) (*CLI, error) {
	t.Helper()
	c := &CLI{}
	k, err := Parser(c, configPath, "test")
	if err != nil { // a broken default config file is reported at construction
		return c, err
	}
	_, err = k.Parse(args)
	return c, err
}

func Test_config_appliesToAgentAndOtherCommands(t *testing.T) {
	path := writeConfig(t, `
interface: wg7
bind-addr: "::"
cluster-port: 17946
wireguard-port: 51821
overlay-net: fd00:10::/64
mtu: 1380
persistent-keepalive: 25s
no-etc-hosts: true
log-level: debug
join:
  - a.example.net
  - b.example.net
`)
	c, err := parse(t, path, "agent")
	require.NoError(t, err)
	assert.Equal(t, netip.IPv6Unspecified(), c.Agent.BindAddr)
	assert.Equal(t, 17946, c.Agent.ClusterPort)
	assert.Equal(t, 51821, c.Agent.WireguardPort)
	assert.Equal(t, "fd00:10::/64", c.Agent.OverlayNet.String())
	assert.Equal(t, "wg7", c.Agent.Interface, "the file says which interface it is for")
	assert.Equal(t, 1380, c.Agent.MTU)
	assert.Equal(t, 25*time.Second, c.Agent.PersistentKeepalive)
	assert.True(t, c.Agent.NoEtcHosts)
	assert.Equal(t, LogLevelFlag("debug"), c.LogLevel)
	assert.Equal(t, []string{"a.example.net", "b.example.net"}, c.Agent.Join)

	// the same file tells the operator commands which agent to talk to
	c, err = parse(t, path, "status")
	require.NoError(t, err)
	assert.Equal(t, "wg7", c.Status.Interface)
	c, err = parse(t, path, "invite")
	require.NoError(t, err)
	assert.Equal(t, "wg7", c.Invite.Interface)
}

func Test_config_commandLineOverrides(t *testing.T) {
	path := writeConfig(t, "interface: wg7\nmtu: 1380\nlog-level: debug\n")
	c, err := parse(t, path, "--log-level", "error", "agent", "--mtu", "1300")
	require.NoError(t, err)
	assert.Equal(t, 1300, c.Agent.MTU, "flag wins")
	assert.Equal(t, "wg7", c.Agent.Interface, "unset flag takes the config value")
	assert.Equal(t, LogLevelFlag("error"), c.LogLevel)
}

// A file that is not there leaves the defaults alone, whether it is the default
// path or one named with --config. Naming a file that does not exist yet is how
// a second cluster on a host is set up, so it cannot be an error.
func Test_config_aMissingFileLeavesTheDefaults(t *testing.T) {
	c, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "agent")
	require.NoError(t, err)
	assert.Equal(t, 1420, c.Agent.MTU, "defaults apply without a config file")

	c, err = parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "--config", filepath.Join(t.TempDir(), "wg2.yaml"), "agent")
	require.NoError(t, err)
	assert.Equal(t, 1420, c.Agent.MTU)

	// a file that is there but unreadable is still an error
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(unreadable, []byte("not: valid: yaml\n"), 0o600))
	_, err = parse(t, filepath.Join(dir, "absent.yaml"), "--config", unreadable, "agent")
	require.Error(t, err)
}

func Test_config_explicitFile(t *testing.T) {
	path := writeConfig(t, "interface: wg7\nmtu: 1300\n")
	c, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "--config", path, "agent")
	require.NoError(t, err)
	assert.Equal(t, 1300, c.Agent.MTU)
	assert.Equal(t, "wg7", c.Agent.Interface)
}

func Test_config_rejectsUnknownAndCommandLineOnlyKeys(t *testing.T) {
	_, err := parse(t, writeConfig(t, "interface: wg7\nmtu: 1300\nbogus: 1\ncluster_port: 7946\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown setting(s) bogus, cluster_port")

	_, err = parse(t, writeConfig(t, "interface: wg7\njoin-key: secret\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "join-key")
	assert.Contains(t, err.Error(), "one-time secret")
	// commands without the flag never resolve it; the file is still refused
	for _, cmd := range []string{"status", "invite"} {
		_, err = parse(t, writeConfig(t, "interface: wg7\njoin-key: secret\n"), cmd)
		assert.ErrorContains(t, err, "one-time secret", cmd)
	}

	// a typo is reported even in a section this command does not act under
	_, err = parse(t, writeConfig(t, "interface: wg7\nbogus: 1\n"), "agent")
	assert.ErrorContains(t, err, "unknown setting(s) bogus")

	_, err = parse(t, writeConfig(t, "interface: wg7\ninit: true\n"), "agent")
	require.Error(t, err, "the flag is gone; the key is unknown like any other")
	assert.Contains(t, err.Error(), "unknown setting(s) init")

	_, err = parse(t, writeConfig(t, "interface: wg7\nversion: true\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown setting(s) version")

	_, err = parse(t, writeConfig(t, "interface: wg7\nmtu: [1, 2]\n"), "agent")
	require.Error(t, err, "a value of the wrong shape is an error")

	_, err = parse(t, writeConfig(t, "not: valid: yaml\n"), "agent")
	require.Error(t, err)
}

func Test_config_namesTheOldSectionedFormat(t *testing.T) {
	// a file keyed by interface name, which is what this used to be
	_, err := parse(t, writeConfig(t, "wg7:\n  mtu: 1380\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "holds settings of its own")
	assert.Contains(t, err.Error(), "--config")
}

func Test_config_theCommandLineWinsOverTheFile(t *testing.T) {
	path := writeConfig(t, "interface: wg7\nmtu: 1380\n")

	c, err := parse(t, path, "agent")
	require.NoError(t, err)
	assert.Equal(t, "wg7", c.Agent.Interface)
	assert.Equal(t, 1380, c.Agent.MTU)

	// another interface on the same host reads its own file; --interface here
	// is what the flag has always been, an override
	c, err = parse(t, path, "--interface", "wg8", "agent")
	require.NoError(t, err)
	assert.Equal(t, "wg8", c.Agent.Interface)
	assert.Equal(t, 1380, c.Agent.MTU, "the rest of the file still applies")

	// the operator commands read it the same way
	c, err = parse(t, path, "status")
	require.NoError(t, err)
	assert.Equal(t, "wg7", c.Status.Interface)
}

func Test_config_emptyFile(t *testing.T) {
	// what a fresh install ships: every setting commented out
	for _, body := range []string{"", "# interface: wgcloth\n# mtu: 1380\n"} {
		c, err := parse(t, writeConfig(t, body), "agent")
		require.NoError(t, err)
		assert.Equal(t, 1420, c.Agent.MTU)
		assert.Equal(t, DefaultInterface, c.Agent.Interface)
	}
}

func Test_noEnvironmentVariables(t *testing.T) {
	t.Setenv("CHEESECLOTH_MTU", "1300")
	t.Setenv("CHEESECLOTH_INTERFACE", "wgenv")
	c, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "agent")
	require.NoError(t, err)
	assert.Equal(t, 1420, c.Agent.MTU, "environment variables are not consulted")
	assert.Equal(t, DefaultInterface, c.Agent.Interface)
}
