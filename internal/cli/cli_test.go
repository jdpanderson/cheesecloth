package cli

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newParser builds the parser with no config file and exits captured.
func newParser(t *testing.T, c *CLI) (*bytes.Buffer, func(args ...string) (string, error)) {
	t.Helper()
	k, err := Parser(c, filepath.Join(t.TempDir(), "absent.yaml"), "1.2.3")
	require.NoError(t, err)
	out := &bytes.Buffer{}
	k.Stdout, k.Stderr = out, out
	k.Exit = func(int) {}
	return out, func(args ...string) (string, error) {
		ctx, perr := k.Parse(args)
		if perr != nil {
			return "", perr
		}
		return ctx.Command(), nil
	}
}

func Test_Parser_commands(t *testing.T) {
	c := &CLI{}
	_, parse := newParser(t, c)

	cmd, err := parse()
	require.NoError(t, err)
	assert.Equal(t, "agent", cmd, "the agent is the default command")
	assert.Equal(t, DefaultInterface, c.Agent.Interface)
	assert.Equal(t, LogLevelFlag("warn"), c.LogLevel)

	cmd, err = parse("--overlay-net", "fd00:10::/64", "--allowed-ips", "192.168.7.0/24,192.168.8.0/24")
	require.NoError(t, err)
	assert.Equal(t, "agent", cmd, "agent flags without the command word")
	assert.Equal(t, "fd00:10::/64", c.Agent.OverlayNet.String())
	assert.Len(t, c.Agent.AllowedIPs, 2)

	cmd, err = parse("invite", "--ttl", "5m")
	require.NoError(t, err)
	assert.Equal(t, "invite", cmd)
	assert.Equal(t, 5*time.Minute, c.Invite.TTL)

	cmd, err = parse("revoke", "node2")
	require.NoError(t, err)
	assert.Equal(t, "revoke <target>", cmd)
	assert.Equal(t, "node2", c.Revoke.Target)

	cmd, err = parse("status", "--json", "--interface", "wg1")
	require.NoError(t, err)
	assert.Equal(t, "status", cmd)
	assert.True(t, c.Status.JSON)

	_, err = parse("--no-such-flag")
	assert.Error(t, err)
	_, err = parse("--mtu", "10")
	assert.ErrorContains(t, err, "unsupported MTU", "command validation runs")
}

func Test_Parser_versionAndHelp(t *testing.T) {
	out, parse := newParser(t, &CLI{})
	_, err := parse("--version")
	require.NoError(t, err)
	assert.Contains(t, out.String(), "1.2.3")

	out.Reset()
	_, _ = parse("--help")
	assert.Contains(t, out.String(), "mesh overlay network manager")
	assert.Contains(t, out.String(), "absent.yaml", "the help names the config file the parser reads")
}
