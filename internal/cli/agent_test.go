package cli

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

// validCmd returns an AgentCmd with the flag defaults that Validate requires.
func validCmd() AgentCmd {
	return AgentCmd{settings: settings{Interface: DefaultInterface, OverlayNet: testOverlay, MTU: 1420, BindAddr: netip.IPv4Unspecified()}}
}

// The settings reach the agent's configuration, whose checks are what
// Validate reports.
func Test_AgentCmd_Validate_errors(t *testing.T) {
	tests := []struct {
		name    string
		cmd     AgentCmd
		wantErr string
	}{
		{
			"interface that is not one",
			AgentCmd{settings: settings{Interface: "../secrets", OverlayNet: testOverlay, MTU: 1420}},
			"interface name",
		},
		{
			"overlay too small",
			AgentCmd{settings: settings{Interface: DefaultInterface, OverlayNet: netip.MustParsePrefix("10.0.0.0/31"), MTU: 1420}},
			"no room for two nodes",
		},
		{
			"allowed ips inside the overlay",
			AgentCmd{settings: settings{Interface: DefaultInterface, OverlayNet: testOverlay, MTU: 1420, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.5.0.0/16")}}},
			"overlaps the overlay network",
		},
		{
			"mtu too small",
			AgentCmd{settings: settings{Interface: DefaultInterface, OverlayNet: testOverlay, MTU: 500}},
			"unsupported MTU",
		},
		{
			"keepalive not whole seconds",
			AgentCmd{settings: settings{Interface: DefaultInterface, OverlayNet: testOverlay, MTU: 1420, PersistentKeepalive: 1500 * time.Millisecond}},
			"unsupported persistent keepalive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func Test_AgentCmd_Validate_joinKey(t *testing.T) {
	cmd := validCmd()
	cmd.JoinKey = "token"
	assert.ErrorContains(t, cmd.Validate(), "needs --join")
	cmd.Join = []string{"member"}
	require.NoError(t, cmd.Validate())
}

// Nothing to check until the cluster has been asked.
func Test_AgentCmd_Validate_overlayNetUnset(t *testing.T) {
	a := validCmd()
	a.OverlayNet = netip.Prefix{}
	a.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	assert.NoError(t, a.Validate())
}

// Every setting crosses to the agent's configuration under the same name.
func Test_AgentCmd_config(t *testing.T) {
	cmd := validCmd()
	cmd.Interface, cmd.stateDir, cmd.JoinKey = "wg1", "/tmp/state", "token"
	cmd.Join = []string{"member"}
	cmd.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}
	cmd.ClusterPort, cmd.WireguardPort, cmd.MTU = 7947, 51821, 1400
	cmd.PersistentKeepalive = 25 * time.Second
	cmd.SyncInterval = 45 * time.Second
	cmd.NoEtcHosts, cmd.Userspace, cmd.ControlSocket = true, true, "/tmp/ctl.sock"

	cfg := cmd.config()
	assert.Equal(t, "wg1", cfg.Interface)
	assert.Equal(t, "/tmp/state", cfg.StateDir)
	assert.Equal(t, "token", cfg.JoinKey)
	assert.Equal(t, []string{"member"}, cfg.Join)
	assert.Equal(t, testOverlay, cfg.OverlayNet)
	assert.Equal(t, cmd.AllowedIPs, cfg.AllowedIPs)
	assert.Equal(t, cmd.BindAddr, cfg.BindAddr)
	assert.Equal(t, 7947, cfg.ClusterPort)
	assert.Equal(t, 51821, cfg.WireguardPort)
	assert.Equal(t, 1400, cfg.MTU)
	assert.Equal(t, 25*time.Second, cfg.PersistentKeepalive)
	assert.Equal(t, 45*time.Second, cfg.SyncInterval)
	assert.True(t, cfg.NoEtcHosts)
	assert.True(t, cfg.Userspace)
	assert.Equal(t, "/tmp/ctl.sock", cfg.ControlSocket)
}

// recordingNotifier is a service manager that remembers what it was told.
type recordingNotifier struct{ ready, stopping atomic.Bool }

func (n *recordingNotifier) Ready(string) error  { n.ready.Store(true); return nil }
func (n *recordingNotifier) Status(string) error { return nil }
func (n *recordingNotifier) Stopping() error     { n.stopping.Store(true); return nil }

func waitErr(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the command did not return")
		return nil
	}
}
