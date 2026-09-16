package cli

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The section is derived from the flag declarations: every setting that
// differs from its default, in the order declared, spelled as it is parsed.
// The interface names the section rather than appearing in it.
func Test_settings_entries(t *testing.T) {
	s, err := defaultSettings()
	require.NoError(t, err)
	entries, err := s.entries()
	require.NoError(t, err)
	assert.Empty(t, entries, "the defaults are not worth writing down")

	s.Interface = "wg7"
	s.Join = []string{"a.example.net", "[fd00::1]:7947"}
	s.BindAddr = netip.MustParseAddr("192.0.2.1")
	s.ClusterPort, s.WireguardPort, s.MTU = 7947, 51821, 1380
	s.OverlayNet = netip.MustParsePrefix("10.42.0.9/16")
	s.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.9/24"), netip.MustParsePrefix("fd00:7::/64")}
	s.PersistentKeepalive = 25 * time.Second
	s.NoEtcHosts, s.Userspace = true, true
	s.ControlSocket = "/run/x.sock"
	entries, err = s.entries()
	require.NoError(t, err)
	assert.Equal(t, []setting{
		{"interface", "wg7"},
		{"join", []any{"a.example.net", "[fd00::1]:7947"}},
		{"bind-addr", "192.0.2.1"},
		{"cluster-port", 7947},
		{"wireguard-port", 51821},
		{"overlay-net", "10.42.0.0/16"},
		{"allowed-ips", []any{"192.168.7.0/24", "fd00:7::/64"}},
		{"mtu", 1380},
		{"persistent-keepalive", "25s"},
		{"no-etc-hosts", true},
		{"userspace", true},
		{"control-socket", "/run/x.sock"},
	}, entries, "networks are written with their host bits cleared, and the interface is not a setting")

	// a setting can be given its default explicitly, and an empty list is nothing
	s, err = defaultSettings()
	require.NoError(t, err)
	s.Join, s.AllowedIPs = []string{}, []netip.Prefix{}
	s.BindAddr = netip.MustParseAddr("0.0.0.0")
	entries, err = s.entries()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// Every flag the file may hold is one the agent's settings declare, and the
// defaults the file leaves out are the ones the agent runs with.
func Test_settings_flags(t *testing.T) {
	s, err := defaultSettings()
	require.NoError(t, err)
	flags, err := s.flags()
	require.NoError(t, err)
	var names []string
	for _, f := range flags {
		names = append(names, f.Name)
	}
	assert.Equal(t, []string{"interface", "join", "bind-addr", "cluster-port", "wireguard-port", "overlay-net", "quorum", "allowed-ips",
		"mtu", "persistent-keepalive", "no-etc-hosts", "userspace", "control-socket"}, names)
	assert.Equal(t, DefaultInterface, s.Interface, "the interface is a flag with a default, just not one of the section's")
}
