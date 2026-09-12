package cli

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/cluster"
)

// stateDirOr is where the agent's state is kept: dir, or the platform's
// directory when a command was not pointed somewhere else, as only a test is.
func stateDirOr(dir string) string {
	if dir == "" {
		return cluster.DefaultDir
	}
	return dir
}

// settings are the flags an interface's config file section may hold. The
// agent runs with them and 'cheesecloth config' writes them, so they are
// declared once and embedded by both.
type settings struct {
	Join          []string       `help:"comma separated list of hostnames or IP addresses of existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members."`
	BindAddr      netip.Addr     `help:"address to bind for cluster membership traffic; 0.0.0.0 or :: binds every interface of that family and advertises one of its addresses. The address family decides whether the cluster runs over IPv4 or IPv6" default:"0.0.0.0"`
	ClusterPort   int            `help:"UDP port used for membership gossip and enrolment (QUIC); must be the same across cluster" default:"7946"`
	WireguardPort int            `help:"port used for wireguard traffic (UDP); must be the same across cluster" default:"51820"`
	OverlayNet    netip.Prefix   `help:"the network in which to allocate addresses for the overlay mesh network (CIDR format); a node that is already a member, or being enrolled, takes the cluster's unless this says otherwise. Defaults to ${default_overlay_net} for a new cluster"`
	AllowedIPs    []netip.Prefix `name:"allowed-ips" help:"extra networks reachable through this node (CIDR, comma separated); peers route them over the mesh via this node, which must forward. Must not overlap --overlay-net"`
	Interface     string         `help:"name of the wireguard interface to create and manage" default:"${default_interface}"`
	MTU           int            `help:"MTU of the wireguard interface" default:"1420"`
	// PersistentKeepalive is a time.Duration so kong accepts "25s"; 0 disables it.
	PersistentKeepalive time.Duration `help:"interval at which peers send keepalives, to keep NAT mappings open (e.g. 25s); 0 disables" default:"0"`
	NoEtcHosts          bool          `help:"disable writing of entries to /etc/hosts"`
	Userspace           bool          `help:"run wireguard inside the agent instead of the kernel module; the default wherever the kernel has none"`
	ControlSocket       string        `help:"unix socket for 'cheesecloth invite' and 'cheesecloth revoke' (default ${default_socket_dir}/<interface>.sock)"`

	stateDir string // where the cluster state is kept; empty means cluster.DefaultDir
}

// state is the directory this node's cluster state is kept in.
func (s *settings) state() string { return stateDirOr(s.stateDir) }

// check is what must hold of any settings, however they are going to be used.
// It is not named Validate so that kong calls it only through the commands
// that embed it, which have their own checks to make as well.
func (s *settings) check() error {
	// an overlay network given here is checked now; one that comes from the
	// cluster is checked once it is known, in Run
	if s.OverlayNet.IsValid() {
		if err := checkOverlayNet(s.OverlayNet.Masked(), s.AllowedIPs); err != nil {
			return err
		}
	}

	if s.MTU < 576 || s.MTU > 65535 {
		return fmt.Errorf("unsupported MTU %d; must be between 576 and 65535", s.MTU)
	}

	if ka := s.PersistentKeepalive; ka != 0 && (ka < time.Second || ka > 65535*time.Second || ka%time.Second != 0) {
		return fmt.Errorf("unsupported persistent keepalive %s; must be whole seconds between 1s and 65535s", ka)
	}

	return nil
}

// defaultSettings is what the flags hold when nothing sets them. It comes from
// the tags above rather than a second copy of the values, so that what
// 'cheesecloth config' leaves out cannot drift from what the agent defaults to.
func defaultSettings() (settings, error) {
	var s settings
	if err := kong.ApplyDefaults(&s, varsFor("", "")); err != nil {
		return s, fmt.Errorf("reading the flag defaults: %w", err)
	}
	return s, nil
}
