package cli

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/agent"
	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/trust"
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
	Interface     string         `help:"name of the wireguard interface to create and manage; at most 15 characters of letters, digits, dots, dashes and underscores, starting with a letter or a digit, since it names this node's state file and control socket as well as the device" default:"${default_interface}"`
	Join          []string       `help:"comma separated list of hostnames or IP addresses of existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members."`
	BindAddr      netip.Addr     `help:"address to bind for cluster membership traffic; 0.0.0.0 or :: binds every interface of that family and advertises one of its addresses. The address family decides whether the cluster runs over IPv4 or IPv6" default:"0.0.0.0"`
	ClusterPort   int            `help:"UDP port this node listens on for membership gossip and enrolment (QUIC); peers learn it and remember it, so it need not match theirs -- but a member listening on another port has to be given as host:port in --join" default:"7946"`
	WireguardPort int            `help:"port used for wireguard traffic (UDP); must be the same across cluster" default:"51820"`
	OverlayNet    netip.Prefix   `help:"the network in which to allocate addresses for the overlay mesh network (CIDR format); a node that is already a member, or being enrolled, takes the cluster's unless this says otherwise. A node that is neither starts a cluster with it, and does nothing without it"`
	Quorum        string         `help:"how many members must agree before a membership takes effect -- every admission and revocation goes through it: 'majority' (the default, and the only value that cannot fork), 'half', or a count. It is the cluster's, settled when the cluster is founded and carried in its records, so it is read from there on every other node" default:"majority"`
	Confirmations int            `help:"how many members besides its signer must confirm an admission or a revocation before it counts. 0 is a cluster one person runs; 1 asks a second node to agree with 'cheesecloth confirm' before anything changes. Clamped to one short of the membership, and settled when the cluster is founded like --quorum" default:"0"`
	AllowedIPs    []netip.Prefix `name:"allowed-ips" help:"extra networks reachable through this node (CIDR, comma separated); peers route them over the mesh via this node, which must forward. Must not overlap --overlay-net"`
	MTU           int            `help:"MTU of the wireguard interface" default:"1420"`
	// PersistentKeepalive is a time.Duration so kong accepts "25s"; 0 disables it.
	PersistentKeepalive time.Duration `help:"interval at which peers send keepalives, to keep NAT mappings open (e.g. 25s); 0 disables" default:"0"`
	SyncInterval        time.Duration `help:"how often this node reconciles its whole membership with one other member, which is what catches anything gossip missed. Lower converges sooner after a fault and costs more traffic; it is this node's own and need not match its peers" default:"90s"`
	NoEtcHosts          bool          `help:"disable writing of entries to /etc/hosts"`
	Userspace           bool          `help:"run wireguard inside the agent instead of the kernel module; the default wherever the kernel has none"`
	ControlSocket       string        `help:"unix socket for 'cheesecloth invite' and 'cheesecloth revoke' (default ${default_socket_dir}/<interface>.sock)"`

	stateDir string // where the cluster state is kept; empty means cluster.DefaultDir
}

// state is the directory this node's cluster state is kept in.
func (s *settings) state() string { return stateDirOr(s.stateDir) }

// config is the settings as the agent runs with them.
func (s *settings) config() agent.Config {
	return agent.Config{
		Interface:           s.Interface,
		Join:                s.Join,
		BindAddr:            s.BindAddr,
		ClusterPort:         s.ClusterPort,
		WireguardPort:       s.WireguardPort,
		OverlayNet:          s.OverlayNet,
		Quorum:              trust.QuorumRule(s.Quorum),
		Confirmations:       s.Confirmations,
		AllowedIPs:          s.AllowedIPs,
		MTU:                 s.MTU,
		PersistentKeepalive: s.PersistentKeepalive,
		SyncInterval:        s.SyncInterval,
		NoEtcHosts:          s.NoEtcHosts,
		Userspace:           s.Userspace,
		ControlSocket:       s.ControlSocket,
		StateDir:            s.stateDir,
	}
}

// check is what must hold of the settings, however they are going to be
// used. It is not named Validate so that kong calls it only through the
// commands that embed it, which have their own checks to make as well.
func (s *settings) check() error { return s.config().Check() }

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

// flags are the settings a config file may hold, as kong declares them: each
// flag's name and the value it holds in s, in declaration order. The interface
// is one of them, since a file describes one interface and has to say which;
// the help flag kong adds is not.
func (s *settings) flags() ([]*kong.Flag, error) {
	k, err := kong.New(s, varsFor("", ""))
	if err != nil {
		return nil, fmt.Errorf("reading the flag declarations: %w", err)
	}
	return slices.DeleteFunc(k.Model.Flags, func(f *kong.Flag) bool { return f.Name == "help" }), nil
}

// setting is one entry of a config file section: a flag name and its value
// as the file spells it.
type setting struct {
	name  string
	value any
}

// entries are what a config file holds for s: every flag whose value
// is not its default, in declaration order, spelled as the flag is parsed.
// They are derived from the flag declarations, so what the agent runs with
// and what the file may hold cannot drift apart.
func (s *settings) entries() ([]setting, error) {
	def, err := defaultSettings()
	if err != nil {
		return nil, err
	}
	flags, err := s.flags()
	if err != nil {
		return nil, err
	}
	defaults, err := def.flags()
	if err != nil {
		return nil, err
	}
	var out []setting
	for i, f := range flags {
		v := f.Target.Interface()
		if reflect.DeepEqual(v, defaults[i].Target.Interface()) {
			continue
		}
		if fv := fileValue(v); fv != nil {
			out = append(out, setting{f.Name, fv})
		}
	}
	return out, nil
}

// fileValue is v as the config file spells it, which is how the flag parses
// it: a value that parses from text is written as text, a network with its
// host bits cleared, a list element by element. An empty list is nothing.
func fileValue(v any) any {
	switch x := v.(type) {
	case netip.Prefix:
		return x.Masked().String()
	case fmt.Stringer:
		return x.String()
	}
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Slice {
		if rv.Len() == 0 {
			return nil
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = fileValue(rv.Index(i).Interface())
		}
		return out
	}
	return v
}
