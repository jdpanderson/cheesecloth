// Package agent is the long-running daemon: it settles this node's
// membership, joins the cluster and keeps the wireguard interface and the
// hosts file in step with the membership. See docs/design.md.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v6"
	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/enrol"
	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/jdpanderson/cheesecloth/internal/wg"
)

// Config is what the agent runs with. The command line and the config file
// fill it in; a zero field means what its comment says.
type Config struct {
	Interface     string       // the wireguard interface to create and manage
	Join          []string     // members to join at, each a host or address with an optional port
	JoinKey       string       // invitation token, needed only the first time this node joins
	BindAddr      netip.Addr   // where cluster traffic is bound; a wildcard advertises an address of its family
	ClusterPort   int          // UDP port for gossip and enrolment
	WireguardPort int          // UDP port for wireguard
	OverlayNet    netip.Prefix // where addresses are allocated; zero takes the cluster's, and starts no cluster
	// Quorum is how many members must agree on the membership before the
	// records that led to it are discarded. It is the cluster's, settled when
	// the cluster is founded, so it is read here only by the node that founds
	// one; every other node takes it from the records.
	Quorum     trust.QuorumRule
	AllowedIPs []netip.Prefix // extra networks reachable through this node
	MTU        int
	// PersistentKeepalive is the interval at which peers send keepalives; 0 disables them.
	PersistentKeepalive time.Duration
	NoEtcHosts          bool   // leave the hosts file alone
	Userspace           bool   // run wireguard in this process even where the kernel could
	ControlSocket       string // the operator socket; empty means control.DefaultSocket(Interface)
	StateDir            string // where the state file is kept; empty means cluster.DefaultDir
}

// Check is what must hold of a configuration, however it is going to be
// used. An overlay network given here is checked now; one that comes from
// the cluster is checked once it is known, in Run.
func (c Config) Check() error {
	if c.JoinKey != "" && len(c.Join) == 0 {
		return fmt.Errorf("--join-key needs --join to say which member to enrol with")
	}
	if c.OverlayNet.IsValid() {
		if err := checkOverlayNet(c.OverlayNet.Masked(), c.AllowedIPs); err != nil {
			return err
		}
	}
	if c.Quorum != "" {
		if err := c.Quorum.Check(); err != nil {
			return err
		}
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("unsupported MTU %d; must be between 576 and 65535", c.MTU)
	}
	if ka := c.PersistentKeepalive; ka != 0 && (ka < time.Second || ka > 65535*time.Second || ka%time.Second != 0) {
		return fmt.Errorf("unsupported persistent keepalive %s; must be whole seconds between 1s and 65535s", ka)
	}
	return nil
}

// checkOverlayNet is what must hold of the overlay network once it is known,
// whether it came from the command line, the cluster or the default.
func checkOverlayNet(overlayNet netip.Prefix, allowedIPs []netip.Prefix) error {
	if overlay.MaxHost(overlayNet) < 2 {
		return fmt.Errorf("overlay network %s has no room for two nodes", overlayNet)
	}
	for _, p := range allowedIPs {
		if p.Overlaps(overlayNet) {
			return fmt.Errorf("--allowed-ips %s overlaps the overlay network %s", p, overlayNet)
		}
	}
	return nil
}

// stateDir is where the state file is kept.
func (c Config) stateDir() string {
	if c.StateDir == "" {
		return cluster.DefaultDir
	}
	return c.StateDir
}

// socket is the control socket the agent answers on.
func (c Config) socket() string {
	if c.ControlSocket == "" {
		return control.DefaultSocket(c.Interface)
	}
	return c.ControlSocket
}

// agent is a configuration being run. The overlay network is settled in
// place once the cluster has been asked.
type agent struct {
	Config

	addrs func(skip string) []net.Addr // lists this host's candidate addresses; nil means the interfaces
}

// Run runs the agent with cfg until ctx is done, reporting to the service
// manager through n.
func Run(ctx context.Context, cfg Config, n notify.Notifier) error {
	return (&agent{Config: cfg}).serve(ctx, n, machineDeps())
}

// settleOverlayNet decides which network this node allocates addresses in and
// keeps it: what the command line or config file says, else the cluster's,
// which the bootstrap knows for every member (the welcome for a node just
// enrolled, the state file for one that already was). An explicit value wins,
// so a cluster can be renumbered by giving every node the new one, but until
// every node has it this node stands alone, and it is told so.
func (a *agent) settleOverlayNet(clusterNet netip.Prefix) error {
	if !a.OverlayNet.IsValid() {
		a.OverlayNet = clusterNet
		slog.Debug("overlay network taken from the cluster", "net", a.OverlayNet)
		return checkOverlayNet(a.OverlayNet, a.AllowedIPs)
	}
	a.OverlayNet = a.OverlayNet.Masked()
	if a.OverlayNet != clusterNet {
		slog.Warn("the overlay network given here is not the one the cluster uses; this node has no peers until every node is given the same one",
			"given", a.OverlayNet, "cluster", clusterNet)
	}
	return checkOverlayNet(a.OverlayNet, a.AllowedIPs)
}

// agentCluster is everything the agent drives a cluster through: the loop's
// part of it, the join, and what the control socket asks of it.
type agentCluster interface {
	clusterController
	membership
	Join(addrs []string) error
}

var _ agentCluster = (*cluster.Cluster)(nil)

// wgDevice is the wireguard interface as the agent uses it: the loop's part,
// plus the public key peers are told about.
type wgDevice interface {
	wgController
	PublicKey() string
}

// controlServer is the control socket, which the agent only ever closes.
type controlServer interface{ Close() }

// deps are the parts of the agent that touch the machine: the host's name,
// the wireguard interface, the cluster and the control socket. Run supplies
// the real ones, so that serve, which is the wiring itself, can be driven by
// a test without a kernel interface or a socket.
type deps struct {
	hostname   func() (string, error)
	newWG      func(wg.Config) (wgDevice, error)
	newCluster func(cluster.Config) (agentCluster, error)
	newHosts   func(iface string) hostsWriter
	listen     func(socket string, h control.Handler) (controlServer, error)
}

// machineDeps drive the machine itself.
func machineDeps() deps {
	return deps{
		hostname: os.Hostname,
		newWG: func(cfg wg.Config) (wgDevice, error) {
			s, err := wg.New(cfg)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
		newCluster: func(cfg cluster.Config) (agentCluster, error) {
			c, err := cluster.New(cfg)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		newHosts: func(iface string) hostsWriter { return HostsFor(iface) },
		listen: func(socket string, h control.Handler) (controlServer, error) {
			s, err := control.Listen(socket, h)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
	}
}

// serve wires up cluster, wireguard and the hosts file, joins the cluster and
// runs the agent loop until ctx is done.
func (a *agent) serve(ctx context.Context, n notify.Notifier, d deps) error {
	hostname, err := d.hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %w", err)
	}
	ctx, stop := context.WithCancel(ctx) // a leave request stops the agent the same way a signal does
	defer stop()

	boot, err := cluster.Load(a.stateDir(), a.Interface)
	if err != nil {
		return err
	}

	joinAddrs, err := a.bootstrap(ctx, boot, hostname)
	if err != nil {
		return err
	}
	if !boot.Enrolled() {
		return a.idle(ctx, n)
	}

	advertise, err := a.advertiseAddr()
	if err != nil {
		return err
	}

	if err = a.settleOverlayNet(boot.OverlayNet); err != nil {
		return err
	}
	adm, err := boot.Assigned()
	if err != nil {
		return err
	}
	overlayAddr, ok := overlay.Addr(a.OverlayNet, adm.Host)
	if !ok {
		return fmt.Errorf("this node's overlay slot %d does not fit in %s; is --overlay-net the same on every node?", adm.Host, a.OverlayNet)
	}
	slog.Debug("assigned overlay address", "addr", overlayAddr, "slot", adm.Host, "name", adm.Name)
	wgstate, err := d.newWG(wg.Config{
		Interface:           a.Interface,
		Port:                a.WireguardPort,
		OverlayAddr:         overlayAddr,
		MTU:                 a.MTU,
		PersistentKeepalive: a.PersistentKeepalive,
		Userspace:           a.Userspace,
	})
	if err != nil {
		return fmt.Errorf("instantiating wireguard controller: %w", err)
	}
	// Where the kernel has wireguard, asking for the interface is what creates
	// it, so from here on a failure would leave one behind that no agent is
	// driving. The loop takes it over once it runs, and downs it itself.
	running := false
	defer func() {
		if running {
			return
		}
		if derr := wgstate.DownInterface(); derr != nil {
			slog.Warn("could not remove the interface after a failed start", "iface", a.Interface, "err", derr)
		}
	}()
	// what peers learn about us: name, overlay address, wireguard key, routes.
	// The name is the admitted one, not this host's current hostname, which is
	// what the cluster goes by and what renaming the host must not change.
	localNode := &overlay.Node{Name: adm.Name, Meta: overlay.Meta{OverlayAddr: overlayAddr, PubKey: wgstate.PublicKey(), AllowedIPs: masked(a.AllowedIPs)}}

	cl, err := d.newCluster(cluster.Config{
		StateDir: a.stateDir(), StateName: a.Interface, BindAddr: a.BindAddr, AdvertiseAddr: advertise, BindPort: a.ClusterPort,
		OverlayNet: a.OverlayNet, LocalNode: localNode, Boot: boot,
	})
	if err != nil {
		return fmt.Errorf("creating cluster: %w", err)
	}

	leave := &leaving{stop: stop, done: make(chan struct{})}
	ctl, err := d.listen(a.socket(), controlHandler{cluster: cl, leaving: leave})
	if err != nil {
		cl.Leave()
		return err
	}
	defer ctl.Close() // answers a leave request once it has been carried out
	defer close(leave.done)

	hostsFile := d.newHosts(a.Interface)

	// Keep trying to join until it works or we are told to stop; a node that gives
	// up would need a manual restart, which is worse than a noisy log.
	peerc := cl.Members() // avoid deadlocks by starting before join
	if _, err := backoff.Retry(ctx,
		func() (struct{}, error) { return struct{}{}, cl.Join(joinAddrs) },
		backoff.WithMaxElapsedTime(0),
		backoff.WithNotify(func(err error, dur time.Duration) {
			slog.Error("could not join cluster, retrying", "err", err, "in", dur)
		}),
	); err != nil {
		cl.Leave()
		if ctx.Err() != nil {
			slog.Info("terminating")
			return a.forget(leave)
		}
		return fmt.Errorf("joining cluster: %w", err) // not reached today: the retry gives up only when ctx does
	}

	running = true
	loopErr := a.loop(ctx, peerc, cl, wgstate, hostsFile, n)
	return errors.Join(loopErr, a.forget(leave))
}

// forget deletes this node's state once a leave has torn everything down, so
// nothing of the cluster it has left is kept.
func (a *agent) forget(l *leaving) error {
	if !l.requested.Load() {
		return nil
	}
	slog.Info("forgetting the cluster", "interface", a.Interface)
	l.err = cluster.Forget(a.stateDir(), a.Interface) // read by the operator waiting on the control socket
	return l.err
}

// bootstrap settles this node's membership before it joins: a node that is
// already enrolled carries on, a join key enrols it with one of the members
// to join, and a configured overlay network with no state to go with it makes
// it the root of a new cluster. It returns the addresses to join the gossip
// ring at; a node it leaves unenrolled has nothing to act on and idles.
func (a *agent) bootstrap(ctx context.Context, boot *cluster.Bootstrap, hostname string) ([]string, error) {
	switch {
	case boot.Enrolled():
		if a.JoinKey != "" {
			slog.Info("already a member of a cluster; ignoring --join-key")
		}
		return a.Join, nil
	case a.JoinKey != "":
		name, err := nodeName(hostname)
		if err != nil {
			return nil, err
		}
		w, member, err := a.enrol(ctx, boot.Identity, name)
		if err != nil {
			return nil, err
		}
		boot.Enrol(w.Records, w.OverlayNet, w.Anchor)
		slog.Info("enrolled in cluster", "members", len(w.Anchor.Members), "via", w.GossipAddr, "member", member.Short())
		return []string{w.GossipAddr}, nil
	case a.OverlayNet.IsValid():
		name, err := nodeName(hostname)
		if err != nil {
			return nil, err
		}
		quorum := a.Quorum
		if quorum == "" {
			quorum = trust.QuorumMajority
		}
		boot.InitRoot(name, a.OverlayNet.Masked(), quorum)
		slog.Info("initialised a new cluster", "identity", boot.Identity.Public().Short(), "overlay-net", boot.OverlayNet, "quorum", quorum)
		if quorum != trust.QuorumMajority {
			slog.Warn("this cluster is founded with a quorum below a majority; a cluster split in two can then "+
				"agree two different memberships and never merge them again. It is the cluster's for good",
				"quorum", quorum)
		}
		return a.Join, nil
	default:
		return nil, nil
	}
}

// nodeName is the name this host asks a cluster for: the first label of its
// hostname, lowercased. The rest of a fully qualified name is dropped rather
// than refused, since a host is commonly named that way and a cluster's names
// are one label; what is left has to be a name a node may hold.
func nodeName(hostname string) (string, error) {
	name, _, _ := strings.Cut(strings.ToLower(hostname), ".")
	if err := trust.CheckName(name); err != nil {
		return "", fmt.Errorf("this host cannot be named in a cluster: %w; rename it or set its hostname to a plain name", err)
	}
	return name, nil
}

// idle waits for a stop signal without configuring anything: this node is not
// a member and was given nothing to act on. Exiting with an error instead
// would leave the service manager restarting the agent until somebody
// configures it, which is noise rather than news.
func (a *agent) idle(ctx context.Context, n notify.Notifier) error {
	slog.Warn("not a member of any cluster and nothing to act on; waiting for a restart with an overlay network to start one, or --join HOST --join-key TOKEN to enrol",
		"interface", a.Interface)
	if err := n.Ready("waiting to be configured"); err != nil {
		slog.Warn("could not notify the service manager", "err", err)
	}
	<-ctx.Done()
	slog.Info("terminating")
	if err := n.Stopping(); err != nil {
		slog.Warn("could not notify the service manager", "err", err)
	}
	return nil
}

// masked is the prefixes with their host bits cleared, as routes are written.
func masked(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.Masked()
	}
	return out
}

// enrol tries each member to join in turn with the join key, returning the
// welcome and the identity of the member that admitted us.
func (a *agent) enrol(ctx context.Context, id *trust.Identity, name string) (*enrol.Welcome, trust.PublicKey, error) {
	var lastErr error
	for _, addr := range a.enrolAddrs() {
		w, member, err := cluster.Enrol(ctx, addr, a.JoinKey, id, name)
		if err == nil {
			return w, member, nil
		}
		lastErr = fmt.Errorf("enrolling with %s: %w", addr, err)
		slog.Warn("enrolment attempt failed", "member", addr, "err", err)
	}
	return nil, trust.PublicKey{}, lastErr
}

// enrolAddrs are the members to join as ip:port, defaulting to the cluster
// port. It is the rule the gossip ring uses for the addresses it is joined at,
// so that a member is named the same way whether this node is enrolling with
// it or rejoining it.
func (a *agent) enrolAddrs() []string {
	return cluster.WithPort(a.Join, a.ClusterPort)
}
