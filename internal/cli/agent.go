package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
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

// AgentCmd is the long-running daemon: it joins the cluster and keeps the
// wireguard interface and /etc/hosts in step with the membership.
type AgentCmd struct {
	settings `embed:""`
	JoinKey  string `help:"invitation token from 'cheesecloth invite' on a member, needed only the first time this node joins"`

	addrs func(skip string) []net.Addr // lists this host's candidate addresses; nil means the interfaces
}

func (a *AgentCmd) Validate() error {
	if a.JoinKey != "" && len(a.Join) == 0 {
		return fmt.Errorf("--join-key needs --join to say which member to enrol with")
	}
	return a.check()
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

// settleOverlayNet decides which network this node allocates addresses in and
// keeps it: what the command line or config file says, then what the cluster
// says (the welcome for a node just enrolled, the state file for one that
// already was a member), then the default for a new cluster. An explicit value
// wins, so a cluster can be renumbered by giving every node the new one, but
// until every node has it this node stands alone, and it is told so.
func (a *AgentCmd) settleOverlayNet(clusterNet netip.Prefix) error {
	switch {
	case !a.OverlayNet.IsValid() && clusterNet.IsValid():
		a.OverlayNet = clusterNet
		slog.Debug("overlay network taken from the cluster", "net", a.OverlayNet)
	case !a.OverlayNet.IsValid():
		a.OverlayNet = DefaultOverlayNet
		slog.Debug("overlay network not given anywhere; using the default", "net", a.OverlayNet)
	default:
		a.OverlayNet = a.OverlayNet.Masked()
		if clusterNet.IsValid() && a.OverlayNet != clusterNet {
			slog.Warn("the overlay network given here is not the one the cluster uses; this node has no peers until every node is given the same one",
				"given", a.OverlayNet, "cluster", clusterNet)
		}
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

// agentDeps are the parts of the agent that touch the machine: the host's
// name, the wireguard interface, the cluster and the control socket. Run
// supplies the real ones, so that serve, which is the wiring itself, can be
// driven by a test without a kernel interface or a socket.
type agentDeps struct {
	hostname   func() (string, error)
	newWG      func(wg.Config) (wgDevice, error)
	newCluster func(cluster.Config) (agentCluster, error)
	newHosts   func(iface string) hostsWriter
	listen     func(socket string, h control.Handler) (controlServer, error)
}

// machineDeps drive the machine itself.
func machineDeps() agentDeps {
	return agentDeps{
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
		newHosts: func(iface string) hostsWriter { return hostsFor(iface) },
		listen: func(socket string, h control.Handler) (controlServer, error) {
			s, err := control.Listen(socket, h)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
	}
}

// Run runs the agent until SIGTERM/SIGINT or ctx is done, reporting to the
// service manager through n.
func (a *AgentCmd) Run(ctx context.Context, n notify.Notifier) error {
	ctx, cancelSignals := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer cancelSignals()
	return a.serve(ctx, n, machineDeps())
}

// serve wires up cluster, wireguard and the hosts file, joins the cluster and
// runs the agent loop until ctx is done.
func (a *AgentCmd) serve(ctx context.Context, n notify.Notifier, d agentDeps) error {
	hostname, err := d.hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %w", err)
	}
	ctx, stop := context.WithCancel(ctx) // a leave request stops the agent the same way a signal does
	defer stop()

	boot, err := cluster.Load(a.state(), a.Interface)
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
	host, err := boot.Host()
	if err != nil {
		return err
	}
	overlayAddr, ok := overlay.Addr(a.OverlayNet, host)
	if !ok {
		return fmt.Errorf("this node's overlay slot %d does not fit in %s; is --overlay-net the same on every node?", host, a.OverlayNet)
	}
	slog.Debug("assigned overlay address", "addr", overlayAddr, "slot", host)
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
	// what peers learn about us: name, overlay address, wireguard key, routes
	localNode := &overlay.Node{Name: hostname, Meta: overlay.Meta{OverlayAddr: overlayAddr, PubKey: wgstate.PublicKey(), AllowedIPs: masked(a.AllowedIPs)}}

	cl, err := d.newCluster(cluster.Config{
		StateDir: a.state(), StateName: a.Interface, BindAddr: a.BindAddr, AdvertiseAddr: advertise, BindPort: a.ClusterPort,
		OverlayNet: a.OverlayNet, LocalNode: localNode, Boot: boot,
	})
	if err != nil {
		return fmt.Errorf("creating cluster: %w", err)
	}

	leave := &leaving{stop: stop, done: make(chan struct{})}
	ctl, err := d.listen(socketFor(a.Interface, a.ControlSocket), agentControl{cluster: cl, leaving: leave})
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

	loopErr := a.loop(ctx, peerc, cl, wgstate, hostsFile, n)
	return errors.Join(loopErr, a.forget(leave))
}

// forget deletes this node's state once a leave has torn everything down, so
// nothing of the cluster it has left is kept.
func (a *AgentCmd) forget(l *leaving) error {
	if !l.requested.Load() {
		return nil
	}
	slog.Info("forgetting the cluster", "interface", a.Interface)
	l.err = cluster.Forget(a.state(), a.Interface) // read by the operator waiting on the control socket
	return l.err
}

// bootstrap settles this node's membership before it joins: a node that is
// already enrolled carries on, --join-key enrols it with one of the --join
// members, and a configured overlay network with no state to go with it makes
// it the root of a new cluster. It returns the addresses to join the gossip
// ring at; a node it leaves unenrolled has nothing to act on and idles.
func (a *AgentCmd) bootstrap(ctx context.Context, boot *cluster.Bootstrap, hostname string) ([]string, error) {
	switch {
	case boot.Enrolled():
		if a.JoinKey != "" {
			slog.Info("already a member of a cluster; ignoring --join-key")
		}
		return a.Join, nil
	case a.JoinKey != "":
		w, member, err := a.enrol(ctx, boot.Identity, hostname)
		if err != nil {
			return nil, err
		}
		boot.Enrol(w.Root, w.Records, w.OverlayNet)
		slog.Info("enrolled in cluster", "root", w.Root.Short(), "via", w.GossipAddr, "member", member.Short())
		return []string{w.GossipAddr}, nil
	case a.OverlayNet.IsValid():
		boot.InitRoot(hostname)
		slog.Info("initialised a new cluster", "root", boot.Root.Short(), "overlay-net", a.OverlayNet)
		return a.Join, nil
	default:
		return nil, nil
	}
}

// idle waits for a stop signal without configuring anything: this node is not
// a member and was given nothing to act on. Exiting with an error instead
// would leave the service manager restarting the agent until somebody
// configures it, which is noise rather than news.
func (a *AgentCmd) idle(ctx context.Context, n notify.Notifier) error {
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

// enrol tries each --join member in turn with the join key, returning the
// welcome and the identity of the member that admitted us.
func (a *AgentCmd) enrol(ctx context.Context, id *trust.Identity, name string) (*enrol.Welcome, trust.PublicKey, error) {
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

// enrolAddrs are the --join members as ip:port, defaulting to the cluster
// port. It is the rule the gossip ring uses for the addresses it is joined at,
// so that a member is named the same way whether this node is enrolling with
// it or rejoining it.
func (a *AgentCmd) enrolAddrs() []string {
	return cluster.WithPort(a.Join, a.ClusterPort)
}
