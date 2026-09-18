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
	"regexp"
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
	// Quorum is how many members must agree before a membership takes effect.
	// It is the cluster's, settled when the cluster is founded, so it is read
	// here only by the node that founds one; every other node takes it from
	// the records.
	Quorum trust.QuorumRule
	// Confirmations is how many members besides its signer must confirm a
	// record before it counts. Like Quorum it is the cluster's, settled when
	// the cluster is founded, so it is read here only by the node that founds
	// one; every other node takes it from the records.
	Confirmations int
	AllowedIPs    []netip.Prefix // extra networks reachable through this node
	MTU           int
	// PersistentKeepalive is the interval at which peers send keepalives; 0 disables them.
	PersistentKeepalive time.Duration
	// SyncInterval is how often this node reconciles its whole membership with
	// one other member. Records reach a member as they are signed; this is the
	// backstop for one that was unreachable just then, so it bounds how long a
	// node can hold a membership the cluster has moved past. 0 takes the default.
	SyncInterval  time.Duration
	NoEtcHosts    bool   // leave the hosts file alone
	Userspace     bool   // run wireguard in this process even where the kernel could
	ControlSocket string // the operator socket; empty means control.DefaultSocket(Interface)
	StateDir      string // where the state file is kept; empty means cluster.DefaultDir
}

// Check is what must hold of a configuration, however it is going to be
// used. An overlay network given here is checked now; one that comes from
// the cluster is checked once it is known, in Run.
func (c Config) Check() error {
	if err := CheckInterface(c.Interface); err != nil {
		return err
	}
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
	// The port is this node's and every peer's at once: an endpoint is the
	// peer's address with this port on it, which is why a cluster agrees on
	// one. Zero would have the kernel pick this node's and leave every
	// endpoint it installs pointing at port 0, and anything past 65535 is
	// truncated to a port nobody is listening on rather than refused.
	if c.WireguardPort < 1 || c.WireguardPort > 65535 {
		return fmt.Errorf("unsupported wireguard port %d; must be between 1 and 65535, and the same on every node", c.WireguardPort)
	}
	// Zero means something here that it does not mean above: peers learn this
	// port and remember it, so it need not be agreed, and asking the operating
	// system for a free one is a thing to do. Out of range the bind refuses it
	// either way, but not until the state has been read and the interface
	// created, so it is said here where every other setting is said.
	if c.ClusterPort < 0 || c.ClusterPort > 65535 {
		return fmt.Errorf("unsupported cluster port %d; must be between 0 and 65535, where 0 asks for a free one", c.ClusterPort)
	}
	if ka := c.PersistentKeepalive; ka != 0 && (ka < time.Second || ka > 65535*time.Second || ka%time.Second != 0) {
		return fmt.Errorf("unsupported persistent keepalive %s; must be whole seconds between 1s and 65535s", ka)
	}
	// Zero is not "off": a node that never reconciles keeps whatever it last
	// heard, and nothing would say so. It means "the default" here and is
	// filled in before the cluster sees it.
	if si := c.SyncInterval; si != 0 && (si < 5*time.Second || si > time.Hour) {
		return fmt.Errorf("unsupported sync interval %s; must be between 5s and 1h", si)
	}
	return nil
}

// ifaceMax is the longest an interface name may be. Linux allows fifteen
// characters -- IFNAMSIZ, less the terminator -- and refuses the device
// otherwise. The same limit holds everywhere, so that a configuration that
// runs on one platform runs on the rest.
const ifaceMax = 15

// ifaceName is one interface name: letters, digits, dots, dashes and
// underscores, starting with a letter or a digit.
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// CheckInterface reports whether name may be a node's wireguard interface.
// The name is more than the device's: it names the state file holding the
// node's identity and the control socket, and marks the agent's block in the
// hosts file. So it has to be one path element and nothing else -- a name
// carrying a separator would put the identity somewhere the operator never
// asked for, and one carrying a newline would split the hosts block, leaving a
// line no leave would clean up again. A name that is not one is refused rather
// than repaired, so that what runs is what was asked for.
//
// Every command that names an interface checks it, not just the ones that run
// an agent: the commands that only talk to one still name files after it.
func CheckInterface(name string) error {
	if name == "" {
		return errors.New("no interface name")
	}
	// the length is checked before the name is quoted into a message, since a
	// name that got this far may be anything at all
	if len(name) > ifaceMax {
		return fmt.Errorf("interface name is %d characters, and the most is %d", len(name), ifaceMax)
	}
	if !ifaceName.MatchString(name) {
		return fmt.Errorf("interface name %q is not one: it must be letters, digits, dots, dashes and "+
			"underscores, starting with a letter or a digit", name)
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
	every time.Duration                // how often a refused snapshot is stated again; zero means retryEvery
}

// retry is how often this node states a snapshot the interface would not take.
func (a *agent) retry() time.Duration {
	if a.every > 0 {
		return a.every
	}
	return retryEvery
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
		return a.idle(ctx, n, d)
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
		OverlayNet: a.OverlayNet, LocalNode: localNode, Boot: boot, SyncInterval: a.SyncInterval,
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
		// The invitation is spent and the cluster has agreed a membership
		// holding this node, so the enrolment is the cluster's as much as this
		// node's. Everything still to do here can fail -- the interface most of
		// all, on a host with no wireguard -- and a node that failed with the
		// enrolment still in memory would need inviting again while the cluster
		// went on holding a member that never came up. Kept here, that costs a
		// restart instead. A node founding a cluster has spent nothing and is
		// left to New, so that a first run which never came up does not settle
		// the overlay network and the quorum for good.
		if err := boot.Save(a.stateDir(), a.Interface); err != nil {
			return nil, fmt.Errorf("enrolled in the cluster but could not keep it: this node would have to be "+
				"invited again: %w", err)
		}
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
		boot.InitRoot(name, a.OverlayNet.Masked(), quorum, a.Confirmations)
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
func (a *agent) idle(ctx context.Context, n notify.Notifier, d deps) error {
	slog.Warn("not a member of any cluster and nothing to act on; waiting for a restart with an overlay network to start one, or --join HOST --join-key TOKEN to enrol",
		"interface", a.Interface)
	// The socket is opened even though every request will be refused. An agent
	// that is running and cannot help says so; one that opened nothing leaves
	// the operator reading "no agent is listening -- is it running?" about an
	// agent that is.
	if ctl, err := d.listen(a.socket(), idleHandler{iface: a.Interface}); err != nil {
		slog.Warn("could not open the control socket; commands will report that nothing is listening", "err", err)
	} else {
		defer ctl.Close()
	}
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

// idleHandler answers the control socket while this node is a member of
// nothing. Every request needs a cluster, so every one is refused -- but by an
// agent that is there and says what would give it one.
type idleHandler struct{ iface string }

func (h idleHandler) refuse(what string) error {
	return fmt.Errorf("cannot %s: this node is not a member of any cluster. Start it with --overlay-net "+
		"to found one, or --join HOST --join-key TOKEN to enrol in one (interface %s)", what, h.iface)
}

func (h idleHandler) Invite(time.Duration) (string, error) {
	return "", h.refuse("invite a node")
}

func (h idleHandler) Revoke(string) (control.RevokeResult, error) {
	return control.RevokeResult{}, h.refuse("revoke a node")
}

func (h idleHandler) Leave(bool) (control.LeaveResult, error) {
	return control.LeaveResult{}, h.refuse("leave the cluster")
}

func (h idleHandler) Pending() ([]control.PendingRecord, error) {
	return nil, h.refuse("list what is waiting to be confirmed")
}

func (h idleHandler) Confirm(string) (control.PendingRecord, error) {
	return control.PendingRecord{}, h.refuse("confirm a record")
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
