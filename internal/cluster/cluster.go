// Package cluster manages membership: a memberlist gossip ring whose transport
// authenticates nodes by identity, a signed admission set, and enrolment of new
// nodes with invitation tokens. See docs/membership.md.
package cluster

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/enrol"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/tally"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// Config is what New needs.
type Config struct {
	StateDir      string       // where the state file lives; DefaultDir when empty
	StateName     string       // the state file is named after it; the wireguard interface in practice
	BindAddr      netip.Addr   // may be a wildcard
	AdvertiseAddr netip.Addr   // what other nodes are told to reach us at
	BindPort      int          // gossip and enrolment, UDP (QUIC); 0 picks a free port
	OverlayNet    netip.Prefix // overlay addresses are admission slots inside it
	LocalNode     *overlay.Node
	Boot          *Bootstrap // identity, trust and last known peers; owned by the cluster from here on
	// Memberlist builds the base memberlist config; nil means the WAN profile.
	// Tests use it for faster timers.
	Memberlist func() *memberlist.Config
}

// Cluster is this node's membership of a running cluster: the gossip ring, the
// trusted record set, enrolment of new nodes and the persisted state.
type Cluster struct {
	statePath   string
	ml          atomic.Pointer[memberlist.Memberlist]
	local       *overlay.Node
	id          *trust.Identity
	set         *trust.Set
	overlay     netip.Prefix
	port        int // this node's gossip port, and the one assumed for a peer address given without one
	tokens      *enrol.TokenStore
	queue       *memberlist.TransmitLimitedQueue
	enrolSrv    *enrol.Server
	boot        *Bootstrap
	resume      []string   // where the peers remembered at startup were last reached
	seenMembers bool       // whether a snapshot has ever held a peer; guarded by stateMu
	stateMu     sync.Mutex // guards boot and its saving
	events      chan memberEvent
	membersMu   sync.Mutex
	members     map[string]member // what memberlist last reported, by name
	changed     chan struct{}     // one-slot signal that the member list changed
	done        chan struct{}     // closed by Leave
	routines    sync.WaitGroup    // forwardEvents and watch; Leave waits for them
	leaveOnce   sync.Once
	subMu       sync.Mutex
	subs        []chan []overlay.Node // Members channels; fed by watch, closed by Leave
	left        bool                  // set by Leave under subMu; Members returns closed channels from then on
	// badState counts the records peers offer that this node will not take, so
	// a peer re-offering one at every sync is reported at this node's rate.
	badState tally.Counter
}

// profile builds the base memberlist config a cluster runs with: what the
// caller gave, or the WAN profile, whose timings decide how long a node that
// left is kept out when the refute of its own death goes astray.
func profile(cfg Config) func() *memberlist.Config {
	if cfg.Memberlist != nil {
		return cfg.Memberlist
	}
	return memberlist.DefaultWANConfig
}

// New creates a Cluster for an enrolled node and starts gossiping and accepting
// enrolments; it is ready to be joined.
func New(cfg Config) (*Cluster, error) {
	if cfg.Boot == nil || cfg.Boot.Identity == nil || cfg.LocalNode == nil || !cfg.OverlayNet.IsValid() {
		return nil, fmt.Errorf("cluster: bootstrap, local node and overlay network are required")
	}
	id := cfg.Boot.Identity
	// the agent has already asked the bootstrap which admission this node
	// holds, so the set is built and every signature in it is checked once
	set := cfg.Boot.Set()
	if !set.Valid(id.Public()) {
		return nil, fmt.Errorf("this node (%s) is not a member of the cluster rooted at %s", id.Public().Short(), cfg.Boot.Root.Short())
	}

	switch adm, want, err := assigned(set, cfg.OverlayNet, id.Public(), set.Conflicts()); {
	case err != nil:
		return nil, err
	case want != cfg.LocalNode.OverlayAddr:
		return nil, fmt.Errorf("local overlay address %s is not the assigned %s", cfg.LocalNode.OverlayAddr, want)
	case cfg.LocalNode.Name != adm.Name:
		return nil, fmt.Errorf("this node is set up as %q but is admitted as %q; peers go by the admission", cfg.LocalNode.Name, adm.Name)
	}

	cfg.Boot.OverlayNet = cfg.OverlayNet // what the cluster runs with is what a restart reads back

	// bind our ephemeral wireguard key, overlay address and routes to our identity
	cfg.LocalNode.Identity = id.Public()
	cfg.LocalNode.Signature = id.Sign(trust.MetaDigest(cfg.LocalNode.Name, cfg.LocalNode.OverlayAddr, cfg.LocalNode.PubKey, cfg.LocalNode.AllowedIPs))

	// Metadata that does not fit is not sent, and a node peers have no
	// metadata for is one they ignore: it would join the ring and have no
	// peers at all. The metadata does not change after this, so checking it
	// once here is checking it for good.
	if _, err := cfg.LocalNode.Encode(memberlist.MetaMaxSize); err != nil {
		return nil, fmt.Errorf("%w: %d advertised networks is more than this node can tell its peers about, and a node whose metadata they cannot read is ignored",
			err, len(cfg.LocalNode.AllowedIPs))
	}

	dir := cfg.StateDir
	if dir == "" {
		dir = DefaultDir
	}
	c := &Cluster{
		statePath: statePath(dir, cfg.StateName),
		local:     cfg.LocalNode,
		id:        id,
		set:       set,
		overlay:   cfg.OverlayNet,
		tokens:    enrol.NewTokenStore(nil),
		events:    make(chan memberEvent, 16),
		members:   map[string]member{},
		changed:   make(chan struct{}, 1),
		done:      make(chan struct{}),
		boot:      cfg.Boot,
		resume:    gossipAddrs(cfg.Boot.Peers),
	}
	c.queue = &memberlist.TransmitLimitedQueue{RetransmitMult: 3, NumNodes: func() int {
		if ml := c.ml.Load(); ml != nil {
			return ml.NumMembers()
		}
		return 1
	}}

	// enrolment shares the gossip listener under its own ALPN; the server is
	// complete, with the bound port in its gossip address, before accepting starts
	transport, err := newQUICTransport(cfg.BindAddr, cfg.BindPort, id, set, func(conn enrol.Conn) { c.enrolSrv.Handle(conn) })
	if err != nil {
		return nil, err
	}
	c.port = transport.port()
	c.enrolSrv = &enrol.Server{
		Identity: id, Tokens: c.tokens, Root: cfg.Boot.Root, Admit: c.admit, OverlayNet: cfg.OverlayNet, Records: set.Records,
		GossipAddr: net.JoinHostPort(cfg.AdvertiseAddr.String(), strconv.Itoa(c.port)),
	}
	transport.start()
	logger := slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)

	mlConfig := profile(cfg)()
	mlConfig.Name = cfg.LocalNode.Name
	mlConfig.Logger = logger
	mlConfig.Transport = transport
	mlConfig.AdvertiseAddr = cfg.AdvertiseAddr.String()
	mlConfig.AdvertisePort = c.port
	mlConfig.BindPort = c.port // the transport binds; memberlist assumes this port for a peer that advertised none
	mlConfig.UDPBufferSize = maxDatagram
	mlConfig.Delegate = c
	mlConfig.Conflict = c
	mlConfig.Events = memberEvents{c}

	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		_ = transport.Shutdown()
		return nil, fmt.Errorf("creating memberlist: %w", err)
	}
	c.ml.Store(ml)

	c.routines.Add(2)
	go c.forwardEvents()
	go c.watch()

	c.persist()
	return c, nil
}

// Identity is this node's identity.
func (c *Cluster) Identity() trust.PublicKey { return c.id.Public() }

// Trust is the membership set.
func (c *Cluster) Trust() *trust.Set { return c.set }

// Invite mints an enrolment token valid for ttl and uses joiners.
func (c *Cluster) Invite(ttl time.Duration, uses int) (string, error) {
	return c.tokens.Mint(ttl, uses)
}

// persist saves the bootstrap under stateMu.
func (c *Cluster) persist() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.saveState()
}

// saveState persists the bootstrap, logging rather than failing on error: the
// state only speeds up the next start. Callers hold stateMu.
func (c *Cluster) saveState() {
	// what a cut has withdrawn goes here rather than as records change: a
	// record is dropped once, on its way to the file, and the set is asked for
	// its contents afterwards
	if dropped := c.set.Sweep(); dropped > 0 {
		slog.Info("dropped membership records a revocation had withdrawn", "records", dropped)
	}
	c.boot.Records = c.set.Records()
	c.boot.Signers = c.set.SignerStates()
	if err := c.boot.save(c.statePath); err != nil {
		slog.Warn("could not save cluster state", "path", c.statePath, "err", err)
	}
}

// Join contacts addrs to join the cluster; given none, it tries the peers
// remembered from the last run, each on the port it was last reached at,
// which need not be this node's. An address without a port is assumed to
// listen on this node's cluster port. It fails if there were addresses to try
// and none could be joined. No addresses and no remembered peers is a cluster
// of one, which is not an error.
//
// The remembered peers are the ones this node started with, not what it knows
// now: the membership replaces those as soon as there is one, and a node that
// has not reached anybody yet knows nobody, so reading them here would leave
// it with nothing to try.
func (c *Cluster) Join(addrs []string) error {
	if len(addrs) == 0 {
		addrs = c.resume
	}
	if _, err := c.ml.Load().Join(WithPort(addrs, c.port)); err != nil {
		return fmt.Errorf("joining cluster: %w", err)
	}
	return nil
}

// gossipAddrs is where peers were last reached, each on its own port, which
// need not be ours.
func gossipAddrs(peers []overlay.Node) []string {
	addrs := make([]string, 0, len(peers))
	for _, n := range peers {
		addrs = append(addrs, n.GossipAddr())
	}
	return addrs
}

// WithPort is addrs with port added to every host or IP address that has none.
// An IPv6 address may arrive in brackets or without them; either way it leaves
// bracketed, once.
func WithPort(addrs []string, port int) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(strings.Trim(a, "[]"), strconv.Itoa(port))
		}
		out[i] = a
	}
	return out
}

// Leave saves the current state, leaves the cluster and stops Members. Safe to call more than once.
func (c *Cluster) Leave() {
	c.leaveOnce.Do(func() {
		c.persist()
		ml := c.ml.Load()
		if err := ml.Leave(10 * time.Second); err != nil {
			slog.Warn("could not announce leave to the cluster", "err", err)
		}
		if err := ml.Shutdown(); err != nil {
			slog.Warn("could not shut down memberlist", "err", err)
		}
		c.subMu.Lock() // under the lock, so nothing is added to routines from here on: see track
		close(c.done)
		c.subMu.Unlock()
		c.routines.Wait()
		c.subMu.Lock() // watch has stopped: nothing sends on these any more
		for _, ch := range c.subs {
			close(ch)
		}
		c.subs = nil
		c.left = true
		c.subMu.Unlock()
	})
}
