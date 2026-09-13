// Package cluster manages membership: a memberlist gossip ring whose transport
// authenticates nodes by identity, a signed admission set, and enrolment of new
// nodes with invitation tokens. See docs/membership.md.
package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/enrol"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	events      chan memberlist.NodeEvent
	changed     chan struct{}  // one-slot signal that the member list changed
	done        chan struct{}  // closed by Leave
	routines    sync.WaitGroup // forwardEvents and watch; Leave waits for them
	leaveOnce   sync.Once
	subMu       sync.Mutex
	subs        []chan []overlay.Node // Members channels; fed by watch, closed by Leave
	left        bool                  // set by Leave under subMu; Members returns closed channels from then on
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
	if cfg.Boot == nil || cfg.Boot.Identity == nil || cfg.LocalNode == nil {
		return nil, fmt.Errorf("cluster: bootstrap and local node are required")
	}
	id := cfg.Boot.Identity
	// the agent has already asked the bootstrap which admission this node
	// holds, so the set is built and every signature in it is checked once
	set := cfg.Boot.Set()
	if !set.Valid(id.Public()) {
		return nil, fmt.Errorf("this node (%s) is not a member of the cluster rooted at %s", id.Public().Short(), cfg.Boot.Root.Short())
	}

	switch adm, want, err := assigned(set, cfg.OverlayNet, id.Public()); {
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
		events:    make(chan memberlist.NodeEvent, 16),
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
	mlConfig.Events = &memberlist.ChannelEventDelegate{Ch: c.events}

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

// signingTime is the date to put on a record, refused if this node's clock is
// behind the last record it signed. Nothing is adjusted: a date is what a
// signer asserts, so the clock is what has to be fixed. A node whose clock ran
// fast has to wait for real time to reach what it already signed.
func (c *Cluster) signingTime() (time.Time, error) {
	now := time.Now()
	if last := c.set.LastSigned(c.id.Public()); now.Unix() < last {
		return time.Time{}, fmt.Errorf("this node's clock is %s behind the last record it signed; "+
			"check that it is synchronised", time.Unix(last, 0).Sub(now).Round(time.Second))
	}
	return now, nil
}

// Invite mints an enrolment token valid for ttl and uses joiners.
func (c *Cluster) Invite(ttl time.Duration, uses int) (string, error) {
	return c.tokens.Mint(ttl, uses)
}

// revoke signs a revocation of id and stores it. It keeps everything we have
// seen id sign, so the members it admitted keep their place and anything it
// signs from here on counts for nothing, whatever that record is dated.
//
// The number a record takes is read from the set and has to still be free
// when the record is stored, so stateMu is held across the whole of it, as
// admit holds it: a number this node used twice would void both records. It
// fails if the revocation does not take effect, which is what a revocation by
// a node the cluster no longer trusts does.
func (c *Cluster) revoke(id trust.PublicKey) (trust.Revocation, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	now, err := c.signingTime()
	if err != nil {
		return trust.Revocation{}, err
	}
	rev := trust.Revoke(c.id, id, c.set.NextSeq(c.id.Public()), c.set.SignedBy(id), now)
	if _, err := c.set.AddRevocation(rev); err != nil {
		return trust.Revocation{}, err
	}
	if c.set.Valid(id) {
		return trust.Revocation{}, fmt.Errorf("the revocation of %s has no effect; this node (%s) is no longer a member itself",
			id.Short(), c.id.Public().Short())
	}
	c.saveState() // before it goes out: a number handed to a peer must not be reused
	return rev, nil
}

// PruneResult is what a prune did, or would do: the identities it removes, how
// many records the set held before and after, and how much of the cluster this
// node could see while it decided.
type PruneResult struct {
	Identities []trust.PublicKey
	Before     int
	After      int
	Seen       int // members this node can reach, itself included
	Members    int // members the records hold
}

// manyIdentities is how many dead identities at once stop looking like the
// ordinary business of retiring nodes. cheesecloth is meant for a homelab, a
// few hundred nodes at the outside, so a cluster that has this many identities
// to drop has either been running a very long time or has had a member
// admitting identities of its own.
const manyIdentities = 100

// reach is how many members this node can currently reach, itself included,
// against how many the records hold. A destructive change decided on a node
// that can see far fewer is decided from records the rest of the cluster does
// not share, and what it removes the others may still need.
func (c *Cluster) reach() (seen, members int) {
	return len(c.snapshot()) + 1, c.set.MemberCount()
}

// warnIfBehind says so when this node cannot see the cluster it is about to
// change. Nothing is refused: only the operator knows whether the members it
// cannot reach are down for good, or merely unreachable from here.
func (c *Cluster) warnIfBehind() {
	if seen, members := c.reach(); seen < members {
		slog.Warn("this node can reach only some of the cluster; what it removes is decided from the records "+
			"it holds, and the members it cannot see may hold records it does not. "+
			"Check that the cluster is in step before changing it.",
			"reachable", seen, "members", members)
	}
}

// Prune signs and distributes a prune of every identity the set offers as
// prunable. With dry it signs nothing and only reports what a prune would
// take. stateMu is held for the same reason revoke holds it: the number the
// record takes has to still be free when it is stored.
func (c *Cluster) Prune(dry bool) (PruneResult, error) {
	c.warnIfBehind()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	res := PruneResult{Identities: c.set.Prunable(), Before: c.records()}
	res.Seen, res.Members = c.reach()
	res.After = res.Before
	if len(res.Identities) > manyIdentities {
		slog.Error("far more identities are out of the cluster than a cluster this size should have got "+
			"through. If retired nodes do not account for them, a member has been admitting identities of "+
			"its own, and a key it still holds can do it again. Rebuilding is the way back from that.",
			"identities", len(res.Identities), "members", res.Members)
	}
	if dry || len(res.Identities) == 0 {
		return res, nil
	}
	now, err := c.signingTime()
	if err != nil {
		return PruneResult{}, err
	}
	p := trust.SignPrune(c.id, res.Identities, c.set.NextSeq(c.id.Public()), now)
	if _, err := c.set.AddPrune(p); err != nil {
		return PruneResult{}, err
	}
	c.saveState() // before it goes out: a number handed to a peer must not be reused
	c.broadcast(recordMsg{Prune: &p})
	c.signalChanged()
	res.After = c.records()
	return res, nil
}

// records is how many records the set holds, of every kind, which is what the
// operator is shown before and after a prune. A prune reduces the admissions
// and adds one record of its own; the revocations stay, since they are what
// still says the pruned identities are out, and so do the earlier prunes.
func (c *Cluster) records() int {
	rs := c.set.Records()
	return len(rs.Admissions) + len(rs.Revocations) + len(rs.Prunes)
}

// Revoke signs and distributes a revocation of id. Nothing warns here about
// this node being out of touch: the node being revoked is usually the one that
// is gone, so the measure would fire on the ordinary case. What matters is
// whether the revocation withdraws records that were standing, and the set
// reports that where it can see it, on every node the record reaches.
func (c *Cluster) Revoke(id trust.PublicKey) error {
	rev, err := c.revoke(id)
	if err != nil {
		return err
	}
	c.broadcast(recordMsg{Revocation: &rev})
	c.signalChanged() // the revoked node drops out of Members at once
	return nil
}

// RevokeSelf revokes this node's own identity, so the cluster stops trusting
// it when it leaves for good, and hands the record to each member over a
// stream before returning: the node is about to stop, so the retransmit queue
// alone would likely lose it. It returns how many members took the record; a
// member that already has it refuses the connection, which is not an error.
func (c *Cluster) RevokeSelf() (int, error) {
	// the revocation keeps every record we have signed, so what this node
	// vouched for stands after it has gone
	rev, err := c.revoke(c.id.Public())
	if err != nil {
		return 0, err
	}
	msg, err := json.Marshal(recordMsg{Revocation: &rev})
	if err != nil {
		return 0, err
	}
	ml := c.ml.Load()
	told := 0
	for _, m := range ml.Members() {
		if m.Name == c.local.Name {
			continue
		}
		if err := ml.SendReliable(m, msg); err != nil {
			slog.Debug("could not hand the revocation to a member", "member", m.Name, "err", err)
			continue
		}
		told++
	}
	c.broadcast(recordMsg{Revocation: &rev}) // for members that were not reachable
	return told, nil
}

// admit is called by the enrolment server once a joiner has proven the token:
// it gives the joiner the lowest free overlay slot and signs its admission.
// Names identify nodes everywhere else, so one already held by another member
// is refused. Serialised under stateMu, as revoke is, so that two joiners
// cannot be handed the same slot and two records this node signs cannot take
// the same sequence number.
func (c *Cluster) admit(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
	if err := trust.CheckName(name); err != nil {
		return trust.Admission{}, trust.Records{}, err
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.set.NameTaken(name, joiner) {
		return trust.Admission{}, trust.Records{}, fmt.Errorf("a member named %q already exists", name)
	}
	var host uint64
	if cur, ok := c.set.Lookup(joiner); ok && c.set.Valid(joiner) {
		host = cur.Host // an identity enrolling again keeps its address
	} else {
		var err error
		if host, err = c.set.FreeHost(overlay.MaxHost(c.overlay)); err != nil {
			return trust.Admission{}, trust.Records{}, fmt.Errorf("%w in %s", err, c.overlay)
		}
	}
	now, err := c.signingTime()
	if err != nil {
		return trust.Admission{}, trust.Records{}, err
	}
	a := trust.Admit(c.id, joiner, name, host, c.set.NextSeq(c.id.Public()), now)
	if _, err := c.set.AddAdmission(a); err != nil {
		return trust.Admission{}, trust.Records{}, err
	}
	c.saveState() // before it goes out: a number handed to a peer must not be reused
	c.broadcast(recordMsg{Admission: &a})
	return a, c.set.Records(), nil
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
	c.boot.Records = c.set.Records()
	if err := c.boot.save(c.statePath); err != nil {
		slog.Warn("could not save cluster state", "path", c.statePath, "err", err)
	}
}

// assigned is the admission that decides who id is, and the overlay address it
// entitles id to. It fails if id is not a member, the slot does not fit the
// overlay net, or another member holds the slot with a stronger claim (see
// trust.Set.HostConflict).
func assigned(set *trust.Set, prefix netip.Prefix, id trust.PublicKey) (trust.Admission, netip.Addr, error) {
	if !set.Valid(id) {
		return trust.Admission{}, netip.Addr{}, fmt.Errorf("identity %s is not a member", id.Short())
	}
	adm, _ := set.Lookup(id)
	addr, ok := overlay.Addr(prefix, adm.Host)
	if !ok {
		return adm, netip.Addr{}, fmt.Errorf("overlay slot %d of %s does not fit in %s", adm.Host, adm.Name, prefix)
	}
	if other, clash := set.HostConflict(id); clash {
		return adm, netip.Addr{}, fmt.Errorf("overlay address %s of %s collides with %s, admitted earlier; %s must be enrolled again", addr, adm.Name, other.Name, adm.Name)
	}
	if other, clash := set.NameConflict(id); clash {
		return adm, netip.Addr{}, fmt.Errorf("the name %q is held by two members: %s was admitted earlier, so %s must be renamed and enrolled again",
			adm.Name, other.Identity.Short(), id.Short())
	}
	return adm, addr, nil
}

// verifyMeta checks a node's metadata: a valid member signed it, it goes by
// the name and the overlay address that member's admission gives it, and its
// wireguard key parses. A node that passes can be installed as a peer as is.
//
// The name is checked against the admission for the same reason the address
// is: a node signs its own metadata, so without it a member could take the
// name of another and every node would write that into its hosts file.
func verifyMeta(set *trust.Set, prefix netip.Prefix, n *overlay.Node) error {
	adm, want, err := assigned(set, prefix, n.Identity)
	if err != nil {
		return err
	}
	if n.Name != adm.Name {
		return fmt.Errorf("%s goes by %q but is admitted as %q", n.Identity.Short(), n.Name, adm.Name)
	}
	if n.OverlayAddr != want {
		return fmt.Errorf("%s claims overlay address %s but is assigned %s", n.Name, n.OverlayAddr, want)
	}
	if !trust.Verify(n.Identity, trust.MetaDigest(n.Name, n.OverlayAddr, n.PubKey, n.AllowedIPs), n.Signature) {
		return fmt.Errorf("metadata signature of %s does not verify", n.Name)
	}
	if _, err := wgtypes.ParseKey(n.PubKey); err != nil {
		return fmt.Errorf("wireguard key of %s: %w", n.Name, err)
	}
	return nil
}

// forwardEvents logs memberlist events about other nodes, learns their
// addresses, and coalesces the events into changed.
func (c *Cluster) forwardEvents() {
	defer c.routines.Done()
	for {
		var event memberlist.NodeEvent
		select {
		case <-c.done:
			return
		case event = <-c.events:
		}
		if event.Node.Name == c.local.Name {
			continue
		}
		switch event.Event {
		case memberlist.NodeJoin:
			slog.Info("node joined", "name", event.Node.Name, "addr", event.Node.Addr)
		case memberlist.NodeUpdate:
			slog.Info("node updated", "name", event.Node.Name, "addr", event.Node.Addr)
		case memberlist.NodeLeave:
			slog.Info("node left", "name", event.Node.Name, "addr", event.Node.Addr)
		}
		c.signalChanged()
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
		close(c.done)
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

// Members returns a channel that receives the current list of other verified
// nodes, metadata decoded, right away and then whenever the membership
// changes. A subscriber that falls behind gets the latest snapshot, not every
// one: bursts of changes coalesce. Nodes that fail verifyMeta are left out.
// The channel is closed after Leave; one asked for after Leave is already closed.
func (c *Cluster) Members() <-chan []overlay.Node {
	ch := make(chan []overlay.Node, 1)
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.left {
		close(ch)
		return ch
	}
	c.subs = append(c.subs, ch)
	c.signalChanged() // the first snapshot may well be empty; the interface still needs to come up
	return ch
}

// watch turns each change signal into one verified snapshot: it is persisted
// as the peers to rejoin on the next start and delivered to every Members
// channel, replacing a snapshot the subscriber has not read yet.
func (c *Cluster) watch() {
	defer c.routines.Done()
	for {
		select {
		case <-c.done:
			return
		case <-c.changed:
		}
		peers := c.snapshot()
		c.stateMu.Lock()
		// Until this node has seen a membership, an empty snapshot says only
		// that it has not joined yet, and the peers it remembers are its way
		// back: they are replaced once there is something to replace them
		// with, not before. A node that has been in touch and is now alone
		// does record that, so the last one standing starts up unencumbered.
		if len(peers) > 0 {
			c.seenMembers = true
		}
		if c.seenMembers {
			c.boot.Peers = peers
		}
		c.saveState()
		c.stateMu.Unlock()

		c.subMu.Lock()
		for _, ch := range c.subs {
			select {
			case <-ch: // an unread snapshot is stale now
			default:
			}
			ch <- slices.Clone(peers) // watch is the only sender, so the slot is free
		}
		c.subMu.Unlock()
	}
}

// snapshot is the current list of other members whose metadata verifies.
func (c *Cluster) snapshot() []overlay.Node {
	if _, _, err := assigned(c.set, c.overlay, c.id.Public()); err != nil {
		slog.Error("this node lost its overlay address; peers will drop it", "err", err)
	}
	ml := c.ml.Load()
	nodes := make([]overlay.Node, 0, ml.NumMembers())
	for _, n := range ml.Members() {
		if n.Name == c.local.Name {
			continue
		}
		meta, err := overlay.DecodeMeta(n.Meta)
		if err != nil {
			slog.Warn("ignoring node with undecodable metadata", "name", n.Name, "addr", n.Addr, "err", err)
			continue
		}
		addr, _ := netip.AddrFromSlice(n.Addr)
		node := overlay.Node{Name: n.Name, Addr: addr.Unmap(), Port: n.Port, Meta: meta}
		if err := verifyMeta(c.set, c.overlay, &node); err != nil {
			slog.Warn("ignoring node with unverified metadata", "name", n.Name, "addr", n.Addr, "err", err)
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// --- memberlist.Delegate: node metadata and membership record distribution ---

var _ memberlist.Delegate = (*Cluster)(nil)
var _ memberlist.ConflictDelegate = (*Cluster)(nil)

// recordMsg is a broadcast carrying one membership record.
type recordMsg struct {
	Admission  *trust.Admission  `json:"admission,omitempty"`
	Revocation *trust.Revocation `json:"revocation,omitempty"`
	Prune      *trust.Prune      `json:"prune,omitempty"`
}

// recordBroadcast implements memberlist.NamedBroadcast: the queue keeps one
// broadcast per name, so a record queued for an identity replaces one for the
// same identity that has not gone out yet. Invalidates is for the unnamed
// case and is never consulted.
type recordBroadcast struct {
	name string
	msg  []byte
}

func (b recordBroadcast) Name() string                                { return b.name }
func (b recordBroadcast) Invalidates(other memberlist.Broadcast) bool { return false }
func (b recordBroadcast) Message() []byte                             { return b.msg }
func (b recordBroadcast) Finished()                                   {}

func (c *Cluster) broadcast(m recordMsg) {
	msg, err := json.Marshal(m)
	if err != nil {
		return
	}
	var name string
	switch {
	case m.Admission != nil:
		name = "adm:" + m.Admission.Identity.String()
	case m.Revocation != nil:
		name = "rev:" + m.Revocation.Identity.String()
	case m.Prune != nil:
		name = fmt.Sprintf("prn:%s:%d", m.Prune.Pruner, m.Prune.Seq)
	}
	c.queue.QueueBroadcast(recordBroadcast{name: name, msg: msg})
}

// NodeMeta implements memberlist.Delegate: our signed metadata.
func (c *Cluster) NodeMeta(limit int) []byte {
	encoded, err := c.local.Encode(limit)
	if err != nil {
		slog.Error("failed to encode local node", "err", err)
		return nil
	}
	return encoded
}

// NotifyMsg implements memberlist.Delegate: a record broadcast from a peer.
// Records that change our set are re-broadcast so they spread epidemically.
func (c *Cluster) NotifyMsg(b []byte) {
	var m recordMsg
	if err := json.Unmarshal(b, &m); err != nil {
		slog.Debug("ignoring undecodable broadcast", "err", err)
		return
	}
	changed := false
	switch {
	case m.Admission != nil:
		ok, err := c.set.AddAdmission(*m.Admission)
		if err != nil {
			slog.Warn("rejecting admission record", "identity", m.Admission.Identity.Short(), "err", err)
			return
		}
		changed = ok
		if ok {
			slog.Info("node admitted", "name", m.Admission.Name, "identity", m.Admission.Identity.Short(), "by", m.Admission.Admitter.Short())
		}
	case m.Revocation != nil:
		ok, err := c.set.AddRevocation(*m.Revocation)
		if err != nil {
			slog.Warn("rejecting revocation record", "identity", m.Revocation.Identity.Short(), "err", err)
			return
		}
		changed = ok
		if ok {
			slog.Warn("node revoked", "identity", m.Revocation.Identity.Short(), "by", m.Revocation.Revoker.Short())
		}
	case m.Prune != nil:
		ok, err := c.set.AddPrune(*m.Prune)
		if err != nil {
			slog.Warn("rejecting prune record", "pruner", m.Prune.Pruner.Short(), "err", err)
			return
		}
		changed = ok
		if ok {
			slog.Info("records pruned", "identities", len(m.Prune.Identities), "by", m.Prune.Pruner.Short())
		}
	default:
		return
	}
	if changed {
		c.broadcast(m)
		c.signalChanged() // watch saves the set, coalescing a burst into one write
	}
}

// GetBroadcasts implements memberlist.Delegate.
func (c *Cluster) GetBroadcasts(overhead, limit int) [][]byte {
	return c.queue.GetBroadcasts(overhead, limit)
}

// LocalState implements memberlist.Delegate: the whole record set, for push/pull.
func (c *Cluster) LocalState(join bool) []byte {
	b, err := json.Marshal(c.set.Records())
	if err != nil {
		return nil
	}
	return b
}

// MergeRemoteState implements memberlist.Delegate: union in a peer's records.
func (c *Cluster) MergeRemoteState(buf []byte, join bool) {
	var rs trust.Records
	if err := json.Unmarshal(buf, &rs); err != nil {
		slog.Debug("ignoring undecodable remote state", "err", err)
		return
	}
	if n := c.set.Merge(rs); n > 0 {
		slog.Debug("merged membership records", "new", n)
		c.signalChanged() // watch saves the set, coalescing a burst into one write
	}
}

// NotifyConflict implements memberlist.ConflictDelegate.
func (c *Cluster) NotifyConflict(existing, other *memberlist.Node) {
	slog.Error("node name conflict detected", "name", other.Name, "addr", other.Addr)
}

// signalChanged wakes the Members loop; a signal already pending is enough.
func (c *Cluster) signalChanged() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}
