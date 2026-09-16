package cluster

import (
	"bytes"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The membership as this node sees it: what memberlist reports about each
// node is copied out as it arrives, and every change is turned into one
// verified snapshot, persisted as the peers to rejoin and delivered to every
// Members channel.

// assigned is the admission that decides who id is, and the overlay address it
// entitles id to. It fails if id is not a member, the slot does not fit the
// overlay net, or another member holds the slot or the name with a stronger
// claim. The conflicts come from trust.Set.Conflicts, so a caller checking a
// whole membership asks once and hands the same answer to each check.
func assigned(set *trust.Set, prefix netip.Prefix, id trust.PublicKey, conflicts map[trust.PublicKey]trust.Conflict) (trust.Member, netip.Addr, error) {
	adm, ok := set.Lookup(id)
	if !ok {
		return trust.Member{}, netip.Addr{}, fmt.Errorf("identity %s is not a member", id.Short())
	}
	addr, ok := overlay.Addr(prefix, adm.Host)
	if !ok {
		return adm, netip.Addr{}, fmt.Errorf("overlay slot %d of %s does not fit in %s", adm.Host, adm.Name, prefix)
	}
	switch c, clash := conflicts[id]; {
	case !clash:
	case c.Contested == trust.ContestedHost:
		return adm, netip.Addr{}, fmt.Errorf("overlay address %s of %s collides with %s, which holds it; %s must be enrolled again", addr, adm.Name, c.Other.Name, adm.Name)
	default:
		return adm, netip.Addr{}, fmt.Errorf("the name %q is held by two members: %s keeps it, so %s must be renamed and enrolled again",
			adm.Name, c.Other.Identity.Short(), id.Short())
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
func verifyMeta(set *trust.Set, prefix netip.Prefix, n *overlay.Node, conflicts map[trust.PublicKey]trust.Conflict) error {
	adm, want, err := assigned(set, prefix, n.Identity, conflicts)
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

// member is a node as memberlist last reported it. memberlist hands a delegate a
// pointer into its own table and goes on writing the node's address, port and
// metadata through it, under a lock it holds only for the delegate call, so the
// details are copied out there and nothing else reads the node itself.
type member struct {
	addr netip.Addr
	port uint16
	meta []byte
}

// memberEvent is one membership change, with what is needed to log it already
// copied out of memberlist's node.
type memberEvent struct {
	kind memberlist.NodeEventType
	name string
	addr netip.Addr
}

// memberEvents implements memberlist.EventDelegate: it keeps the cluster's own
// copy of the membership in step and passes each change on to be logged.
type memberEvents struct{ c *Cluster }

var _ memberlist.EventDelegate = memberEvents{}

func (e memberEvents) NotifyJoin(n *memberlist.Node)   { e.c.noteMember(memberlist.NodeJoin, n) }
func (e memberEvents) NotifyUpdate(n *memberlist.Node) { e.c.noteMember(memberlist.NodeUpdate, n) }
func (e memberEvents) NotifyLeave(n *memberlist.Node)  { e.c.noteMember(memberlist.NodeLeave, n) }

// noteMember records what memberlist reports about a node and passes the event
// on. memberlist calls it under the lock its own writes to the node take, so
// this is where the node is read and copied, and it stays short for the same
// reason, leaving the logging to forwardEvents.
func (c *Cluster) noteMember(kind memberlist.NodeEventType, n *memberlist.Node) {
	addr, _ := netip.AddrFromSlice(n.Addr)
	m := member{addr: addr.Unmap(), port: n.Port, meta: bytes.Clone(n.Meta)}
	name := n.Name

	c.membersMu.Lock()
	if kind == memberlist.NodeLeave {
		delete(c.members, name)
	} else {
		c.members[name] = m
	}
	c.membersMu.Unlock()

	c.events <- memberEvent{kind: kind, name: name, addr: m.addr}
}

// currentMembers is the membership as this node last copied it. The map is
// copied rather than handed out, so a caller can walk it without holding
// anything memberlist's delegate calls wait on.
func (c *Cluster) currentMembers() map[string]member {
	c.membersMu.Lock()
	defer c.membersMu.Unlock()
	return maps.Clone(c.members)
}

// forwardEvents logs memberlist events about other nodes, learns their
// addresses, and coalesces the events into changed.
func (c *Cluster) forwardEvents() {
	defer c.routines.Done()
	for {
		var event memberEvent
		select {
		case <-c.done:
			return
		case event = <-c.events:
		}
		if event.name == c.local.Name {
			continue
		}
		switch event.kind {
		case memberlist.NodeJoin:
			slog.Info("node joined", "name", event.name, "addr", event.addr)
		case memberlist.NodeUpdate:
			slog.Info("node updated", "name", event.name, "addr", event.addr)
		case memberlist.NodeLeave:
			slog.Info("node left", "name", event.name, "addr", event.addr)
		}
		c.signalChanged()
	}
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
		// Every node states what it now believes the membership is, not only
		// the one that signed the record that changed it: a node that learns of
		// a change from a peer has the same answer to give, and until enough of
		// them have given it the membership is still being derived from records
		// rather than read from an agreed list. Doing it here coalesces a burst
		// of records into one statement.
		c.attest()
		peers := c.snapshot()
		c.stateMu.Lock()
		// Until this node has seen a membership, an empty snapshot says only
		// that it has not joined yet, and the peers it remembers are its way
		// back: they are replaced once there is something to replace them with.
		// A node that has been in touch and is now alone does record that, so
		// the last one standing starts up unencumbered.
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

// snapshot is the current list of other members whose metadata verifies, in
// name order so that what is persisted does not churn.
func (c *Cluster) snapshot() []overlay.Node {
	// asked once for the whole membership, then handed to each check below
	conflicts := c.set.Conflicts()
	if _, _, err := assigned(c.set, c.overlay, c.id.Public(), conflicts); err != nil {
		slog.Error("this node lost its overlay address; peers will drop it", "err", err)
	}
	current := c.currentMembers()
	nodes := make([]overlay.Node, 0, len(current))
	for _, name := range slices.Sorted(maps.Keys(current)) {
		if name == c.local.Name {
			continue
		}
		m := current[name]
		meta, err := overlay.DecodeMeta(m.meta)
		if err != nil {
			slog.Warn("ignoring node with undecodable metadata", "name", name, "addr", m.addr, "err", err)
			continue
		}
		node := overlay.Node{Name: name, Addr: m.addr, Port: m.port, Meta: meta}
		if err := verifyMeta(c.set, c.overlay, &node, conflicts); err != nil {
			slog.Warn("ignoring node with unverified metadata", "name", name, "addr", m.addr, "err", err)
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// signalChanged wakes the Members loop; a signal already pending is enough.
func (c *Cluster) signalChanged() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}
