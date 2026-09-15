package cluster

import (
	"encoding/json"
	"log/slog"
	"slices"
	"sync"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// How records travel: the memberlist delegate carries this node's metadata,
// takes records from broadcasts and state syncs into the set, and spreads a
// record on the gossip queue or, when it is too large for a datagram, by
// hand over a stream to each member.

var _ memberlist.Delegate = (*Cluster)(nil)
var _ memberlist.ConflictDelegate = (*Cluster)(nil)

// recordMsg is a broadcast carrying one membership record.
type recordMsg struct {
	Admission  *trust.Admission  `json:"admission,omitempty"`
	Revocation *trust.Revocation `json:"revocation,omitempty"`
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

// maxBroadcast is the largest record the gossip queue will ever carry:
// memberlist fills a datagram of UDPBufferSize with a compound header and offers
// what is left to the delegate, charging an overhead per message. A record above
// it is never chosen, so its transmit count never rises and it is never retired
// either: it sits in the queue for the life of the process. Anything this large
// goes out by hand instead; see distribute.
const maxBroadcast = maxDatagram - 2 - (2 + 1)

// broadcast puts a record on the retransmit queue, where it spreads
// epidemically: every node that takes it passes it on. It reports whether the
// record was queued at all, which one too large for a datagram is not.
func (c *Cluster) broadcast(m recordMsg) bool {
	msg, err := json.Marshal(m)
	if err != nil {
		return false
	}
	if len(msg) > maxBroadcast {
		return false
	}
	var name string
	switch {
	case m.Admission != nil:
		name = "adm:" + m.Admission.Identity.String()
	case m.Revocation != nil:
		name = "rev:" + m.Revocation.Identity.String()
	}
	c.queue.QueueBroadcast(recordBroadcast{name: name, msg: msg})
	return true
}

// kind names the record a message carries, for the operator's log.
func (m recordMsg) kind() string {
	switch {
	case m.Admission != nil:
		return "admission"
	case m.Revocation != nil:
		return "revocation"
	}
	return "record"
}

// distribute sends a record the cluster has to have. One that fits a datagram
// goes on the gossip queue and spreads from there. One that does not is handed
// to each member over a stream, the way a leaving node hands out its own
// revocation; a record grows with how much its subject had signed, so this is
// what a revocation of a node that admitted many members takes.
//
// The hand-out runs on its own. A record is saved before it goes out and
// travels in the full state sync, so a member that misses it takes it at the
// next one. Waiting would put whoever asked for the record behind a dial
// timeout for every member that has gone away.
//
// Only the node that signs a record hands it out. A node that receives one
// passes on what it can gossip and no more, so a record that has to go by hand
// costs one round of streams rather than one from every node that sees it.
func (c *Cluster) distribute(m recordMsg) {
	if c.broadcast(m) {
		return
	}
	msg, err := json.Marshal(m)
	if err != nil {
		return
	}
	if !c.track() {
		return
	}
	go func() {
		defer c.routines.Done()
		slog.Debug("record is larger than a gossip datagram; handing it to each member over a stream",
			"bytes", len(msg), "fits", maxBroadcast)
		told, missed := c.handOut(msg)
		c.reportHandOut(m.kind(), told, missed)
	}()
}

// track counts a background routine about to start, unless the cluster is
// leaving, in which case it reports false and the caller starts none. Leave
// closes done under the same lock before it waits, so nothing is added to the
// wait group once the wait has begun.
func (c *Cluster) track() bool {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	select {
	case <-c.done:
		return false
	default:
		c.routines.Add(1)
		return true
	}
}

// reportHandOut says so when a record did not reach every member. The record is
// saved before it goes out and travels in the full state sync, so a member that
// missed it takes it within a push/pull interval; what this is for is the case
// where it does not, and the case where this node is stopping and will not sync
// again. The members are named: which ones missed it is the actionable half.
func (c *Cluster) reportHandOut(kind string, told int, missed []string) {
	if len(missed) == 0 {
		return
	}
	select {
	case <-c.done:
		slog.Warn("this agent stopped before the "+kind+" reached every member. It is saved and goes out "+
			"when this agent starts again. If this node is leaving the cluster for good, run the same "+
			"command on another member.",
			"told", told, "missed", missed)
	default:
		slog.Warn("could not hand the "+kind+" to every member. They take it at the next full state sync; "+
			"if they still do not have it after a few minutes, the cluster is partitioned.",
			"told", told, "missed", missed)
	}
}

// handOut gives msg to every other member over a stream. It reports how many
// took it and names the ones that did not. A member that already has the record
// refuses the connection, which is not an error. The members are told in
// parallel, so one that has gone away costs one dial timeout rather than its
// turn in a queue.
func (c *Cluster) handOut(msg []byte) (told int, missed []string) {
	ml := c.ml.Load()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, m := range c.currentMembers() {
		if name == c.local.Name {
			continue
		}
		wg.Add(1)
		go func(name string, m member) {
			defer wg.Done()
			// SendReliable wants a node only for its name and address
			err := ml.SendReliable(&memberlist.Node{Name: name, Addr: m.addr.AsSlice(), Port: m.port}, msg)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				slog.Debug("could not hand the record to a member", "member", name, "err", err)
				missed = append(missed, name)
				return
			}
			told++
		}(name, m)
	}
	wg.Wait()
	slices.Sort(missed) // so the warning reads the same however the members answered
	return told, missed
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
	res := c.set.Merge(rs)
	if res.Refused > 0 {
		// The same record broadcast on its own is logged by NotifyMsg as it
		// arrives. A state sync carries the whole set, so a peer offering one
		// bad record offers it again every minute; it is counted rather than
		// written out each time, and either way the operator hears about it.
		c.badState.Note("a member's state sync carried records this node will not take; its records and "+
			"this node's disagree about what verifies", "refused", res.Refused, "of", len(rs.Admissions)+
			len(rs.Revocations), "recent", res.Reason)
	}
	if res.Changed > 0 {
		slog.Debug("merged membership records", "new", res.Changed)
		c.signalChanged() // watch saves the set, coalescing a burst into one write
	}
}

// NotifyConflict implements memberlist.ConflictDelegate.
func (c *Cluster) NotifyConflict(existing, other *memberlist.Node) {
	slog.Error("node name conflict detected", "name", other.Name, "addr", other.Addr)
}
