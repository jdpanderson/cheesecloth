package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// The records this node signs: admissions for joiners, revocations and
// prunes for the operator. Each takes the next number of this node's counter
// and is saved before it goes out, under stateMu from reading the number to
// storing the record, so that no number is used twice.

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

// signPrune signs a prune of every identity the set offers as prunable and
// stores it, returning the record, the identities it names and how many records
// the set holds once it is in. It names nothing when there is nothing to prune,
// which is what a second prune racing the first finds.
//
// The number a record takes is read from the set and has to still be free when
// the record is stored, so stateMu is held across the whole of it, as revoke
// holds it. The identities are read under the lock too: two prunes started at
// once would otherwise both sign the same list, and every prune record is kept
// for good.
func (c *Cluster) signPrune() (trust.Prune, []trust.PublicKey, int, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	ids := c.set.Prunable()
	if len(ids) == 0 {
		return trust.Prune{}, nil, c.records(), nil
	}
	now, err := c.signingTime()
	if err != nil {
		return trust.Prune{}, nil, 0, err
	}
	p := trust.SignPrune(c.id, ids, c.set.NextSeq(c.id.Public()), now)
	if _, err := c.set.AddPrune(p); err != nil {
		return trust.Prune{}, nil, 0, err
	}
	c.saveState() // before it goes out: a number handed to a peer must not be reused
	return p, ids, c.records(), nil
}

// Prune signs and distributes a prune of every identity the set offers as
// prunable. With dry it signs nothing and only reports what a prune would take.
//
// The record goes out after the lock is released. Handing one to every member
// takes a dial timeout for each that has gone away, and nothing that signs
// should wait behind that: an enrolment in flight gives up after fifteen
// seconds.
func (c *Cluster) Prune(dry bool) (PruneResult, error) {
	res := PruneResult{Identities: c.set.Prunable(), Before: c.records()}
	res.After = res.Before
	res.Seen, res.Members = c.reach()
	// Nothing is refused: only the operator knows whether the members it cannot
	// reach are down for good, or merely unreachable from here.
	if res.Seen < res.Members {
		slog.Warn("this node can reach only some of the cluster; what it removes is decided from the records "+
			"it holds, and the members it cannot see may hold records it does not. "+
			"Check that the cluster is in step before changing it.",
			"reachable", res.Seen, "members", res.Members)
	}
	if len(res.Identities) > manyIdentities {
		slog.Error("far more identities are out of the cluster than a cluster this size should have got "+
			"through. If retired nodes do not account for them, a member has been admitting identities of "+
			"its own, and a key it still holds can do it again. Rebuilding is the way back from that.",
			"identities", len(res.Identities), "members", res.Members)
	}
	if dry || len(res.Identities) == 0 {
		return res, nil
	}
	p, ids, after, err := c.signPrune()
	if err != nil {
		return PruneResult{}, err
	}
	if len(ids) == 0 {
		res.Identities = nil // another prune got there first
		return res, nil
	}
	res.Identities, res.After = ids, after
	c.signalChanged()
	c.distribute(recordMsg{Prune: &p})
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
	c.distribute(recordMsg{Revocation: &rev})
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
	// the count goes back to the operator waiting on the control socket, which
	// says the same thing a warning would and says it where it was asked for
	told, _ := c.handOut(msg)
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
	c.distribute(recordMsg{Admission: &a})
	return a, c.set.Records(), nil
}
