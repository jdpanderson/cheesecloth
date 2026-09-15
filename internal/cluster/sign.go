package cluster

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// The records this node signs: admissions for joiners and revocations for the
// operator. Each takes the next number of this node's counter
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

// revoke signs a revocation of id, marking its sequence at upTo, and stores
// it. It reports the members the mark withdraws besides id itself. The mark
// ordinarily goes where this node has seen id's records reach, so the nodes it
// admitted keep their place and anything it signs from here on counts for
// nothing, whatever that record is dated. A lower mark withdraws more: it is
// how a member that was signing records nobody asked for is undone, back to
// where it was still trusted.
//
// What the mark would do is worked out before anything is signed, so that a
// revocation this node cannot make, or one that would take this node out with
// its subject, costs neither a sequence number nor a record the cluster can
// never get back. The number a record takes is read from the set and has to
// still be free when the record is stored, so stateMu is held across the whole
// of it, as admit holds it: a number this node used twice would void both
// records.
func (c *Cluster) revoke(id trust.PublicKey, upTo uint64) (trust.Revocation, []trust.Admission, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	now, err := c.signingTime()
	if err != nil {
		return trust.Revocation{}, nil, err
	}
	seq := c.set.NextSeq(c.id.Public())
	var withdrawn []trust.Admission
	if id == c.id.Public() {
		// a node leaving keeps everything it signed, this record included: the
		// cut is on its own sequence, so it has to reach the number it is
		// taking. It counts whatever else is held, so there is nothing to check
		upTo = seq
	} else {
		if upTo < c.set.Head(id) {
			if err = c.inTouch(id); err != nil {
				return trust.Revocation{}, nil, err
			}
		}
		if withdrawn, err = c.effect(id, seq, upTo); err != nil {
			return trust.Revocation{}, nil, err
		}
	}
	rev := trust.Revoke(c.id, id, seq, upTo, now)
	if _, err := c.set.AddRevocation(rev); err != nil {
		return trust.Revocation{}, nil, err
	}
	c.saveState() // before it goes out: a number handed to a peer must not be reused
	return rev, withdrawn, nil
}

// effect is what a revocation of id at upTo would withdraw besides id itself,
// or an error saying why this node will not sign it. Both answers come from
// the records: the membership the set would have with the record in it, against
// the one it has.
//
// Two of them stop the record being signed. A revocation that does not take its
// own subject out is one this node is no longer a member to make, and would
// spend a number and reach every peer while doing nothing. One that withdraws
// this node is a mark cutting off the chain this node stands on, which runs
// through the node being revoked: the operator wants it run from somewhere else
// rather than to be told afterwards.
func (c *Cluster) effect(id trust.PublicKey, seq, upTo uint64) ([]trust.Admission, error) {
	var others []trust.Admission
	subject, self := false, false
	for _, a := range c.set.Withdraws(trust.Revocation{Identity: id, Revoker: c.id.Public(), Seq: seq, UpTo: upTo}) {
		switch a.Identity {
		case id:
			subject = true
		case c.id.Public():
			self = true
		default:
			others = append(others, a)
		}
	}
	name := nameOf(c.set, id)
	switch {
	case self:
		return nil, fmt.Errorf("cutting %s off at %d would withdraw the admission chain this node (%s) stands on, "+
			"which runs through %s: this node would stop being a member itself, and so would the record it signed. "+
			"Run it from a node %s did not admit",
			name, upTo, c.id.Public().Short(), name, name)
	case !subject:
		return nil, fmt.Errorf("the revocation of %s has no effect; this node (%s) is no longer a member itself",
			id.Short(), c.id.Public().Short())
	}
	return others, nil
}

// inTouch fails when this node cannot reach the members its own records say
// exist, the node being revoked aside. A mark below where a node has been seen
// to sign withdraws records that were standing, so it is only as good as what
// this node has seen: one that is out of touch marks lower than the cluster
// would and takes out members nobody asked to remove.
//
// An ordinary revocation is deliberately not checked this way. The node being
// revoked is usually the one that has gone, so the measure would fire on almost
// every legitimate revocation and be learned as noise; see docs/operations.md.
//
// The node being revoked is left out by identity rather than by name: two
// members can go by one name, and leaving both of them out would count one
// member too few and refuse a mark that is fine.
func (c *Cluster) inTouch(id trust.PublicKey) error {
	name := nameOf(c.set, id)
	want := c.set.MemberCount() - 1 // the node being revoked is not expected to answer
	reached := 0
	for reported, m := range c.currentMembers() {
		who, known := m.identity()
		if (known && who == id) || (!known && reported == name) {
			continue // the node being revoked, by its name alone where it says nothing this node can read
		}
		reached++ // this node is in the list too, and it has certainly seen itself
	}
	if reached >= want {
		return nil
	}
	return fmt.Errorf("this node is in touch with %d of the %d members its records name besides %s, so it may not have seen "+
		"everything %s signed; withdrawing what a node admitted is decided from what this node holds. Check 'cheesecloth status', "+
		"run it from a node that can see the cluster, or revoke %s on its own, which keeps the nodes it admitted",
		reached, want, name, name, name)
}

// nameOf is what the operator calls id: the name its admission gives it, or
// its fingerprint where no record names it.
func nameOf(set *trust.Set, id trust.PublicKey) string {
	if adm, ok := set.Lookup(id); ok {
		return adm.Name
	}
	return id.Short()
}

// Revoke signs and distributes a revocation of id, marking its sequence at
// upTo, and reports the members that withdraws besides id itself. Those nodes
// were admitted by id above the mark, so nothing stands for them any more and
// they have to enrol again.
func (c *Cluster) Revoke(id trust.PublicKey, upTo uint64) ([]trust.Admission, error) {
	rev, withdrawn, err := c.revoke(id, upTo)
	if err != nil {
		return nil, err
	}
	c.distribute(recordMsg{Revocation: &rev})
	c.signalChanged() // the revoked node drops out of Members at once
	return withdrawn, nil
}

// RevokeSelf revokes this node's own identity, so the cluster stops trusting
// it when it leaves for good, and hands the record to each member over a
// stream before returning: the node is about to stop, so the retransmit queue
// alone would likely lose it. It returns how many members took the record; a
// member that already has it refuses the connection, which is not an error.
func (c *Cluster) RevokeSelf() (int, error) {
	// revoke puts the cut at the end of our own sequence, so what this node
	// vouched for stands after it has gone
	rev, _, err := c.revoke(c.id.Public(), 0)
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
