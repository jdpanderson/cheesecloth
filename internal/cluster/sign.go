package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/jdpanderson/cheesecloth/internal/wire"
)

// The records this node signs: admissions for joiners, revocations for the
// operator, and the checkpoints that state what the membership became. Each is
// saved before it goes out, under stateMu, so that nothing the cluster has seen
// is missing here.

// ratifySlack is how much longer an enrolment waits than the interval that
// repairs a record immediate delivery missed. It covers the exchange itself
// and the attestation that follows it, both of which are a round trip.
const ratifySlack = 30 * time.Second

// ratifyWait is how long an enrolment waits for the cluster to agree a
// membership holding the joiner. A reachable cluster agrees in well under a
// second, so what this really bounds is how long the operator waits to be told
// that it did not.
//
// It is a sync interval and a margin rather than a figure of its own, because
// the sync is what the rest of the design leans on: a record goes out once,
// best effort, and a member that misses it takes it at the next full state
// sync. A wait shorter than that interval cannot cover the repair it depends
// on, so it would be certain to give up in exactly the case the repair is for.
// A node told to reconcile seldom therefore enrols others slowly, which is the
// same trade the setting makes everywhere else.
func (c *Cluster) ratifyWait() time.Duration { return c.syncInterval + ratifySlack }

// revoke signs a revocation of id and stores it. It reports the joiners that go
// with it: nodes it vouched for that the cluster has not agreed on yet.
//
// What the record would do is worked out before anything is signed, so that a
// revocation this node cannot make, or one that would take this node out with
// its subject, costs neither a signature nor a record the cluster can never get
// back. stateMu is held across the whole of it, as admit holds it.
func (c *Cluster) revoke(id trust.PublicKey) (trust.Revocation, []trust.Member, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	var withdrawn []trust.Member
	var err error
	if id != c.id.Public() {
		// a node leaving takes itself out and needs no check: the record
		// names nobody else, so there is nothing it withdraws by surprise
		if withdrawn, err = c.effect(id); err != nil {
			return trust.Revocation{}, nil, err
		}
	}
	rev := trust.Revoke(c.id, id)
	if _, err := c.set.AddRevocation(rev); err != nil {
		return trust.Revocation{}, nil, err
	}
	c.saveState() // before it goes out
	return rev, withdrawn, nil
}

// effect is what a revocation of id would take out besides id itself, or an
// error saying why this node will not sign it. Both answers come from the
// records: the membership the set would have with the record in it, against the
// one it has.
//
// A record takes out one member, but it can still cost more than that: a joiner
// the subject admitted that the cluster has not agreed on yet is a member only
// through a record its admitter signed, and that stops counting. The operator
// is told before anything is signed.
//
// Two things stop the record being signed. A revocation that does not take its
// own subject out is one this node is no longer a member to make, and would
// reach every peer while doing nothing. And one that withdraws this node would
// take the node running it out along with its subject.
func (c *Cluster) effect(id trust.PublicKey) ([]trust.Member, error) {
	var others []trust.Member
	subject, self := false, false
	for _, m := range c.set.Withdraws(trust.Revocation{Identity: id, Revoker: c.id.Public()}) {
		switch m.Identity {
		case id:
			subject = true
		case c.id.Public():
			self = true
		default:
			others = append(others, m)
		}
	}
	name := nameOf(c.set, id)
	switch {
	case self:
		return nil, fmt.Errorf("revoking %s would take this node (%s) out of the cluster with it: this node "+
			"is a member through %s. Run it from a node %s did not admit",
			name, c.id.Public().Short(), name, name)
	case !subject:
		return nil, fmt.Errorf("the revocation of %s has no effect; this node (%s) is no longer a member itself",
			id.Short(), c.id.Public().Short())
	}
	return others, nil
}

// nameOf is what the operator calls id: the name the membership gives it, or
// its fingerprint where it is no member.
func nameOf(set *trust.Set, id trust.PublicKey) string {
	if m, ok := set.Lookup(id); ok {
		return m.Name
	}
	return id.Short()
}

// Revoke signs and distributes a revocation of id, and reports what it takes
// out besides id itself -- a joiner the cluster had not yet agreed on, where
// the node being revoked is what vouched for it.
func (c *Cluster) Revoke(id trust.PublicKey) ([]trust.Member, error) {
	rev, withdrawn, err := c.revoke(id)
	if err != nil {
		return nil, err
	}
	c.distribute(recordMsg{Revocation: &rev})
	c.signalChanged() // every node states the membership without it, and it goes once enough agree
	return withdrawn, nil
}

// RevokeSelf revokes this node's own identity, so the cluster stops trusting it
// when it leaves for good, and hands the record to each member over a stream
// before returning: the node is about to stop, so the retransmit queue alone
// would likely lose it. It returns how many members took the record.
//
// It then attests to the membership without this node, and hands that over as
// well. A revocation only takes effect once the cluster agrees on it, and this
// node is still one of the members whose attestation counts towards that -- in
// a cluster of two it is half of them. Leaving without signing would put the
// others one short of ever agreeing it had gone.
//
// Attesting hands the membership out too, but on a goroutine that races the
// memberlist shutdown a leave starts; this one has finished before the agent is
// told to stop. A member that gets both takes the second as one it already
// holds.
func (c *Cluster) RevokeSelf() (int, error) {
	rev, _, err := c.revoke(c.id.Public())
	if errors.Is(err, trust.ErrSuperseded) {
		// A member has revoked this node already, or the membership has stopped
		// naming it. Either way the cluster has been told what a leave would
		// tell it, and a second record saying the same thing is one it never
		// gets back.
		return 0, ErrAlreadyOut
	}
	if err != nil {
		return 0, err
	}
	msg, err := wire.Marshal(recordMsg{Revocation: &rev})
	if err != nil {
		return 0, err
	}
	// the count goes back to the operator waiting on the control socket, which
	// says the same thing a warning would and says it where it was asked for
	told, _ := c.handOut(msg)
	c.broadcast(recordMsg{Revocation: &rev}) // for members that were not reachable
	if cp, signed := c.attest(); signed {
		if b, err := wire.Marshal(recordMsg{Checkpoint: &cp}); err == nil {
			_, _ = c.handOut(b)
		}
	}
	return told, nil
}

// ErrAlreadyOut is RevokeSelf finding the cluster has taken this node out
// before it asked to go: there is nothing left to tell, so a leave carries on
// rather than stopping for an operator to insist on it.
var ErrAlreadyOut = errors.New("this node has already been taken out of the cluster")

// Awaiting is every record this node is holding until enough members confirm
// it, for the operator deciding whether to.
func (c *Cluster) Awaiting() []trust.Awaiting { return c.set.Awaiting() }

// Confirm signs this node's agreement that a record should count and sends it
// out. A cluster that asks for confirmations holds a record until enough have
// arrived, so this is what lets one take effect.
//
// A record this node signed is refused. Its signer's own agreement is not the
// second pair of eyes the cluster asked for, so it is never counted; signing
// one anyway would put a confirmation that can do nothing into the state file
// and into every peer's, and tell the operator something had happened.
func (c *Cluster) Confirm(record trust.Digest) error {
	c.stateMu.Lock()
	for _, w := range c.set.Awaiting() {
		if w.Record == record && w.Signer == c.id.Public() {
			c.stateMu.Unlock()
			return fmt.Errorf("this node signed the %s of %s, so its own confirmation is not the second pair "+
				"of eyes the cluster is asking for. Run 'cheesecloth confirm %s' on another member",
				w.Kind, w.Name, w.Name)
		}
	}
	conf := trust.Confirm(c.id, record)
	if _, err := c.set.AddConfirmation(conf); err != nil {
		c.stateMu.Unlock()
		return err
	}
	c.saveState() // before it goes out
	c.stateMu.Unlock()
	c.distribute(recordMsg{Confirmation: &conf})
	c.signalChanged() // the record it confirms may be the last one it needed
	return nil
}

// admit is called by the enrolment server once a joiner has proven the token:
// it gives the joiner the lowest free overlay slot, signs its admission, and
// waits for the cluster to agree a membership that names it. Only then is the
// joiner a member anywhere, so only then is the enrolment finished.
func (c *Cluster) admit(ctx context.Context, joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
	a, err := c.propose(joiner, name)
	if err != nil {
		return trust.Admission{}, trust.Records{}, err
	}
	// A cluster that asks for confirmations is waiting for a person, not for a
	// round of gossip, so nothing here decides how long that takes. The joiner
	// waits with it and the operator stops either of them with Ctrl+C.
	wait := c.ratifyWait()
	if c.set.Confirmations() > 0 {
		wait = 0
	}
	if err := c.agreedOn(ctx, joiner, wait); err != nil {
		return trust.Admission{}, trust.Records{}, err
	}
	return a, c.set.Records(), nil
}

// propose signs the admission and sends it out. Serialised under stateMu so
// that two joiners this node is admitting cannot be handed the same slot; two
// being admitted by different nodes can still contest one, which is settled
// when the membership is agreed and costs the loser a second attempt.
func (c *Cluster) propose(joiner trust.PublicKey, name string) (trust.Admission, error) {
	if err := trust.CheckName(name); err != nil {
		return trust.Admission{}, err
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	// Nothing admits a revoked identity back while the checkpoints still
	// remember it, so a record signed here would put nobody in the cluster: it
	// would leave the joiner believing itself admitted while every peer refused
	// it. The joiner is told what is actually wrong instead, and the token use
	// it proved is given back rather than spent on an enrolment that cannot
	// happen.
	if c.set.Revoked(joiner) {
		return trust.Admission{}, fmt.Errorf("the identity %s has been revoked, and nothing "+
			"admits a revoked identity back while the cluster still remembers it; this node needs a fresh "+
			"identity, which it gets by deleting its state file and enrolling again", joiner.Short())
	}
	// A name or a slot is free only where neither the agreed membership nor the
	// proposed one holds it: one another joiner has been given is taken even
	// though the cluster has yet to say so, and one a member on its way out
	// still holds is not free until the cluster has agreed it has gone.
	if c.set.NameTaken(name, joiner) {
		return trust.Admission{}, fmt.Errorf("a member named %q already exists", name)
	}
	var host uint64
	if cur, ok := c.set.Proposal().Holds(joiner); ok {
		host = cur.Host // an identity enrolling again keeps its address
	} else {
		var err error
		if host, err = c.set.FreeHost(overlay.MaxHost(c.overlay)); err != nil {
			return trust.Admission{}, fmt.Errorf("%w in %s", err, c.overlay)
		}
	}
	a := trust.Admit(c.id, joiner, name, host)
	if _, err := c.set.AddAdmission(a); err != nil {
		return trust.Admission{}, err
	}
	c.saveState() // before it goes out
	c.distribute(recordMsg{Admission: &a})
	c.signalChanged() // every node states the membership the joiner is part of
	return a, nil
}

// agreedOn waits for the cluster to agree a membership that names id.
//
// An admission is a proposal. Until enough members have attested to a
// membership holding the joiner, no peer will accept its connections, so
// returning at the signature would hand back a node that comes up and
// configures nothing. Waiting means the operator is told what happened: that
// the node is in, or why it is not.
func (c *Cluster) agreedOn(ctx context.Context, id trust.PublicKey, wait time.Duration) error {
	var timeout <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		timeout = t.C
	}
	for {
		agreed := c.agreement()
		if c.set.Valid(id) {
			return nil
		}
		if _, proposed := c.set.Proposal().Holds(id); !proposed && !c.waitingOn(id) {
			return fmt.Errorf("another node was given the name or the overlay address this node was "+
				"admitted with, at the same moment, and the cluster settled the contest the other way; "+
				"nothing was agreed for %s. Enrol it again", id.Short())
		}
		select {
		case <-agreed:
		case <-ctx.Done():
			// The joiner has gone, or this node is stopping. The admission was
			// signed and sent before this wait, so it stands: the cluster
			// agrees it when enough members have, and the node is in from its
			// next start.
			return fmt.Errorf("the enrolment of %s ended before the cluster agreed a membership holding it. "+
				"The admission stands; start the node again once the cluster has agreed it", id.Short())
		case <-c.done:
			return errors.New("this node is leaving the cluster")
		case <-timeout:
			// What this says is measured rather than surmised. Too few
			// attestations with every member in the ring is a cluster still
			// coming to terms with itself; too few members in the ring is one
			// that cannot be reached. They are different problems and the
			// operator is the one who has to tell them apart.
			members := c.set.MemberCount()
			return fmt.Errorf("the cluster did not agree a membership holding %s within %s: %d of the %d "+
				"members have to attest to it and %d have, with %d in this node's gossip ring. The "+
				"admission stands and is agreed as soon as enough of them do; enrol the node again then",
				id.Short(), wait, c.set.Quorum().Size(members), members, c.attested(id), c.reachable())
		}
	}
}

// attested is the most attestations any membership naming id has gathered. It
// is what the wait was short of, and the number the operator would otherwise
// have to read the records to find.
func (c *Cluster) attested(id trust.PublicKey) int {
	best := 0
	for _, cp := range c.set.Records().Checkpoints {
		if slices.ContainsFunc(cp.Members, func(m trust.Member) bool { return m.Identity == id }) {
			best = max(best, len(cp.Attestations))
		}
	}
	return best
}

// reachable is how many nodes this node's gossip ring holds, itself included:
// the members it could have heard an attestation from.
func (c *Cluster) reachable() int {
	if ml := c.ml.Load(); ml != nil {
		return ml.NumMembers()
	}
	return 1
}

// waitingOn reports whether a record about this identity is held waiting for
// confirmations. It is not in the proposed membership while it waits, which is
// the same thing a record that lost a contest looks like -- and the difference
// is whether there is anything still to come.
func (c *Cluster) waitingOn(id trust.PublicKey) bool {
	for _, w := range c.set.Awaiting() {
		if w.Identity == id {
			return true
		}
	}
	return false
}

// agreement is closed when the agreed membership next changes, so that a
// caller can wait for it without polling. watch closes it after every pass,
// whether this node attested or took a peer's checkpoint.
func (c *Cluster) agreement() <-chan struct{} {
	c.agreeMu.Lock()
	defer c.agreeMu.Unlock()
	if c.agreed == nil {
		c.agreed = make(chan struct{})
	}
	return c.agreed
}

// noteAgreement wakes everything waiting on agreement.
func (c *Cluster) noteAgreement() {
	c.agreeMu.Lock()
	defer c.agreeMu.Unlock()
	if c.agreed != nil {
		close(c.agreed)
		c.agreed = nil
	}
}

// attest states what this node believes the membership should now be, and signs
// it. Every node does the same on its own, and two that agree produce the same
// digest, so their signatures accumulate on one checkpoint and it ratifies
// wherever enough of them have arrived. There is no proposer and nothing to
// wait for: a node that disagrees simply signs something else, and nothing
// ratifies until they converge.
//
// Until one ratifies, nothing has changed: the records are a proposal and the
// membership is still the one the cluster last agreed. Once one has, what it
// accounts for is trimmed -- the membership is stated, so the records that led
// to it answer nothing that is still being asked.
func (c *Cluster) attest() (trust.Checkpoint, bool) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	cp, worth := c.set.Next(c.id)
	if !worth {
		return trust.Checkpoint{}, false
	}
	// Whether anybody has stated this membership yet decides what goes out. If
	// somebody has, all this node adds is its own signature: a membership goes
	// to each member over a stream, so every node restating one would be a
	// round of streams from each of them to each of the others.
	stated := c.set.Holds(cp.Digest())
	if _, err := c.set.AddCheckpoint(cp); err != nil {
		slog.Warn("could not attest to the membership", "err", err)
		return trust.Checkpoint{}, false
	}
	c.saveState()
	if stated {
		c.distribute(recordMsg{Agreement: &agreement{Digest: cp.Digest(), By: cp.Attestations[0]}})
	} else {
		c.distribute(recordMsg{Checkpoint: &cp})
	}
	return cp, true
}
