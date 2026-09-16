package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// The records this node signs: admissions for joiners, revocations for the
// operator, and the checkpoints that state what the membership became. Each is
// saved before it goes out, under stateMu, so that nothing the cluster has seen
// is missing here.

// retain is how many checkpoints below the ratified one are kept. It is the
// only thing that decides how far behind a node may fall and still find its way
// to the present, so it is generous: a cluster would have to change membership
// this many times while a node was away before that node had to enrol again.
const retain = 64

// signingTime is the date to put on a record, refused if this node's clock is
// behind the last record it signed. Nothing is adjusted: a date is what a
// signer asserts, so the clock is what has to be fixed.
//
// A backdated record is worth refusing because of what a date decides: of two
// admitters' records for one identity the later is preferred, so a record this
// node signs behind its own last one would be beaten by that one, and the
// admission or rename it carries would quietly decide nothing.
func (c *Cluster) signingTime() (time.Time, error) {
	now := time.Now()
	if last := c.set.LastSigned(c.id.Public()); now.Unix() < last {
		return time.Time{}, fmt.Errorf("this node's clock is %s behind the last record it signed; "+
			"check that it is synchronised", time.Unix(last, 0).Sub(now).Round(time.Second))
	}
	return now, nil
}

// revoke signs a revocation of id, and of disown along with it, and stores it.
// It reports the members that go besides id itself.
//
// What the record would do is worked out before anything is signed, so that a
// revocation this node cannot make, or one that would take this node out with
// its subject, costs neither a signature nor a record the cluster can never get
// back. stateMu is held across the whole of it, as admit holds it.
func (c *Cluster) revoke(id trust.PublicKey, disown []trust.PublicKey) (trust.Revocation, []trust.Member, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	now, err := c.signingTime()
	if err != nil {
		return trust.Revocation{}, nil, err
	}
	var withdrawn []trust.Member
	if id != c.id.Public() {
		// a node leaving takes itself out and needs no check: its own
		// revocation counts whatever else is held
		if withdrawn, err = c.effect(id, disown); err != nil {
			return trust.Revocation{}, nil, err
		}
	}
	rev := trust.Revoke(c.id, id, disown, now)
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
// Three things stop the record being signed. A revocation that does not take
// its own subject out is one this node is no longer a member to make, and would
// reach every peer while doing nothing. One that withdraws this node would take
// the node running it out along with its subject. And one that leaves a node
// the operator named standing is not what was asked for, and a revocation
// cannot be taken back once it is out.
func (c *Cluster) effect(id trust.PublicKey, disown []trust.PublicKey) ([]trust.Member, error) {
	var others []trust.Member
	subject, self := false, false
	gone := map[trust.PublicKey]bool{}
	for _, m := range c.set.Withdraws(trust.Revocation{Identity: id, Revoker: c.id.Public(), Disowned: disown}) {
		gone[m.Identity] = true
		switch m.Identity {
		case id:
			subject = true
		case c.id.Public():
			self = true
		default:
			others = append(others, m)
		}
	}
	var kept []string
	for _, d := range disown {
		if !gone[d] {
			kept = append(kept, nameOf(c.set, d))
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
	case len(kept) > 0:
		return nil, fmt.Errorf("revoking %s would not withdraw %s: each of those is a member in its own right, "+
			"which this record does not reach. Nothing is signed. Revoke each of them by name instead",
			name, strings.Join(kept, ", "))
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

// Revoke signs and distributes a revocation of id, and of disown along with it,
// and reports the members that takes out besides id itself.
func (c *Cluster) Revoke(id trust.PublicKey, disown []trust.PublicKey) ([]trust.Member, error) {
	rev, withdrawn, err := c.revoke(id, disown)
	if err != nil {
		return nil, err
	}
	c.distribute(recordMsg{Revocation: &rev})
	c.attest()
	c.signalChanged() // the revoked node drops out of Members at once
	return withdrawn, nil
}

// RevokeSelf revokes this node's own identity, so the cluster stops trusting it
// when it leaves for good, and hands the record to each member over a stream
// before returning: the node is about to stop, so the retransmit queue alone
// would likely lose it. It returns how many members took the record.
func (c *Cluster) RevokeSelf() (int, error) {
	rev, _, err := c.revoke(c.id.Public(), nil)
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
// Serialised under stateMu so that two joiners cannot be handed the same slot.
func (c *Cluster) admit(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
	if err := trust.CheckName(name); err != nil {
		return trust.Admission{}, trust.Records{}, err
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
		return trust.Admission{}, trust.Records{}, fmt.Errorf("the identity %s has been revoked, and nothing "+
			"admits a revoked identity back while the cluster still remembers it; this node needs a fresh "+
			"identity, which it gets by deleting its state file and enrolling again", joiner.Short())
	}
	if c.set.NameTaken(name, joiner) {
		return trust.Admission{}, trust.Records{}, fmt.Errorf("a member named %q already exists", name)
	}
	var host uint64
	if cur, ok := c.set.Lookup(joiner); ok {
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
	a := trust.Admit(c.id, joiner, name, host, now)
	if _, err := c.set.AddAdmission(a); err != nil {
		return trust.Admission{}, trust.Records{}, err
	}
	c.saveState() // before it goes out
	c.distribute(recordMsg{Admission: &a})
	go c.attest() // not under stateMu: the checkpoint is saved and sent on its own
	return a, c.set.Records(), nil
}

// attest states what this node believes the membership now is, and signs it.
// Every node does the same on its own, and two that agree produce the same
// digest, so their signatures accumulate on one checkpoint and it ratifies
// wherever enough of them have arrived. There is no proposer and nothing to
// wait for: a node that disagrees simply signs something else, and nothing
// ratifies until they converge.
//
// Once one has ratified, what it accounts for is trimmed. That is the whole
// point of it: the membership is stated, so the records that led to it answer
// nothing that is still being asked.
func (c *Cluster) attest() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	base, founded := c.set.Base()
	members := c.set.Members()
	if founded && sameMembership(base.Members, members) {
		return // the ratified checkpoint already says this
	}
	prev := trust.Digest{}
	was := map[trust.PublicKey]bool{}
	if founded {
		prev = base.Digest()
		for _, m := range base.Members {
			was[m.Identity] = true
		}
	}
	list := make([]trust.Member, 0, len(members))
	for _, m := range members {
		list = append(list, m)
		delete(was, m.Identity)
	}
	// Everything this checkpoint is about to let the trim erase: the members it
	// drops, and every identity a revocation still held has put out. Without
	// the second, trimming would take away the only record saying they are out
	// and the admissions that let them in would stand again.
	removed := make([]trust.PublicKey, 0, len(was))
	for id := range was {
		removed = append(removed, id)
	}
	for _, id := range c.set.RevokedIdentities() {
		if _, still := members[id]; !still {
			removed = append(removed, id)
		}
	}
	cp := trust.Propose(c.id, c.set.Depth()+1, prev, c.set.Quorum(), list, removed)
	if _, err := c.set.AddCheckpoint(cp); err != nil {
		slog.Warn("could not attest to the membership", "err", err)
		return
	}
	if gone := c.set.Trim(retain); gone > 0 {
		slog.Info("the cluster agreed what the membership is; the records that led to it are no longer needed",
			"depth", c.set.Depth(), "records", gone, "members", c.set.MemberCount())
	}
	c.saveState()
	c.distribute(recordMsg{Checkpoint: &cp})
}

// sameMembership reports whether a checkpoint already states this membership.
func sameMembership(stated []trust.Member, now map[trust.PublicKey]trust.Member) bool {
	if len(stated) != len(now) {
		return false
	}
	for _, m := range stated {
		if cur, ok := now[m.Identity]; !ok || cur != m {
			return false
		}
	}
	return true
}
