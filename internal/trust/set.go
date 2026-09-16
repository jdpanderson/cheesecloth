package trust

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
)

// Set is the membership: the checkpoint this node has satisfied itself of, and
// what has been signed since. Safe for concurrent use.
//
// There is no chain of trust to walk. A checkpoint is trusted because the
// membership below it agreed to it, and that membership was trusted for the
// same reason; once a node has seen that happen it keeps the result and throws
// the rest away. So the anchor is the whole of what this node knows, membership
// is read from it rather than derived, and nothing asks who trusted whom.
//
// The checkpoints kept past the anchor are not for this node. They are the
// steps a peer that has been away needs to get from its own anchor to here, and
// nothing in deciding the membership reads them. See docs/membership.md.
type Set struct {
	mu sync.RWMutex
	// anchor is the membership the cluster has agreed on, and everything this
	// node reads. Nil until the cluster is founded or a joiner adopts one.
	anchor *Checkpoint
	// checkpoints is every valid checkpoint held, by digest: the anchor, the
	// steps behind it a peer may need, and candidates ahead of it that have not
	// been agreed yet.
	checkpoints map[Digest]*Checkpoint
	admissions  map[PublicKey]map[PublicKey][]Admission // identity -> admitter -> its records
	revocations map[PublicKey][]Revocation              // revoker -> its records
	// view is the membership the records make, built when a query finds it
	// stale and dropped whenever a record changes. Nil means stale. It is read
	// without the lock: the gossip transport asks whether a peer is a member
	// for every packet.
	view atomic.Pointer[view]
	// seen is the deepest membership this node has been offered, used or not.
	// It is what says whether the cluster has moved out of reach.
	seen uint64
}

// NewSet creates an empty set. It knows nothing until it is given a membership,
// by founding a cluster, by adopting one at enrolment, or by reading back what
// this node last verified.
func NewSet() *Set {
	return &Set{
		checkpoints: map[Digest]*Checkpoint{},
		admissions:  map[PublicKey]map[PublicKey][]Admission{},
		revocations: map[PublicKey][]Revocation{},
	}
}

// ErrSuperseded is returned for a record the agreed membership has already
// accounted for. Nothing is wrong with it; it is simply history, and taking it
// back in would put back what the agreement was made to discard. A peer that is
// behind offers these at every state sync, so the caller counts them rather
// than reporting each one.
var ErrSuperseded = errors.New("the agreed membership has already accounted for this record")

// AddAdmission stores a signature-valid record. It reports whether the set
// changed, which a record already held does not.
func (s *Set) AddAdmission(a Admission) (bool, error) {
	if s.held(func(s *Set) bool { return s.holdsAdmission(a) }) {
		return false, nil
	}
	if err := a.Validate(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holdsAdmission(a) {
		return false, nil // the other copy of it landed while this one was being checked
	}
	v := s.viewLocked()
	if v.removed[a.Identity] {
		return false, ErrSuperseded
	}
	// A name or an overlay slot an agreed member holds is not this joiner's to
	// take. Two joiners can contest one, and the membership is where that is
	// settled; once it has been, the record that lost says nothing that can
	// ever take effect, and taking it back would only be something to discard
	// again at the next agreement.
	if held, ok := v.byName[a.Name]; ok && held != a.Identity {
		return false, ErrSuperseded
	}
	if held, ok := v.slots[a.Host]; ok && held != a.Identity {
		return false, ErrSuperseded
	}
	by := s.admissions[a.Identity]
	if by == nil {
		by = map[PublicKey][]Admission{}
		s.admissions[a.Identity] = by
	}
	by[a.Admitter] = append(by[a.Admitter], a)
	s.forget()
	return true, nil
}

// AddRevocation stores a signature-valid revocation. Any member may be revoked:
// every one of them is a peer, not an authority over the others.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	if s.held(func(s *Set) bool { return s.holdsRevocation(r) }) {
		return false, nil
	}
	if err := r.Validate(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holdsRevocation(r) {
		return false, nil
	}
	// A revocation whose every subject the agreed membership has already
	// removed says nothing it does not; one that still takes somebody out is
	// kept, since it may be what the next agreement is made from.
	if s.supersededRevocation(r) {
		return false, ErrSuperseded
	}
	s.revocations[r.Revoker] = append(s.revocations[r.Revoker], r)
	s.forget()
	return true, nil
}

// AddCheckpoint takes a checkpoint, merges its attestations into one already
// held, and moves the anchor on where enough of the agreed membership has
// signed the next one. Two nodes attesting to the same membership produce the
// same digest, so their signatures accumulate on one record.
func (s *Set) AddCheckpoint(c Checkpoint) (bool, error) {
	if err := c.Validate(); err != nil {
		return false, err
	}
	d := c.Digest()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = max(s.seen, c.Depth)
	// A checkpoint further ahead than any chain this node could walk is not one
	// it will ever use: the anchor moves one step at a time, and a peer keeps
	// only Keep steps to hand over, so nothing past that is reachable from
	// here. Storing it would keep it for good, since the trim only drops what
	// is behind the anchor.
	if s.anchor != nil && !canReach(s.anchor.Depth, c.Depth) {
		return false, fmt.Errorf("this node's membership is at depth %d and cannot reach one at %d; "+
			"it has been away too long and has to be enrolled again", s.anchor.Depth, c.Depth)
	}
	changed := false
	if held, ok := s.checkpoints[d]; ok {
		// A stored checkpoint is never edited in place: a view built earlier
		// may point at it, and a view is whole or it is nothing.
		var added []Attestation
		for _, at := range c.Attestations {
			if !slices.ContainsFunc(held.Attestations, func(h Attestation) bool { return h.Signer == at.Signer }) {
				added = append(added, at)
			}
		}
		if len(added) > 0 {
			merged := *held
			merged.Attestations = append(slices.Clone(held.Attestations), added...)
			s.checkpoints[d] = &merged
			if s.anchor == held {
				s.anchor = &merged
			}
			changed = true
		}
	} else {
		stored := c
		stored.Attestations = slices.Clone(c.Attestations)
		s.checkpoints[d] = &stored
		changed = true
	}
	if s.advance() || changed {
		s.forget()
		return true, nil
	}
	return false, nil
}

// advance moves the anchor forward while a checkpoint following it carries the
// agreement of enough of its members. Taking one may make the next usable, so
// it repeats. Callers hold the write lock.
func (s *Set) advance() bool {
	moved := false
	for s.anchor != nil {
		next := s.agreedAfter(*s.anchor)
		if next == nil {
			return moved
		}
		s.anchor, moved = next, true
	}
	return moved
}

// agreedAfter is the checkpoint following anchor that enough of anchor's
// members have attested to, if one is held. Callers hold the lock.
func (s *Set) agreedAfter(anchor Checkpoint) *Checkpoint {
	prev := anchor.Digest()
	members := make(map[PublicKey]bool, len(anchor.Members))
	for _, m := range anchor.Members {
		members[m.Identity] = true
	}
	need := anchor.Quorum.Size(len(anchor.Members))
	var best *Checkpoint
	for _, c := range s.checkpoints {
		if c.Prev != prev {
			continue
		}
		votes := 0
		for _, at := range c.Attestations {
			if members[at.Signer] {
				votes++
			}
		}
		if votes < need {
			continue
		}
		// Two of these can only exist where the quorum is set low enough for
		// two of them to be disjoint, which is the operator's choice; the
		// smaller digest, so that every node picks the same one.
		if bd, cd := digestOf(best), c.Digest(); best == nil || bytes.Compare(cd[:], bd[:]) < 0 {
			best = c
		}
	}
	return best
}

func digestOf(c *Checkpoint) Digest {
	if c == nil {
		return Digest{}
	}
	return c.Digest()
}

// Anchor is the membership this node has satisfied itself of, and whether it
// has one. It is what a restart starts from, so it belongs in the state file.
func (s *Set) Anchor() (Checkpoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.anchor == nil {
		return Checkpoint{}, false
	}
	return *s.anchor, true
}

// Adopt takes a checkpoint as this node's membership without checking it
// against anything, and is how a node comes to trust one it has no way to
// check: a joiner takes what the member that admitted it hands over, on the
// strength of the token exchange, and a founding node takes its own. It is
// refused for a checkpoint no further on than the one already held, since that
// would be giving up ground this node has covered.
func (s *Set) Adopt(c Checkpoint) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor != nil && c.Depth <= s.anchor.Depth {
		return fmt.Errorf("checkpoint at depth %d is no further on than the one this node holds at %d", c.Depth, s.anchor.Depth)
	}
	s.seen = max(s.seen, c.Depth)
	stored := c
	stored.Attestations = slices.Clone(c.Attestations)
	s.checkpoints[stored.Digest()] = &stored
	s.anchor = &stored
	s.advance()
	s.forget()
	return nil
}

// held runs a question under the read lock, which is the cheap path taken
// before a record is verified.
func (s *Set) held(q func(*Set) bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return q(s)
}

// A record the set holds was checked when it arrived, and a signature is what
// identifies a record, so one already held needs no second check. That is what
// keeps a state sync, which carries a peer's whole record set, from verifying
// the whole membership again. The signed bytes are compared as well as the
// signature, so a record differing from a held one in any signed field still
// takes the checked path.
//
// The question is asked twice, once before the record is verified and again
// under the write lock, because two copies of one record can be on their way in
// at once: memberlist delivers a broadcast and a state sync on different
// goroutines and each carries what the other does.

// holdsAdmission reports whether the set already holds a. Callers hold the lock.
func (s *Set) holdsAdmission(a Admission) bool {
	signed := a.signedBytes()
	for _, h := range s.admissions[a.Identity][a.Admitter] {
		if bytes.Equal(h.Signature, a.Signature) && bytes.Equal(h.signedBytes(), signed) {
			return true
		}
	}
	return false
}

// holdsRevocation reports whether the set already holds r. Callers hold the lock.
func (s *Set) holdsRevocation(r Revocation) bool {
	signed := r.signedBytes()
	for _, h := range s.revocations[r.Revoker] {
		if bytes.Equal(h.Signature, r.Signature) && bytes.Equal(h.signedBytes(), signed) {
			return true
		}
	}
	return false
}

// MergeResult is what a merge did: how many records changed the set, how many
// it would not take, and the last reason one was refused.
type MergeResult struct {
	Changed    int
	Superseded int // history the agreed membership has already accounted for
	Stale      int // admissions from a set too far behind to reach this one
	Refused    int
	Reason     error // the last refusal, as an example of what is being sent
}

// Merge adds every record in rs and reports what it did with them. Checkpoints
// go in first, shallowest first, so that the anchor moves as far as it can
// before the records are judged against it.
//
// Admissions from a set too far behind to reach this one are not taken. Such a
// set has not seen the memberships in between, so it can still hold an
// admission that one of them accounted for, of an identity this one has since
// forgotten -- and taking it back would put that identity into the membership
// again. Revocations are taken whatever the sender's depth: they can only ever
// remove, so a stale one costs a member its place at worst, never a stranger a
// place in the cluster.
func (s *Set) Merge(rs Records) MergeResult {
	var res MergeResult
	for _, c := range slices.SortedFunc(slices.Values(rs.Checkpoints), func(a, b Checkpoint) int {
		return cmp.Compare(a.Depth, b.Depth)
	}) {
		res.note(s.AddCheckpoint(c))
	}
	if s.unreachable(rs) {
		res.Stale = len(rs.Admissions)
	} else {
		for _, a := range rs.Admissions {
			res.note(s.AddAdmission(a))
		}
	}
	for _, r := range rs.Revocations {
		res.note(s.AddRevocation(r))
	}
	return res
}

// unreachable reports whether rs comes from a set that cannot reach this one:
// its newest checkpoint is older than the oldest this set still holds, so there
// is no way to walk from there to here and no way for it to have seen what
// happened in between. Records that say nothing about where they came from are
// not judged this way.
func (s *Set) unreachable(rs Records) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.anchor == nil || s.anchor.Depth <= Keep || len(rs.Checkpoints) == 0 {
		return false
	}
	var newest uint64
	for _, c := range rs.Checkpoints {
		newest = max(newest, c.Depth)
	}
	return !canReach(newest, s.anchor.Depth)
}

// canReach reports whether a node whose membership is at depth from could still
// walk to one at depth to. Every node keeps Keep memberships behind its own to
// hand over, so the one at from+1 -- the step the walk starts with -- is still
// there right up to from+Keep+1, and past that nobody holds it any more.
func canReach(from, to uint64) bool { return from+Keep+1 >= to }

// Stranded reports whether the cluster has moved out of this node's reach,
// along with the deepest membership it has been offered. Nothing will move its
// anchor again: the memberships it needs to walk forward have been discarded by
// everyone that had them, so it goes on configuring peers from a membership the
// cluster has left behind until it is enrolled afresh.
func (s *Set) Stranded() (uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.anchor == nil {
		return s.seen, false
	}
	return s.seen, !canReach(s.anchor.Depth, s.seen)
}

// note records what adding one record did.
func (res *MergeResult) note(ok bool, err error) {
	switch {
	case ok:
		res.Changed++
	case errors.Is(err, ErrSuperseded):
		res.Superseded++
	case err != nil:
		res.Refused++
		res.Reason = err
	}
}

// Records returns the set's contents in a deterministic order, so that the
// state file and what goes to a peer do not churn.
func (s *Set) Records() Records {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs := Records{}
	for _, c := range s.checkpoints {
		held := *c
		held.Attestations = slices.Clone(c.Attestations)
		slices.SortFunc(held.Attestations, func(a, b Attestation) int { return byIdentity(a.Signer, b.Signer) })
		rs.Checkpoints = append(rs.Checkpoints, held)
	}
	for _, by := range s.admissions {
		for _, as := range by {
			rs.Admissions = append(rs.Admissions, as...)
		}
	}
	for _, revs := range s.revocations {
		rs.Revocations = append(rs.Revocations, revs...)
	}
	slices.SortFunc(rs.Checkpoints, func(a, b Checkpoint) int {
		if a.Depth != b.Depth {
			return cmp.Compare(a.Depth, b.Depth)
		}
		ad, bd := a.Digest(), b.Digest()
		return bytes.Compare(ad[:], bd[:])
	})
	slices.SortFunc(rs.Admissions, func(a, b Admission) int {
		if c := byIdentity(a.Identity, b.Identity); c != 0 {
			return c
		}
		if c := byIdentity(a.Admitter, b.Admitter); c != 0 {
			return c
		}
		return bytes.Compare(a.Signature, b.Signature)
	})
	slices.SortFunc(rs.Revocations, func(a, b Revocation) int {
		if c := byIdentity(a.Identity, b.Identity); c != 0 {
			return c
		}
		if c := byIdentity(a.Revoker, b.Revoker); c != 0 {
			return c
		}
		return bytes.Compare(a.Signature, b.Signature)
	})
	return rs
}

// Trim discards what the agreed membership has accounted for: the records about
// every identity it names, and the checkpoints more than Keep behind it. It
// reports how many records went.
//
// A record is accounted for only if the anchor names the identity it is about,
// as a member or as one it removed, and its statement about that identity is
// still this set's answer. Records arrive without the lock the anchor was taken
// under, so one landing in between leaves the anchor out of date about that
// identity; the record that made it so has to stay, or the change it carries
// would be thrown away before anyone agreed to discard it.
//
// The checkpoints Keep holds are the steps a peer that has been away needs to
// get from its own anchor to this one; nothing here reads them. They fall away
// at the same depth as the departures named in the anchor, and that is not a
// coincidence: a departure is remembered for exactly as long as there can be a
// peer that has not yet seen it.
func (s *Set) Trim() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor == nil {
		return 0
	}
	v := s.viewLocked()
	// An identity is accounted for when the anchor's statement about it is both
	// the membership now and the membership the records propose. The second
	// half matters: a revocation the cluster has yet to agree still names a
	// member of the anchor, and dropping it as "accounted for" would erase the
	// only record saying that member is on its way out.
	proposed := make(map[PublicKey]Member)
	for _, m := range s.proposalLocked().Members {
		proposed[m.Identity] = m
	}
	accounted := make(map[PublicKey]bool, len(s.anchor.Members)+len(s.anchor.Removed))
	for _, m := range s.anchor.Members {
		if cur, ok := v.members[m.Identity]; ok && cur == m && proposed[m.Identity] == m {
			accounted[m.Identity] = true
		}
	}
	for _, d := range s.anchor.Removed {
		_, member := v.members[d.Identity]
		_, coming := proposed[d.Identity]
		if !member && !coming {
			accounted[d.Identity] = true
		}
	}
	gone := 0
	for id, by := range s.admissions {
		if accounted[id] {
			gone += len(by)
			delete(s.admissions, id)
			continue
		}
		// Not accounted for is what an admission waiting for the next agreement
		// looks like -- and also what one that will never be agreed looks like.
		// Two kinds are dead: one asking for a name or a slot an agreed member
		// holds, which the membership settled against, and one whose admitter
		// is neither a member nor about to be, which nothing can make count.
		// Without this they stay for the life of the cluster, since no
		// membership ever names the identity for the rule above to reach.
		for admitter, as := range by {
			kept := as[:0]
			for _, adm := range as {
				if !dead(v, proposed, adm) {
					kept = append(kept, adm)
					continue
				}
				gone++
			}
			if len(kept) == 0 {
				delete(by, admitter)
				continue
			}
			by[admitter] = kept
		}
		if len(by) == 0 {
			delete(s.admissions, id)
		}
	}
	for revoker, revs := range s.revocations {
		kept := revs[:0]
		for _, r := range revs {
			if accountedFor(r, accounted) {
				gone++
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == 0 {
			delete(s.revocations, revoker)
			continue
		}
		s.revocations[revoker] = kept
	}
	floor := uint64(0)
	if s.anchor.Depth > Keep {
		floor = s.anchor.Depth - Keep
	}
	for d, c := range s.checkpoints {
		if c.Depth < floor {
			delete(s.checkpoints, d)
			gone++
		}
	}
	if gone > 0 {
		s.forget()
	}
	return gone
}

// dead reports whether an admission is one no agreement can ever act on: its
// admitter is nobody the cluster holds, or it asks for a name or an overlay
// slot an agreed member already holds.
func dead(v *view, proposed map[PublicKey]Member, a Admission) bool {
	if _, ok := proposed[a.Admitter]; !ok {
		return true
	}
	if held, ok := v.byName[a.Name]; ok && held != a.Identity {
		return true
	}
	if held, ok := v.slots[a.Host]; ok && held != a.Identity {
		return true
	}
	return false
}

// accountedFor reports whether the anchor names every identity a revocation
// takes out, so that nothing it says is lost by dropping it.
func accountedFor(r Revocation, accounted map[PublicKey]bool) bool {
	if !accounted[r.Identity] {
		return false
	}
	for _, d := range r.Disowned {
		if !accounted[d] {
			return false
		}
	}
	return true
}

// forget says the answers no longer match the records. The next query builds
// them again. Callers hold the write lock.
func (s *Set) forget() { s.view.Store(nil) }

// Quorum is the rule the cluster keeps: how many members must agree on a
// membership before what led to it is discarded.
func (s *Set) Quorum() QuorumRule { return s.current().quorum }

// Depth is how far the agreed membership has come, or 0 before there is one.
func (s *Set) Depth() uint64 { return s.current().depth }
