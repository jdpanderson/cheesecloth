package trust

import (
	"bytes"
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
	if s.viewLocked().removed[a.Identity] {
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
	Refused    int
	Reason     error // the last refusal, as an example of what is being sent
}

// Merge adds every record in rs and reports what it did with them. Checkpoints
// go in first, shallowest first, so that the anchor moves as far as it can
// before the records are judged against it.
func (s *Set) Merge(rs Records) MergeResult {
	var res MergeResult
	for _, c := range slices.SortedFunc(slices.Values(rs.Checkpoints), func(a, b Checkpoint) int {
		return int(a.Depth) - int(b.Depth)
	}) {
		res.note(s.AddCheckpoint(c))
	}
	for _, a := range rs.Admissions {
		res.note(s.AddAdmission(a))
	}
	for _, r := range rs.Revocations {
		res.note(s.AddRevocation(r))
	}
	return res
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
			return int(a.Depth) - int(b.Depth)
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
// every identity it names, and the checkpoints more than retain behind it. It
// reports how many records went.
//
// A record is accounted for only if the anchor names the identity it is about,
// as a member or as one it removed, and its statement about that identity is
// still this set's answer. Records arrive without the lock the anchor was taken
// under, so one landing in between leaves the anchor out of date about that
// identity; the record that made it so has to stay, or the change it carries
// would be thrown away before anyone agreed to discard it.
//
// What retain keeps is the steps a peer that has been away needs to get from
// its own anchor to this one. Nothing here reads them.
func (s *Set) Trim(retain int) int {
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
	for _, r := range s.anchor.Removed {
		_, member := v.members[r]
		_, coming := proposed[r]
		if !member && !coming {
			accounted[r] = true
		}
	}
	gone := 0
	for id, by := range s.admissions {
		if !accounted[id] {
			continue // signed since the anchor was taken; it still has to say so
		}
		gone += len(by)
		delete(s.admissions, id)
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
	if int(s.anchor.Depth) > retain {
		floor = s.anchor.Depth - uint64(retain)
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
