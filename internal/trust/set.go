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
// The checkpoints kept past the anchor are the ones the cluster is still
// signing: deciding the membership is asking whether any of them carries a
// quorum yet. Everything behind the anchor goes, since a node takes the
// membership the cluster is on now in one step. See docs/membership.md.
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
	// confirmations is, per record, the members that have agreed it should
	// count. Empty where the cluster asks for none, which is the default.
	confirmations map[Digest]map[PublicKey]Confirmation
	// pending is an attestation whose membership has not arrived yet, one per
	// signer -- which is all a node can honestly have, since it agrees with one
	// membership at a time. It keeps an agreement from being lost to the order
	// two datagrams happen to arrive in.
	pending map[PublicKey]pendingAt
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
		checkpoints:   map[Digest]*Checkpoint{},
		confirmations: map[Digest]map[PublicKey]Confirmation{},
		pending:       map[PublicKey]pendingAt{},
		admissions:    map[PublicKey]map[PublicKey][]Admission{},
		revocations:   map[PublicKey][]Revocation{},
	}
}

// couldCount reports whether a signature from this identity could make a record
// count: only a member's does, which is the rule claimFor applies when the
// membership is worked out. Anything else is refused rather than stored.
//
// Nothing is lost by refusing. A record can reach a node before the membership
// that makes its signer a member -- gossip carries single records in no
// order -- but the state sync carries a peer's whole set every round and Merge
// applies the memberships in it first, so a record refused early is offered
// again once it can be judged, and offered by whoever signed it for as long as
// they think it matters. What cannot be judged later is junk, and this is what
// keeps it out of memory, out of the state file and off the wire.
//
// The collection rule in dead is the same question asked of the proposed
// membership rather than the agreed one, so it is the more forgiving of the
// two. That is the safe direction: a record this refuses was never stored, and
// one it lets through is judged again when the membership moves.
func (s *Set) couldCount(v *view, signer PublicKey) bool {
	_, ok := v.members[signer]
	return ok
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
	if !s.couldCount(v, a.Admitter) {
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
	if s.supersededRevocation(r) || !s.couldCount(s.viewLocked(), r.Revoker) {
		return false, ErrSuperseded
	}
	s.revocations[r.Revoker] = append(s.revocations[r.Revoker], r)
	s.forget()
	return true, nil
}

// pendingAt is an attestation for a membership this node does not hold yet.
type pendingAt struct {
	digest Digest
	at     Attestation
}

// Holds reports whether the set has the membership with this digest.
func (s *Set) Holds(d Digest) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.checkpoints[d]
	return ok
}

// AddAttestation takes one node's agreement with a membership, which is all a
// node has to send once somebody has stated that membership: two nodes that
// agree produce the same digest, so the signature is the whole of what is new.
// A membership costs kilobytes and every member signs the same one, so sending
// it each time is the difference between a datagram and a stream to every peer.
//
// Where the membership has not arrived yet the attestation is kept, so that an
// agreement is not lost to the order two datagrams happen to arrive in. Only
// from a member: what is kept is then bounded by the membership rather than by
// whoever is sending.
func (s *Set) AddAttestation(d Digest, at Attestation) (bool, error) {
	if !Verify(at.Signer, attestedBytes(d), at.Signature) {
		return false, fmt.Errorf("attestation by %s does not verify", at.Signer.Short())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if held, ok := s.checkpoints[d]; ok {
		if slices.ContainsFunc(held.Attestations, func(h Attestation) bool { return h.Signer == at.Signer }) {
			return false, nil
		}
		// a stored checkpoint is never edited in place: a view built earlier
		// may point at it, and a view is whole or it is nothing
		merged := *held
		merged.Attestations = append(slices.Clone(held.Attestations), at)
		s.checkpoints[d] = &merged
		if s.anchor == held {
			s.anchor = &merged
		}
		s.advance()
		s.forget()
		return true, nil
	}
	if _, member := s.viewLocked().members[at.Signer]; !member {
		return false, nil
	}
	if was, ok := s.pending[at.Signer]; ok && was.digest == d {
		return false, nil
	}
	s.pending[at.Signer] = pendingAt{digest: d, at: at}
	return true, nil
}

// AddConfirmation takes one member's agreement that a record should count. A
// cluster that asks for confirmations holds a record until enough have arrived,
// so this is what makes one take effect.
func (s *Set) AddConfirmation(c Confirmation) (bool, error) {
	if err := c.Validate(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.couldCount(s.viewLocked(), c.Confirmer) {
		return false, ErrSuperseded // only a member's agreement is worth anything
	}
	by := s.confirmations[c.Record]
	if _, held := by[c.Confirmer]; held {
		return false, nil
	}
	if by == nil {
		by = map[PublicKey]Confirmation{}
		s.confirmations[c.Record] = by
	}
	by[c.Confirmer] = c
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
	// A checkpoint no member of this node's membership has attested to can
	// never be adopted here, whatever arrives afterwards: attestations only
	// accumulate on a digest, and every one on this is from somebody this node
	// knows nothing about. Keeping it would keep it for good, since the trim
	// reaches nothing past the anchor.
	if s.anchor != nil && c.Depth > s.anchor.Depth && attestedBy(&c, memberSet(s.anchor)) == 0 {
		return false, fmt.Errorf("this node's membership is at depth %d and none of its members has "+
			"attested to the one at %d; it has been away too long and has to be enrolled again",
			s.anchor.Depth, c.Depth)
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
		// agreements that arrived before the membership they are for
		for signer, p := range s.pending {
			if p.digest != d {
				continue
			}
			if !slices.ContainsFunc(stored.Attestations, func(h Attestation) bool { return h.Signer == signer }) {
				stored.Attestations = append(stored.Attestations, p.at)
			}
			delete(s.pending, signer)
		}
		s.checkpoints[d] = &stored
		changed = true
	}
	if s.advance() || changed {
		s.forget()
		return true, nil
	}
	return false, nil
}

// advance moves the anchor forward while a checkpoint deeper than it carries
// the agreement of enough of its members. Taking one may make a deeper one
// usable, so it repeats. Callers hold the write lock.
func (s *Set) advance() bool {
	moved := false
	for s.anchor != nil {
		next := s.agreed(*s.anchor)
		if next == nil {
			break
		}
		s.anchor, moved = next, true
	}
	if !moved {
		return false
	}
	s.forget() // the answers were the old membership's
	// Everything that led here is spent, and this is the moment it becomes so.
	// Discarding it anywhere else would be a step somebody has to remember to
	// take, and the records would pile up wherever they forgot.
	s.prune()
	// This node is keeping up, so whatever it was once offered and could not
	// use says nothing about where the cluster is now. A membership it cannot
	// verify is the only evidence it has of being left behind, and evidence
	// that old is no evidence at all.
	s.seen = s.anchor.Depth
	return true
}

// agreed is the deepest checkpoint past anchor that enough of anchor's members
// have attested to, if one is held. Callers hold the lock.
//
// It does not have to be the next one. A node that has been away takes the
// membership the cluster is on now in a single step, provided a quorum of the
// members it still knows about signed it -- which is the same question asked of
// the very next checkpoint, and the same answer. Walking there one at a time
// would say more: it would show every membership in between, so a key that was
// a member when this node last looked and has been revoked since would stop
// counting on the way past. That is the whole of what a walk would add, and it
// would mean every node carrying the last sixty-four memberships in every state
// sync. An attacker who has collected a quorum of this node's membership can
// move it wherever it likes either way.
func (s *Set) agreed(anchor Checkpoint) *Checkpoint {
	members := memberSet(&anchor)
	need := anchor.Quorum.Size(len(anchor.Members))
	var best *Checkpoint
	for _, c := range s.checkpoints {
		if c.Depth <= anchor.Depth || attestedBy(c, members) < need {
			continue
		}
		// the deepest, and where two are equally deep -- which takes a quorum
		// low enough for two to be disjoint, the operator's choice -- the
		// smaller digest, so that every node picks the same one
		switch {
		case best == nil, c.Depth > best.Depth:
			best = c
		case c.Depth == best.Depth:
			if bd, cd := best.Digest(), c.Digest(); bytes.Compare(cd[:], bd[:]) < 0 {
				best = c
			}
		}
	}
	return best
}

// attestedBy is how many of members have attested to c.
func attestedBy(c *Checkpoint, members map[PublicKey]bool) int {
	votes := 0
	for _, at := range c.Attestations {
		if members[at.Signer] {
			votes++
		}
	}
	return votes
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
	for _, c := range rs.Confirmations {
		res.note(s.AddConfirmation(c))
	}
	// A state sync is the cluster's regular tick, and the only one a quiet
	// cluster has: advancing the anchor is what usually spends records, and a
	// membership that is not changing never does it. Collecting here as well
	// means what can never count goes whether or not anything is happening.
	s.mu.Lock()
	s.prune()
	s.mu.Unlock()
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

// canReach reports whether a node whose membership is at depth from is near
// enough to one at depth to for its records to be worth taking. A membership
// names what it removed in the last Keep agreements, so one that far back is
// still accounted for; a node older than that missed removals nothing here
// records any more, and may still be holding the admissions they spent.
func canReach(from, to uint64) bool { return from+Keep >= to }

// memberSet is the identities a checkpoint names, for counting attestations.
func memberSet(c *Checkpoint) map[PublicKey]bool {
	members := make(map[PublicKey]bool, len(c.Members))
	for _, m := range c.Members {
		members[m.Identity] = true
	}
	return members
}

// Stranded reports whether the cluster has moved out of this node's reach,
// along with the deepest membership it has been offered. It has seen one past
// its own and holds nothing that could become it: every attestation on the
// memberships since is from somebody it does not know, so the cluster has
// turned over further than it can follow. Nothing will move its anchor again,
// and it goes on configuring peers from a membership the cluster has left
// behind until it is enrolled afresh.
func (s *Set) Stranded() (uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.anchor == nil || s.seen <= s.anchor.Depth {
		return s.seen, false
	}
	for _, c := range s.checkpoints {
		if c.Depth > s.anchor.Depth {
			return s.seen, false // one it can still take, waiting for the rest to sign
		}
	}
	return s.seen, true
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
	for _, by := range s.confirmations {
		for _, c := range by {
			rs.Confirmations = append(rs.Confirmations, c)
		}
	}
	slices.SortFunc(rs.Confirmations, func(a, b Confirmation) int {
		return cmp.Or(bytes.Compare(a.Record[:], b.Record[:]), byIdentity(a.Confirmer, b.Confirmer))
	})
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

// prune discards what the agreed membership has accounted for: the records
// about every identity it names, and every membership behind it. It runs when
// the anchor moves, which is when they become spent. Callers hold the write
// lock.
//
// A record is accounted for only if the anchor names the identity it is about,
// as a member or as one it removed, and its statement about that identity is
// still this set's answer. Records arrive without the lock the anchor was taken
// under, so one landing in between leaves the anchor out of date about that
// identity; the record that made it so has to stay, or the change it carries
// would be thrown away before anyone agreed to discard it.
//
// What a node keeps is therefore its membership, the deeper ones peers are
// still signing, and whatever has been signed since -- not a history. How far
// behind a node may fall and still catch up is decided by who signed the
// current membership, not by how many are kept.
func (s *Set) prune() {
	if s.anchor == nil {
		return
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
	for id, by := range s.admissions {
		if accounted[id] {
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
				}
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
			// A record still gathering confirmations has not had its say yet:
			// its subject is a member because nobody has agreed to take it
			// out, which is the opposite of the membership having accounted
			// for it.
			if s.confirmed(v, r.Digest(), revoker) && accountedFor(v, s, r, accounted) {
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
	// A confirmation says something about one record, so it goes when that
	// record does -- and one for a record this node never held says nothing it
	// could ever act on.
	held := map[Digest]bool{}
	for _, by := range s.admissions {
		for _, as := range by {
			for _, a := range as {
				held[a.Digest()] = true
			}
		}
	}
	for _, revs := range s.revocations {
		for _, r := range revs {
			held[r.Digest()] = true
		}
	}
	for d := range s.confirmations {
		if !held[d] {
			delete(s.confirmations, d)
		}
	}

	// Every membership behind the anchor goes. Nothing walks from one to the
	// next any more -- a node that has been away takes the membership the
	// cluster is on now in one step -- so the only ones worth holding are the
	// anchor itself and the deeper ones still gathering attestations.
	anchored := s.anchor.Digest()
	members := memberSet(s.anchor)
	for d, c := range s.checkpoints {
		switch {
		case d == anchored:
		case c.Depth <= s.anchor.Depth, attestedBy(c, members) == 0:
			// behind the membership, or signed by nobody this node knows and so
			// never adoptable here
			delete(s.checkpoints, d)
		}
	}
	s.forget()
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

// accountedFor reports whether the anchor accounts for every identity a
// revocation takes out that the cluster has heard of, so that nothing it says
// is lost by dropping it.
func accountedFor(v *view, s *Set, r Revocation, accounted map[PublicKey]bool) bool {
	for _, id := range append([]PublicKey{r.Identity}, r.Disowned...) {
		// An identity the cluster knows nothing about is one this record says
		// nothing about, so it is no reason to keep it. Without this a member
		// could name a thousand strangers in one revocation and every node
		// would hold it for good: the membership can never account for an
		// identity it has never heard of.
		if !accounted[id] && s.knows(v, id) {
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
