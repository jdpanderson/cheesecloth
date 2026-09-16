package trust

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Set is the membership: a pinned root, the checkpoints that state who the
// members are, and the admissions and revocations signed since the newest of
// them. Safe for concurrent use.
//
// A checkpoint states the membership rather than deriving it, so once one has
// ratified nothing has to walk a chain of signatures to decide who is a member:
// the answer is read from the list. Everything the checkpoint accounts for can
// then be thrown away, which is what keeps the set from growing for ever. See
// docs/checkpoints.md.
//
// Between checkpoints the records answer for themselves: an admission vouches
// while its admitter is a member, and a revocation counts while its revoker is.
// Those two questions can reach each other -- two members revoking each other
// is the case -- so the walk carries a guard, and re-entering it is false. That
// walk is at most as deep as the changes since the last checkpoint, rather than
// as deep as the cluster's whole history.
type Set struct {
	mu   sync.RWMutex
	root PublicKey
	// checkpoints is every checkpoint held, by digest. Two nodes may hold one
	// with different attestations collected; adding merges them.
	checkpoints map[Digest]*Checkpoint
	admissions  map[PublicKey]map[PublicKey][]Admission // identity -> admitter -> its records
	revocations map[PublicKey][]Revocation              // revoker -> its records
	// view is the membership the records make, built when a query finds it
	// stale and dropped whenever a record changes. Nil means stale. It is read
	// without the lock: the gossip transport asks whether a peer is a member
	// for every packet.
	view atomic.Pointer[view]
	// now is the clock a record's date is checked against; tests move it.
	now func() time.Time
}

// NewSet creates a set trusting root. The root's own record is added like any
// other, when it arrives, and it is what says which quorum rule the cluster
// was founded with.
func NewSet(root PublicKey) *Set {
	return &Set{
		root:        root,
		checkpoints: map[Digest]*Checkpoint{},
		admissions:  map[PublicKey]map[PublicKey][]Admission{},
		revocations: map[PublicKey][]Revocation{},
		now:         time.Now,
	}
}

// Bounds on a record's date. They are wide on purpose: what they are for is
// keeping a date no clock could honestly have produced out of the set, not
// policing skew, which the warning does.
const (
	// epoch is the earliest plausible date: nothing predates the project.
	epoch = 1577836800 // 2020-01-01 UTC
	// ahead is how far in the future a record may be dated and still be kept.
	ahead = 24 * time.Hour
	// skewed is the gap worth warning about; NTP holds milliseconds.
	skewed = 5 * time.Minute
)

// checkClock rejects a record no clock could honestly have produced, and warns
// about one that is merely ahead of ours. Only the future is a signal: a record
// dated in the past is indistinguishable from an old one, which is what most
// records are.
func (s *Set) checkClock(kind string, signer PublicKey, issuedAt int64) error {
	if issuedAt < epoch {
		return fmt.Errorf("%s is dated before %s", kind, time.Unix(epoch, 0).UTC().Format(time.DateOnly))
	}
	gap := time.Unix(issuedAt, 0).Sub(s.now())
	if gap > ahead {
		return fmt.Errorf("%s is dated %s in the future", kind, gap.Round(time.Second))
	}
	if gap > skewed {
		slog.Warn("record is dated ahead of this node; check that the cluster's clocks are synchronised",
			"signer", signer.Short(), "ahead", gap.Round(time.Second))
	}
	return nil
}

// errUntrustedRoot is returned for a self-signed admission of a non-root identity.
var errUntrustedRoot = errors.New("self-signed admission is not the pinned root")

// ErrSuperseded is returned for a record a ratified checkpoint has accounted
// for. Nothing is wrong with it; it is simply history, and taking it back in
// would put back what the checkpoint was made to discard. A peer that is behind
// offers these at every state sync, so the caller counts them rather than
// reporting each one.
var ErrSuperseded = errors.New("a ratified checkpoint has already accounted for this record")

// AddAdmission stores a signature-valid record. It reports whether the set
// changed, which a record already held does not.
func (s *Set) AddAdmission(a Admission) (bool, error) {
	if s.held(func(s *Set) bool { return s.holdsAdmission(a) }) {
		return false, nil
	}
	if err := a.Validate(); err != nil {
		return false, err
	}
	if a.Admitter == a.Identity && a.Identity != s.root {
		return false, errUntrustedRoot
	}
	if err := s.checkClock("admission", a.Admitter, a.IssuedAt); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holdsAdmission(a) {
		return false, nil // the other copy of it landed while this one was being checked
	}
	// The root's own record is the anchor every checkpoint chain chains back
	// to, so it is kept whatever the checkpoints say.
	if a.Admitter != a.Identity && s.supersedes(a.Identity) {
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

// AddRevocation stores a signature-valid revocation. Any member may be revoked,
// the root included: it is a peer, not an authority over the others.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	if s.held(func(s *Set) bool { return s.holdsRevocation(r) }) {
		return false, nil
	}
	if err := r.Validate(); err != nil {
		return false, err
	}
	if err := s.checkClock("revocation", r.Revoker, r.IssuedAt); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holdsRevocation(r) {
		return false, nil
	}
	// A revocation whose every subject a checkpoint has already removed says
	// nothing the checkpoint does not; one that still takes somebody out is
	// kept, since it may be the record the next checkpoint is made from.
	if s.supersededRevocation(r) {
		return false, ErrSuperseded
	}
	s.revocations[r.Revoker] = append(s.revocations[r.Revoker], r)
	s.forget()
	return true, nil
}

// AddCheckpoint stores a checkpoint, or merges its attestations into one the
// set already holds. Two nodes attesting to the same membership produce the
// same digest, so their signatures accumulate on one record and a checkpoint
// ratifies wherever enough of them have arrived.
func (s *Set) AddCheckpoint(c Checkpoint) (bool, error) {
	if err := c.Validate(); err != nil {
		return false, err
	}
	for _, at := range c.Attestations {
		if err := s.checkClock("checkpoint", at.Signer, s.now().Unix()); err != nil {
			return false, err
		}
		break // the record carries no date of its own; the bound is on the records it follows
	}
	d := c.Digest()
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.checkpoints[d]
	if !ok {
		stored := c
		stored.Attestations = slices.Clone(c.Attestations)
		s.checkpoints[d] = &stored
		s.forget()
		return true, nil
	}
	// A stored checkpoint is never edited in place: a view built earlier still
	// points at it, and a view is whole or it is nothing. Merging replaces it
	// with a new one, so the old value stays true for whoever is reading it.
	var added []Attestation
	for _, at := range c.Attestations {
		if slices.ContainsFunc(held.Attestations, func(h Attestation) bool { return h.Signer == at.Signer }) {
			continue
		}
		added = append(added, at)
	}
	if len(added) == 0 {
		return false, nil
	}
	merged := *held
	merged.Attestations = append(slices.Clone(held.Attestations), added...)
	s.checkpoints[d] = &merged
	s.forget()
	return true, nil
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
	Superseded int // history a checkpoint has already accounted for
	Refused    int
	Reason     error // the last refusal, as an example of what is being sent
}

// Merge adds every record in rs and reports what it did with them. Checkpoints
// go in first, so that the records they supersede are recognised as history
// rather than taken back in.
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
		ad, bd := a.Digest(), b.Digest()
		if a.Depth != b.Depth {
			return int(a.Depth) - int(b.Depth)
		}
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

// Trim discards what the ratified checkpoint has accounted for: the records
// about every identity it names, and every checkpoint deeper than retain below
// it. It reports how many records went.
//
// A record is accounted for only if the checkpoint names the identity it is
// about, as a member or as one it removed. That is what makes trimming safe
// against a record that arrives while a checkpoint is being made: the
// membership it states was fixed before that record landed, so the checkpoint
// says nothing about it, so the trim leaves it alone and the next checkpoint
// takes it in. Deleting everything instead would throw away a change nobody had
// agreed to discard.
//
// The chain of checkpoints is what a node returning from an absence walks, so
// that is what retain keeps. The root's own record stays whatever happens: it
// is the anchor the chain ends at.
func (s *Set) Trim(retain int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	base := s.ratified()
	if base == nil {
		return 0
	}
	// An identity is accounted for only where the checkpoint's statement about
	// it is still the set's answer. Records arrive without the lock the
	// checkpoint was made under, so one can land between the membership being
	// read and this running; where it has, the checkpoint is out of date about
	// that identity and the record that made it so has to stay.
	v := s.viewLocked()
	accounted := make(map[PublicKey]bool, len(base.Members)+len(base.Removed))
	for _, m := range base.Members {
		if cur, ok := v.members[m.Identity]; ok && cur == m {
			accounted[m.Identity] = true
		}
	}
	for _, r := range base.Removed {
		if _, ok := v.members[r]; !ok {
			accounted[r] = true
		}
	}
	gone := 0
	for id, by := range s.admissions {
		if !accounted[id] {
			continue // signed since the checkpoint was made; it still has to say so
		}
		for admitter, as := range by {
			if admitter == id && id == s.root {
				continue // the anchor
			}
			gone += len(as)
			delete(by, admitter)
		}
		if len(by) == 0 {
			delete(s.admissions, id)
		}
	}
	for revoker, revs := range s.revocations {
		kept := revs[:0]
		for _, r := range revs {
			if !accountedFor(r, accounted) {
				kept = append(kept, r)
				continue
			}
			gone++
		}
		if len(kept) == 0 {
			delete(s.revocations, revoker)
			continue
		}
		s.revocations[revoker] = kept
	}
	floor := uint64(0)
	if int(base.Depth) > retain {
		floor = base.Depth - uint64(retain)
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

// accountedFor reports whether the checkpoint names every identity a
// revocation takes out, so that nothing it says is lost by dropping it.
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
// them again. Callers hold the write lock, so no view derived from the records
// as they were can be stored after this.
func (s *Set) forget() { s.view.Store(nil) }

// LastSigned is the newest date on the records signer has been seen to sign,
// which is the floor under anything it signs next: a record dated behind one
// its signer has already made would lose to it, so the admission or rename it
// carries would quietly decide nothing.
func (s *Set) LastSigned(signer PublicKey) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	last := int64(0)
	for _, by := range s.admissions {
		for _, a := range by[signer] {
			last = max(last, a.IssuedAt)
		}
	}
	for _, r := range s.revocations[signer] {
		last = max(last, r.IssuedAt)
	}
	return last
}

// Root is the identity every chain of checkpoints ends at.
func (s *Set) Root() PublicKey { return s.root }

// Quorum is the rule the cluster was founded with: how many members must attest
// to a checkpoint before it ratifies.
func (s *Set) Quorum() QuorumRule { return s.current().quorum }

// Depth is the depth of the ratified checkpoint, or 0 before the first one.
func (s *Set) Depth() uint64 { return s.current().depth }

// Base is the ratified checkpoint the membership is read from, and whether
// there is one yet.
func (s *Set) Base() (Checkpoint, bool) {
	v := s.current()
	if v.base == nil {
		return Checkpoint{}, false
	}
	return *v.base, true
}

// Removed is every identity a retained checkpoint has taken out. They stay out
// while the chain remembers them, which is what stops a record from before a
// checkpoint putting back what it removed. Once the chain is trimmed past them
// they are forgotten, and the identity may be invited again.
func (s *Set) Removed() map[PublicKey]bool { return maps.Clone(s.current().removed) }
