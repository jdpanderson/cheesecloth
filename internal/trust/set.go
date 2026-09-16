package trust

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Set is the membership: a pinned root plus every signature-valid record seen.
// Validity is decided at query time from the root, so records may arrive in
// any order. Safe for concurrent use.
//
// Records are held per signer: an identity's admissions by admitter, its
// revocations by revoker. A signer only ever changes what it said itself, and
// every answer it gives is a union, a maximum or a minimum over what is held,
// so two nodes with the same records agree whatever order those records
// arrived in.
//
// Every record a signer signed about an identity is kept, of either kind. Of an
// admitter's, the earliest stops it retracting a membership it vouched for and
// the latest lets a member that enrols again be renamed; of a revoker's, the one
// that marks lowest decides, whichever of them it signed first. The rest decide
// nothing, but dropping one would leave a gap in the signer's sequence, and a
// node given the set would stop at it. So nothing is ever dropped: the set
// only grows, and the records alone say how far each signer's sequence goes.
//
// Records are ordered by the signer's own counter rather than by its clock, and
// a revocation marks where its subject's records stop, so whether a record was
// signed while its signer was a member is decided without one. What the date on
// a record does decide is which of two records made by different signers to
// prefer, where their counters say nothing about each other; see the rule on
// IssuedAt in records.go.
type Set struct {
	mu          sync.RWMutex
	root        PublicKey
	admissions  map[PublicKey]map[PublicKey][]Admission  // identity -> admitter -> its records
	revocations map[PublicKey]map[PublicKey][]Revocation // identity -> revoker -> its records
	// signers is what is remembered about each signer beyond its records.
	signers map[PublicKey]signerState
	// view is the membership the records make, built when a query finds it
	// stale and dropped whenever a record changes; see view.go. Nil means
	// stale. It is read without the lock: the gossip transport asks whether a
	// peer is a member for every packet.
	view atomic.Pointer[view]
	// now is the clock a record's date is checked against; tests move it.
	now func() time.Time
}

// signerState is what a set remembers about a signer apart from its records:
// how far its sequence has been taken, and the newest date it has been seen to
// sign, which is the floor under whatever it signs next.
type signerState struct {
	head       uint64
	lastSigned int64
}

// NewSet creates a set trusting root. The root's own record is added like any
// other, when it arrives.
func NewSet(root PublicKey) *Set {
	return &Set{
		root:        root,
		admissions:  map[PublicKey]map[PublicKey][]Admission{},
		revocations: map[PublicKey]map[PublicKey][]Revocation{},
		signers:     map[PublicKey]signerState{},
		now:         time.Now,
	}
}

// Bounds on a record's date. They are wide on purpose: what they are for is
// keeping a date no clock could honestly have produced out of a set that never
// forgets, not policing skew, which the warning does. Two nodes disagree about
// a record only if it is dated within their mutual skew of a bound, and a clock
// that far out has already failed.
//
// The future bound is the one that does work beyond tidiness. Of two admitters'
// records for one identity the later dated decides, so a record dated far
// enough ahead would decide for ever; bounded to a day, an admitter can hold
// its claim a day against a node whose clock is right, and re-enrolling settles
// it after that.
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

// LastSigned is the newest date on the records signer has been seen to sign,
// which is the floor under anything it signs next.
func (s *Set) LastSigned(signer PublicKey) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signers[signer].lastSigned
}

// errUntrustedRoot is returned for a self-signed admission of a non-root identity.
var errUntrustedRoot = errors.New("self-signed admission is not the pinned root")

// AddAdmission stores a signature-valid record, in its admitter's sequence
// order. Every record an admitter signs is kept, so nothing it signs later
// displaces what it signed before. It reports whether the set changed, which a
// record already held does not; one ahead of its admitter's sequence is
// refused as ErrAhead.
func (s *Set) AddAdmission(a Admission) (bool, error) {
	signed := a.signedBytes()
	if s.heldAdmission(a, signed) {
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
	if s.holdsAdmission(a, signed) {
		return false, nil // the other copy of it landed while this one was being checked
	}
	if err := s.extend(a.Admitter, a.Seq); err != nil {
		return false, err
	}
	s.claim(a.Admitter, a.Seq, a.IssuedAt)
	by := s.admissions[a.Identity]
	if by == nil {
		by = map[PublicKey][]Admission{}
		s.admissions[a.Identity] = by
	}
	by[a.Admitter] = append(by[a.Admitter], a) // in sequence order: extend saw to that
	s.forget()
	return true, nil
}

// A record the set holds was checked when it arrived, and a signature is what
// identifies a record, so one already held needs no second check. That is what
// keeps a state sync, which carries a peer's whole record set, from verifying
// the whole membership again. The signed bytes are compared as well as the
// signature, so a record differing from a held one in any signed field still
// takes the checked path and is refused there.
//
// The question is asked twice: once before the record is verified, which is the
// cheap path, and again under the write lock. Two copies of one record can be on
// their way in at once — memberlist delivers a broadcast and a push/pull state
// sync on different goroutines, and each carries what the other does — and
// without the second check the copy that arrived while the other was being
// verified would look like a second record at a number its signer had already
// used, and be reported as a key used outside its agent.

// heldAdmission reports whether the set already holds a, whose signed bytes are
// signed.
func (s *Set) heldAdmission(a Admission, signed []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.holdsAdmission(a, signed)
}

// holdsAdmission is heldAdmission with the lock already held.
func (s *Set) holdsAdmission(a Admission, signed []byte) bool {
	for _, held := range s.admissions[a.Identity][a.Admitter] {
		if bytes.Equal(held.Signature, a.Signature) && bytes.Equal(held.signedBytes(), signed) {
			return true
		}
	}
	return false
}

// heldRevocation reports whether the set already holds r, whose signed bytes
// are signed.
func (s *Set) heldRevocation(r Revocation, signed []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.holdsRevocation(r, signed)
}

// holdsRevocation is heldRevocation with the lock already held.
func (s *Set) holdsRevocation(r Revocation, signed []byte) bool {
	for _, held := range s.revocations[r.Identity][r.Revoker] {
		if bytes.Equal(held.Signature, r.Signature) && bytes.Equal(held.signedBytes(), signed) {
			return true
		}
	}
	return false
}

// ErrAhead is returned for a record whose signer has not been seen to sign the
// one before it. It says nothing against the record: the next state sync
// carries the whole set in sequence order and takes it then.
var ErrAhead = errors.New("record is ahead of its signer's sequence")

// errSpent is returned for a record at a number its signer has already used.
// Nothing is ever dropped, so a record that gets this far is one the set does
// not hold at a number it has: a second, different record at one of the
// signer's own numbers, which its agent cannot produce. It says the key has
// been used outside that agent, and the caller reports it; see
// cluster.MergeRemoteState, which counts what a peer re-offers rather than
// writing a line for each.
var errSpent = errors.New("a second record at a sequence number its signer has already used; " +
	"the signer's key has been used outside its agent")

// extend reports whether a record at seq is one this signer may add.
//
// A signer's records are taken in the order it signed them, so every number up
// to its head has been spent and no new record ever goes at one of them. That
// is what lets a revocation say where a signer's records stop rather than
// listing them: a signer that left a gap under such a mark could otherwise sign
// into it afterwards. Callers hold the write lock.
func (s *Set) extend(signer PublicKey, seq uint64) error {
	switch head := s.head(signer); {
	case seq == head+1:
		return nil
	case seq > head+1:
		return fmt.Errorf("%w: %d does not follow %d", ErrAhead, seq, head)
	}
	return fmt.Errorf("%w: %d", errSpent, seq)
}

// claim records that a signer signed at one of its numbers: the number is spent
// from here on, and the date is the floor under whatever it signs next. Only
// the add paths call it, once the record is one the set is taking. Callers hold
// the write lock.
func (s *Set) claim(signer PublicKey, seq uint64, issuedAt int64) {
	st := s.signers[signer]
	st.head = max(st.head, seq)
	st.lastSigned = max(st.lastSigned, issuedAt)
	s.signers[signer] = st
}

// bySeq orders one signer's records by its own counter, and at the same number
// by signature so that a reused number still orders the same way everywhere.
func bySeq(a, b Admission) int {
	return cmp.Or(cmp.Compare(a.Seq, b.Seq), bytes.Compare(a.Signature, b.Signature))
}

// AddRevocation stores a signature-valid revocation. Any member may be
// revoked, the root included: it is a peer, not an authority over the others.
//
// Every revocation a revoker signs is kept, as every admission is. The lowest
// mark of the ones that count is what decides, so a revoker cannot weaken a
// revocation it has already issued by signing a later one that keeps more: the
// later record simply decides nothing. It is still held, because the number it
// took is spent either way, and a number with no record at it is a gap in its
// signer's sequence that no node given the set could step over.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	signed := r.signedBytes()
	if s.heldRevocation(r, signed) {
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
	if s.holdsRevocation(r, signed) {
		return false, nil // the other copy of it landed while this one was being checked
	}
	if err := s.extend(r.Revoker, r.Seq); err != nil {
		return false, err
	}
	s.claim(r.Revoker, r.Seq, r.IssuedAt)
	by := s.revocations[r.Identity]
	if by == nil {
		by = map[PublicKey][]Revocation{}
		s.revocations[r.Identity] = by
	}
	by[r.Revoker] = append(by[r.Revoker], r)
	s.reportNarrowing(r) // with the record stored: whether it counts is asked of the set that holds it
	s.forget()
	return true, nil
}

// reportNarrowing says what a cut takes away that this node was counting on.
// Records above it were signed by a node the revoker says was already out, so
// they no longer count: the nodes they admitted are not members, and whoever
// they revoked was never validly revoked and is a member again.
//
// Three things produce that and the records cannot tell them apart. An operator
// asked for it, which is the ordinary cause and wants nothing done; or the
// revoker had not caught up with what the subject had done, so the cluster was
// changed from a node that could not see it; or the subject's key signed after
// it was out, which means the key is being used outside its agent. Only the
// first is anybody's intention and none of them is this node's to decide, so it
// says what it saw rather than what it thinks.
//
// A revocation that carries no weight is not reported, because it takes nothing
// away: anyone may sign a record naming any identity, and one from a key that is
// no member of this cluster changes no answer here. A revocation that starts
// counting later, once its signer's own admission arrives, goes unreported for
// the same reason — nothing had changed when it landed. Callers hold the write
// lock, with r already stored.
func (s *Set) reportNarrowing(r Revocation) {
	if !s.counts(r, map[question]bool{}) {
		return
	}
	admissions, revocations := 0, 0
	for _, by := range s.admissions {
		for _, a := range by[r.Identity] {
			if a.Seq > r.UpTo {
				admissions++
			}
		}
	}
	for _, by := range s.revocations {
		for _, v := range by[r.Identity] {
			// r itself is above its own mark where a node marked its own
			// sequence below the number this record takes; it withdrew nothing
			// that was standing before it arrived
			if v.Seq > r.UpTo && !bytes.Equal(v.Signature, r.Signature) {
				revocations++
			}
		}
	}
	if admissions == 0 && revocations == 0 {
		return
	}
	slog.Warn("a revocation cuts its subject's records off below where this node had seen them reach, "+
		"so what it signed above the cut no longer counts: nodes it admitted have to enrol again, and "+
		"nodes it revoked are members again. An operator asking for that with 'cheesecloth revoke "+
		"--disown' is the ordinary cause and wants nothing done. Otherwise either the revocation was "+
		"signed by a node that had not caught up, so the cluster was changed from somewhere that could "+
		"not see it, or the subject's key signed after it was out, which means it is being used outside "+
		"its agent and the cluster should be rebuilt. Compare 'cheesecloth status' across the cluster.",
		"revoked", r.Identity.Short(), "by", r.Revoker.Short(),
		"admissions", admissions, "revocations", revocations)
}

// MergeResult is what a merge did: how many records changed the set, how many
// it would not take, and the last reason one was refused. A record that fails
// verification is skipped rather than fatal, since it came from the network,
// but a peer sending them is worth knowing about: see cluster.MergeRemoteState.
type MergeResult struct {
	Changed  int
	Deferred int // ahead of their signer's sequence; the next sync carries them again
	Refused  int
	Reason   error // the last refusal, as an example of what is being sent
}

// Merge adds every record in rs and reports what it did with them.
//
// A signer's records go in in the order it signed them, whatever kind they
// are: the counter is the signer's own and covers all of them, and a record is
// taken only once the one before it is. A set that arrives with a gap in it
// leaves the records above the gap for the next state sync, which carries the
// whole set again.
func (s *Set) Merge(rs Records) MergeResult {
	var res MergeResult
	for _, p := range inSeqOrder(rs) {
		res.note(p.add(s))
	}
	return res
}

// note records what adding one record did. Callers add records one at a time,
// so this is where what happened to each becomes what happened to the set.
func (res *MergeResult) note(ok bool, err error) {
	switch {
	case ok:
		res.Changed++
	case errors.Is(err, ErrAhead):
		res.Deferred++
	case err != nil:
		res.Refused++
		res.Reason = err
	}
}

// pending is one record waiting to be added, tagged with the signer, number
// and signature that decide where in the order it goes.
type pending struct {
	signer PublicKey
	seq    uint64
	sig    []byte
	add    func(*Set) (bool, error)
}

// inSeqOrder is the records of rs grouped by signer, each signer's in the order
// it signed them, so that a whole set offered at once goes in without a record
// waiting on one that comes later in the list.
//
// Two records at one of a signer's numbers are ordered by signature, so that
// the one every node takes is the same one: only the first at a number is
// taken, and a signer that put two there has had its key used outside its
// agent, which the nodes should at least agree about.
func inSeqOrder(rs Records) []pending {
	out := make([]pending, 0, len(rs.Admissions)+len(rs.Revocations))
	for _, a := range rs.Admissions {
		out = append(out, pending{a.Admitter, a.Seq, a.Signature, func(s *Set) (bool, error) { return s.AddAdmission(a) }})
	}
	for _, r := range rs.Revocations {
		out = append(out, pending{r.Revoker, r.Seq, r.Signature, func(s *Set) (bool, error) { return s.AddRevocation(r) }})
	}
	slices.SortFunc(out, func(a, b pending) int {
		return cmp.Or(
			bytes.Compare(a.signer[:], b.signer[:]),
			cmp.Compare(a.seq, b.seq),
			bytes.Compare(a.sig, b.sig),
		)
	})
	return out
}

// Records returns the set's contents in a deterministic order, so that the
// state file and what goes to a peer do not churn.
func (s *Set) Records() Records {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs := Records{}
	for _, by := range s.admissions {
		for _, as := range by {
			rs.Admissions = append(rs.Admissions, as...)
		}
	}
	for _, by := range s.revocations {
		for _, revs := range by {
			rs.Revocations = append(rs.Revocations, revs...)
		}
	}
	slices.SortFunc(rs.Admissions, func(a, b Admission) int {
		return cmp.Or(bytes.Compare(a.Identity[:], b.Identity[:]), bytes.Compare(a.Admitter[:], b.Admitter[:]), bySeq(a, b))
	})
	slices.SortFunc(rs.Revocations, func(a, b Revocation) int {
		return cmp.Or(
			bytes.Compare(a.Identity[:], b.Identity[:]),
			bytes.Compare(a.Revoker[:], b.Revoker[:]),
			cmp.Compare(a.Seq, b.Seq),
			bytes.Compare(a.Signature, b.Signature), // only one record ever takes a number; this settles a tie without one
		)
	})
	return rs
}

// Head is how far signer's sequence has been taken here, which is what a
// revocation of it marks as where its records stop: everything this node has
// seen it sign still counts, and anything it signs afterwards does not.
func (s *Set) Head(signer PublicKey) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.head(signer)
}

// NextSeq is the number signer's next record takes: one past everything it has
// been seen to sign.
func (s *Set) NextSeq(signer PublicKey) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.head(signer) + 1
}

// head is how far signer's sequence has been taken. Callers hold the lock.
func (s *Set) head(signer PublicKey) uint64 { return s.signers[signer].head }
