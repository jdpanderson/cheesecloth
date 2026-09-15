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
// every answer it gives is a union or a maximum over what is held, so two nodes
// with the same records agree whatever order those records arrived in.
//
// Every record an admitter signed for an identity is kept, in the order it
// signed them. The earliest stops an admitter retracting a membership it
// vouched for; the latest lets a member that enrols again be renamed. The ones
// between decide nothing, but dropping them would leave a gap in the
// admitter's sequence, and a node given the set would stop at it.
//
// Records are ordered by the signer's own counter rather than by its clock, and
// a revocation names the records of its subject that still count, so whether a
// record was signed while its signer was a member is decided without one.
type Set struct {
	mu          sync.RWMutex
	root        PublicKey
	admissions  map[PublicKey]map[PublicKey][]Admission // identity -> admitter -> earliest and latest
	revocations map[PublicKey]map[PublicKey]Revocation  // identity -> revoker -> record
	// signers is what is remembered about each signer beyond its records.
	signers map[PublicKey]signerState
	// view is the membership the records make, built when a query finds it
	// stale and dropped whenever a record changes; see view.go. Nil means
	// stale. It is read without the lock: the gossip transport asks whether a
	// peer is a member for every packet.
	view atomic.Pointer[view]
	// now is the clock the record dates are checked against; tests move it.
	now func() time.Time
}

// signerState is what a set remembers about a signer apart from its records.
type signerState struct {
	lastSigned int64                 // newest date seen, the floor under whatever it signs next
	head       uint64                // how far its sequence has been taken, even once the record that took it is gone
	seen       map[uint64]*numberUse // what it signed at each number, so that using one twice is noticed
}

// numberUse is the first record seen at one of a signer's numbers, and whether
// a second one at that number has already been reported, so that a peer
// re-offering it at every push/pull is not reported again.
type numberUse struct {
	sig      []byte
	reported bool
}

// NewSet creates a set trusting root. The root's own record is added like any
// other, when it arrives.
func NewSet(root PublicKey) *Set {
	return &Set{
		root:        root,
		admissions:  map[PublicKey]map[PublicKey][]Admission{},
		revocations: map[PublicKey]map[PublicKey]Revocation{},
		signers:     map[PublicKey]signerState{},
		now:         time.Now,
	}
}

// Clock bounds on a record's date. They are wide on purpose: the point is to
// keep a record from a grossly wrong clock out of a set that never forgets,
// not to police skew, which the warning does. Two nodes disagree only about a
// record dated within their mutual skew of the bound, and a clock that far out
// has already failed.
const (
	// epoch is the earliest plausible date: nothing predates the project.
	epoch = 1577836800 // 2020-01-01 UTC
	// ahead is how far in the future a record may be dated and still be kept.
	ahead = 24 * time.Hour
	// skewed is the gap worth warning about; NTP holds milliseconds.
	skewed = 5 * time.Minute
)

// checkClock rejects a record no clock could honestly have produced, and warns
// about one that is merely ahead of ours. Only the future is a signal: a
// record dated in the past is indistinguishable from an old one, which is what
// most records are.
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

// AddAdmission stores a signature-valid record. It reports whether the set
// changed: a record an admitter has already been heard to better is dropped.
func (s *Set) AddAdmission(a Admission) (bool, error) {
	if s.heldAdmission(a) {
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
	if err := s.extend(a.Admitter, a.Seq, a.Signature); err != nil {
		return false, err
	}
	s.claim(a.Admitter, a.Seq, a.IssuedAt, a.Signature)
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

// heldAdmission reports whether the set already holds a.
func (s *Set) heldAdmission(a Admission) bool {
	signed := a.signedBytes()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, held := range s.admissions[a.Identity][a.Admitter] {
		if bytes.Equal(held.Signature, a.Signature) && bytes.Equal(held.signedBytes(), signed) {
			return true
		}
	}
	return false
}

// heldRevocation reports whether the set already holds r.
func (s *Set) heldRevocation(r Revocation) bool {
	signed := r.signedBytes()
	s.mu.RLock()
	defer s.mu.RUnlock()
	held, ok := s.revocations[r.Identity][r.Revoker]
	return ok && bytes.Equal(held.Signature, r.Signature) && bytes.Equal(held.signedBytes(), signed)
}

// claim records that a signer signed at one of its numbers: the date is the
// floor under whatever it signs next, and the number is spent from here on,
// whether or not the record that used it is kept. Only extend calls it, so the
// number is always the one past the signer's head. Callers hold the write lock.
//
// The signature is kept so that a second record at the number can be told from
// the one already there; see reportReuse. It is not persisted and never
// dropped, so a restart remembers nothing of earlier records and the map grows
// with every record taken. Neither matters, since nothing here decides
// membership: what keeps a number from being spent twice is the head, which is
// persisted; see Heads.
func (s *Set) claim(signer PublicKey, seq uint64, issuedAt int64, sig []byte) {
	st := s.signers[signer]
	st.lastSigned = max(st.lastSigned, issuedAt)
	st.head = max(st.head, seq)
	if st.seen == nil {
		st.seen = map[uint64]*numberUse{}
	}
	st.seen[seq] = &numberUse{sig: sig}
	s.signers[signer] = st
}

// ErrAhead is returned for a record whose signer has not been seen to sign the
// one before it. It says nothing against the record: the next state sync
// carries the whole set in sequence order and takes it then.
var ErrAhead = errors.New("record is ahead of its signer's sequence")

// errSpent is returned for a record at a number its signer has already used.
var errSpent = errors.New("sequence number has already been used")

// extend reports whether a record at seq is the next one signer may add.
//
// A signer's records are taken in the order it signed them, so every number up
// to its head has been spent and none of them is ever free again. That is what
// lets a revocation say where a signer's records stop rather than listing them,
// and what keeps a number spent once the record that spent it has been
// dropped: a signer that left a gap under such a mark could otherwise sign
// into it afterwards. Callers hold the write lock.
func (s *Set) extend(signer PublicKey, seq uint64, sig []byte) error {
	switch head := s.head(signer); {
	case seq == head+1:
		return nil
	case seq > head+1:
		return fmt.Errorf("%w: %d does not follow %d", ErrAhead, seq, head)
	default:
		s.reportReuse(signer, seq, sig)
		return fmt.Errorf("%w: %d", errSpent, seq)
	}
}

// reportReuse says so when a signer has two different records at one of its own
// numbers, which its agent cannot do: the number comes from NextSeq and every
// path that signs holds the cluster's lock from reading it to storing the
// record. A second record there says the key has been used somewhere else.
// Nothing can be mended here, and the record is refused either way; what the
// operator does with it is rebuild the cluster, which they cannot decide if
// nobody tells them.
//
// A number whose record the set no longer holds says nothing, so it is passed
// over in silence: a peer that has not caught up re-offers what this node
// dropped, and that is ordinary. Only what this process has seen can be
// reported, since the signatures are not persisted. Callers hold the write
// lock.
func (s *Set) reportReuse(signer PublicKey, seq uint64, sig []byte) {
	use, held := s.signers[signer].seen[seq]
	if !held || bytes.Equal(use.sig, sig) || use.reported {
		return
	}
	use.reported = true
	slog.Error("a node signed two different records at one of its own sequence numbers, "+
		"which its agent cannot do; its key has been used outside it. "+
		"Treat this cluster as compromised and rebuild it.",
		"signer", signer.Short(), "seq", seq)
}

// bySeq orders one signer's records by its own counter, and at the same number
// by signature so that a reused number still orders the same way everywhere.
func bySeq(a, b Admission) int {
	return cmp.Or(cmp.Compare(a.Seq, b.Seq), bytes.Compare(a.Signature, b.Signature))
}

// AddRevocation stores a signature-valid revocation. Any member may be
// revoked, the root included: it is a peer, not an authority over the others.
// A revoker's earlier record is the one kept, so that nobody can weaken a
// revocation it has already issued by signing a later one that keeps more.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	if s.heldRevocation(r) {
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
	if err := s.extend(r.Revoker, r.Seq, r.Signature); err != nil {
		return false, err
	}
	s.claim(r.Revoker, r.Seq, r.IssuedAt, r.Signature)
	by := s.revocations[r.Identity]
	if by == nil {
		by = map[PublicKey]Revocation{}
		s.revocations[r.Identity] = by
	}
	if cur, ok := by[r.Revoker]; ok && !supersedes(r, cur) {
		return false, nil
	}
	s.reportNarrowing(r) // before it is stored, so a self-revocation does not count itself
	by[r.Revoker] = r
	s.forget()
	return true, nil
}

// reportNarrowing says what a revocation takes away that this node was still
// counting on. A revoker marks where it had seen its subject's records reach,
// so a node that has seen further loses the difference, and several revocations
// leave only what the lowest of them keeps. That is the safe direction, but it
// is worth knowing about: it means two nodes were working from different
// records when the cluster was changed. Callers hold the write lock.
func (s *Set) reportNarrowing(r Revocation) {
	admissions, revocations := 0, 0
	for _, by := range s.admissions {
		for _, a := range by[r.Identity] {
			if a.Seq > r.UpTo {
				admissions++
			}
		}
	}
	for _, by := range s.revocations {
		if v, held := by[r.Identity]; held && v.Seq > r.UpTo {
			revocations++
		}
	}
	switch {
	case revocations > 0:
		// Whoever those revocations put out is a member again. The ordinary way
		// of leaving keeps everything the node signed, so this is either somebody
		// restoring a revoked node or two revocations crossing on a cluster that
		// was not in step. Neither is a state to keep running in.
		slog.Error("a revocation has been withdrawn by a later revocation of the node that signed it, "+
			"so nodes that had been put out of the cluster are members again. This is not ordinary "+
			"operation and the cluster's membership can no longer be relied on: treat it as compromised "+
			"and rebuild it.",
			"revoked", r.Identity.Short(), "by", r.Revoker.Short(), "revocations", revocations)
	case admissions > 0:
		slog.Warn("a revocation cuts its subject's records off below where this node had seen them "+
			"reach; the nodes those admitted are no longer members and have to enrol again. "+
			"Revoke from a node that is in touch with the cluster.",
			"revoked", r.Identity.Short(), "by", r.Revoker.Short(), "admissions", admissions)
	}
}

// supersedes reports whether r is the one to keep of two revocations by one
// revoker: the one that cuts lower, and at one mark the smaller signature, so
// that two nodes keep the same one whatever order the records reached them.
// Cuts intersect rather than union, so a revoker cannot widen what it has
// already withdrawn by signing again.
func supersedes(r, cur Revocation) bool {
	return cmp.Or(cmp.Compare(r.UpTo, cur.UpTo), bytes.Compare(r.Signature, cur.Signature)) < 0
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
		switch ok, err := p.add(s); {
		case ok:
			res.Changed++
		case errors.Is(err, ErrAhead):
			res.Deferred++
		case err != nil:
			res.Refused++
			res.Reason = err
		}
	}
	return res
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
		for _, r := range by {
			rs.Revocations = append(rs.Revocations, r)
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
			bytes.Compare(a.Signature, b.Signature), // a revoker can have two records at one number
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

// Heads is how far each signer's sequence has been taken, which a node
// persists alongside the records: a record that took a number may since have
// been dropped, so the records a node holds do not say. Every number up to a
// signer's head is spent, and a record offered at one of them is refused, so
// losing this would let a record be put where one has already been.
func (s *Set) Heads() map[PublicKey]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	heads := make(map[PublicKey]uint64, len(s.signers))
	for signer, st := range s.signers {
		heads[signer] = st.head
	}
	return heads
}

// RestoreHeads reads back what Heads persisted. A head is never lowered, so a
// state file older than the records it is loaded with costs nothing.
func (s *Set) RestoreHeads(heads map[PublicKey]uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for signer, seq := range heads {
		st := s.signers[signer]
		st.head = max(st.head, seq)
		s.signers[signer] = st
	}
	s.forget()
}

// head is how far signer's sequence has been taken. It is kept as the records
// arrive rather than derived from them, so a number stays spent whether the
// record that used it was dropped or ignored. Callers hold the lock.
func (s *Set) head(signer PublicKey) uint64 { return s.signers[signer].head }
