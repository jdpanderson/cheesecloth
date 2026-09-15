package trust

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"maps"
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
// node given the set would stop at it.
//
// Records are ordered by the signer's own counter rather than by its clock, and
// a revocation marks where its subject's records stop, so whether a record was
// signed while its signer was a member is decided without one.
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
	// now is the clock the record dates are checked against; tests move it.
	now func() time.Time
}

// signerState is what a set remembers about a signer apart from its records.
type signerState struct {
	lastSigned int64                 // newest date seen, the floor under whatever it signs next
	head       uint64                // how far its sequence has been taken, even once the record that took it is gone
	seen       map[uint64]*numberUse // what it signed at each number, so that using one twice is noticed
	// dropped is what took each of the numbers this node has swept, so the
	// record can be taken back when a peer offers it again; see sweep.go.
	dropped map[uint64][]byte
}

// SignerState is what a node persists about a signer beside its records.
type SignerState struct {
	Head    uint64            `json:"head"`
	Dropped map[uint64][]byte `json:"dropped,omitempty"` // number -> digest of the record swept from it
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
		revocations: map[PublicKey]map[PublicKey][]Revocation{},
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

// AddAdmission stores a signature-valid record, in its admitter's sequence
// order. Every record an admitter signs is kept, so nothing it signs later
// displaces what it signed before. It reports whether the set changed, which a
// record already held does not; one this node swept and still withdraws is
// refused as ErrWithdrawn, and one ahead of its admitter's sequence as
// ErrAhead.
func (s *Set) AddAdmission(a Admission) (bool, error) {
	return s.addAdmission(a, true)
}

// addAdmission is AddAdmission, taking the record where its admitter's
// sequence has reached unless it comes from this node's own state file, which
// says where that is itself; see Restore.
func (s *Set) addAdmission(a Admission, ordered bool) (bool, error) {
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
	if ordered {
		if err := s.extend(a.Admitter, a.Seq, a.Signature); err != nil {
			return false, err
		}
	}
	s.claim(a.Admitter, a.Seq, a.IssuedAt, a.Signature)
	by := s.admissions[a.Identity]
	if by == nil {
		by = map[PublicKey][]Admission{}
		s.admissions[a.Identity] = by
	}
	by[a.Admitter] = append(by[a.Admitter], a) // ordinarily in sequence order, which is how extend takes them
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
	delete(st.dropped, seq) // the record is held again, so it is the record that says so
	s.signers[signer] = st
}

// ErrAhead is returned for a record whose signer has not been seen to sign the
// one before it. It says nothing against the record: the next state sync
// carries the whole set in sequence order and takes it then.
var ErrAhead = errors.New("record is ahead of its signer's sequence")

// errSpent is returned for a record at a number its signer has already used.
var errSpent = errors.New("sequence number has already been used")

// ErrWithdrawn is returned for a record this node swept whose signer's cut
// still withdraws it. It says nothing against the record or against the peer
// offering it: a peer that has not swept carries it in every state sync, and
// this is what keeps taking it back from being a change. Should the cut rise,
// the next sync puts it back in.
var ErrWithdrawn = errors.New("record was swept and is still withdrawn")

// extend reports whether a record at seq is one this signer may add.
//
// A signer's records are taken in the order it signed them, so every number up
// to its head has been spent and no new record ever goes at one of them. That
// is what lets a revocation say where a signer's records stop rather than
// listing them: a signer that left a gap under such a mark could otherwise sign
// into it afterwards.
//
// The exception is a number this node swept itself. A peer that has not swept
// offers the record back at every state sync, and taking it back is what makes
// the sweep reversible: a cut rises when the revocation that set it is shown
// not to count, and the records it withdrew have to stand again. Only the
// record that was there may return, which its digest settles; anything else at
// that number is a second record at one of the signer's numbers, as before.
//
// It comes back only once the cut has actually risen. While the cut still
// withdraws it, taking it back would add a record that stands for nobody,
// throw the answers away to derive them again, and sweep it out at the next
// save — for every sync from every peer that has not swept, for ever. So it is
// refused as withdrawn, which is neither a refusal to report nor a record to
// wait for. Callers hold the write lock.
func (s *Set) extend(signer PublicKey, seq uint64, sig []byte) error {
	switch head := s.head(signer); {
	case seq == head+1:
		return nil
	case seq > head+1:
		return fmt.Errorf("%w: %d does not follow %d", ErrAhead, seq, head)
	}
	if held, ok := s.signers[signer].dropped[seq]; ok && bytes.Equal(held, digest(sig)) {
		if cut := s.cut(signer, map[question]bool{}); seq > cut {
			return fmt.Errorf("%w: %d is above the cut at %d on %s", ErrWithdrawn, seq, cut, signer.Short())
		}
		return nil
	}
	s.reportReuse(signer, seq, sig)
	return fmt.Errorf("%w: %d", errSpent, seq)
}

// digest identifies a record by its signature, which is what a set keeps of one
// it has swept. A signature is unforgeable without the signer's key, so a
// record offered at a swept number either is the one that was there or was
// signed by a key that should no longer be signing.
func digest(sig []byte) []byte {
	sum := sha256.Sum256(sig)
	return sum[:]
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
//
// Every revocation a revoker signs is kept, as every admission is. The lowest
// mark of the ones that count is what decides, so a revoker cannot weaken a
// revocation it has already issued by signing a later one that keeps more: the
// later record simply decides nothing. It is still held, because the number it
// took is spent either way, and a number with no record at it is a gap in its
// signer's sequence that no node given the set could step over.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	return s.addRevocation(r, true)
}

// addRevocation is AddRevocation, taking the record where its revoker's
// sequence has reached unless it comes from this node's own state file; see
// Restore.
func (s *Set) addRevocation(r Revocation, ordered bool) (bool, error) {
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
	if ordered {
		if err := s.extend(r.Revoker, r.Seq, r.Signature); err != nil {
			return false, err
		}
	}
	s.claim(r.Revoker, r.Seq, r.IssuedAt, r.Signature)
	by := s.revocations[r.Identity]
	if by == nil {
		by = map[PublicKey][]Revocation{}
		s.revocations[r.Identity] = by
	}
	s.reportNarrowing(r) // before it is stored, so a self-revocation does not count itself
	by[r.Revoker] = append(by[r.Revoker], r)
	s.forget()
	return true, nil
}

// reportNarrowing says what a cut takes away that this node was counting on.
// Records above it were signed by a node the revoker says was already out, so
// they never counted: the nodes they admitted are not members, and whoever they
// revoked was never validly revoked and is a member again.
//
// Which of two things happened cannot be told from the records. Either the
// subject's key signed after it was out of the cluster, or the revocation was
// signed by a node that had not caught up with what the subject had done. The
// first means a key is being used outside its agent; the second means the
// cluster was changed from a node that could not see it. Both are worth an
// operator's attention and neither is this node's to decide, so it says what it
// saw rather than what it thinks. Callers hold the write lock.
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
		for _, v := range by[r.Identity] {
			if v.Seq > r.UpTo {
				revocations++
			}
		}
	}
	if admissions == 0 && revocations == 0 {
		return
	}
	slog.Warn("a revocation cuts its subject's records off below where this node had seen them reach, "+
		"so what it signed above the cut never counted: nodes it admitted have to enrol again, and "+
		"nodes it revoked are members again. Either its key signed after it was out of the cluster, "+
		"or the revocation was signed by a node that had not caught up. Compare 'cheesecloth status' "+
		"across the cluster; a key signing after it was out means rebuilding.",
		"revoked", r.Identity.Short(), "by", r.Revoker.Short(),
		"admissions", admissions, "revocations", revocations)
}

// MergeResult is what a merge did: how many records changed the set, how many
// it would not take, and the last reason one was refused. A record that fails
// verification is skipped rather than fatal, since it came from the network,
// but a peer sending them is worth knowing about: see cluster.MergeRemoteState.
type MergeResult struct {
	Changed   int
	Deferred  int // ahead of their signer's sequence; the next sync carries them again
	Withdrawn int // swept here and still withdrawn; the peer offering them has not swept
	Refused   int
	Reason    error // the last refusal, as an example of what is being sent
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
	case errors.Is(err, ErrWithdrawn):
		res.Withdrawn++
	case err != nil:
		res.Refused++
		res.Reason = err
	}
}

// Restore loads the records and signer states this node persisted itself, and
// reports what it did with them.
//
// The records go in as they are rather than in their signers' sequence order.
// They were taken in that order once, before they were written, and what a
// signer's numbers have reached is in the file beside them rather than
// derivable from them: the sweep drops records a cut withdrew, so the set the
// file holds is what is left of each signer's sequence, and the heads say how
// far it really went. Loading in sequence order would make the records answer a
// question they are not the source of, and anything above a number with no
// record at it would be deferred, then refused for good once the heads were
// restored above it.
//
// Everything else is checked as it is for a record off the network: the
// signature verifies, a self-signed record is the pinned root's, and the date
// is in bounds. A record that fails is skipped and counted, so a damaged file
// costs what it damaged rather than the whole membership.
func (s *Set) Restore(rs Records, signers map[PublicKey]SignerState) MergeResult {
	var res MergeResult
	for _, a := range rs.Admissions {
		res.note(s.addAdmission(a, false))
	}
	for _, r := range rs.Revocations {
		res.note(s.addRevocation(r, false))
	}
	s.RestoreSigners(signers)
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

// SignerStates is what a node persists beside the records: how far each
// signer's sequence has been taken, and what took each number this node has
// swept. The records alone say neither, because a record that took a number may
// since have gone. Losing the heads would let a record be put where one has
// already been; losing what was swept would leave those records unable to come
// back when a cut rises.
func (s *Set) SignerStates() map[PublicKey]SignerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[PublicKey]SignerState, len(s.signers))
	for signer, st := range s.signers {
		out[signer] = SignerState{Head: st.head, Dropped: maps.Clone(st.dropped)}
	}
	return out
}

// RestoreSigners reads back what SignerStates persisted. A head is never
// lowered, so a state file older than the records it is loaded with costs
// nothing.
func (s *Set) RestoreSigners(signers map[PublicKey]SignerState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for signer, saved := range signers {
		st := s.signers[signer]
		st.head = max(st.head, saved.Head)
		for seq, sum := range saved.Dropped {
			// a number whose record is held says so itself; the rest are ones
			// this node swept and would take back
			if _, held := st.seen[seq]; held {
				continue
			}
			if st.dropped == nil {
				st.dropped = map[uint64][]byte{}
			}
			st.dropped[seq] = sum
		}
		s.signers[signer] = st
	}
	s.forget()
}

// head is how far signer's sequence has been taken. It is kept as the records
// arrive rather than derived from them, so a number stays spent whether the
// record that used it was dropped or ignored. Callers hold the lock.
func (s *Set) head(signer PublicKey) uint64 { return s.signers[signer].head }
