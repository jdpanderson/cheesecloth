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
// Of one admitter's records two are kept: the earliest, which vouched for the
// identity in the first place, and the latest, which is that admitter's current
// statement of its name and slot. The earliest stops an admitter retracting a
// membership it vouched for; the latest lets a member that enrols again be
// renamed.
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
	// prunes are the prune records held, by signature. They are kept and passed
	// on whether or not this node has acted on them, so one that arrives before
	// the records it covers takes effect when they do.
	prunes map[string]Prune
	// pruned are the identities a prune has removed. A record naming one is
	// refused, so a peer that has not pruned yet cannot put it back. The key's
	// presence is what says an identity has gone; the value is whether a refusal
	// is still worth reporting, so that the same records re-offered at every
	// state sync are reported once rather than every minute.
	pruned map[PublicKey]bool
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
	highWater  uint64                // how far its counter reached, even once the record that used it is gone
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
		prunes:      map[string]Prune{},
		pruned:      map[PublicKey]bool{},
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
	if s.gone(a.Identity) || s.gone(a.Admitter) {
		s.reportRefusal(a.Identity)
		s.reportRefusal(a.Admitter)
		return false, nil
	}
	s.claim(a.Admitter, a.Seq, a.IssuedAt, a.Signature)
	by := s.admissions[a.Identity]
	if by == nil {
		by = map[PublicKey][]Admission{}
		s.admissions[a.Identity] = by
	}
	if kept, changed := keepEnds(by[a.Admitter], a); changed {
		by[a.Admitter] = kept
		s.forget()
		return true, nil
	}
	return false, nil
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

// heldPrune reports whether the set already holds p.
func (s *Set) heldPrune(p Prune) bool {
	signed := p.signedBytes()
	s.mu.RLock()
	defer s.mu.RUnlock()
	held, ok := s.prunes[string(p.Signature)]
	return ok && bytes.Equal(held.signedBytes(), signed)
}

// claim records that a signer signed at one of its numbers: the date is the
// floor under whatever it signs next, and the number is spent from here on,
// whether or not the record that used it was kept. Callers hold the write lock.
//
// A signer that has used a number twice is reported. Its agent cannot do that:
// the number comes from NextSeq and every path that signs holds the cluster's
// lock from reading it to storing the record, so two different records at one
// number say the key was used somewhere else. Nothing is refused over it, since
// the two records are indistinguishable and choosing between them is not
// possible.
//
// Only what this process has seen can be reported: the signatures are not
// persisted, and never dropped, so a restart notices nothing about earlier
// records and the map grows with every record accepted. Neither matters here,
// where nothing decides membership. What keeps a number from being spent twice
// is the counter, which is persisted; see HighWater.
func (s *Set) claim(signer PublicKey, seq uint64, issuedAt int64, sig []byte) {
	st := s.signers[signer]
	st.lastSigned = max(st.lastSigned, issuedAt)
	st.highWater = max(st.highWater, seq)
	if st.seen == nil {
		st.seen = map[uint64]*numberUse{}
	}
	switch use, held := st.seen[seq]; {
	case !held:
		st.seen[seq] = &numberUse{sig: sig}
	case !bytes.Equal(use.sig, sig) && !use.reported:
		use.reported = true
		slog.Error("a node signed two different records at one of its own sequence numbers, "+
			"which its agent cannot do; its key has been used outside it. "+
			"Treat this cluster as compromised and rebuild it.",
			"signer", signer.Short(), "seq", seq)
	}
	s.signers[signer] = st
}

// bySeq orders one signer's records by its own counter, and at the same number
// by signature so that a reused number still orders the same way everywhere.
func bySeq(a, b Admission) int {
	return cmp.Or(cmp.Compare(a.Seq, b.Seq), bytes.Compare(a.Signature, b.Signature))
}

// keepEnds adds a to one admitter's records, which are its earliest and its
// latest, and reports whether it changed them.
func keepEnds(cur []Admission, a Admission) ([]Admission, bool) {
	if len(cur) == 0 {
		return []Admission{a}, true
	}
	// cur is sorted, so a either comes before what is held, after it, or
	// between the two, in which case it is neither end and nothing changes
	first, last := cur[0], cur[len(cur)-1]
	switch {
	case bySeq(a, first) < 0:
		return []Admission{a, last}, true
	case bySeq(a, last) > 0:
		return []Admission{first, a}, true
	}
	return cur, false
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
	if s.gone(r.Identity) || s.gone(r.Revoker) {
		return false, nil
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
// counting on. A revoker keeps the records it had seen its subject sign, so a
// node that has seen more loses the difference, and what several revocations
// keep is only what all of them name. That is the safe direction, but it is
// worth knowing about: it means two nodes were working from different records
// when the cluster was changed. Callers hold the write lock.
func (s *Set) reportNarrowing(r Revocation) {
	admissions, revocations := 0, 0
	for _, by := range s.admissions {
		for _, a := range by[r.Identity] {
			if !r.keeps(a.Signature) {
				admissions++
			}
		}
	}
	for _, by := range s.revocations {
		if v, held := by[r.Identity]; held && !r.keeps(v.Signature) {
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
		slog.Warn("a revocation does not keep every record this node had seen its subject sign; "+
			"the nodes those admitted are no longer members and have to enrol again. "+
			"Revoke from a node that is in touch with the cluster.",
			"revoked", r.Identity.Short(), "by", r.Revoker.Short(), "admissions", admissions)
	}
}

// supersedes reports whether r is the one to keep of two revocations by one
// revoker: the earlier by its counter, and at one number the smaller signature,
// so that two nodes keep the same one whatever order the records reached them.
func supersedes(r, cur Revocation) bool {
	return cmp.Or(cmp.Compare(r.Seq, cur.Seq), bytes.Compare(r.Signature, cur.Signature)) < 0
}

// MergeResult is what a merge did: how many records changed the set, how many
// it would not take, and the last reason one was refused. A record that fails
// verification is skipped rather than fatal, since it came from the network,
// but a peer sending them is worth knowing about: see cluster.MergeRemoteState.
type MergeResult struct {
	Changed int
	Refused int
	Reason  error // the last refusal, as an example of what is being sent
}

// Merge adds every record in rs and reports what it did with them.
func (s *Set) Merge(rs Records) MergeResult {
	var res MergeResult
	take := func(ok bool, err error) {
		switch {
		case ok:
			res.Changed++
		case err != nil:
			res.Refused++
			res.Reason = err
		}
	}
	for _, a := range rs.Admissions {
		take(s.AddAdmission(a))
	}
	for _, r := range rs.Revocations {
		take(s.AddRevocation(r))
	}
	for _, p := range rs.Prunes {
		take(s.AddPrune(p))
	}
	// a prune already held may only now have the records that confirm it
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyPrunes() {
		res.Changed++
	}
	return res
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
	for _, p := range s.prunes {
		rs.Prunes = append(rs.Prunes, p)
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
	slices.SortFunc(rs.Prunes, func(a, b Prune) int {
		return cmp.Or(
			bytes.Compare(a.Pruner[:], b.Pruner[:]),
			cmp.Compare(a.Seq, b.Seq),
			bytes.Compare(a.Signature, b.Signature),
		)
	})
	return rs
}

// SignedBy is the signatures of the records signed by signer that the set
// holds, which is what a revocation of it names as the records that still
// count. Sorted and without repeats, so that two nodes holding the same
// records sign the same revocation.
func (s *Set) SignedBy(signer PublicKey) [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var sigs [][]byte
	for _, by := range s.admissions {
		for _, a := range by[signer] {
			sigs = append(sigs, a.Signature)
		}
	}
	for _, by := range s.revocations {
		if r, held := by[signer]; held {
			sigs = append(sigs, r.Signature)
		}
	}
	for _, p := range s.prunes {
		if p.Pruner == signer {
			sigs = append(sigs, p.Signature)
		}
	}
	return sortedSignatures(sigs)
}

// NextSeq is the number signer's next record takes: one past everything it has
// been seen to sign.
func (s *Set) NextSeq(signer PublicKey) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.highWater(signer) + 1
}

// HighWater is the highest number signer has been seen to sign at, which is
// what a node persists of its own counter: a prune removes records, so the
// records a node still holds do not say how far its counter reached.
func (s *Set) HighWater(signer PublicKey) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.highWater(signer)
}

// Spent records that signer has already signed at seq, so that its next record
// takes a later number whether or not a record using seq is still held. A node
// reads its own counter back this way at startup; it never lowers one.
func (s *Set) Spent(signer PublicKey, seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.signers[signer]
	st.highWater = max(st.highWater, seq)
	s.signers[signer] = st
}

// highWater is the highest number signer has been seen to sign at. It is kept
// as the records arrive rather than derived from them, so a number stays spent
// whether the record that used it was dropped or ignored. A record a prune
// removed is gone from the records altogether, which is what Spent restores.
// Callers hold the lock.
func (s *Set) highWater(signer PublicKey) uint64 { return s.signers[signer].highWater }
