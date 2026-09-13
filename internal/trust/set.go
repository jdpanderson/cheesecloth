package trust

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Records is the wire and file form of a Set's contents.
type Records struct {
	Admissions  []Admission  `json:"admissions"`
	Revocations []Revocation `json:"revocations"`
}

// Set is the membership: a pinned root plus every signature-valid record seen.
// Validity is decided at query time from the root, so records may arrive in
// any order. Safe for concurrent use.
//
// Records are held per signer: the admissions of one identity are kept by
// admitter and its revocations by revoker, and a signer only ever changes what
// it said itself. Nothing an identity signs can therefore displace what
// another signed, and since every answer below is a union or a maximum over
// what is held, two nodes with the same records agree whatever order those
// records arrived in.
//
// Of one admitter's records two are kept: the earliest, which is the one that
// vouched for the identity in the first place, and the latest, which is that
// admitter's current statement of the identity's name and slot. Keeping the
// earliest is what stops an admitter from retracting a membership it vouched
// for, which once it has been revoked is not its to retract; keeping the
// latest is what lets a member that enrols again be renamed.
//
// Records are ordered by the signer's own counter rather than by its clock,
// and a revocation names the counter it was issued against, so whether a
// record was signed while its signer was a member is decided without one.
type Set struct {
	mu          sync.RWMutex
	root        PublicKey
	admissions  map[PublicKey]map[PublicKey][]Admission // identity -> admitter -> earliest and latest
	revocations map[PublicKey]map[PublicKey]Revocation  // identity -> revoker -> record
	// occupied remembers the record seen at each (signer, seq), so a signer
	// that uses one number twice is noticed however far apart the records
	// arrive, and whatever they say. It holds every record seen, including
	// ones keepEnds did not keep, and holds two of them for a number that was
	// reused. Neither of those two counts once the signer is out, see spoiled.
	// The pair is kept because it is what another node needs to see the reuse
	// for itself: Records hands it on like any other record, so the answers
	// follow from the records alone.
	occupied map[slot]Records
	// lastSigned is the newest date seen on each signer's records, which is the
	// floor under anything it signs next.
	lastSigned map[PublicKey]int64
	// members caches the identities found valid, until a record changes: the
	// gossip transport asks for every packet, and the walk to the root costs
	// more the longer the chain of admitters. Only valid answers are cached;
	// an unknown identity is decided in one lookup, and caching those would
	// let anything that can open a connection grow the map.
	members atomic.Pointer[sync.Map]
	now     func() time.Time // nil means the wall clock
}

// slot is one position in a signer's sequence.
type slot struct {
	signer PublicKey
	seq    uint64
}

// NewSet creates a set trusting root. The root's own record is added like any
// other, when it arrives.
func NewSet(root PublicKey) *Set {
	s := &Set{
		root:        root,
		admissions:  map[PublicKey]map[PublicKey][]Admission{},
		revocations: map[PublicKey]map[PublicKey]Revocation{},
		occupied:    map[slot]Records{},
		lastSigned:  map[PublicKey]int64{},
		now:         time.Now,
	}
	s.members.Store(&sync.Map{})
	return s
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
	return s.lastSigned[signer]
}

// forget drops the cached answers, because a record just changed them.
// Callers hold the write lock, so no answer computed from the new records can
// be stored in the map being replaced.
func (s *Set) forget() { s.members.Store(&sync.Map{}) }

// errUntrustedRoot is returned for a self-signed admission of a non-root identity.
var errUntrustedRoot = errors.New("self-signed admission is not the pinned root")

// AddAdmission stores a signature-valid record. It reports whether the set
// changed: a record an admitter has already been heard to better is dropped.
func (s *Set) AddAdmission(a Admission) (bool, error) {
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
	keep := func(rs Records) Records { rs.Admissions = append(rs.Admissions, a); return rs }
	spoils, ignore := s.claim(slot{a.Admitter, a.Seq}, a.Signature, a.IssuedAt, keep)
	if ignore {
		return false, nil
	}
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
	return spoils, nil
}

// claim records that a signer used one of its numbers for the record with
// signature sig, keeping the record itself through add. It reports whether
// this record is the one that made the number a reuse, and whether it is to be
// ignored, which it is when the set has already seen it and when a third
// record claims a number two already do: that one proves nothing the first two
// do not, so a signer cannot grow the record set by signing at one number over
// and over. A record claim does not ignore is stored by the caller as well,
// where the set keeps records of its kind.
func (s *Set) claim(k slot, sig []byte, issuedAt int64, add func(Records) Records) (spoils, ignore bool) {
	s.lastSigned[k.signer] = max(s.lastSigned[k.signer], issuedAt)
	at := s.occupied[k]
	switch {
	case at.holds(sig):
		return false, true
	case at.count() == 0:
		s.occupied[k] = add(at)
		return false, false
	case at.count() == 1:
		s.occupied[k] = add(at)
		slog.Warn("a node signed two records with one sequence number; neither will count once it is no longer a member, and a member it admitted there would then have to enrol again",
			"signer", k.signer.Short(), "seq", k.seq)
		s.forget()
		return true, false
	}
	return false, true
}

// reused reports whether the signer used k's number for two records. Callers
// hold the lock.
func (s *Set) reused(k slot) bool { return s.occupied[k].count() > 1 }

// spoiled reports whether nothing signed at k's number counts: the signer used
// it for two records and is no longer a member. Two records at one number
// cannot be told apart, so from a key the cluster no longer trusts they are
// taken for what they would be, an attempt to slip a record in under a number
// the revocation's mark covers, and neither counts. A signer that is still a
// member has nothing to gain by reusing a number, and taking its records away
// would only cost the members it admitted their place. Callers hold the lock.
func (s *Set) spoiled(k slot, visiting map[question]bool) bool {
	return s.reused(k) && !s.validFor(k.signer, math.MaxUint64, visiting)
}

// count is how many records rs holds.
func (rs Records) count() int { return len(rs.Admissions) + len(rs.Revocations) }

// holds reports whether rs already has the record with this signature.
func (rs Records) holds(sig []byte) bool {
	for _, a := range rs.Admissions {
		if bytes.Equal(a.Signature, sig) {
			return true
		}
	}
	for _, r := range rs.Revocations {
		if bytes.Equal(r.Signature, sig) {
			return true
		}
	}
	return false
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
	first, last := cur[0], cur[len(cur)-1]
	switch {
	case bySeq(a, first) < 0:
		first = a
	case bySeq(a, last) > 0:
		last = a
	default:
		return cur, false
	}
	if bySeq(first, last) == 0 {
		return []Admission{first}, true
	}
	return []Admission{first, last}, true
}

// AddRevocation stores a signature-valid revocation. Any member may be
// revoked, the root included: it is a peer, not an authority over the others.
// A revoker's earlier record is the one kept, so that nobody can weaken a
// revocation it has already issued by signing a later one.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
	}
	if err := s.checkClock("revocation", r.Revoker, r.IssuedAt); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := func(rs Records) Records { rs.Revocations = append(rs.Revocations, r); return rs }
	spoils, ignore := s.claim(slot{r.Revoker, r.Seq}, r.Signature, r.IssuedAt, keep)
	if ignore {
		return false, nil
	}
	by := s.revocations[r.Identity]
	if by == nil {
		by = map[PublicKey]Revocation{}
		s.revocations[r.Identity] = by
	}
	if cur, ok := by[r.Revoker]; ok && cur.Seq <= r.Seq {
		return spoils, nil
	}
	by[r.Revoker] = r
	s.forget()
	return true, nil
}

// Merge adds every record in rs, returning how many changed the set. Records
// that fail verification are skipped, not fatal: they came from the network.
func (s *Set) Merge(rs Records) int {
	changed := 0
	for _, a := range rs.Admissions {
		if ok, _ := s.AddAdmission(a); ok {
			changed++
		}
	}
	for _, r := range rs.Revocations {
		if ok, _ := s.AddRevocation(r); ok {
			changed++
		}
	}
	return changed
}

// Records returns the set's contents in a deterministic order: what the set
// holds, and with it the records that prove a signer reused a number, which
// decide nothing themselves but are how the node they reach decides the same
// way this one does.
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
	for k, at := range s.occupied {
		if !s.reused(k) {
			continue
		}
		for _, a := range at.Admissions {
			if !rs.holds(a.Signature) {
				rs.Admissions = append(rs.Admissions, a)
			}
		}
		for _, r := range at.Revocations {
			if !rs.holds(r.Signature) {
				rs.Revocations = append(rs.Revocations, r)
			}
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

// HighWater is the highest sequence number seen from signer, which is what a
// revocation of it names as its mark.
func (s *Set) HighWater(signer PublicKey) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.highWater(signer)
}

// NextSeq is the number signer's next record takes: one past everything it has
// been seen to sign, so a node continues its own sequence across a restart
// without keeping a counter of its own.
func (s *Set) NextSeq(signer PublicKey) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.highWater(signer) + 1
}

// highWater is HighWater with the lock held. It reads the occupied slots, not
// the records, so a number a dropped or ignored record used is not handed out.
func (s *Set) highWater(signer PublicKey) uint64 {
	var high uint64
	for k := range s.occupied {
		if k.signer == signer {
			high = max(high, k.seq)
		}
	}
	return high
}

// Valid reports whether id is currently a member: not revoked by itself or by
// a member, and holding at least one admission by the root or by an identity
// that was a member at the time it signed. The root needs no admission.
func (s *Set) Valid(id PublicKey) bool {
	// the map is taken before the answer is computed, so an answer from before
	// a record change can only be stored in the map that change discarded
	cached := s.members.Load()
	if _, ok := cached.Load(id); ok {
		return true
	}
	s.mu.RLock()
	valid := s.valid(id)
	s.mu.RUnlock()
	if valid {
		cached.Store(id, struct{}{})
	}
	return valid
}

// valid is Valid with the lock held. A number past any counter asks about the
// identity now, so every revocation of it applies.
func (s *Set) valid(id PublicKey) bool {
	return s.validFor(id, math.MaxUint64, map[question]bool{})
}

// question is one thing the recursion has already set out to answer: was this
// identity a member when it signed its seq'th record. The same identity is
// asked about at several points along one chain, so the number belongs in the
// key.
type question struct {
	id  PublicKey
	seq uint64
}

// validAdmissions iterates over the valid members' effective records, one per
// member; callers hold the lock.
func (s *Set) validAdmissions() iter.Seq[Admission] {
	return func(yield func(Admission) bool) {
		for id := range s.admissions {
			if !s.valid(id) {
				continue
			}
			if a, ok := s.effective(id); ok && !yield(a) {
				return
			}
		}
	}
}

// validFor reports whether id was a member when it signed its seq'th record.
// A revocation excludes only what its subject signed past the mark it names,
// so an admission stays valid if its admitter was a member when it signed,
// even once that admitter is revoked. A member may always revoke itself: only
// the holder of that key can sign such a record, and it takes nobody else out.
//
// An identity is a member if any one of its admissions holds, so a record by
// an admitter nobody believes neither makes an identity a member nor stops
// another record from doing so.
//
// Asking whether a revoker was a member reaches the identity it revokes again,
// at the earlier record that admitted it, so the cycle guard tracks the number
// as well as the identity. A record's number never changes, so the questions
// the recursion can ask are finite and it always ends.
//
// The root differs from the rest only in needing no admitter. It is revoked by
// the same rule, and judging a revocation of the root reaches the root again
// at a record the revocation does not reach, so what it signed while it was a
// member stays valid after it leaves.
func (s *Set) validFor(id PublicKey, seq uint64, visiting map[question]bool) bool {
	q := question{id, seq}
	if visiting[q] {
		return false
	}
	visiting[q] = true
	defer delete(visiting, q)

	if s.revokedBeyond(id, seq, visiting) {
		return false
	}
	if id == s.root {
		return true
	}
	for admitter, as := range s.admissions[id] {
		if admitter == id {
			continue // a self-signed record makes nobody but the root a member
		}
		for _, a := range as {
			if !s.spoiled(slot{admitter, a.Seq}, visiting) && s.validFor(admitter, a.Seq, visiting) {
				return true
			}
		}
	}
	return false
}

// revokedBeyond reports whether a revocation of id leaves its seq'th record
// past the mark, the revoker being id itself or a member when it signed.
func (s *Set) revokedBeyond(id PublicKey, seq uint64, visiting map[question]bool) bool {
	for _, r := range s.revocations[id] {
		if seq <= r.Mark || s.spoiled(slot{r.Revoker, r.Seq}, visiting) {
			continue
		}
		if r.Revoker == id || s.validFor(r.Revoker, r.Seq, visiting) {
			return true
		}
	}
	return false
}

// vouched reports whether a is a record that can make its identity a member:
// the root's own, or one whose admitter was a member when it signed.
func (s *Set) vouched(a Admission) bool {
	if s.spoiled(slot{a.Admitter, a.Seq}, map[question]bool{}) {
		return false
	}
	if a.Admitter == a.Identity {
		return a.Identity == s.root
	}
	return s.validFor(a.Admitter, a.Seq, map[question]bool{})
}

// laterClaim reports whether a is the record to prefer over b as the one that
// decides an identity's name and slot, where the two are by different
// admitters: the later one, and at the same time the one from the smaller
// admitter, so every node prefers the same record. Between admitters the date
// is all there is; one admitter's own records are separated by its counter,
// which is what claim does.
func laterClaim(a, b Admission) bool {
	return cmp.Or(
		cmp.Compare(a.IssuedAt, b.IssuedAt),
		bytes.Compare(b.Admitter[:], a.Admitter[:]),
	) > 0
}

// claimOf is what one admitter currently says: of its records that vouch, its
// own latest, which its counter decides without a clock. Callers hold the lock.
func (s *Set) claimOf(as []Admission) (Admission, bool) {
	var best Admission
	found := false
	for _, a := range as {
		if !s.vouched(a) {
			continue
		}
		if !found || bySeq(a, best) > 0 {
			best, found = a, true
		}
	}
	return best, found
}

// effective is the record that decides id's name and overlay slot: of what
// each admitter currently says about id, the latest. A record nobody believes
// decides nothing, which is what keeps an identity that is no longer a member
// from renaming, renumbering or unseating one that is. Callers hold the lock.
func (s *Set) effective(id PublicKey) (Admission, bool) {
	var best Admission
	found := false
	for _, as := range s.admissions[id] {
		claim, ok := s.claimOf(as)
		if !ok {
			continue
		}
		if !found || laterClaim(claim, best) {
			best, found = claim, true
		}
	}
	return best, found
}

// Lookup returns the admission record that decides id's name and overlay slot,
// if one vouches for it. It says nothing about whether id is still a member:
// ask Valid for that.
func (s *Set) Lookup(id PublicKey) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.effective(id)
}

// ByName returns the valid member with the given name, if exactly one exists.
func (s *Set) ByName(name string) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found Admission
	n := 0
	for a := range s.validAdmissions() {
		if a.Name == name {
			found, n = a, n+1
		}
	}
	return found, n == 1
}

// ErrOverlayFull is returned by FreeHost when every slot is taken.
var ErrOverlayFull = errors.New("no free overlay address")

// FreeHost picks the lowest overlay slot in [1, limit] that no admission
// uses. Slots held only by records that are no longer valid (revoked members)
// are reused when nothing else is free.
func (s *Set) FreeHost(limit uint64) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	taken := map[uint64]bool{}
	validTaken := map[uint64]bool{}
	for id, by := range s.admissions {
		for _, as := range by {
			for _, a := range as {
				taken[a.Host] = true
			}
		}
		if !s.valid(id) {
			continue
		}
		if a, ok := s.effective(id); ok {
			validTaken[a.Host] = true
		}
	}
	for _, used := range []map[uint64]bool{taken, validTaken} {
		for h := uint64(1); h <= limit && h != 0; h++ {
			if !used[h] {
				return h, nil
			}
		}
	}
	return 0, ErrOverlayFull
}

// HostConflict reports whether another valid member holds id's overlay slot
// with a stronger claim: an earlier admission, or the same time and a smaller
// identity. Every node evaluates the same records, so all agree on who yields.
func (s *Set) HostConflict(id PublicKey) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mine, ok := s.effective(id)
	if !ok {
		return Admission{}, false
	}
	for a := range s.validAdmissions() {
		if a.Identity == id || a.Host != mine.Host {
			continue
		}
		if a.IssuedAt < mine.IssuedAt || (a.IssuedAt == mine.IssuedAt && bytes.Compare(a.Identity[:], id[:]) < 0) {
			return a, true
		}
	}
	return Admission{}, false
}

// NameTaken reports whether a valid member other than except has the name.
func (s *Set) NameTaken(name string, except PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for a := range s.validAdmissions() {
		if a.Name == name && a.Identity != except {
			return true
		}
	}
	return false
}
