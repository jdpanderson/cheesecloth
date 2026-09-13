package trust

import (
	"bytes"
	"cmp"
	"errors"
	"iter"
	"math"
	"slices"
	"sync"
	"sync/atomic"
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
type Set struct {
	mu          sync.RWMutex
	root        PublicKey
	admissions  map[PublicKey]map[PublicKey][]Admission // identity -> admitter -> earliest and latest
	revocations map[PublicKey]map[PublicKey]Revocation  // identity -> revoker -> record
	// members caches the identities found valid, until a record changes: the
	// gossip transport asks for every packet, and the walk to the root costs
	// more the longer the chain of admitters. Only valid answers are cached;
	// an unknown identity is decided in one lookup, and caching those would
	// let anything that can open a connection grow the map.
	members atomic.Pointer[sync.Map]
}

// NewSet creates a set trusting root. The root's own record is added like any
// other, when it arrives.
func NewSet(root PublicKey) *Set {
	s := &Set{
		root:        root,
		admissions:  map[PublicKey]map[PublicKey][]Admission{},
		revocations: map[PublicKey]map[PublicKey]Revocation{},
	}
	s.members.Store(&sync.Map{})
	return s
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
	s.mu.Lock()
	defer s.mu.Unlock()
	by := s.admissions[a.Identity]
	if by == nil {
		by = map[PublicKey][]Admission{}
		s.admissions[a.Identity] = by
	}
	kept, changed := keepEnds(by[a.Admitter], a)
	if !changed {
		return false, nil
	}
	by[a.Admitter] = kept
	s.forget()
	return true, nil
}

// issuedFirst orders one admitter's records by time, and at the same time by
// signature, so that every node keeps the same records whatever order they
// arrive in. Two records of the same identity by the same admitter at the same
// second differ in what they say, so their signatures differ too.
func issuedFirst(a, b Admission) int {
	return cmp.Or(cmp.Compare(a.IssuedAt, b.IssuedAt), bytes.Compare(a.Signature, b.Signature))
}

// keepEnds adds a to one admitter's records, which are its earliest and its
// latest, and reports whether it changed them.
func keepEnds(cur []Admission, a Admission) ([]Admission, bool) {
	if len(cur) == 0 {
		return []Admission{a}, true
	}
	first, last := cur[0], cur[len(cur)-1]
	switch {
	case issuedFirst(a, first) < 0:
		first = a
	case issuedFirst(a, last) > 0:
		last = a
	default:
		return cur, false
	}
	if issuedFirst(first, last) == 0 {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	by := s.revocations[r.Identity]
	if by == nil {
		by = map[PublicKey]Revocation{}
		s.revocations[r.Identity] = by
	}
	if cur, ok := by[r.Revoker]; ok && cur.IssuedAt <= r.IssuedAt {
		return false, nil
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

// Records returns the set's contents in a deterministic order.
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
		return cmp.Or(bytes.Compare(a.Identity[:], b.Identity[:]), bytes.Compare(a.Admitter[:], b.Admitter[:]), issuedFirst(a, b))
	})
	slices.SortFunc(rs.Revocations, func(a, b Revocation) int {
		return cmp.Or(bytes.Compare(a.Identity[:], b.Identity[:]), bytes.Compare(a.Revoker[:], b.Revoker[:]))
	})
	return rs
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

// valid is Valid with the lock held.
func (s *Set) valid(id PublicKey) bool {
	return s.validAt(id, math.MaxInt64, map[question]bool{})
}

// question is one thing the recursion has already set out to answer: was this
// identity a member at this time. The same identity is asked about at several
// times along one chain, so the time belongs in the key.
type question struct {
	id PublicKey
	at int64
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

// validAt evaluates membership as of unix time at: revocations issued later
// are ignored, so an admission stays valid if its admitter was a member when
// it signed, even if the admitter was revoked afterwards. A member may always
// revoke itself: only the holder of that key can sign such a record, and it
// takes nobody else out.
//
// An identity is a member if any one of its admissions holds, so a record by
// an admitter nobody believes neither makes an identity a member nor stops
// another record from doing so.
//
// Asking whether a revoker was a member reaches the identity it revokes again,
// at the earlier time that identity was admitted, so the cycle guard tracks
// the time as well as the identity. A record's time never changes, so the
// questions the recursion can ask are finite and it always ends.
//
// The root differs from the rest only in needing no admitter. It is revoked by
// the same rule, and judging a revocation of the root reaches the root again
// at the earlier time its revoker was admitted, where the revocation does not
// yet apply. Records the root signed while it was a member therefore stay
// valid after it leaves, and the chains that rest on them are unaffected.
func (s *Set) validAt(id PublicKey, at int64, visiting map[question]bool) bool {
	q := question{id, at}
	if visiting[q] {
		return false
	}
	visiting[q] = true
	defer delete(visiting, q)

	if s.revokedAt(id, at, visiting) {
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
			if s.validAt(admitter, a.IssuedAt, visiting) {
				return true
			}
		}
	}
	return false
}

// revokedAt reports whether any revocation of id issued no later than at was
// signed by id itself or by an identity that was a member when it signed.
func (s *Set) revokedAt(id PublicKey, at int64, visiting map[question]bool) bool {
	for _, r := range s.revocations[id] {
		if r.IssuedAt > at {
			continue
		}
		if r.Revoker == id || s.validAt(r.Revoker, r.IssuedAt, visiting) {
			return true
		}
	}
	return false
}

// vouched reports whether a is a record that can make its identity a member:
// the root's own, or one whose admitter was a member when it signed.
func (s *Set) vouched(a Admission) bool {
	if a.Admitter == a.Identity {
		return a.Identity == s.root
	}
	return s.validAt(a.Admitter, a.IssuedAt, map[question]bool{})
}

// laterClaim reports whether a is the record to prefer over b as the one that
// decides an identity's name and slot: the later one, and at the same time the
// one from the smaller admitter, so every node prefers the same record.
func laterClaim(a, b Admission) bool {
	return cmp.Or(
		cmp.Compare(a.IssuedAt, b.IssuedAt),
		bytes.Compare(b.Admitter[:], a.Admitter[:]),
		bytes.Compare(b.Signature, a.Signature),
	) > 0
}

// effective is the record that decides id's name and overlay slot: the latest
// of the admissions that vouch for it. A record nobody believes decides
// nothing, which is what keeps an identity that is no longer a member from
// renaming, renumbering or unseating one that is. Callers hold the lock.
func (s *Set) effective(id PublicKey) (Admission, bool) {
	var best Admission
	found := false
	for _, as := range s.admissions[id] {
		for _, a := range as {
			if !s.vouched(a) {
				continue
			}
			if !found || laterClaim(a, best) {
				best, found = a, true
			}
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
