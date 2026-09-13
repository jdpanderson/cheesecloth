package trust

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Records is the wire and file form of a Set's contents.
type Records struct {
	Admissions  []Admission  `json:"admissions"`
	Revocations []Revocation `json:"revocations"`
	Prunes      []Prune      `json:"prunes,omitempty"`
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
	// refused, so a peer that has not pruned yet cannot put it back.
	pruned map[PublicKey]bool
	// members caches the identities found valid, until a record changes: the
	// gossip transport asks for every packet, and the walk to the root costs
	// more the longer the chain of admitters. Only valid answers are cached;
	// an unknown identity is decided in one lookup, and caching those would
	// let anything that can open a connection grow the map.
	members atomic.Pointer[sync.Map]
	// now is the clock the record dates are checked against; tests move it.
	now func() time.Time
}

// signerState is what a set remembers about a signer apart from its records:
// the newest date it has been seen to sign, which is the floor under anything
// it signs next, how far its counter has reached, so that a number stays spent
// even once the record that used it is gone, and what it signed at each number,
// so that using one twice is noticed.
type signerState struct {
	lastSigned int64
	highWater  uint64
	seen       map[uint64]*numberUse
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
	s := &Set{
		root:        root,
		admissions:  map[PublicKey]map[PublicKey][]Admission{},
		revocations: map[PublicKey]map[PublicKey]Revocation{},
		signers:     map[PublicKey]signerState{},
		prunes:      map[string]Prune{},
		pruned:      map[PublicKey]bool{},
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
	return s.signers[signer].lastSigned
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
	if s.pruned[a.Identity] || s.pruned[a.Admitter] {
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

// claim records that a signer signed at one of its numbers: the date is the
// floor under whatever it signs next, and the number is spent from here on,
// whether or not the record that used it was kept. Callers hold the write lock.
//
// A signer that has used a number twice is reported. Its agent cannot do that:
// the number comes from NextSeq, which is one past everything the set has seen
// it sign, and every path that signs holds the cluster's lock from reading the
// number to storing the record. Two different records at one number therefore
// say the key was used somewhere else. Nothing is refused over it, because the
// two records are indistinguishable and choosing between them is not possible;
// this only says so.
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
	if err := r.Validate(); err != nil {
		return false, err
	}
	if err := s.checkClock("revocation", r.Revoker, r.IssuedAt); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruned[r.Identity] || s.pruned[r.Revoker] {
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
		// Whoever those revocations put out is a member again. Revoking a node
		// that had itself revoked somebody, in a way that takes its revocations
		// with it, is not the ordinary business of running a cluster: the
		// ordinary way of leaving keeps everything the node signed. Whether this
		// is somebody restoring a revoked node or two revocations crossing on a
		// cluster that was not in step, the result is the same and neither is a
		// state to keep running in, so it is reported as what it is.
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

// AddPrune stores a signature-valid prune and acts on as much of it as this
// node can confirm for itself. It reports whether the set changed.
func (s *Set) AddPrune(p Prune) (bool, error) {
	if err := p.Validate(); err != nil {
		return false, err
	}
	if err := s.checkClock("prune", p.Pruner, p.IssuedAt); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruned[p.Pruner] {
		return false, nil
	}
	if _, held := s.prunes[string(p.Signature)]; held {
		return false, nil
	}
	s.claim(p.Pruner, p.Seq, p.IssuedAt, p.Signature)
	s.prunes[string(p.Signature)] = p
	s.applyPrunes()
	return true, nil // the record is new, whether or not it removed anything yet
}

// applyPrunes removes the identities the prunes ask for that this node derives
// as prunable itself, and remembers that they went. Any subset of Prunable may
// go: each of those identities is already no member, and nothing still standing
// runs through it, so leaving one behind costs only the space it takes. A prune
// naming an identity this node still holds valid therefore removes nothing,
// here or ever, and one that arrives before the records it covers is applied
// when they do. Callers hold the write lock.
func (s *Set) applyPrunes() bool {
	named := map[PublicKey]bool{}
	for _, p := range s.prunes {
		if !s.validFor(p.Pruner, p.Signature, map[question]bool{}) {
			continue // signed by a node that was not a member at the time
		}
		for _, id := range p.Identities {
			named[id] = true
		}
	}
	if len(named) == 0 {
		return false
	}
	changed := false
	for _, id := range s.prunable() {
		if !named[id] || s.pruned[id] {
			continue
		}
		s.remove(id)
		changed = true
	}
	if changed {
		s.forget()
	}
	return changed
}

// remove drops the admissions of id and the ones id signed, and tombstones it
// so a peer that has not pruned cannot hand them straight back.
//
// The revocations stay. They are what still says id is out once its admissions
// are gone, so a node that never saw them can be given the smaller set and
// reach the same answer. The prunes stay too, so a node that could not act on
// one yet still can later, and id's counter stays in signers, so a number it
// spent is never handed out again. Callers hold the write lock.
func (s *Set) remove(id PublicKey) {
	delete(s.admissions, id)
	for subject, by := range s.admissions {
		if delete(by, id); len(by) == 0 {
			delete(s.admissions, subject)
		}
	}
	s.pruned[id] = true
}

// Prunable is the identities whose admissions may be dropped: ones that are no
// longer members, and that nothing still standing runs through. Dropping their
// admissions changes no answer about any member, on this node or on one that is
// given the smaller set and little else.
//
// An identity qualifies whether a revocation put it out or the admissions that
// vouched for it were withdrawn and nothing else reaches the root. Acting on the
// second is what makes a compromise recoverable: one revocation of the admitter
// that keeps only the records the operator recognises, then a prune, and the
// rest of what that admitter signed is gone rather than sitting in the records
// for good.
//
// It rests on this node's records being current. A record that has not arrived
// yet could put an identity back in reach, and a node that pruned meanwhile
// would answer differently from one that did not. Pruning is for a node that is
// in touch with the cluster; see docs/operations.md.
//
// An identity qualifies only if every identity it admitted qualifies too, since
// an admission it signed may be what makes a member a member; and only if it
// revoked nobody but itself, since a revocation it signed keeps its subject out
// and needs its signer to still be judgeable. A self-revocation counts without
// its signer, so it costs nothing. This is the largest set closed under both,
// found by striking out whoever reaches outside it until nobody does.
//
// The result is sorted, so two nodes holding the same records offer the same
// list.
func (s *Set) Prunable() []PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.prunable()
}

// prunable is Prunable with the lock held.
func (s *Set) prunable() []PublicKey {
	// what each admitter vouched for, which is what it is needed for
	admitted := map[PublicKey][]PublicKey{}
	for id, by := range s.admissions {
		for admitter := range by {
			admitted[admitter] = append(admitted[admitter], id)
		}
	}
	// a revocation of somebody else counts only while its signer can be judged a
	// member, so that signer stays; one of its own needs nothing of its signer
	revokers := map[PublicKey]bool{}
	for subject, by := range s.revocations {
		for revoker := range by {
			if revoker != subject {
				revokers[revoker] = true
			}
		}
	}
	// only identities with admissions to drop, so one already pruned is not
	// offered again after a restart has forgotten the tombstone
	in := map[PublicKey]bool{}
	for id := range s.admissions {
		if id != s.root && !revokers[id] && !s.valid(id) {
			in[id] = true
		}
	}
	for shrank := true; shrank; {
		shrank = false
		for id := range in {
			for _, subject := range admitted[id] {
				if !in[subject] {
					delete(in, id)
					shrank = true
					break
				}
			}
		}
	}
	out := slices.Collect(maps.Keys(in))
	slices.SortFunc(out, func(a, b PublicKey) int { return bytes.Compare(a[:], b[:]) })
	return out
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
	for _, p := range rs.Prunes {
		if ok, _ := s.AddPrune(p); ok {
			changed++
		}
	}
	// a prune already held may only now have the records that confirm it
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyPrunes() {
		changed++
	}
	return changed
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

// valid is Valid with the lock held. No record asks about the identity now, so
// every revocation of it applies.
func (s *Set) valid(id PublicKey) bool {
	return s.validFor(id, nil, map[question]bool{})
}

// question is one thing the recursion has already set out to answer: was this
// identity a member when it signed this record. The same identity is asked
// about at several points along one chain, so the record belongs in the key.
type question struct {
	id  PublicKey
	sig string
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

// validFor reports whether id was a member when it signed the record with
// signature sig; a nil sig asks about id now. A revocation withdraws every
// record of its subject but the ones it names, so an admission stays valid if
// its admitter was a member when it signed and the revoker had seen that
// admission. A member may always revoke itself: only the holder of that key can
// sign such a record, and it takes nobody else out.
//
// An identity is a member if any one of its admissions holds, so a record by
// an admitter nobody believes neither makes an identity a member nor stops
// another record from doing so.
//
// Asking whether a revoker was a member reaches the identity it revokes again,
// at the earlier record that admitted it, so the cycle guard tracks the record
// as well as the identity. A record's signature never changes, so the questions
// the recursion can ask are finite and it always ends.
//
// The root differs from the rest only in needing no admitter. It is revoked by
// the same rule, and judging a revocation of the root reaches the root again
// at a record the revocation keeps, so what it signed while it was a member
// stays valid after it leaves.
func (s *Set) validFor(id PublicKey, sig []byte, visiting map[question]bool) bool {
	q := question{id, string(sig)}
	if visiting[q] {
		return false
	}
	visiting[q] = true
	defer delete(visiting, q)

	if s.revoked(id, sig, visiting) {
		return false
	}
	if id == s.root {
		return true
	}
	for admitter, as := range s.admissions[id] {
		if admitter == id {
			// Nothing reaches here: AddAdmission refuses a self-signed record
			// from anyone but the root, and the root is answered above. It
			// stays so that the rule holds where membership is decided, rather
			// than only where records are taken in.
			continue
		}
		for _, a := range as {
			if s.validFor(admitter, a.Signature, visiting) {
				return true
			}
		}
	}
	return false
}

// revoked reports whether a revocation of id withdraws the record signed with
// sig, the revoker being id itself or a member when it signed. A revocation
// that keeps the record withdraws it from nobody; one asked about a nil sig,
// which is the identity itself rather than anything it signed, withdraws it
// whatever it keeps.
func (s *Set) revoked(id PublicKey, sig []byte, visiting map[question]bool) bool {
	for _, r := range s.revocations[id] {
		if sig != nil && r.keeps(sig) {
			continue
		}
		if r.Revoker == id || s.validFor(r.Revoker, r.Signature, visiting) {
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
	return s.validFor(a.Admitter, a.Signature, map[question]bool{})
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
// with a stronger claim. Two admitters enrolling at once, neither having seen
// the other's record yet, is the way one slot is handed out twice.
func (s *Set) HostConflict(id PublicKey) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conflict(id, func(a, mine Admission) bool { return a.Host == mine.Host })
}

// NameConflict reports whether another valid member holds id's name with a
// stronger claim. A name is handed out twice the same way a slot is, and the
// records settle it the same way: the name is how every other node addresses
// this one, so two members cannot keep it between them.
func (s *Set) NameConflict(id PublicKey) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conflict(id, func(a, mine Admission) bool { return a.Name == mine.Name })
}

// conflict returns the valid member whose claim to what contested says the two
// share beats id's: the earlier admission, or at the same time the smaller
// identity. Every node evaluates the same records, so all agree on who yields.
// Callers hold the lock.
func (s *Set) conflict(id PublicKey, contested func(a, mine Admission) bool) (Admission, bool) {
	mine, ok := s.effective(id)
	if !ok {
		return Admission{}, false
	}
	for a := range s.validAdmissions() {
		if a.Identity == id || !contested(a, mine) {
			continue
		}
		if a.IssuedAt < mine.IssuedAt || (a.IssuedAt == mine.IssuedAt && bytes.Compare(a.Identity[:], id[:]) < 0) {
			return a, true
		}
	}
	return Admission{}, false
}

// MemberCount is how many identities the records make members, the root
// included. It is what a destructive change is measured against: a node that
// can reach far fewer members than it holds records for is working from a view
// the rest of the cluster does not share.
func (s *Set) MemberCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for range s.validAdmissions() {
		n++
	}
	return n
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
