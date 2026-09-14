package trust

import (
	"bytes"
	"log/slog"
	"maps"
	"slices"
)

// Pruning: a prune record asks every node to drop the admissions of
// identities that are out of the cluster and that no member's chain runs
// through. Each node derives that set for itself and removes only what it can
// confirm, so nodes reach the same answers whether or not either has acted.

// AddPrune stores a signature-valid prune and acts on as much of it as this
// node can confirm for itself. It reports whether the set changed.
func (s *Set) AddPrune(p Prune) (bool, error) {
	if s.heldPrune(p) {
		return false, nil
	}
	if err := p.Validate(); err != nil {
		return false, err
	}
	if err := s.checkClock("prune", p.Pruner, p.IssuedAt); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gone(p.Pruner) {
		return false, nil
	}
	if _, held := s.prunes[string(p.Signature)]; held {
		return false, nil // two copies arrived at once and both passed heldPrune
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
		if !named[id] || s.gone(id) {
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

// gone reports whether a prune has removed id here. Callers hold the lock.
func (s *Set) gone(id PublicKey) bool {
	_, pruned := s.pruned[id]
	return pruned
}

// reportRefusal says so the first time a record is refused for an identity this
// node pruned and holds no revocation of.
//
// A peer that has not pruned yet re-offers what it removed, which is ordinary:
// the revocation that put the identity out is still held here, and both nodes
// already agree. An identity with no revocation of its own is the other case.
// It was pruned because the records vouching for it were withdrawn, a judgement
// from what this node held at the time, and a member whose records still reach
// it disagrees. The refusal keeps them apart for as long as this node runs.
// Callers hold the write lock.
func (s *Set) reportRefusal(id PublicKey) {
	if !s.pruned[id] || len(s.revocations[id]) > 0 {
		return
	}
	s.pruned[id] = false
	slog.Warn("refusing records for an identity this node pruned and nothing here revoked; it went "+
		"because the records vouching for it were withdrawn. A member that still holds those records "+
		"counts it as a member, and this node will refuse them for as long as it runs. Compare "+
		"'cheesecloth status' across the cluster, and restart this agent to take them again.",
		"identity", id.Short())
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
// admissions changes no answer about any member, on this node or on one given
// the smaller set.
//
// An identity qualifies whether a revocation put it out or the admissions that
// vouched for it were withdrawn and nothing else reaches the root. The second is
// what makes a compromise recoverable: one revocation of the admitter keeping
// only the records the operator recognises, then a prune, and the rest of what
// that admitter signed is gone rather than sitting in the records for good.
//
// It rests on this node's records being current. A record that has not arrived
// yet could put an identity back in reach, and a node that pruned meanwhile
// would refuse it; reportRefusal says so when that happens, and a restart undoes
// it. Pruning is for a node that is in touch with the cluster; see
// docs/operations.md.
//
// An identity qualifies only if every identity it admitted qualifies too, since
// an admission it signed may be what makes a member a member; and only if it
// revoked nobody but itself, since a revocation it signed needs its signer to
// still be judgeable. This is the largest set closed under both, found by
// striking out whoever reaches outside it until nobody does. The result is
// sorted, so two nodes holding the same records offer the same list.
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
