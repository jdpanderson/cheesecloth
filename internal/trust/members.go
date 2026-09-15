package trust

import (
	"bytes"
	"cmp"
	"errors"
	"maps"
	"slices"
)

// Queries over the valid membership as a whole: which member holds a name or
// an overlay slot, which slot is free, and how many members the records make.
// Each of them reads the view; see view.go.

// ByName returns the valid member with the given name, if exactly one exists.
func (s *Set) ByName(name string) (Admission, bool) {
	v := s.current()
	ids := v.byName[name]
	if len(ids) != 1 {
		return Admission{}, false
	}
	return v.members[ids[0]], true
}

// ErrOverlayFull is returned by FreeHost when every slot is taken.
var ErrOverlayFull = errors.New("no free overlay address")

// FreeHost picks the lowest overlay slot in [1, limit] that no admission
// uses. Slots held only by records that are no longer valid (revoked members)
// are reused when nothing else is free.
func (s *Set) FreeHost(limit uint64) (uint64, error) {
	v := s.current()
	for _, used := range []map[uint64]bool{v.taken, v.validTaken} {
		for h := uint64(1); h <= limit && h != 0; h++ {
			if !used[h] {
				return h, nil
			}
		}
	}
	return 0, ErrOverlayFull
}

// Contested is what two members can be given the same of, named for the
// operator's log.
const (
	ContestedHost = "overlay address"
	ContestedName = "name"
)

// Conflict is a claim on an identity's overlay slot or name that beats its
// own: what the two share, and the member that keeps it.
type Conflict struct {
	Contested string // ContestedHost or ContestedName
	Other     Admission
}

// Conflicts is, for every valid member that has to give up its overlay slot or
// its name, the member that keeps it. Two admitters enrolling a node at once,
// neither having seen the other's record yet, is the way one slot or one name
// is handed out twice; the records settle both the same way. A slot is reported
// ahead of a name, since a member has to be enrolled again either way. One pass
// answers for the whole membership, so a caller checking every member asks once
// rather than once per member.
func (s *Set) Conflicts() map[PublicKey]Conflict {
	return maps.Clone(s.current().conflicts) // the view's own map is never handed out
}

// strongerClaim reports whether a beats b as the holder of an overlay slot or
// a name the two share: the earlier admission, or at the same time the smaller
// identity. Every node evaluates the same records, so all agree on who yields.
func strongerClaim(a, b Admission) bool {
	return cmp.Or(cmp.Compare(a.IssuedAt, b.IssuedAt), bytes.Compare(a.Identity[:], b.Identity[:])) < 0
}

// MemberCount is how many identities the records make members, the root
// included. It is what a destructive change is measured against: a node that
// can reach far fewer members than it holds records for is working from a view
// the rest of the cluster does not share.
func (s *Set) MemberCount() int { return len(s.current().members) }

// NameTaken reports whether a valid member other than except has the name.
func (s *Set) NameTaken(name string, except PublicKey) bool {
	for _, id := range s.current().byName[name] {
		if id != except {
			return true
		}
	}
	return false
}

// Members is every valid member, by the record that names it. It is a copy:
// the view's own map is never handed out.
func (s *Set) Members() map[PublicKey]Admission { return maps.Clone(s.current().members) }

// VouchedAt is the first of admitter's numbers at which it signed for
// identity, and whether it ever did. It is what a revocation's mark is worked
// out from: cutting an admitter off below the number it first vouched at
// withdraws that node and everything the admitter signed afterwards.
func (s *Set) VouchedAt(admitter, identity PublicKey) (uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	first, found := uint64(0), false
	for _, a := range s.admissions[identity][admitter] {
		if !found || a.Seq < first {
			first, found = a.Seq, true
		}
	}
	return first, found
}

// Withdraws is who a revocation would take out and whether the set it would
// leave can still be swept: the members that would stop being members with r in
// the set, the subject among them, and whether the records the mark cuts off
// could then be dropped without changing any of that. It is the answer the
// records would give, asked before anything is signed, so that a node can see
// what it is about to do and refuse to do it.
//
// A revocation this node is no longer a member to make withdraws nobody, its
// subject included, which is how a node with nothing left to say finds out. A
// mark that cuts off the chain this node itself stands on withdraws this node,
// which is how it finds that out before rather than after.
//
// Withdrawing this node is not the only way to cut off the chain it stands on,
// which is what the second answer is for. Where the chain runs on through an
// admitter the mark withdraws, this node stays a member — through the cycle
// guard, from within the revocation's own walk — and every node that holds the
// record agrees, but no node can ever drop the records the mark cuts off,
// because dropping them would take this node out. The set grows and never
// gives anything back, so a record like that is one not to sign; see sweep.go.
//
// r is not verified and nothing is stored: only its subject, revoker, number
// and mark are read, so an unsigned record answers as well as a signed one.
func (s *Set) Withdraws(r Revocation) (withdrawn []Admission, sweepable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	trial := s.with(r)
	before, after := s.viewLocked(), trial.build()
	for id, a := range before.members {
		if _, still := after.members[id]; !still {
			withdrawn = append(withdrawn, a)
		}
	}
	// by name, so the operator reads them in the order they are written to a
	// hosts file rather than in map order
	slices.SortFunc(withdrawn, func(a, b Admission) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), bytes.Compare(a.Identity[:], b.Identity[:]))
	})
	_, _, _, sweepable = trial.sweepable(after)
	return withdrawn, sweepable
}

// with is this set's records plus r, as a set of its own holding what deciding
// membership reads and nothing else. The maps above the record it adds are
// copied, so nothing here touches this set. Callers hold the lock.
func (s *Set) with(r Revocation) *Set {
	revocations := maps.Clone(s.revocations)
	by := maps.Clone(revocations[r.Identity])
	if by == nil {
		by = map[PublicKey][]Revocation{}
	}
	by[r.Revoker] = append(slices.Clone(by[r.Revoker]), r)
	revocations[r.Identity] = by
	return &Set{root: s.root, admissions: s.admissions, revocations: revocations}
}
