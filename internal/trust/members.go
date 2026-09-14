package trust

import (
	"bytes"
	"cmp"
	"errors"
)

// Queries over the valid membership as a whole: which member holds a name or
// an overlay slot, which slot is free, and how many members the records make.

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
	s.mu.RLock()
	defer s.mu.RUnlock()
	var members []Admission
	byHost := map[uint64]Admission{}
	byName := map[string]Admission{}
	for a := range s.validAdmissions() {
		members = append(members, a)
		if best, held := byHost[a.Host]; !held || strongerClaim(a, best) {
			byHost[a.Host] = a
		}
		if best, held := byName[a.Name]; !held || strongerClaim(a, best) {
			byName[a.Name] = a
		}
	}
	out := map[PublicKey]Conflict{}
	for _, a := range members {
		switch {
		case byHost[a.Host].Identity != a.Identity:
			out[a.Identity] = Conflict{Contested: ContestedHost, Other: byHost[a.Host]}
		case byName[a.Name].Identity != a.Identity:
			out[a.Identity] = Conflict{Contested: ContestedName, Other: byName[a.Name]}
		}
	}
	return out
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
