package trust

import (
	"cmp"
	"errors"
	"maps"
	"slices"
	"strings"
)

// The membership, derived once and read many times.
//
//	member(X) = the agreed membership names X, or a member it names has
//	            admitted X since; and no member it names, nor X itself, has
//	            revoked X
//
// That is the whole rule. It is flat: only the membership the cluster has
// agreed on can change the membership, so nothing has to ask whether the signer
// of a record was itself admitted by somebody who was admitted by somebody, and
// two nodes revoking each other cannot chase each other in a circle. A node
// admitted since the last agreement can be admitted and revoked but cannot
// admit or revoke, which lasts until the next agreement and costs a moment.
//
// Nothing here reads a clock. Where two records have to be compared -- which
// happens only among those signed since the last agreement -- they are ordered
// by identity, which every node reads the same way.

// view is the answers a set of records gives. It is built whole and never
// edited, so a reader holding one has answers that agree with each other.
type view struct {
	depth   uint64
	quorum  QuorumRule
	removed map[PublicKey]bool
	revoked map[PublicKey]bool
	members map[PublicKey]Member
	byName  map[string][]PublicKey
	// taken is every overlay slot the membership uses. A slot a departed member
	// held is free: nothing records that it ever held it.
	taken     map[uint64]bool
	conflicts map[PublicKey]Conflict
	// agreed is the members the anchor names, which are the ones whose records
	// count and the ones that keep a contested name or slot.
	agreed map[PublicKey]bool
}

// current is the view, built first if a record has changed since the last one.
// Callers must not hold the lock.
func (s *Set) current() *view {
	if v := s.view.Load(); v != nil {
		return v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked()
}

// viewLocked is current for a caller that already holds the write lock.
func (s *Set) viewLocked() *view {
	if v := s.view.Load(); v != nil {
		return v
	}
	v := s.build()
	s.view.Store(v)
	return v
}

// build derives the view from the anchor and what has been signed since.
// Callers hold the write lock.
func (s *Set) build() *view {
	v := &view{
		quorum:    QuorumMajority,
		removed:   map[PublicKey]bool{},
		revoked:   map[PublicKey]bool{},
		members:   map[PublicKey]Member{},
		byName:    map[string][]PublicKey{},
		taken:     map[uint64]bool{},
		conflicts: map[PublicKey]Conflict{},
		agreed:    map[PublicKey]bool{},
	}
	if s.anchor == nil {
		return v // nothing has been agreed, so this node knows no membership
	}
	v.depth, v.quorum = s.anchor.Depth, s.anchor.Quorum
	for _, m := range s.anchor.Members {
		v.members[m.Identity] = m
		v.agreed[m.Identity] = true
	}
	for _, r := range s.anchor.Removed {
		v.removed[r] = true
	}

	// What has been revoked, before anything is admitted: a node that is out
	// must not still be letting nodes in. A node may always revoke itself, and
	// that is judged first, so that nothing else it signed goes on counting
	// afterwards -- which is the only way to say "after" without a clock.
	for revoker, revs := range s.revocations {
		for _, r := range revs {
			if revoker == r.Identity {
				takeOut(v, r)
			}
		}
	}
	// Who may revoke is settled before any of it is applied, or two members
	// revoking each other would come out differently depending on which the map
	// happened to hand over first. Both count, so both go: the conservative
	// answer, and the same one on every node.
	var eligible []PublicKey
	for revoker := range s.revocations {
		if v.agreed[revoker] && !v.revoked[revoker] {
			eligible = append(eligible, revoker)
		}
	}
	for _, revoker := range eligible {
		for _, r := range s.revocations[revoker] {
			takeOut(v, r)
		}
	}
	for id := range v.revoked {
		delete(v.agreed, id)
	}

	// Admitted since, by a member the cluster agreed on and has not put out. An
	// identity the anchor already names keeps what the anchor says: the agreed
	// membership decides a member's name and slot, and a later one is agreed
	// the same way.
	for id, by := range s.admissions {
		if v.removed[id] || v.revoked[id] || v.members[id].Identity == id {
			continue
		}
		if a, ok := claimFor(by, v.agreed); ok {
			v.members[id] = Member{Identity: id, Name: a.Name, Host: a.Host}
		}
	}

	for id, m := range v.members {
		v.taken[m.Host] = true
		v.byName[m.Name] = append(v.byName[m.Name], id)
	}
	v.conflicts = conflicts(v.members, v.agreed)
	return v
}

// takeOut records that a revocation puts its subject, and everything it
// disowns, out of the cluster.
func takeOut(v *view, r Revocation) {
	for _, id := range append([]PublicKey{r.Identity}, r.Disowned...) {
		v.revoked[id] = true
		delete(v.members, id)
	}
}

// claimFor is the record that says what an identity admitted since the last
// agreement is called and where it sits: of the admissions by members the
// cluster agreed on, the one from the smallest admitter, and at the same
// admitter the smallest signature. Nothing about it needs a date -- an identity
// has one admitter in practice, and where it has two the choice between them is
// arbitrary and only has to be the same everywhere.
func claimFor(by map[PublicKey][]Admission, agreed map[PublicKey]bool) (Admission, bool) {
	var best Admission
	found := false
	for admitter, as := range by {
		if !agreed[admitter] {
			continue
		}
		for _, a := range as {
			if !found || preferred(a, best) {
				best, found = a, true
			}
		}
	}
	return best, found
}

// preferred reports whether a beats b as the record that speaks for an
// identity: the smaller admitter, then the smaller signature.
func preferred(a, b Admission) bool {
	if c := byIdentity(a.Admitter, b.Admitter); c != 0 {
		return c < 0
	}
	return slices.Compare(a.Signature, b.Signature) < 0
}

// Valid reports whether id is currently a member.
func (s *Set) Valid(id PublicKey) bool {
	_, ok := s.current().members[id]
	return ok
}

// Revoked reports whether id has been put out of the cluster, by a revocation
// that counts or by an agreed membership that dropped it. It is not the
// negation of Valid: an identity no record names is no member and has not been
// revoked either. Nothing admits a revoked identity back while the cluster
// still remembers it; once it is forgotten, the identity may be invited again.
func (s *Set) Revoked(id PublicKey) bool {
	v := s.current()
	return v.revoked[id] || v.removed[id]
}

// Lookup returns the name and overlay slot id holds, if it is a member.
func (s *Set) Lookup(id PublicKey) (Member, bool) {
	m, ok := s.current().members[id]
	return m, ok
}

// Members is every member, by identity. It is a copy: the view's own map is
// never handed out.
func (s *Set) Members() map[PublicKey]Member { return maps.Clone(s.current().members) }

// MemberCount is how many identities are members, the founding node included.
func (s *Set) MemberCount() int { return len(s.current().members) }

// ByName returns the member with the given name, if exactly one exists.
func (s *Set) ByName(name string) (Member, bool) {
	v := s.current()
	ids := v.byName[name]
	if len(ids) != 1 {
		return Member{}, false
	}
	return v.members[ids[0]], true
}

// NameTaken reports whether a member other than except has the name.
func (s *Set) NameTaken(name string, except PublicKey) bool {
	for _, id := range s.current().byName[name] {
		if id != except {
			return true
		}
	}
	return false
}

// AdmittedBy is every identity this set still holds a record of admitter having
// vouched for. It is what "everything this node admitted" is worked out from,
// and it is only as complete as the records: once the cluster has agreed a
// membership and the admissions have been trimmed, it no longer records who
// admitted whom, and this returns nothing.
func (s *Set) AdmittedBy(admitter PublicKey) []PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []PublicKey
	for id, by := range s.admissions {
		if id != admitter && len(by[admitter]) > 0 {
			out = append(out, id)
		}
	}
	return canonicalKeys(out)
}

// Withdraws is who a revocation would take out: the members that would stop
// being members with r in the set, its subject among them. It is the answer the
// records would give, asked before anything is signed, so that a node can see
// what it is about to do and refuse to do it.
//
// r is not verified and nothing is stored: only the identities it names and its
// revoker are read, so an unsigned record answers as well as a signed one.
func (s *Set) Withdraws(r Revocation) []Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.viewLocked()
	trial := &Set{anchor: s.anchor, checkpoints: s.checkpoints, admissions: s.admissions, revocations: maps.Clone(s.revocations)}
	trial.revocations[r.Revoker] = append(slices.Clone(trial.revocations[r.Revoker]), r)
	after := trial.build()
	var gone []Member
	for id, m := range before.members {
		if _, still := after.members[id]; !still {
			gone = append(gone, m)
		}
	}
	// by name, so the operator reads them in the order they are written to a
	// hosts file rather than in map order
	slices.SortFunc(gone, func(a, b Member) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), byIdentity(a.Identity, b.Identity))
	})
	return gone
}

// RevokedIdentities is every identity a revocation the set still holds has put
// out, together with those an agreed membership already removed. It is what a
// checkpoint records as removed before those records are trimmed: without it
// the trim would erase the only thing saying they are out, and the records that
// admitted them would stand again.
func (s *Set) RevokedIdentities() []PublicKey {
	v := s.current()
	out := make([]PublicKey, 0, len(v.revoked)+len(v.removed))
	for id := range v.revoked {
		out = append(out, id)
	}
	for id := range v.removed {
		out = append(out, id)
	}
	return canonicalKeys(out)
}

// supersededRevocation reports whether every identity r names is already out.
// Callers hold the write lock.
func (s *Set) supersededRevocation(r Revocation) bool {
	v := s.viewLocked()
	if s.anchor == nil {
		return false
	}
	for _, id := range append([]PublicKey{r.Identity}, r.Disowned...) {
		if _, ok := v.members[id]; ok {
			return false
		}
	}
	return true
}

// ErrOverlayFull is returned by FreeHost when every slot is taken.
var ErrOverlayFull = errors.New("no free overlay address")

// FreeHost picks the lowest overlay slot in [1, limit] no member holds. A slot
// a departed member held is free, since nothing records that it ever held it.
func (s *Set) FreeHost(limit uint64) (uint64, error) {
	taken := s.current().taken
	for h := uint64(1); h <= limit && h != 0; h++ {
		if !taken[h] {
			return h, nil
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

// Conflict is a claim on a member's overlay slot or name that beats its own:
// what the two share, and the member that keeps it.
type Conflict struct {
	Contested string // ContestedHost or ContestedName
	Other     Member
}

// Conflicts is, for every member that has to give up its overlay slot or its
// name, the member that keeps it.
func (s *Set) Conflicts() map[PublicKey]Conflict { return maps.Clone(s.current().conflicts) }

// conflicts is, for every member that has to give up its overlay slot or its
// name, the member that keeps it. A member the cluster agreed on cannot be in
// one with another agreed member: an agreed membership is where any such
// contest was settled. Only what has been admitted since can collide, with an
// agreed member or with another newcomer.
//
// An agreed member always keeps what it holds. Between two newcomers it goes by
// identity, which is arbitrary and has to be no more than that: both were
// admitted moments ago, so there is no established node to prefer.
func conflicts(members map[PublicKey]Member, agreed map[PublicKey]bool) map[PublicKey]Conflict {
	byHost := map[uint64]PublicKey{}
	byName := map[string]PublicKey{}
	for id, m := range members {
		if held, ok := byHost[m.Host]; !ok || keeps(id, held, agreed) {
			byHost[m.Host] = id
		}
		if held, ok := byName[m.Name]; !ok || keeps(id, held, agreed) {
			byName[m.Name] = id
		}
	}
	out := map[PublicKey]Conflict{}
	for id, m := range members {
		switch {
		case byHost[m.Host] != id:
			out[id] = Conflict{Contested: ContestedHost, Other: members[byHost[m.Host]]}
		case byName[m.Name] != id:
			out[id] = Conflict{Contested: ContestedName, Other: members[byName[m.Name]]}
		}
	}
	return out
}

// keeps reports whether a beats b as the holder of something the two share.
func keeps(a, b PublicKey, agreed map[PublicKey]bool) bool {
	if agreed[a] != agreed[b] {
		return agreed[a]
	}
	return byIdentity(a, b) < 0
}
