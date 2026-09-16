package trust

import (
	"bytes"
	"cmp"
	"errors"
	"maps"
	"slices"
)

// The membership the records make, derived once and read many times.
//
//	base(S)     = the deepest checkpoint enough of the membership below it has
//	              attested to, starting from this node's anchor; before either,
//	              the root alone
//	vouched(X)  = X is in base, or some admission of X by a member is held and
//	              no retained checkpoint has removed X
//	counts(r)   = r is signed by its own subject, or by a member
//	member(X)   = vouched(X) and no revocation that counts names X
//
// The walk carries a guard over the one question it asks, because two members
// revoking each other reach each other: re-entering is false, so both of them
// are out, on every node and whatever order the records arrived in. The walk is
// only as deep as the changes since base, not as deep as the cluster's history.

// view is the answers a set of records gives. It is built whole and never
// edited, so a reader holding one has answers that agree with each other.
type view struct {
	base    *Checkpoint
	depth   uint64
	quorum  QuorumRule
	removed map[PublicKey]bool
	members map[PublicKey]Member
	byName  map[string][]PublicKey
	// taken is every overlay slot the membership uses. A slot a revocation
	// freed is free: the checkpoint that ratified the removal took the record
	// that claimed it with it.
	taken     map[uint64]bool
	conflicts map[PublicKey]Conflict
	// claims is the record that decides each member's name and slot, where one
	// does. A member a checkpoint names has none, and needs none.
	claims map[PublicKey]Admission
	// revoked is every identity a revocation that counts has named, whether or
	// not a checkpoint has ratified it yet. With removed it is what stops an
	// identity that is out being admitted again.
	revoked map[PublicKey]bool
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

// build derives the view from the records. Callers hold the write lock.
func (s *Set) build() *view {
	v := &view{
		quorum:  QuorumMajority,
		removed: map[PublicKey]bool{},
		members: map[PublicKey]Member{},
		byName:  map[string][]PublicKey{},
		taken:   map[uint64]bool{},
		claims:  map[PublicKey]Admission{},
		revoked: map[PublicKey]bool{},
	}
	// The walk starts at what this node has already satisfied itself of: its
	// anchor, or the root's own record where it has none yet. Nothing below the
	// anchor is read, which is what lets it be thrown away.
	standing := map[PublicKey]Member{}
	prev := Digest{}
	switch genesis, founded := s.genesis(); {
	case s.anchor != nil:
		v.base, v.depth, prev = s.anchor, s.anchor.Depth, s.anchor.Digest()
		v.quorum = s.anchor.Quorum
		for _, m := range s.anchor.Members {
			standing[m.Identity] = m
		}
		for _, r := range s.anchor.Removed {
			v.removed[r] = true
		}
	case founded:
		v.quorum = genesis.Quorum
		standing[genesis.Identity] = Member{Identity: genesis.Identity, Name: genesis.Name, Host: genesis.Host}
	default:
		v.conflicts = map[PublicKey]Conflict{}
		return v // nothing has told us who the root is, and nothing has been agreed
	}
	if v.quorum == "" {
		v.quorum = QuorumMajority
	}

	// The chain: each checkpoint ratifies against the membership below it, so
	// the walk climbs from there while the attestations hold.
	for {
		next := s.ratifiedAbove(prev, standing, v.quorum)
		if next == nil {
			break
		}
		v.base, v.depth, prev = next, next.Depth, next.Digest()
		standing = map[PublicKey]Member{}
		for _, m := range next.Members {
			standing[m.Identity] = m
		}
		for _, r := range next.Removed {
			v.removed[r] = true
		}
		if next.Quorum != "" {
			v.quorum = next.Quorum
		}
	}
	for id := range standing {
		delete(v.removed, id) // named as a member by a later checkpoint than the one that took it out
	}

	// Everything signed since: an admission vouches while its admitter is a
	// member, a revocation counts while its revoker is.
	named := map[PublicKey]bool{}
	maps.Copy(named, mapKeys(standing))
	for id := range s.admissions {
		named[id] = true
	}
	for _, revs := range s.revocations {
		for _, r := range revs {
			named[r.Identity] = true
			for _, d := range r.Disowned {
				named[d] = true
			}
		}
	}
	for id := range named {
		if !s.isMember(id, standing, v.removed, map[PublicKey]bool{}) {
			continue
		}
		m, ok := standing[id]
		if claim, held := s.claimFor(id, standing, v.removed); held {
			m, ok = Member{Identity: id, Name: claim.Name, Host: claim.Host}, true
			v.claims[id] = claim
		}
		if !ok {
			continue
		}
		v.members[id] = m
		v.taken[m.Host] = true
		v.byName[m.Name] = append(v.byName[m.Name], id)
	}
	for revoker, revs := range s.revocations {
		for _, r := range revs {
			if revoker != r.Identity && !s.isMember(revoker, standing, v.removed, map[PublicKey]bool{}) {
				continue
			}
			v.revoked[r.Identity] = true
			for _, d := range r.Disowned {
				v.revoked[d] = true
			}
		}
	}
	v.conflicts = conflicts(v.members, v.claims)
	return v
}

// mapKeys is the keys of m as a set.
func mapKeys[V any](m map[PublicKey]V) map[PublicKey]bool {
	out := make(map[PublicKey]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// genesis is the root's own record, which says who founded the cluster and
// which quorum rule it was founded with. Callers hold the lock.
func (s *Set) genesis() (Admission, bool) {
	for _, a := range s.admissions[s.root][s.root] {
		return a, true
	}
	return Admission{}, false
}

// ratifiedAbove is the checkpoint following prev that enough of the membership
// below it has attested to, if one is held. Callers hold the lock.
func (s *Set) ratifiedAbove(prev Digest, standing map[PublicKey]Member, quorum QuorumRule) *Checkpoint {
	need := quorum.Size(len(standing))
	var best *Checkpoint
	for _, c := range s.checkpoints {
		if c.Prev != prev {
			continue
		}
		votes := 0
		for _, at := range c.Attestations {
			if _, ok := standing[at.Signer]; ok {
				votes++
			}
		}
		if votes < need {
			continue
		}
		// Two ratified checkpoints above one parent can only exist where the
		// quorum is set low enough for two of them to be disjoint, which is the
		// operator's choice; the deeper one, then the smaller digest, so that
		// every node picks the same one.
		if best == nil || c.Depth > best.Depth {
			best = c
			continue
		}
		if c.Depth == best.Depth {
			cd, bd := c.Digest(), best.Digest()
			if bytes.Compare(cd[:], bd[:]) < 0 {
				best = c
			}
		}
	}
	return best
}

// isMember answers the rule at the top of this file. Callers hold the lock.
func (s *Set) isMember(id PublicKey, standing map[PublicKey]Member, removed map[PublicKey]bool, visiting map[PublicKey]bool) bool {
	if visiting[id] {
		return false
	}
	visiting[id] = true
	defer delete(visiting, id)

	if _, vouched := standing[id]; !vouched {
		if removed[id] || !s.vouchedSince(id, standing, removed, visiting) {
			return false
		}
	}
	for revoker, revs := range s.revocations {
		for _, r := range revs {
			if !r.names(id) {
				continue
			}
			if revoker == r.Identity {
				return false // a node may always revoke itself, and takes what it disowns with it
			}
			if s.isMember(revoker, standing, removed, visiting) {
				return false
			}
		}
	}
	return true
}

// vouchedSince reports whether an admission signed since base makes id a
// member: one by an admitter that is a member. Callers hold the lock.
func (s *Set) vouchedSince(id PublicKey, standing map[PublicKey]Member, removed, visiting map[PublicKey]bool) bool {
	for admitter, as := range s.admissions[id] {
		if admitter == id || len(as) == 0 {
			continue // the root's own record vouches through base, not through itself
		}
		if s.isMember(admitter, standing, removed, visiting) {
			return true
		}
	}
	return false
}

// names reports whether the revocation takes id out.
func (r *Revocation) names(id PublicKey) bool {
	return r.Identity == id || slices.Contains(r.Disowned, id)
}

// claimFor is the record that decides id's name and slot, where one has been
// signed since base: of each admitter's latest, the latest of those. Callers
// hold the lock.
func (s *Set) claimFor(id PublicKey, standing map[PublicKey]Member, removed map[PublicKey]bool) (Admission, bool) {
	var best Admission
	found := false
	for admitter, as := range s.admissions[id] {
		if admitter == id {
			continue
		}
		if !s.isMember(admitter, standing, removed, map[PublicKey]bool{}) {
			continue
		}
		for _, a := range as {
			if !found || laterRecord(a.IssuedAt, a.Admitter, best.IssuedAt, best.Admitter) {
				best, found = a, true
			}
		}
	}
	return best, found
}

// supersedes reports whether a ratified checkpoint has already taken id out, so
// that a record about it from before is history rather than news. Callers hold
// the write lock.
func (s *Set) supersedes(id PublicKey) bool { return s.viewLocked().removed[id] }

// supersededRevocation reports whether every identity r names is already out.
// Callers hold the write lock.
func (s *Set) supersededRevocation(r Revocation) bool {
	v := s.viewLocked()
	if _, ok := v.members[r.Identity]; ok {
		return false
	}
	for _, d := range r.Disowned {
		if _, ok := v.members[d]; ok {
			return false
		}
	}
	return v.base != nil
}

// ratified is the checkpoint the membership is read from. Callers hold the write lock.
func (s *Set) ratified() *Checkpoint { return s.viewLocked().base }

// Revoked reports whether id has been put out of the cluster, either by a
// revocation that counts or by a checkpoint that ratified one. It is not the
// negation of Valid: an identity no record names is no member and has not been
// revoked either. Nothing admits a revoked identity back while the checkpoint
// chain still remembers it; once the chain is trimmed past that, the identity
// is forgotten and may be invited again.
func (s *Set) Revoked(id PublicKey) bool {
	v := s.current()
	return v.revoked[id] || v.removed[id]
}

// RevokedIdentities is every identity a revocation the set still holds has put
// out. It is what a checkpoint has to record as removed before those records
// are trimmed: without it the trim would erase the only thing saying they are
// out, and the records that admitted them would put them back.
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
	trial := &Set{
		root:        s.root,
		checkpoints: s.checkpoints,
		admissions:  s.admissions,
		revocations: maps.Clone(s.revocations),
	}
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
		return cmp.Or(cmp.Compare(a.Name, b.Name), byIdentity(a.Identity, b.Identity))
	})
	return gone
}

// AdmittedBy is every member this set still holds a record of admitter having
// vouched for. It is what "everything this node admitted" is worked out from,
// and it is only as complete as the records: once a checkpoint has ratified and
// the admissions have been trimmed, the cluster no longer records who admitted
// whom, and this returns nothing. The caller says so rather than pretending the
// answer is the whole of it.
func (s *Set) AdmittedBy(admitter PublicKey) []PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []PublicKey
	for id, by := range s.admissions {
		if id == admitter {
			continue
		}
		if len(by[admitter]) > 0 {
			out = append(out, id)
		}
	}
	return canonicalKeys(out)
}

// Valid reports whether id is currently a member.
func (s *Set) Valid(id PublicKey) bool {
	_, ok := s.current().members[id]
	return ok
}

// Lookup returns the name and overlay slot id holds, if it is a member.
func (s *Set) Lookup(id PublicKey) (Member, bool) {
	m, ok := s.current().members[id]
	return m, ok
}

// Members is every member, by identity. It is a copy: the view's own map is
// never handed out.
func (s *Set) Members() map[PublicKey]Member { return maps.Clone(s.current().members) }

// MemberCount is how many identities the records make members, the root included.
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
// name, the member that keeps it. Two admitters enrolling a node at once,
// neither having seen the other's record yet, is the way one slot or one name
// is handed out twice.
func (s *Set) Conflicts() map[PublicKey]Conflict { return maps.Clone(s.current().conflicts) }

// conflicts is, for every member that has to give up its overlay slot or its
// name, the member that keeps it. A member a checkpoint names cannot be in a
// conflict: the membership it is part of was agreed, so anything contested was
// settled before it ratified. Only claims signed since can collide.
func conflicts(members map[PublicKey]Member, claims map[PublicKey]Admission) map[PublicKey]Conflict {
	byHost := map[uint64]PublicKey{}
	byName := map[string]PublicKey{}
	for id, m := range members {
		if held, ok := byHost[m.Host]; !ok || strongerClaim(id, held, claims) {
			byHost[m.Host] = id
		}
		if held, ok := byName[m.Name]; !ok || strongerClaim(id, held, claims) {
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

// strongerClaim reports whether a beats b as the holder of an overlay slot or a
// name the two share. A member a checkpoint named beats one admitted since,
// because the cluster agreed on it; between two admitted since, the earlier
// admission, or at the same second the smaller identity.
//
// The earlier one is what makes the answer useful rather than merely
// consistent. Two admitters hand out one slot only by acting at the same
// moment, and one of the two is almost always a node that has been running: the
// earlier admission is that node, and the node that has to be enrolled again is
// the one that has not started yet.
func strongerClaim(a, b PublicKey, claims map[PublicKey]Admission) bool {
	ca, aClaimed := claims[a]
	cb, bClaimed := claims[b]
	if aClaimed != bClaimed {
		return !aClaimed // the one the checkpoint named keeps it
	}
	if !aClaimed {
		return byIdentity(a, b) < 0
	}
	return cmp.Or(cmp.Compare(ca.IssuedAt, cb.IssuedAt), byIdentity(a, b)) < 0
}
