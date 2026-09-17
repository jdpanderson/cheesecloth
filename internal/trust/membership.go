package trust

import (
	"bytes"
	"cmp"
	"errors"
	"maps"
	"slices"
	"strings"
)

// The membership, derived once and read many times.
//
//	member(X) = the agreed membership names X
//
// That is the whole rule, and it is the whole of what a node reads. An
// admission or a revocation is a proposal: it changes nothing until enough of
// the cluster has attested to a membership that accounts for it. So there is
// one answer to who belongs, every node reads it from the same list, and
// nothing has to ask who admitted whom or judge a record against another.
//
// What the records propose is a separate question, asked only when a node
// states the next membership. See Proposal.
//
// Nothing here reads a clock. Where two records have to be compared -- which
// happens only among those signed since the last agreement -- they are ordered
// by identity, which every node reads the same way.

// view is the answers the agreed membership gives. It is built whole and never
// edited, so a reader holding one has answers that agree with each other.
type view struct {
	depth         uint64
	quorum        QuorumRule
	confirmations int
	removed       map[PublicKey]bool
	// revoked is every identity a revocation a member has signed names. Those
	// are still members until the cluster agrees a membership without them;
	// what this decides is that none of them is admitted back in the meantime.
	revoked map[PublicKey]bool
	members map[PublicKey]Member
	byName  map[string]PublicKey
	// slots is who holds each overlay slot the membership uses. A slot a
	// departed member held is free: nothing records that it ever held it.
	slots map[uint64]PublicKey
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

// build derives the view from the anchor. Callers hold the write lock.
func (s *Set) build() *view {
	v := &view{
		quorum:  QuorumMajority,
		removed: map[PublicKey]bool{},
		revoked: map[PublicKey]bool{},
		members: map[PublicKey]Member{},
		byName:  map[string]PublicKey{},
		slots:   map[uint64]PublicKey{},
	}
	if s.anchor == nil {
		return v // nothing has been agreed, so this node knows no membership
	}
	v.depth, v.quorum, v.confirmations = s.anchor.Depth, s.anchor.Quorum, s.anchor.Confirmations
	// A checkpoint cannot name two members sharing a name or a slot, so this
	// needs no contest to settle: whatever there was, the agreement settled it.
	for _, m := range s.anchor.Members {
		v.members[m.Identity] = m
		v.byName[m.Name] = m.Identity
		v.slots[m.Host] = m.Identity
	}
	for _, d := range s.anchor.Removed {
		v.removed[d.Identity] = true
	}
	// A revocation a member has signed has not taken anybody out yet. What it
	// does at once is stop the identity being admitted again, so that an
	// admission and a revocation of the same node cannot race into the next
	// membership.
	for revoker, revs := range s.revocations {
		if _, ok := v.members[revoker]; !ok {
			continue
		}
		for _, r := range revs {
			for _, id := range append([]PublicKey{r.Identity}, r.Disowned...) {
				if s.knows(v, id) {
					v.revoked[id] = true
				}
			}
		}
	}
	return v
}

// Proposal is the membership the records propose: the agreed membership with
// what its members have admitted since added to it, and what they have revoked
// taken out. It is what a node states when it attests, and it is the only thing
// that reads the records at all -- who belongs is the anchor's answer alone.
type Proposal struct {
	// Depth is the depth the checkpoint stating this membership would have,
	// which is one past the anchor's.
	Depth   uint64
	Members []Member
	// Removed is every identity out of the cluster that is still worth naming:
	// the members this membership drops, and those an earlier one dropped
	// within the last Keep agreements. Naming them is what lets the records
	// that admitted them be discarded without those records standing again.
	Removed []Departure
}

// Proposal is the membership the records propose. It is derived on each call,
// which is as often as a node attests.
func (s *Set) Proposal() Proposal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proposalLocked()
}

// Next is the checkpoint this node would sign to state the membership the
// records propose, and whether there is anything to state -- there is not, once
// the cluster has agreed one, which is the usual case.
//
// The membership and the anchor it follows are read together. Taken separately,
// one agreed in between leaves the depth from the new anchor and the lineage
// from the old, and no other node would ever produce that pair: it could never
// gather an attestation, and nothing would collect it either.
func (s *Set) Next(id *Identity) (Checkpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor == nil {
		return Checkpoint{}, false // no membership to state one against
	}
	p := s.proposalLocked()
	if slices.Equal(s.anchor.Members, p.Members) && slices.Equal(s.anchor.Removed, p.Removed) {
		return Checkpoint{}, false // the agreed membership already says this
	}
	return Propose(id, p.Depth, s.anchor.Digest(), s.anchor.Quorum, s.anchor.Confirmations, p.Members, p.Removed), true
}

// proposalLocked is Proposal for a caller that holds the write lock.
func (s *Set) proposalLocked() Proposal {
	v := s.viewLocked()
	members := maps.Clone(v.members)
	// Only a member may propose anything: being one of them is the whole of the
	// authority to sign a record, and one from anybody else says nothing about
	// who belongs, whoever it names.
	signers := maps.Clone(v.members)
	revoked := map[PublicKey]bool{}

	// Revocations first: a node on its way out must not still be letting nodes
	// in. A member's own revocation is judged before the rest, so that nothing
	// else it signed goes on counting afterwards -- which is the only way to
	// say "after" without a clock.
	for revoker, revs := range s.revocations {
		if _, ok := signers[revoker]; !ok {
			continue
		}
		for _, r := range revs {
			if revoker == r.Identity && s.confirmed(v, r.Digest(), revoker) {
				takeOut(members, revoked, r)
			}
		}
	}
	// Who may revoke anyone else is settled before any of it is applied, or two
	// members revoking each other would come out differently depending on which
	// the map happened to hand over first. Both count, so both go: the
	// conservative answer, and the same one on every node.
	var eligible []PublicKey
	for revoker := range s.revocations {
		if _, ok := signers[revoker]; ok && !revoked[revoker] {
			eligible = append(eligible, revoker)
		}
	}
	for _, revoker := range eligible {
		for _, r := range s.revocations[revoker] {
			if s.confirmed(v, r.Digest(), revoker) {
				takeOut(members, revoked, r)
			}
		}
	}
	for id := range revoked {
		delete(signers, id)
	}

	// Then what the members still standing have admitted. A joiner that wants a
	// name or a slot one of them holds does not get it, and neither does the
	// loser of a contest between two joiners: a membership naming two nodes the
	// same could never be agreed, so a node that cannot be admitted cleanly is
	// not admitted at all and enrols again. Candidates are taken in identity
	// order, which is arbitrary and only has to be the same everywhere -- both
	// were admitted moments ago, so there is no established node to prefer.
	byName := map[string]bool{}
	taken := map[uint64]bool{}
	for _, m := range members {
		byName[m.Name], taken[m.Host] = true, true
	}
	candidates := make([]Member, 0, len(s.admissions))
	for id, by := range s.admissions {
		if revoked[id] || v.removed[id] {
			continue
		}
		if _, ok := members[id]; ok {
			continue // already a member: the agreed membership says what it is called
		}
		if a, ok := claimFor(by, signers, func(a Admission) bool { return s.confirmed(v, a.Digest(), a.Admitter) }); ok {
			candidates = append(candidates, Member{Identity: id, Name: a.Name, Host: a.Host})
		}
	}
	slices.SortFunc(candidates, func(a, b Member) int { return byIdentity(a.Identity, b.Identity) })
	for _, m := range candidates {
		if byName[m.Name] || taken[m.Host] {
			continue
		}
		members[m.Identity] = m
		byName[m.Name], taken[m.Host] = true, true
	}

	// What this membership names as gone: every identity it does not hold that
	// an earlier membership dropped or a revocation has put out. Naming them is
	// what lets the records that admitted them be discarded -- without it the
	// trim would take away the only thing saying they are out, and a peer still
	// holding the admission would put them back at the next state sync.
	//
	// An identity is dropped from the list Keep agreements after it went. By
	// then every node that can still reach the present has taken a checkpoint
	// naming it and discarded its own copy of the record, so there is nothing
	// left for the entry to guard against. A node further behind than that
	// cannot get here at all and has to enrol again.
	next := v.depth + 1
	floor := uint64(0)
	if next > Keep {
		floor = next - Keep
	}
	gone := make(map[PublicKey]uint64, len(v.removed))
	for _, d := range s.anchor.Removed {
		if d.Depth >= floor {
			gone[d.Identity] = d.Depth
		}
	}
	// An entry keeps the depth it first went at; a revocation still held must
	// not restamp it, or the identity would be remembered afresh for as long as
	// the record survives and never age out at all.
	for id := range revoked {
		if _, ok := gone[id]; ok || !s.knows(v, id) {
			continue
		}
		gone[id] = next
	}
	for id := range v.members {
		if _, ok := gone[id]; !ok {
			gone[id] = next
		}
	}
	list := make([]Member, 0, len(members))
	for id, m := range members {
		list = append(list, m)
		delete(gone, id)
	}
	departed := make([]Departure, 0, len(gone))
	for id, at := range gone {
		departed = append(departed, Departure{Identity: id, Depth: at})
	}
	return Proposal{Depth: next, Members: canonicalMembers(list), Removed: canonicalDepartures(departed)}
}

// knows reports whether the cluster has anything to say about an identity: it
// is a member, or a member has admitted it.
//
// A revocation may name any identity at all, and one naming a single member is
// taken by every node. Without this, one record could put a thousand identities
// the cluster has never heard of into its membership as removed -- refused
// enrolment for Keep agreements, and carried in every checkpoint, state file
// and welcome until they age out. Leaving them out costs nothing: a revocation
// naming an identity the membership cannot account for is not trimmed away, so
// it goes on saying what it says for as long as that is worth anything.
func (s *Set) knows(v *view, id PublicKey) bool {
	if _, ok := v.members[id]; ok {
		return true
	}
	for admitter := range s.admissions[id] {
		if _, ok := v.members[admitter]; ok {
			return true
		}
	}
	return false
}

// confirmationsNeeded is how many members besides its signer must confirm a
// record before it counts.
//
// It is clamped to one short of the membership, so a cluster smaller than its
// own setting asks for what it can supply rather than freezing: a cluster of
// three that wants five confirmations asks for two. The clamp reads the agreed
// membership, not the members that happen to be reachable -- every node has to
// reach the same number, or two of them would disagree about whether a record
// counts and never agree on a membership at all. What that costs is the same
// thing quorum costs: enough members have to be reachable.
func (v *view) confirmationsNeeded() int {
	if v.confirmations <= 0 {
		return 0
	}
	return min(v.confirmations, len(v.members)-1)
}

// confirmed reports whether a record has gathered the confirmations the cluster
// asks for, from members other than the one that signed it.
func (s *Set) confirmed(v *view, record Digest, signer PublicKey) bool {
	need := v.confirmationsNeeded()
	if need == 0 {
		return true
	}
	have := 0
	for confirmer := range s.confirmations[record] {
		if _, ok := v.members[confirmer]; !ok || confirmer == signer {
			continue
		}
		have++
	}
	return have >= need
}

// Confirmations is how many members besides its signer the cluster asks to
// confirm a record, clamped to what the membership can supply.
func (s *Set) Confirmations() int { return s.current().confirmationsNeeded() }

// Awaiting is a record the cluster is holding until enough members confirm it,
// described for the operator who has to decide.
type Awaiting struct {
	Record   Digest
	Kind     string // "admission" or "revocation"
	Identity PublicKey
	Name     string // what the record calls the subject, where it says
	Signer   PublicKey
	Have     int
	Need     int
}

// Awaiting is every record a member has signed that is waiting for
// confirmations, in a fixed order so the list does not shuffle between calls.
func (s *Set) Awaiting() []Awaiting {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.viewLocked()
	need := v.confirmationsNeeded()
	if need == 0 {
		return nil
	}
	var out []Awaiting
	add := func(kind string, d Digest, id PublicKey, name string, signer PublicKey) {
		if _, ok := v.members[signer]; !ok {
			return // nothing it signs counts, confirmed or not
		}
		have := 0
		for confirmer := range s.confirmations[d] {
			if _, ok := v.members[confirmer]; ok && confirmer != signer {
				have++
			}
		}
		if have >= need {
			return
		}
		out = append(out, Awaiting{Record: d, Kind: kind, Identity: id, Name: name, Signer: signer, Have: have, Need: need})
	}
	for _, by := range s.admissions {
		for _, as := range by {
			for _, a := range as {
				add("admission", a.Digest(), a.Identity, a.Name, a.Admitter)
			}
		}
	}
	for _, revs := range s.revocations {
		for _, r := range revs {
			name := r.Identity.Short()
			if m, ok := v.members[r.Identity]; ok {
				name = m.Name
			}
			add("revocation", r.Digest(), r.Identity, name, r.Revoker)
		}
	}
	slices.SortFunc(out, func(a, b Awaiting) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), bytes.Compare(a.Record[:], b.Record[:]))
	})
	return out
}

// takeOut records that a revocation puts its subject, and everything it
// disowns, out of the cluster.
func takeOut(members map[PublicKey]Member, revoked map[PublicKey]bool, r Revocation) {
	for _, id := range append([]PublicKey{r.Identity}, r.Disowned...) {
		revoked[id] = true
		delete(members, id)
	}
}

// Holds returns what the proposed membership calls id, if it names it.
func (p Proposal) Holds(id PublicKey) (Member, bool) {
	i := slices.IndexFunc(p.Members, func(m Member) bool { return m.Identity == id })
	if i < 0 {
		return Member{}, false
	}
	return p.Members[i], true
}

// NameTaken reports whether a member other than except holds the name, in the
// agreed membership or in the one the records propose.
func (s *Set) NameTaken(name string, except PublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if held, ok := s.viewLocked().byName[name]; ok && held != except {
		return true
	}
	return slices.ContainsFunc(s.proposalLocked().Members,
		func(m Member) bool { return m.Name == name && m.Identity != except })
}

// FreeHost picks the lowest overlay slot in [1, limit] that neither the agreed
// membership nor the proposed one holds. A slot a departed member held comes
// free once the cluster has agreed the membership that gave it up, and not
// before: handing it out while the removal is only proposed would make an
// admission that every node which has not yet seen the removal refuses, since
// its own membership still has somebody at that slot.
func (s *Set) FreeHost(limit uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken := map[uint64]bool{}
	for h := range s.viewLocked().slots {
		taken[h] = true
	}
	for _, m := range s.proposalLocked().Members {
		taken[m.Host] = true
	}
	for h := uint64(1); h <= limit && h != 0; h++ {
		if !taken[h] {
			return h, nil
		}
	}
	return 0, ErrOverlayFull
}

// claimFor is the record that says what an identity a member has admitted is
// called and where it sits: of the admissions by members, the one from the
// smallest admitter, and at the same admitter the smallest signature. Nothing
// about it needs a date -- an identity has one admitter in practice, and where
// it has two the choice between them is arbitrary and only has to be the same
// everywhere.
func claimFor(by map[PublicKey][]Admission, signers map[PublicKey]Member, confirmed func(Admission) bool) (Admission, bool) {
	var best Admission
	found := false
	for admitter, as := range by {
		if _, ok := signers[admitter]; !ok {
			continue
		}
		for _, a := range as {
			if !confirmed(a) {
				continue
			}
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

// Revoked reports whether id has been put out of the cluster, or is on its way
// out because a member has revoked it. It is not the negation of Valid: an
// identity no record names is no member and has not been revoked either.
// Nothing admits a revoked identity back while the cluster still remembers it;
// once it is forgotten, the identity may be invited again.
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

// ByName returns the member with the given name, if one exists.
func (s *Set) ByName(name string) (Member, bool) {
	v := s.current()
	id, ok := v.byName[name]
	if !ok {
		return Member{}, false
	}
	return v.members[id], true
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

// Withdraws is who a revocation would take out: the members the cluster would
// stop naming with r in the set, its subject among them. It is the answer the
// records would give, asked before anything is signed, so that a node can see
// what it is about to do and refuse to do it.
//
// r is not verified and nothing is stored: only the identities it names and its
// revoker are read, so an unsigned record answers as well as a signed one.
func (s *Set) Withdraws(r Revocation) []Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.proposalLocked()
	trial := &Set{anchor: s.anchor, checkpoints: s.checkpoints, admissions: s.admissions, revocations: maps.Clone(s.revocations)}
	trial.revocations[r.Revoker] = append(slices.Clone(trial.revocations[r.Revoker]), r)
	after := trial.proposalLocked()
	var gone []Member
	for _, m := range before.Members {
		if _, still := after.Holds(m.Identity); !still {
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

// supersededRevocation reports whether every identity r names is already out.
// It asks the proposed membership, not the agreed one: a node that has been
// admitted and not yet agreed on can still be revoked, and that is what stops
// it becoming a member at all. Callers hold the write lock.
func (s *Set) supersededRevocation(r Revocation) bool {
	if s.anchor == nil {
		return false
	}
	p := s.proposalLocked()
	for _, id := range append([]PublicKey{r.Identity}, r.Disowned...) {
		if _, ok := p.Holds(id); ok {
			return false
		}
	}
	return true
}

// ErrOverlayFull is returned by FreeHost when every slot is taken.
var ErrOverlayFull = errors.New("no free overlay address")
