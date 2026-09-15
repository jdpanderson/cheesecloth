package trust

import (
	"bytes"
	"cmp"
	"math"
)

// The validity rule. An identity is a member if it holds an admission that
// stands, and no revocation that counts has put it out:
//
//	stands(a) = a is the root's own record, or
//	            a.Seq <= cut(a.Admitter) && chain(a.Admitter)
//	chain(X)  = X is the root, or some admission of X stands
//	cut(A)    = the lowest UpTo of the revocations of A that count
//	counts(r) = r.Revoker is r.Identity, or r.Seq <= cut(r.Revoker) && chain(r.Revoker)
//	member(X) = some admission of X stands, and no revocation of X counts
//
// stands is vouched below, and member is what build in view.go asks of each
// identity the records name. Nothing reads a clock: a signer's own numbers
// order its records, and a cut says where they stop.
//
// The cycle guard makes where a question is asked from part of its answer: a
// chain that can only be justified through the identity being asked about
// counts for nothing, so chain re-entered from within its own walk is false and
// cut re-entered is noCut. Membership is therefore asked once, from an empty
// stack, and asked as one question: the record that stands is the record the
// answer is made of. Asking chain(X) at the top and then which of X's records
// vouches for it would be two walks from two stacks, which could disagree —
// where a revocation withdraws the chain its own signer stands on, chain(X)
// reached through that revocation's own walk is true while nothing vouches for
// X from the outside. One walk cannot disagree with itself, whatever the
// records are, which is what makes an answer safe to drop records against; see
// sweep.go.

// noCut is the cut on a signer nothing has revoked: every number it reaches.
const noCut = uint64(math.MaxUint64)

// question is one thing the recursion has set out to answer about an identity.
// Two are asked — whether it reaches the root, and where its records stop — and
// each can reach the other, so both belong in the guard.
type question struct {
	id  PublicKey
	cut bool // where its records stop, rather than whether it reaches the root
}

// Valid reports whether id is currently a member.
func (s *Set) Valid(id PublicKey) bool {
	_, ok := s.current().members[id]
	return ok
}

// chain reports whether id reaches the root through admissions that stand. It
// says nothing about whether id has since been revoked, and it is a step in
// judging somebody else rather than the question the set publishes: membership
// is decided by effective and revoked together, in build.
//
// Judging a revoker reaches the identity it revokes again, and a record that
// can only be justified through itself must not count, which returning false
// on re-entry settles. Callers hold the lock.
func (s *Set) chain(id PublicKey, visiting map[question]bool) bool {
	if id == s.root {
		return true // the root needs no admission
	}
	q := question{id: id}
	if visiting[q] {
		return false
	}
	visiting[q] = true
	defer delete(visiting, q)

	for admitter, as := range s.admissions[id] {
		if admitter == id {
			// Nothing reaches here: AddAdmission refuses a self-signed record
			// from anyone but the root, and the root is answered above. It
			// stays so that the rule holds where membership is decided, rather
			// than only where records are taken in.
			continue
		}
		cut := s.cut(admitter, visiting)
		for _, a := range as {
			if a.Seq <= cut && s.chain(admitter, visiting) {
				return true
			}
		}
	}
	return false
}

// cut is the last of id's numbers whose record still stands: the lowest mark
// any revocation that counts has put on it.
//
// A cut is not one-way. Taking a further revocation of id lowers it, but a
// revocation that stops counting — because its own signer is shown to have been
// out when it signed — raises it again, and the records it had withdrawn stand
// once more. That is not a revocation being undone: it never counted, so the
// node it named was never validly revoked. It is why a swept record has to be
// able to come back; see sweep.go. Callers hold the lock.
func (s *Set) cut(id PublicKey, visiting map[question]bool) uint64 {
	q := question{id: id, cut: true}
	if visiting[q] {
		return noCut // a cut that can only be justified through itself is none
	}
	visiting[q] = true
	defer delete(visiting, q)

	cut := noCut
	for _, r := range s.revocations[id] {
		if s.counts(r, visiting) {
			cut = min(cut, r.UpTo)
		}
	}
	return cut
}

// counts reports whether a revocation carries weight: its subject may always
// revoke itself, and anyone else must have been a member when it signed, which
// its own cut and chain answer.
//
// The cut on the revoker is what stops a node that has been revoked from going
// on revoking: its own revocation put a mark on its sequence, and everything it
// signs afterwards is above it. That is the same mark a later revocation of the
// revoker would use to withdraw a revocation it had already issued, so a
// revocation is not permanent; see docs/membership.md. Callers hold the lock.
func (s *Set) counts(r Revocation, visiting map[question]bool) bool {
	if r.Revoker == r.Identity {
		return true // only the holder of that key can sign it, and it takes nobody else out
	}
	return r.Seq <= s.cut(r.Revoker, visiting) && s.chain(r.Revoker, visiting)
}

// revoked reports whether a revocation that counts has put id out. Callers hold
// the lock.
func (s *Set) revoked(id PublicKey) bool {
	for _, r := range s.revocations[id] {
		if s.counts(r, map[question]bool{}) {
			return true
		}
	}
	return false
}

// vouched reports whether a is a record that can make its identity a member:
// the root's own, or one that stands. Callers hold the lock.
func (s *Set) vouched(a Admission) bool {
	if a.Admitter == a.Identity {
		return a.Identity == s.root
	}
	visiting := map[question]bool{}
	return a.Seq <= s.cut(a.Admitter, visiting) && s.chain(a.Admitter, visiting)
}

// laterClaim reports whether a is the record to prefer over b as the one that
// decides an identity's name and slot, where the two are by different
// admitters: the later one, and at the same time the one from the smaller
// admitter, so every node prefers the same record. Between admitters the date
// is all there is; one admitter's own records are separated by its counter.
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
	a, ok := s.current().effective[id]
	return a, ok
}
