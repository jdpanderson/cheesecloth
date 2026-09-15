package trust

import (
	"bytes"
	"cmp"
)

// The validity rule: an identity is a member if it holds an admission by the
// root or by an identity that was itself a member when it signed, and no
// revocation that counts has withdrawn it. It is evaluated from the records
// at query time, walking each chain of admitters back to the root, with the
// cached answers kept in Set.members.

// Valid reports whether id is currently a member: not revoked by itself or by
// a member, and holding at least one admission by the root or by an identity
// that was a member at the time it signed. The root needs no admission.
func (s *Set) Valid(id PublicKey) bool {
	_, ok := s.current().members[id]
	return ok
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

// validFor reports whether id was a member when it signed the record with
// signature sig; a nil sig asks about id now. A revocation withdraws every
// record of its subject but the ones it names, so an admission stays valid if
// its admitter was a member when it signed and the revoker had seen that
// admission. A member may always revoke itself: only the holder of that key can
// sign such a record, and it takes nobody else out. An identity is a member if
// any one of its admissions holds, so a record by an admitter nobody believes
// neither makes it a member nor stops another record from doing so.
//
// Asking whether a revoker was a member reaches the identity it revokes again,
// at the earlier record that admitted it, so the cycle guard tracks the record
// as well as the identity. A record's signature never changes, so the questions
// the recursion can ask are finite and it always ends.
//
// The root differs only in needing no admitter. It is revoked by the same rule,
// and judging a revocation of the root reaches the root again at a record the
// revocation keeps, so what it signed while it was a member stays valid after it
// leaves.
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
	a, ok := s.current().effective[id]
	return a, ok
}
