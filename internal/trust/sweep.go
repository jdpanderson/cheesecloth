package trust

import (
	"bytes"
	"log/slog"
	"maps"
)

// Sweeping: a revocation marks where its subject's records stop, and the ones
// above the mark decide nothing. They are dropped, so a set that would
// otherwise only grow gives back what a departure or a bad member cost it.
//
// A cut is not the end of the story, which is what makes this more than a
// delete. A revocation counts only while its own signer's records still stand,
// so one that is later shown to have been signed by a node that was already out
// stops counting, the cut it set rises, and the records it withdrew have to
// stand again — the node it revoked was never validly revoked. The number each
// swept record took is kept with its digest, so a peer offering the record
// again is taking it back rather than putting something new where it was.
//
// A node that cut itself loose is the exception: a self-revocation counts
// whatever else is held, so its mark can never rise and the records above it
// are gone for good, with nothing kept about them. That mark is also the only
// one the sweep works to for such a signer. A foreign cut below it says less
// than the node's own departure does, and the departure record is the one a cut
// never reaches, so sweeping to the lower mark would take the records in
// between and leave the departure stranded above a gap that nothing can step
// over: a node given the records would defer it for ever, and one that had
// restored its heads would refuse it as a number already spent. The cost is
// that the space between a lower foreign cut and a departed node's own mark is
// not reclaimed. A departed node's records are held to where it said they stop.
//
// Nothing here may change an answer. A record above a cut usually stands for
// nobody, here or on a node given the smaller set, but the cycle guard means
// "usually": a record that is withdrawn when the question is asked from outside
// can still be load-bearing inside another walk, where a revocation withdraws
// the chain its own signer stands on. So the sweep does not trust the
// reasoning. It works out what would go, asks the smaller set who its members
// are, and throws the records away only if the answer is the one this set is
// already giving.

// Sweep drops the records that a cut has withdrawn and reports how many went.
// It changes no answer about any member: what it would drop is checked against
// the membership before anything goes, and records that would change it are
// kept.
//
// It runs before every write of the state file, so it walks the records once
// and builds the membership at most twice: the answers this set is giving, and
// the ones the smaller set would give, which becomes this set's own if the drop
// goes ahead.
func (s *Set) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	marks := s.sweepMarks()
	if len(marks) == 0 {
		return 0 // nothing that counts has marked any signer
	}
	reduced, dropped := s.reduce(marks)
	if len(dropped) == 0 {
		return 0
	}
	before, after := s.viewLocked(), reduced.build()
	if !maps.EqualFunc(before.members, after.members, sameRecord) {
		// The records above the cut are what somebody's membership is resting
		// on, which only a revocation that withdraws the chain its own signer
		// stands on can do: judged from outside, the revocation counts and the
		// records are withdrawn; judged from within its own walk, the signer is
		// a member and they stand. Holding both is what keeps every node
		// answering the same way, so the records stay until the records
		// themselves settle it.
		slog.Warn("a revocation withdraws the chain its own signer stands on, so dropping the records "+
			"it cuts off would change who is a member of this cluster. They are kept instead. Revoke "+
			"that signer from a node it did not admit, or leave it: a revocation of the revoker settles "+
			"which of the two answers stands.",
			"records", len(dropped), "members", len(after.members), "was", len(before.members))
		return 0
	}

	s.admissions, s.revocations = reduced.admissions, reduced.revocations
	for _, d := range dropped {
		s.keepDigest(d)
	}
	s.view.Store(after) // the answers the records now held give, already built
	return len(dropped)
}

// sameRecord reports whether two records are the same one. A signature is
// unforgeable, so it identifies the record, and the identity it names is
// compared with it so that nothing rests on the signature alone.
func sameRecord(a, b Admission) bool {
	return a.Identity == b.Identity && a.Admitter == b.Admitter && bytes.Equal(a.Signature, b.Signature)
}

// mark is how far a sweep keeps one signer's records, and how far it keeps
// anything about the ones it drops.
type mark struct {
	keep uint64 // records at or below this number stay
	own  uint64 // where the signer cut its own sequence; above it nothing can stand again
}

// swept is a record the sweep would drop: the number it took of its signer's
// sequence, and what it was, so the number stays spent and the record can come
// back if the cut that withdrew it rises.
type swept struct {
	signer  PublicKey
	seq     uint64
	sig     []byte
	forever bool // above the signer's own departure: nothing is kept about it
}

// sweepMarks is how far each signer's records are worth holding, for the
// signers something has marked. Callers hold the lock.
func (s *Set) sweepMarks() map[PublicKey]mark {
	marks := map[PublicKey]mark{}
	for id := range s.revocations {
		keep := s.cut(id, map[question]bool{})
		own, last, left := s.departure(id)
		if left {
			// its own mark, never a foreign one below it, and never below the
			// departure record itself: what it leaves has to be a run of
			// numbers a set given the records can take in order
			keep = max(own, last-1)
		}
		if keep == noCut {
			continue // nothing that counts has marked this signer
		}
		marks[id] = mark{keep: keep, own: own}
	}
	return marks
}

// departure is the mark id put on its own sequence when it left and the number
// the record that says so took, or left false if it has not. A self-revocation
// counts whatever else is held, so nothing can raise that mark. Callers hold
// the lock.
func (s *Set) departure(id PublicKey) (own, last uint64, left bool) {
	own = noCut
	for _, r := range s.revocations[id][id] {
		// the lowest mark of them decides, and the records have to reach the
		// highest-numbered of them for a node given the set to take it
		own, last, left = min(own, r.UpTo), max(last, r.Seq), true
	}
	return own, last, left
}

// reduce is the records this set would hold with everything above the marks
// dropped, as a set of its own, and the records that would go. Nothing here
// touches this set: the answers the smaller one gives are compared with this
// one's before anything is thrown away.
//
// The set it returns has only what deciding membership reads — the root and the
// two record maps — since that is all it is for. Callers hold the lock.
func (s *Set) reduce(marks map[PublicKey]mark) (*Set, []swept) {
	out := &Set{
		root:        s.root,
		admissions:  make(map[PublicKey]map[PublicKey][]Admission, len(s.admissions)),
		revocations: make(map[PublicKey]map[PublicKey][]Revocation, len(s.revocations)),
	}
	var dropped []swept
	drop := func(signer PublicKey, seq uint64, sig []byte) {
		dropped = append(dropped, swept{signer: signer, seq: seq, sig: sig, forever: seq > marks[signer].own})
	}

	for identity, by := range s.admissions {
		kept := make(map[PublicKey][]Admission, len(by))
		for admitter, as := range by {
			m, marked := marks[admitter]
			if !marked {
				kept[admitter] = as
				continue
			}
			stands := make([]Admission, 0, len(as))
			for _, a := range as {
				if a.Seq <= m.keep {
					stands = append(stands, a)
					continue
				}
				drop(admitter, a.Seq, a.Signature)
			}
			if len(stands) > 0 {
				kept[admitter] = stands
			}
		}
		if len(kept) > 0 {
			out.admissions[identity] = kept
		}
	}

	for identity, by := range s.revocations {
		kept := make(map[PublicKey][]Revocation, len(by))
		for revoker, revs := range by {
			m, marked := marks[revoker]
			stands := make([]Revocation, 0, len(revs))
			for _, r := range revs {
				switch {
				case !marked || r.Seq <= m.keep:
				case identity == revoker:
					// A node's own departure counts whatever else is held, so
					// the record stands however the cut falls; dropping it
					// would let the node back in. It is the one record a cut
					// does not reach.
				default:
					drop(revoker, r.Seq, r.Signature)
					continue
				}
				stands = append(stands, r)
			}
			if len(stands) > 0 {
				kept[revoker] = stands
			}
		}
		if len(kept) > 0 {
			out.revocations[identity] = kept
		}
	}
	return out, dropped
}

// keepDigest remembers what took the number a dropped record had, so a peer
// that has not swept can hand the record back when the cut rises. Above the
// signer's own departure the cut can never rise, so nothing is kept and the
// number stays spent by the head alone. Callers hold the write lock.
func (s *Set) keepDigest(d swept) {
	if d.forever {
		return
	}
	st := s.signers[d.signer]
	if st.dropped == nil {
		st.dropped = map[uint64][]byte{}
	}
	st.dropped[d.seq] = digest(d.sig)
	s.signers[d.signer] = st
}
