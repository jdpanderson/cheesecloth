package trust

import (
	"log/slog"
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
// are gone for good, with nothing kept about them.

// Sweep drops the records that a cut has withdrawn and reports how many went.
// It changes no answer about any member: a record above a cut is one that
// stands for nobody, here or on a node given the smaller set.
func (s *Set) Sweep() int {
	before := len(s.current().members)

	s.mu.Lock()
	dropped := 0
	for id := range s.revocations {
		visiting := map[question]bool{}
		cut := s.cut(id, visiting)
		if cut == noCut {
			continue // nothing that counts has marked this signer
		}
		dropped += s.dropAbove(id, cut, s.ownCut(id))
	}
	if dropped > 0 {
		s.forget()
	}
	s.mu.Unlock()

	if dropped == 0 {
		return 0
	}
	// A dropped record stood for nobody, so the membership cannot have moved.
	// Saying so costs one comparison and is worth it: this is the one place
	// that throws records away.
	if after := len(s.current().members); after != before {
		slog.Error("sweeping records that no longer stand changed the membership, which it cannot do. "+
			"This is a bug in cheesecloth; the records on this node may no longer agree with its peers.",
			"members", after, "was", before, "dropped", dropped)
	}
	return dropped
}

// ownCut is the mark id put on its own sequence when it left, or noCut if it
// has not. A self-revocation counts whatever else is held, so nothing can raise
// it. Callers hold the lock.
func (s *Set) ownCut(id PublicKey) uint64 {
	if r, held := s.revocations[id][id]; held {
		return r.UpTo
	}
	return noCut
}

// dropAbove removes the records signer signed above cut and reports how many
// went. What it keeps about each one is its digest, so the record can be taken
// back if the cut rises; above own, where the signer cut itself loose, the cut
// cannot rise and nothing is kept. Callers hold the write lock.
func (s *Set) dropAbove(signer PublicKey, cut, own uint64) int {
	dropped := 0
	drop := func(seq uint64, sig []byte) {
		dropped++
		if seq > own {
			return // the signer's own mark is above it: it can never stand again
		}
		st := s.signers[signer]
		if st.dropped == nil {
			st.dropped = map[uint64][]byte{}
		}
		st.dropped[seq] = digest(sig)
		s.signers[signer] = st
	}

	for identity, by := range s.admissions {
		kept := by[signer][:0]
		for _, a := range by[signer] {
			if a.Seq > cut {
				drop(a.Seq, a.Signature)
				continue
			}
			kept = append(kept, a)
		}
		if len(kept) == 0 {
			delete(by, signer)
		} else {
			by[signer] = kept
		}
		if len(by) == 0 {
			delete(s.admissions, identity)
		}
	}

	for identity, by := range s.revocations {
		r, held := by[signer]
		if !held || r.Seq <= cut {
			continue
		}
		if identity == signer {
			// A node's own departure counts whatever else is held, so the
			// record stands however the cut falls; dropping it would let the
			// node back in. It is the one record a cut does not reach.
			continue
		}
		drop(r.Seq, r.Signature)
		delete(by, signer)
		if len(by) == 0 {
			delete(s.revocations, identity)
		}
	}
	return dropped
}
