package trust

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/wire"
)

// Records is the wire and file form of a Set's contents.
type Records struct {
	Admissions  []Admission  `json:"admissions"`
	Revocations []Revocation `json:"revocations"`
	Prunes      []Prune      `json:"prunes,omitempty"`
}

// Admission says that Admitter vouches for Identity as a member and assigns
// it Host, its slot in the overlay network (the host part of its address,
// never 0). The root admits itself (Admitter == Identity) and takes slot 1.
//
// Seq is the admitter's own counter, which every record it signs advances.
// Ordering one signer's records by it needs no clock, so a signer whose clock
// jumps cannot reorder what it said.
type Admission struct {
	Identity  PublicKey `json:"identity"`
	Name      string    `json:"name"`
	Host      uint64    `json:"host"`
	Admitter  PublicKey `json:"admitter"`
	Seq       uint64    `json:"seq"`      // the admitter's counter; from 1
	IssuedAt  int64     `json:"issuedAt"` // unix seconds, advisory
	Signature []byte    `json:"signature"`
}

const (
	// rootHost is the overlay slot the root assigns itself.
	rootHost = 1
	// rootSeq is the first number any signer's counter takes.
	rootSeq = 1
)

// Revocation says that Revoker withdraws Identity's membership. It withdraws
// everything that identity ever signed, except the records Keeps names: the
// ones the revoker had already seen, which the cluster may be relying on.
//
// Naming the records is what makes a revocation final. A range of sequence
// numbers would not: the numbers a signer has used are the signer's to choose,
// so one that left gaps under the range could go on signing into them after it
// was out. Seq is the revoker's own counter.
type Revocation struct {
	Identity PublicKey `json:"identity"`
	Revoker  PublicKey `json:"revoker"`
	Seq      uint64    `json:"seq"`
	// Keeps are the signatures of Identity's records that still count, sorted
	// and without repeats. Empty withdraws everything, which is what revoking a
	// node that has signed nothing does.
	Keeps     [][]byte `json:"keeps,omitempty"`
	IssuedAt  int64    `json:"issuedAt"`
	Signature []byte   `json:"signature"`
}

// Prune says that Pruner removes Identities from the records: identities that
// are no longer members and that nothing a member relies on runs through, so
// dropping every record naming them changes no answer about any member. Seq is
// the pruner's own counter.
//
// A prune is a request, not an instruction. Every node derives for itself which
// identities may go (see Set.Prunable) and removes only those, so a node still
// holding a record that makes one of them a member keeps it.
type Prune struct {
	Identities []PublicKey `json:"identities"` // sorted, without repeats
	Pruner     PublicKey   `json:"pruner"`
	Seq        uint64      `json:"seq"`
	IssuedAt   int64       `json:"issuedAt"`
	Signature  []byte      `json:"signature"`
}

const (
	admissionDomain  = "cheesecloth/admission/v1"
	revocationDomain = "cheesecloth/revocation/v1"
	pruneDomain      = "cheesecloth/prune/v1"
	metaDomain       = "cheesecloth/meta/v1"
)

func i64(v int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(v)) }

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func (a *Admission) signedBytes() []byte {
	return wire.Canonical(admissionDomain, a.Identity[:], []byte(a.Name), u64(a.Host), a.Admitter[:], u64(a.Seq), i64(a.IssuedAt))
}

// signedBytes counts the kept records before listing them, so that no two lists
// of different lengths can be read out of one signature.
func (r *Revocation) signedBytes() []byte {
	fields := [][]byte{r.Identity[:], r.Revoker[:], u64(r.Seq), u64(uint64(len(r.Keeps)))}
	fields = append(fields, r.Keeps...)
	fields = append(fields, i64(r.IssuedAt))
	return wire.Canonical(revocationDomain, fields...)
}

// signedBytes counts the identities before listing them, so that no two lists
// of different lengths can be read out of one signature.
func (p *Prune) signedBytes() []byte {
	fields := [][]byte{u64(uint64(len(p.Identities)))}
	for i := range p.Identities {
		fields = append(fields, p.Identities[i][:])
	}
	fields = append(fields, p.Pruner[:], u64(p.Seq), i64(p.IssuedAt))
	return wire.Canonical(pruneDomain, fields...)
}

// Admit creates an admission of (identity, name) at overlay slot host, signed
// by admitter as its seq'th record.
func Admit(admitter *Identity, identity PublicKey, name string, host, seq uint64, now time.Time) Admission {
	a := Admission{Identity: identity, Name: name, Host: host, Admitter: admitter.Public(), Seq: seq, IssuedAt: now.Unix()}
	a.Signature = admitter.Sign(a.signedBytes())
	return a
}

// SelfAdmit creates the root record for id, which is the first thing it signs.
func SelfAdmit(id *Identity, name string, now time.Time) Admission {
	return Admit(id, id.Public(), name, rootHost, rootSeq, now)
}

// Revoke creates a revocation of identity signed by revoker as its seq'th
// record, letting identity's records signed with keeps stand.
func Revoke(revoker *Identity, identity PublicKey, seq uint64, keeps [][]byte, now time.Time) Revocation {
	r := Revocation{Identity: identity, Revoker: revoker.Public(), Seq: seq, Keeps: sortedSignatures(keeps), IssuedAt: now.Unix()}
	r.Signature = revoker.Sign(r.signedBytes())
	return r
}

// sortedSignatures is signatures in one order and without repeats, so that two
// revokers holding the same records sign the same bytes.
func sortedSignatures(sigs [][]byte) [][]byte {
	return slices.CompactFunc(slices.SortedFunc(slices.Values(sigs), bytes.Compare), bytes.Equal)
}

// keeps reports whether the revocation lets the record signed with sig stand.
// Validate has held Keeps to one order, so it can be searched.
func (r *Revocation) keeps(sig []byte) bool {
	_, found := slices.BinarySearchFunc(r.Keeps, sig, bytes.Compare)
	return found
}

// SignPrune creates a prune of identities signed by pruner as its seq'th
// record. The list is sorted and stripped of repeats, so that two nodes
// pruning the same identities sign the same bytes.
func SignPrune(pruner *Identity, identities []PublicKey, seq uint64, now time.Time) Prune {
	ids := slices.SortedFunc(slices.Values(identities), func(a, b PublicKey) int {
		return bytes.Compare(a[:], b[:])
	})
	p := Prune{Identities: slices.Compact(ids), Pruner: pruner.Public(), Seq: seq, IssuedAt: now.Unix()}
	p.Signature = pruner.Sign(p.signedBytes())
	return p
}

// Validate checks the record's fields and that the admitter signed it.
func (a *Admission) Validate() error {
	if err := CheckName(a.Name); err != nil {
		return fmt.Errorf("admission: %w", err)
	}
	if a.Host == 0 {
		return errors.New("admission without an overlay slot")
	}
	if a.Seq == 0 {
		return errors.New("admission without a sequence number")
	}
	if !Verify(a.Admitter, a.signedBytes(), a.Signature) {
		return errors.New("admission signature does not verify")
	}
	return nil
}

// Validate checks the record's fields and that the revoker signed it. The kept
// records are held to one order, so that a revocation cannot be reshuffled into
// a second one saying the same thing, and so that keeps can search them.
func (r *Revocation) Validate() error {
	if r.Seq == 0 {
		return errors.New("revocation without a sequence number")
	}
	for i, sig := range r.Keeps {
		if len(sig) != ed25519.SignatureSize {
			return errors.New("revocation keeps something that is not a signature")
		}
		if i > 0 && bytes.Compare(r.Keeps[i-1], sig) >= 0 {
			return errors.New("revocation's kept records are not sorted, or repeat")
		}
	}
	if !Verify(r.Revoker, r.signedBytes(), r.Signature) {
		return errors.New("revocation signature does not verify")
	}
	return nil
}

// Validate checks the record's fields and that the pruner signed it. The list
// is held to one order so that a record cannot be reshuffled into a second one
// saying the same thing, and a pruner may not name itself: a prune only ever
// names identities that are no longer members, and one signed by a member.
func (p *Prune) Validate() error {
	if p.Seq == 0 {
		return errors.New("prune without a sequence number")
	}
	if len(p.Identities) == 0 {
		return errors.New("prune without any identities")
	}
	for i, id := range p.Identities {
		if id == p.Pruner {
			return errors.New("prune names the node that signed it")
		}
		if i > 0 && bytes.Compare(p.Identities[i-1][:], id[:]) >= 0 {
			return errors.New("prune identities are not sorted, or repeat")
		}
	}
	if !Verify(p.Pruner, p.signedBytes(), p.Signature) {
		return errors.New("prune signature does not verify")
	}
	return nil
}

// MetaDigest is what a node signs to bind its (ephemeral) wireguard key,
// overlay address and the extra networks it routes to its identity in
// gossiped metadata.
func MetaDigest(name string, overlay netip.Addr, wgPubKey string, allowedIPs []netip.Prefix) []byte {
	fields := [][]byte{[]byte(name), overlay.AsSlice(), []byte(wgPubKey)}
	for _, p := range allowedIPs {
		fields = append(fields, append(p.Addr().AsSlice(), byte(p.Bits())))
	}
	return wire.Canonical(metaDomain, fields...)
}
