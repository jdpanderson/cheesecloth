package trust

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/wire"
)

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

// Revocation says that Revoker withdraws Identity's membership. Mark is the
// highest sequence number the revoker had seen from Identity, so records the
// revoked node signs afterwards are recognisable however they are dated: only
// those at or below it still count. Seq is the revoker's own counter.
type Revocation struct {
	Identity  PublicKey `json:"identity"`
	Revoker   PublicKey `json:"revoker"`
	Seq       uint64    `json:"seq"`
	Mark      uint64    `json:"mark"`
	IssuedAt  int64     `json:"issuedAt"`
	Signature []byte    `json:"signature"`
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

func (r *Revocation) signedBytes() []byte {
	return wire.Canonical(revocationDomain, r.Identity[:], r.Revoker[:], u64(r.Seq), u64(r.Mark), i64(r.IssuedAt))
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
// record, admitting identity's records up to mark.
func Revoke(revoker *Identity, identity PublicKey, seq, mark uint64, now time.Time) Revocation {
	r := Revocation{Identity: identity, Revoker: revoker.Public(), Seq: seq, Mark: mark, IssuedAt: now.Unix()}
	r.Signature = revoker.Sign(r.signedBytes())
	return r
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

// Validate checks the record's fields and that the revoker signed it.
func (r *Revocation) Validate() error {
	if r.Seq == 0 {
		return errors.New("revocation without a sequence number")
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
