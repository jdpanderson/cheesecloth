package trust

import (
	"encoding/binary"
	"errors"
	"net/netip"
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

const (
	admissionDomain  = "cheesecloth/admission/v1"
	revocationDomain = "cheesecloth/revocation/v1"
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

// Validate checks the record's fields and that the admitter signed it.
func (a *Admission) Validate() error {
	if a.Name == "" {
		return errors.New("admission without a name")
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
