package trust

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/wire"
)

// Records is the wire and file form of a Set's contents.
type Records struct {
	Admissions  []Admission  `json:"admissions"`
	Revocations []Revocation `json:"revocations"`
}

// Admission says that Admitter vouches for Identity as a member and assigns
// it Host, its slot in the overlay network (the host part of its address,
// never 0). The root admits itself (Admitter == Identity) and takes slot 1.
//
// Seq is the admitter's own counter, which every record it signs advances.
// Ordering one signer's records by it needs no clock, so a signer whose clock
// jumps cannot reorder what it said.
//
// IssuedAt is what orders records across signers, where no counter can. Nothing
// about membership reads it: who is a member, what a revocation withdraws and
// which records stand are all decided from the counters and the marks, so a
// forged date cannot put a node in the cluster or take one out. What it decides
// is which of two records that both stand is preferred — the later of two
// admitters' records for one identity, and the earlier of two admissions
// contesting a name or an overlay slot. Both are choices between legitimate
// records where the alternative is an arbitrary one; see laterClaim and
// strongerClaim. A wrong clock therefore costs a node a re-enrolment, never its
// membership, and the bounds in set.go keep a grossly wrong one out.
type Admission struct {
	Identity  PublicKey `json:"identity"`
	Name      string    `json:"name"`
	Host      uint64    `json:"host"`
	Admitter  PublicKey `json:"admitter"`
	Seq       uint64    `json:"seq"`      // the admitter's counter; from 1
	IssuedAt  int64     `json:"issuedAt"` // unix seconds; orders records across signers, see above
	Signature []byte    `json:"signature"`
}

const (
	// rootHost is the overlay slot the root assigns itself.
	rootHost = 1
	// rootSeq is the first number any signer's counter takes.
	rootSeq = 1
)

// Revocation says that Revoker withdraws Identity's membership, and marks
// where its records stop: those at Seq up to and including UpTo still count,
// and everything above is withdrawn. Seq is the revoker's own counter.
//
// A number rather than a list of records is what a set takes in sequence order
// can afford. The numbers a signer has used are its own to choose, so one that
// left gaps below the mark could sign into them afterwards; there are no gaps
// to leave, because a record is taken only once the one before it is.
type Revocation struct {
	Identity PublicKey `json:"identity"`
	Revoker  PublicKey `json:"revoker"`
	Seq      uint64    `json:"seq"`
	// UpTo is the last of Identity's numbers whose record still counts. Zero
	// withdraws everything, which is what revoking a node that has signed
	// nothing does.
	UpTo      uint64 `json:"upTo,omitempty"`
	IssuedAt  int64  `json:"issuedAt"`
	Signature []byte `json:"signature"`
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
	return wire.Canonical(revocationDomain, r.Identity[:], r.Revoker[:], u64(r.Seq), u64(r.UpTo), i64(r.IssuedAt))
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
// record, letting identity's records up to and including upTo stand.
func Revoke(revoker *Identity, identity PublicKey, seq, upTo uint64, now time.Time) Revocation {
	r := Revocation{Identity: identity, Revoker: revoker.Public(), Seq: seq, UpTo: upTo, IssuedAt: now.Unix()}
	r.Signature = revoker.Sign(r.signedBytes())
	return r
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
