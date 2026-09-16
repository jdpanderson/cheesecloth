package trust

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/wire"
)

// Records is the wire and file form of a Set's contents: the checkpoints that
// state the membership, and the admissions and revocations that have changed it
// since the newest of them.
type Records struct {
	Checkpoints []Checkpoint `json:"checkpoints,omitempty"`
	Admissions  []Admission  `json:"admissions"`
	Revocations []Revocation `json:"revocations"`
}

// Digest identifies a checkpoint by its contents.
type Digest [sha256.Size]byte

// Member is one entry in a checkpoint: an identity, the name it goes by and the
// overlay slot it holds. A checkpoint says nothing about how it got there,
// which is what lets everything that put it there be thrown away.
type Member struct {
	Identity PublicKey `json:"identity"`
	Name     string    `json:"name"`
	Host     uint64    `json:"host"`
}

// Checkpoint is a statement of the whole membership, carrying the signatures of
// the nodes that have attested to it. It ratifies once Quorum of the members it
// follows have signed, and from then on membership is read from it rather than
// derived from the records that led to it.
//
// Depth orders the checkpoints and Prev names the one this follows, so a node
// that has been away can walk from a checkpoint it recognises to the present.
// Attestations are not part of the digest: two nodes may hold the same
// checkpoint with different signatures collected, and merging takes the union.
type Checkpoint struct {
	Depth        uint64        `json:"depth"`
	Prev         Digest        `json:"prev,omitzero"` // zero at depth 1, which follows the root's own record
	Quorum       QuorumRule    `json:"quorum"`
	Members      []Member      `json:"members"`
	Removed      []PublicKey   `json:"removed,omitempty"` // identities this checkpoint takes out
	Attestations []Attestation `json:"attestations"`
}

// Attestation is one member's signature over a checkpoint's digest.
type Attestation struct {
	Signer    PublicKey `json:"signer"`
	Signature []byte    `json:"signature"`
}

// QuorumRule says how many members must attest to a checkpoint before it
// ratifies: "majority" (N/2+1), "half" (N/2), or a decimal count.
//
// It is a synchronization knob, not a security one. It decides how many nodes
// must agree on the membership before history is discarded, never how many must
// agree before the membership may change: any member still admits and revokes
// on its own. See docs/checkpoints.md.
type QuorumRule string

const (
	// QuorumMajority is the default and the only value that cannot fork: two
	// majorities of one membership always have a member in common.
	QuorumMajority QuorumRule = "majority"
	// QuorumHalf is what an operator may choose instead, knowing that a cluster
	// split down the middle can ratify two different checkpoints.
	QuorumHalf QuorumRule = "half"
)

// Size is how many attestations ratify a checkpoint over a membership of n.
func (q QuorumRule) Size(n int) int {
	switch q {
	case QuorumMajority:
		return n/2 + 1
	case QuorumHalf:
		if n < 2 {
			return 1
		}
		return n / 2
	}
	fixed, err := strconv.Atoi(string(q))
	if err != nil || fixed < 1 {
		return n/2 + 1 // an unreadable rule is the safe one; Validate refuses it on the way in
	}
	return min(fixed, n)
}

// Check reports whether the rule is one a cluster may be founded with.
func (q QuorumRule) Check() error {
	switch q {
	case QuorumMajority, QuorumHalf:
		return nil
	case "":
		return errors.New("quorum rule is empty")
	}
	if n, err := strconv.Atoi(string(q)); err != nil || n < 1 {
		return fmt.Errorf("quorum %q is not %q, %q or a count of one or more", string(q), QuorumMajority, QuorumHalf)
	}
	return nil
}

// Admission says that Admitter vouches for Identity as a member and assigns it
// Host, its slot in the overlay network (the host part of its address, never
// 0). The root admits itself (Admitter == Identity) and takes slot 1; that
// record carries the cluster's quorum rule and is the only one that does.
//
// An admission decides anything only while its admitter is a member. The
// members an admitter vouched for before it was revoked keep their place
// because a ratified checkpoint names them, not because the record that
// admitted them still stands.
//
// IssuedAt orders records across signers, where nothing else can. Nothing about
// membership reads it: who is a member is the checkpoint plus what members have
// signed since. What it decides is which of two records that both stand is
// preferred -- the later of two admitters' records for one identity, and the
// earlier of two admissions contesting a name or an overlay slot. Both are
// choices between legitimate records where the alternative is an arbitrary one;
// see laterClaim and strongerClaim. A wrong clock therefore costs a node a
// re-enrolment, never its membership.
type Admission struct {
	Identity  PublicKey  `json:"identity"`
	Name      string     `json:"name"`
	Host      uint64     `json:"host"`
	Admitter  PublicKey  `json:"admitter"`
	Quorum    QuorumRule `json:"quorum,omitempty"` // the root's own record only; see Checkpoint
	IssuedAt  int64      `json:"issuedAt"`         // unix seconds; orders records across signers, see above
	Signature []byte     `json:"signature"`
}

// rootHost is the overlay slot the root assigns itself.
const rootHost = 1

// Revocation says that Revoker withdraws Identity's membership, and Disowned
// with it. Everything named goes out entirely: the identity, the name and the
// overlay slot, and once a checkpoint has ratified it, the records too.
//
// Disowned carries the identities themselves rather than a rule for finding
// them. A record that said "and everything this node admitted" would have each
// node work the list out from its own records, and nodes that are behind would
// work out different lists, so no two of them would attest to the same
// membership and no checkpoint could ever form.
type Revocation struct {
	Identity  PublicKey   `json:"identity"`
	Revoker   PublicKey   `json:"revoker"`
	Disowned  []PublicKey `json:"disowned,omitempty"`
	IssuedAt  int64       `json:"issuedAt"`
	Signature []byte      `json:"signature"`
}

const (
	admissionDomain  = "cheesecloth/admission/v2"
	revocationDomain = "cheesecloth/revocation/v2"
	checkpointDomain = "cheesecloth/checkpoint/v1"
	attestDomain     = "cheesecloth/attestation/v1"
	metaDomain       = "cheesecloth/meta/v1"
)

func i64(v int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(v)) }

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func (a *Admission) signedBytes() []byte {
	return wire.Canonical(admissionDomain, a.Identity[:], []byte(a.Name), u64(a.Host),
		a.Admitter[:], []byte(a.Quorum), i64(a.IssuedAt))
}

func (r *Revocation) signedBytes() []byte {
	fields := [][]byte{r.Identity[:], r.Revoker[:], i64(r.IssuedAt)}
	for _, d := range r.Disowned {
		fields = append(fields, d[:])
	}
	return wire.Canonical(revocationDomain, fields...)
}

// Digest identifies a checkpoint by everything in it but the attestations, so
// that signatures collected separately are signatures over the same statement.
func (c *Checkpoint) Digest() Digest {
	fields := [][]byte{u64(c.Depth), c.Prev[:], []byte(c.Quorum)}
	for _, m := range c.Members {
		fields = append(fields, m.Identity[:], []byte(m.Name), u64(m.Host))
	}
	for _, r := range c.Removed {
		fields = append(fields, r[:])
	}
	return sha256.Sum256(wire.Canonical(checkpointDomain, fields...))
}

// attestedBytes is what an attestation signs: the digest under its own domain,
// so a signature over a checkpoint can be nothing else.
func attestedBytes(d Digest) []byte { return wire.Canonical(attestDomain, d[:]) }

// Admit creates an admission of (identity, name) at overlay slot host, signed
// by admitter.
func Admit(admitter *Identity, identity PublicKey, name string, host uint64, now time.Time) Admission {
	a := Admission{Identity: identity, Name: name, Host: host, Admitter: admitter.Public(), IssuedAt: now.Unix()}
	a.Signature = admitter.Sign(a.signedBytes())
	return a
}

// SelfAdmit creates the root record for id, which is the first thing it signs
// and the only one that carries the cluster's quorum rule.
func SelfAdmit(id *Identity, name string, quorum QuorumRule, now time.Time) Admission {
	a := Admission{Identity: id.Public(), Name: name, Host: rootHost, Admitter: id.Public(), Quorum: quorum, IssuedAt: now.Unix()}
	a.Signature = id.Sign(a.signedBytes())
	return a
}

// Revoke creates a revocation of identity, and of disowned along with it,
// signed by revoker.
func Revoke(revoker *Identity, identity PublicKey, disowned []PublicKey, now time.Time) Revocation {
	r := Revocation{Identity: identity, Revoker: revoker.Public(), Disowned: canonicalKeys(disowned), IssuedAt: now.Unix()}
	r.Signature = revoker.Sign(r.signedBytes())
	return r
}

// canonicalKeys is keys in a fixed order with duplicates removed, so that two
// nodes given the same set sign and compare the same bytes.
func canonicalKeys(keys []PublicKey) []PublicKey {
	if len(keys) == 0 {
		return nil
	}
	out := slices.Clone(keys)
	slices.SortFunc(out, func(a, b PublicKey) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(out)
}

// Propose creates the checkpoint that states members, following prev at depth,
// attested by the node proposing it. Every node reaching the same membership
// produces the same digest, so their attestations accumulate on one record.
func Propose(id *Identity, depth uint64, prev Digest, quorum QuorumRule, members []Member, removed []PublicKey) Checkpoint {
	c := Checkpoint{Depth: depth, Prev: prev, Quorum: quorum, Members: canonicalMembers(members), Removed: canonicalKeys(removed)}
	c.Attestations = []Attestation{Attest(id, c.Digest())}
	return c
}

// Attest signs a checkpoint's digest.
func Attest(id *Identity, d Digest) Attestation {
	return Attestation{Signer: id.Public(), Signature: id.Sign(attestedBytes(d))}
}

// canonicalMembers is members in identity order, which the digest depends on.
func canonicalMembers(members []Member) []Member {
	out := slices.Clone(members)
	slices.SortFunc(out, func(a, b Member) int { return bytes.Compare(a.Identity[:], b.Identity[:]) })
	return out
}

// Validate checks the record's fields and that the admitter signed it.
func (a *Admission) Validate() error {
	if err := CheckName(a.Name); err != nil {
		return fmt.Errorf("admission: %w", err)
	}
	if a.Host == 0 {
		return errors.New("admission without an overlay slot")
	}
	if a.Quorum != "" && a.Admitter != a.Identity {
		return errors.New("only the root's own record carries the cluster's quorum rule")
	}
	if a.Quorum != "" {
		if err := a.Quorum.Check(); err != nil {
			return fmt.Errorf("admission: %w", err)
		}
	}
	if !Verify(a.Admitter, a.signedBytes(), a.Signature) {
		return errors.New("admission signature does not verify")
	}
	return nil
}

// Validate checks the record's fields and that the revoker signed it.
func (r *Revocation) Validate() error {
	if !slices.Equal(r.Disowned, canonicalKeys(r.Disowned)) {
		return errors.New("revocation's disowned identities are not in canonical order")
	}
	if !Verify(r.Revoker, r.signedBytes(), r.Signature) {
		return errors.New("revocation signature does not verify")
	}
	return nil
}

// Validate checks a checkpoint's shape and every attestation on it. It says
// nothing about whether the checkpoint has ratified, which depends on who the
// members were when it was made; see Set.
func (c *Checkpoint) Validate() error {
	if c.Depth == 0 {
		return errors.New("checkpoint without a depth")
	}
	if err := c.Quorum.Check(); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	if len(c.Members) == 0 {
		return errors.New("checkpoint states no members")
	}
	if !slices.Equal(c.Members, canonicalMembers(c.Members)) {
		return errors.New("checkpoint's members are not in canonical order")
	}
	if !slices.Equal(c.Removed, canonicalKeys(c.Removed)) {
		return errors.New("checkpoint's removed identities are not in canonical order")
	}
	// A membership enough of the cluster agreed on cannot hold two members
	// sharing a name or an address: whatever contest there was is what the
	// agreement settled. Records signed since can still collide, and Conflicts
	// answers for those.
	names, hosts := map[string]bool{}, map[uint64]bool{}
	for _, m := range c.Members {
		if err := CheckName(m.Name); err != nil {
			return fmt.Errorf("checkpoint: %w", err)
		}
		if m.Host == 0 {
			return errors.New("checkpoint gives a member no overlay slot")
		}
		if names[m.Name] {
			return fmt.Errorf("checkpoint states two members named %q", m.Name)
		}
		if hosts[m.Host] {
			return fmt.Errorf("checkpoint states two members at overlay slot %d", m.Host)
		}
		names[m.Name], hosts[m.Host] = true, true
	}
	signed := attestedBytes(c.Digest())
	seen := map[PublicKey]bool{}
	for _, at := range c.Attestations {
		if seen[at.Signer] {
			return errors.New("checkpoint carries two attestations by one signer")
		}
		seen[at.Signer] = true
		if !Verify(at.Signer, signed, at.Signature) {
			return fmt.Errorf("attestation by %s does not verify", at.Signer.Short())
		}
	}
	return nil
}

// byIdentity orders members and the keys a revocation names the same way.
func byIdentity(a, b PublicKey) int { return bytes.Compare(a[:], b[:]) }

// laterRecord orders two records by date and then by signer, so that every node
// prefers the same one of two that both stand.
func laterRecord(aAt int64, aBy PublicKey, bAt int64, bBy PublicKey) bool {
	return cmp.Or(cmp.Compare(aAt, bAt), byIdentity(bBy, aBy)) > 0
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
