package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/jdpanderson/cheesecloth/internal/wire"
)

// Records is the wire and file form of a Set's contents: the membership the
// cluster has agreed on, the checkpoints a peer that is behind would need to
// reach it, and what has been signed since.
type Records struct {
	Checkpoints   []Checkpoint   `codec:"c,omitempty" json:"checkpoints,omitempty"`
	Admissions    []Admission    `codec:"a" json:"admissions"`
	Revocations   []Revocation   `codec:"r" json:"revocations"`
	Confirmations []Confirmation `codec:"f,omitempty" json:"confirmations,omitempty"`
}

// Digest identifies a checkpoint by its contents.
type Digest [sha256.Size]byte

// String is the base64 form used in files and on the wire.
func (d Digest) String() string { return base64.StdEncoding.EncodeToString(d[:]) }

// Short is a fingerprint for humans: the first 8 base64 characters.
func (d Digest) Short() string { return d.String()[:8] }

// MarshalText implements encoding.TextMarshaler. Without it a digest travels
// as an array of thirty-two numbers, which costs twice the bytes and cannot be
// read in a state file.
func (d Digest) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Digest) UnmarshalText(text []byte) error { return decodeKey("digest", text, d[:]) }

// Member is one entry in a checkpoint: an identity, the name it goes by and the
// overlay slot it holds.
type Member struct {
	Identity PublicKey `codec:"i" json:"identity"`
	Name     string    `codec:"n" json:"name"`
	Host     uint64    `codec:"h" json:"host"`
}

// Checkpoint is a statement of the whole membership, carrying the signatures of
// the members that agree with it. It is the only thing a node needs: the
// membership it states was trusted by the membership below it, which is what
// makes it trusted in turn, and from there the cluster moves forward. Nothing
// reads what came before.
//
// Prev names the membership this one was proposed against, which binds it to a
// lineage: it is in the digest, so an attestation cannot be lifted onto another
// checkpoint. Nothing compares it to anything -- a node takes any membership a
// quorum of its own members signed, whatever it follows -- so what the binding
// rests on is honest nodes computing Prev from the anchor they hold. Depth
// orders them, and is what decides which of two a node takes. Attestations are not part of the
// digest: two nodes may hold the same checkpoint with different signatures
// collected, and merging takes the union.
type Checkpoint struct {
	Depth   uint64      `codec:"d" json:"depth"`
	Prev    Digest      `codec:"p,omitempty" json:"prev,omitzero"` // zero at the founding checkpoint
	Quorum  QuorumRule  `codec:"q" json:"quorum"`
	Members []Member    `codec:"m" json:"members"`
	Removed []Departure `codec:"x,omitempty" json:"removed,omitempty"` // identities out of the cluster, and when
	// Confirmations is how many members besides its signer must confirm a
	// record before it counts. It is the cluster's, settled when the cluster is
	// founded and carried here so no node's configuration can make it disagree
	// with its peers -- the same reasoning as Quorum.
	Confirmations int           `codec:"f,omitempty" json:"confirmations,omitempty"`
	Attestations  []Attestation `codec:"t" json:"attestations"`
}

// Confirmation is one member agreeing that a record should count. Where the
// cluster asks for them, a record that has not gathered enough is held and does
// nothing: it is what a second pair of eyes looks like on the wire.
type Confirmation struct {
	Record    Digest    `codec:"e" json:"record"` // the admission or revocation confirmed
	Confirmer PublicKey `codec:"u" json:"confirmer"`
	Signature []byte    `codec:"s" json:"signature"`
}

// Attestation is one member's signature over a checkpoint's digest.
type Attestation struct {
	Signer    PublicKey `codec:"g" json:"signer"`
	Signature []byte    `codec:"s" json:"signature"`
}

// QuorumRule says how many of the members a checkpoint follows must attest to
// it before it is taken: "majority" (N/2+1), "half" (N/2), or a decimal count.
//
// Every change to the membership goes through it: an admission or a revocation
// is a proposal, and it is this many attestations that turn the membership that
// follows from it into the membership. So the cluster has one answer to who
// belongs, and cannot change it while too few members are reachable to sign
// one. See docs/membership.md.
type QuorumRule string

const (
	// QuorumMajority is the default: two majorities of one membership always
	// have a member in common, so above two members it cannot fork. At two it
	// is relaxed, for the reason given in Size.
	QuorumMajority QuorumRule = "majority"
	// QuorumHalf is what an operator may choose instead, knowing that a cluster
	// split down the middle can agree two different memberships.
	QuorumHalf QuorumRule = "half"
)

// Size is how many attestations take a checkpoint over a membership of n.
func (q QuorumRule) Size(n int) int {
	switch q {
	case QuorumMajority:
		// Two is the one size where a majority is everybody, so a node that
		// will not attest -- switched off, unreachable, or the subject of the
		// revocation and not co-operating -- would freeze the other's
		// membership for good: it could neither evict its peer nor enrol a
		// third node to break the tie. Either of them may agree instead.
		//
		// The price is a split, and only in one case: both nodes changing the
		// membership while they cannot see each other, which takes an operator
		// at each end. A partition alone produces no records and so no
		// checkpoint, and a change on one side is one the other accepts when it
		// hears of it. It costs nothing against a stolen key, which this never
		// defended against: an honest node attests to whatever a member
		// proposes, its own removal included, so requiring both signatures
		// never stopped one compromised node of two from evicting the other.
		if n == 2 {
			return 1
		}
		return n/2 + 1
	case QuorumHalf:
		if n < 2 {
			return 1
		}
		return n / 2
	}
	fixed, err := strconv.Atoi(string(q))
	if err != nil || fixed < 1 {
		return n/2 + 1 // an unreadable rule is the safe one; Check refuses it on the way in
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
// 0).
//
// It decides anything only while its admitter is one of the members the cluster
// has agreed on. The members an admitter vouched for before it was revoked keep
// their place because an agreed membership names them, not because the record
// that admitted them still stands.
//
// There is no date on it. Nothing here needs one: an admission is either signed
// by an agreed member or it is not, and where two of them have to be compared
// -- which happens only among records signed since the last agreement -- they
// are ordered by identity, which every node reads the same way and no clock can
// be wrong about.
type Admission struct {
	Identity  PublicKey `codec:"i" json:"identity"`
	Name      string    `codec:"n" json:"name"`
	Host      uint64    `codec:"h" json:"host"`
	Admitter  PublicKey `codec:"b" json:"admitter"`
	Signature []byte    `codec:"s" json:"signature"`
}

// rootHost is the overlay slot the founding node takes.
const rootHost = 1

// Revocation says that Revoker withdraws Identity's membership. It goes out
// entirely: the identity, the name and the overlay slot, and once the cluster
// has agreed a membership without it, the records too.
//
// One record takes out one member. Members stand in their own right, so taking
// out several is several records -- and a joiner the subject had admitted but
// the cluster had not yet agreed on goes with it anyway, since nothing a member
// signs counts once it is no longer one.
type Revocation struct {
	Identity  PublicKey `codec:"i" json:"identity"`
	Revoker   PublicKey `codec:"v" json:"revoker"`
	Signature []byte    `codec:"s" json:"signature"`
}

const (
	admissionDomain  = "cheesecloth/admission/v3"
	revocationDomain = "cheesecloth/revocation/v3"
	checkpointDomain = "cheesecloth/checkpoint/v1"
	attestDomain     = "cheesecloth/attestation/v1"
	confirmDomain    = "cheesecloth/confirmation/v1"
	metaDomain       = "cheesecloth/meta/v1"
)

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func (a *Admission) signedBytes() []byte {
	return wire.Canonical(admissionDomain, a.Identity[:], []byte(a.Name), u64(a.Host), a.Admitter[:])
}

func (r *Revocation) signedBytes() []byte {
	return wire.Canonical(revocationDomain, r.Identity[:], r.Revoker[:])
}

// Digest identifies a checkpoint by everything in it but the attestations, so
// that signatures collected separately are signatures over the same statement.
func (c *Checkpoint) Digest() Digest {
	fields := [][]byte{u64(c.Depth), c.Prev[:], []byte(c.Quorum), u64(uint64(c.Confirmations))}
	for _, m := range c.Members {
		fields = append(fields, m.Identity[:], []byte(m.Name), u64(m.Host))
	}
	for _, d := range c.Removed {
		fields = append(fields, d.Identity[:], u64(d.Depth))
	}
	return sha256.Sum256(wire.Canonical(checkpointDomain, fields...))
}

// attestedBytes is what an attestation signs: the digest under its own domain,
// so a signature over a checkpoint can be nothing else.
func attestedBytes(d Digest) []byte { return wire.Canonical(attestDomain, d[:]) }

// confirmedBytes is what a confirmation signs: the record's digest under its
// own domain, so a confirmation of one record can be nothing else.
func confirmedBytes(d Digest) []byte { return wire.Canonical(confirmDomain, d[:]) }

// Digest identifies an admission by everything it says, so that a confirmation
// names one record and no other.
func (a *Admission) Digest() Digest { return sha256.Sum256(a.signedBytes()) }

// Digest identifies a revocation the same way.
func (r *Revocation) Digest() Digest { return sha256.Sum256(r.signedBytes()) }

// Confirm signs one member's agreement that a record should count.
func Confirm(id *Identity, record Digest) Confirmation {
	return Confirmation{Record: record, Confirmer: id.Public(), Signature: id.Sign(confirmedBytes(record))}
}

// Validate checks that the confirmer signed it.
func (c *Confirmation) Validate() error {
	if !Verify(c.Confirmer, confirmedBytes(c.Record), c.Signature) {
		return fmt.Errorf("confirmation by %s does not verify", c.Confirmer.Short())
	}
	return nil
}

// Admit creates an admission of (identity, name) at overlay slot host, signed
// by admitter.
func Admit(admitter *Identity, identity PublicKey, name string, host uint64) Admission {
	a := Admission{Identity: identity, Name: name, Host: host, Admitter: admitter.Public()}
	a.Signature = admitter.Sign(a.signedBytes())
	return a
}

// Found creates the checkpoint a new cluster starts from: id alone, at the
// first slot, under the quorum rule the cluster keeps. It is the first
// membership, agreed by the only member there is.
func Found(id *Identity, name string, quorum QuorumRule, confirmations int) Checkpoint {
	return Propose(id, 1, Digest{}, quorum, confirmations,
		[]Member{{Identity: id.Public(), Name: name, Host: rootHost}}, nil)
}

// Revoke creates a revocation of identity, signed by revoker.
func Revoke(revoker *Identity, identity PublicKey) Revocation {
	r := Revocation{Identity: identity, Revoker: revoker.Public()}
	r.Signature = revoker.Sign(r.signedBytes())
	return r
}

// Propose creates the checkpoint that states members, following prev at depth,
// attested by the node proposing it. Every node reaching the same membership
// produces the same digest, so their attestations accumulate on one record.
func Propose(id *Identity, depth uint64, prev Digest, quorum QuorumRule, confirmations int, members []Member, removed []Departure) Checkpoint {
	c := Checkpoint{Depth: depth, Prev: prev, Quorum: quorum, Confirmations: confirmations,
		Members: canonicalMembers(members), Removed: canonicalDepartures(removed)}
	c.Attestations = []Attestation{Attest(id, c.Digest())}
	return c
}

// Attest signs a checkpoint's digest.
func Attest(id *Identity, d Digest) Attestation {
	return Attestation{Signer: id.Public(), Signature: id.Sign(attestedBytes(d))}
}

// Departure is an identity an agreed membership put out, and the depth of the
// membership that did it. The depth is what lets the entry be forgotten again:
// see Keep.
type Departure struct {
	Identity PublicKey `codec:"i" json:"identity"`
	Depth    uint64    `codec:"d" json:"depth"`
}

// Keep is how many agreements a membership remembers what it removed for. A
// node that has been away takes the membership the cluster is on now in one
// step, so what it never sees is the memberships in between -- and the only
// thing that tells it those identities are out is the one it lands on still
// naming them. Forgetting sooner would leave it holding admissions nothing says
// are spent, to be offered back at the next state sync. That is also why a node
// further behind than this has its records refused rather than merged.
//
// It is a protocol constant, not a setting: it decides what a checkpoint
// contains, so two nodes using different values would state different
// memberships and never agree on one.
const Keep = 64

// canonicalDepartures is departures in identity order, which the digest
// depends on.
func canonicalDepartures(gone []Departure) []Departure {
	if len(gone) == 0 {
		return nil
	}
	out := slices.Clone(gone)
	slices.SortFunc(out, func(a, b Departure) int { return byIdentity(a.Identity, b.Identity) })
	return slices.Compact(out)
}

// canonicalMembers is members in identity order, which the digest depends on.
func canonicalMembers(members []Member) []Member {
	out := slices.Clone(members)
	slices.SortFunc(out, func(a, b Member) int { return byIdentity(a.Identity, b.Identity) })
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
	if !Verify(a.Admitter, a.signedBytes(), a.Signature) {
		return errors.New("admission signature does not verify")
	}
	return nil
}

// Validate checks that the revoker signed it.
func (r *Revocation) Validate() error {
	if !Verify(r.Revoker, r.signedBytes(), r.Signature) {
		return errors.New("revocation signature does not verify")
	}
	return nil
}

// Validate checks a checkpoint's shape and every attestation on it. It says
// nothing about whether the membership below it agreed, which is the Set's to
// decide.
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
	if c.Confirmations < 0 {
		return errors.New("checkpoint asks for a negative number of confirmations")
	}
	if !slices.Equal(c.Members, canonicalMembers(c.Members)) {
		return errors.New("checkpoint's members are not in canonical order")
	}
	if !slices.Equal(c.Removed, canonicalDepartures(c.Removed)) {
		return errors.New("checkpoint's removed identities are not in canonical order")
	}
	seenGone := map[PublicKey]bool{}
	for _, d := range c.Removed {
		if seenGone[d.Identity] {
			return fmt.Errorf("checkpoint removes %s twice", d.Identity.Short())
		}
		seenGone[d.Identity] = true
		if d.Depth == 0 || d.Depth > c.Depth {
			return fmt.Errorf("checkpoint at depth %d says %s went at depth %d", c.Depth, d.Identity.Short(), d.Depth)
		}
	}
	// A membership the cluster agreed on cannot contradict itself: no two
	// members sharing a name or an address, and nobody both named as a member
	// and named as having gone. Whatever contest there was is what the
	// agreement settled, and a node that read such a checkpoint would hold an
	// identity that is a member and revoked at once -- a member no operator
	// could take out, since revoke refuses an identity already on its way.
	// Nothing honest states one: the proposal drops every member it holds from
	// the list of the departed before it states either.
	names, hosts := map[string]bool{}, map[uint64]bool{}
	for _, m := range c.Members {
		if seenGone[m.Identity] {
			return fmt.Errorf("checkpoint names %s as a member and as removed", m.Identity.Short())
		}
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
	if len(c.Attestations) == 0 {
		return errors.New("checkpoint carries no attestations; a membership nobody has signed is not one")
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

// byIdentity orders identities, which is how every choice between two records
// is settled: it needs no clock and every node reads it the same way.
func byIdentity(a, b PublicKey) int { return bytes.Compare(a[:], b[:]) }

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
