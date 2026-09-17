package overlay

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// Meta is what a node gossips about itself: its overlay address, its
// wireguard key, the extra networks reachable through it, and a signature by
// its identity over all of that (see trust.MetaDigest). The state file keeps
// all of it as JSON; the gossip form is smaller, see wireMeta.
type Meta struct {
	OverlayAddr netip.Addr      `json:"overlay"`
	PubKey      string          `json:"wg"`
	AllowedIPs  []netip.Prefix  `json:"routes,omitempty"`
	Identity    trust.PublicKey `json:"id"`
	Signature   []byte          `json:"sig"`
}

// Node is a member as memberlist sees it, with its metadata decoded. The
// gossip endpoint is observed rather than signed: it is where this node last
// reached the member, not something the member asserts.
type Node struct {
	Name string     `json:"name"`
	Addr netip.Addr `json:"addr"` // where memberlist reaches the node
	Port uint16     `json:"port"` // the node's own gossip port, which need not be ours
	Meta
}

// GossipAddr is where memberlist reaches the node, as "ip:port".
func (n Node) GossipAddr() string { return netip.AddrPortFrom(n.Addr, n.Port).String() }

// wireMeta is the gossip form. The identity and the overlay address are left
// out of it: memberlist already carries the node's name, the agreed membership
// gives that name an identity and an overlay slot, and a peer works both out
// from there. Sending them would be sending what the receiver has to derive
// anyway to check them, and the budget this has to fit is 512 bytes.
//
// They stay fields of Meta because the state file keeps them: what a node
// persists about a peer is what it has already verified, not what arrived.
type wireMeta struct {
	PubKey     string         `json:"wg"`
	AllowedIPs []netip.Prefix `json:"routes,omitempty"`
	Signature  []byte         `json:"sig"`
}

// Encode is the wire form of the metadata, failing if it exceeds limit.
func (m Meta) Encode(limit int) ([]byte, error) {
	b, err := json.Marshal(wireMeta{PubKey: m.PubKey, AllowedIPs: m.AllowedIPs, Signature: m.Signature})
	if err != nil {
		return nil, fmt.Errorf("encoding node meta: %w", err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("could not fit node metadata into %d bytes", limit)
	}
	return b, nil
}

// DecodeMeta parses the wire form. The identity and the overlay address are not
// in it and are left zero: only the membership says what they are, so filling
// them in belongs with checking them. Nothing may read a decoded Meta before
// something has done both; see cluster.verifyMeta, which is the only caller.
func DecodeMeta(b []byte) (Meta, error) {
	var w wireMeta
	if err := json.Unmarshal(b, &w); err != nil {
		return Meta{}, fmt.Errorf("decoding node meta: %w", err)
	}
	return Meta{PubKey: w.PubKey, AllowedIPs: w.AllowedIPs, Signature: w.Signature}, nil
}
