package overlay

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// Meta is what a node gossips about itself: its overlay address, its
// wireguard key, the extra networks reachable through it, and a signature by
// its identity over all of that (see trust.MetaDigest). On the wire and in
// the state file it is JSON, with the identity as base64.
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

// Encode is the wire form of the metadata, failing if it exceeds limit.
func (m Meta) Encode(limit int) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encoding node meta: %w", err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("could not fit node metadata into %d bytes", limit)
	}
	return b, nil
}

// DecodeMeta parses the wire form.
func DecodeMeta(b []byte) (Meta, error) {
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Meta{}, fmt.Errorf("decoding node meta: %w", err)
	}
	return m, nil
}
