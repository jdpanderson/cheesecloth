package overlay

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The gossip form leaves out the identity and the overlay address, which a
// peer takes from the membership instead. What it does carry round-trips.
func Test_Meta_Encode_Decode(t *testing.T) {
	pubKey := "abcdefghijklmnopkqstuvwxyzABCDEF"
	for _, ip := range []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8::1")} {
		m := Meta{
			OverlayAddr: ip,
			PubKey:      pubKey,
			AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24"), netip.MustParsePrefix("2001:db8:1::/48")},
			Identity:    trust.PublicKey{1, 2, 3, 31: 32},
			Signature:   []byte("sig"),
		}
		encoded, err := m.Encode(1024)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), `"overlay"`)
		assert.NotContains(t, string(encoded), `"id"`)

		decoded, err := DecodeMeta(encoded)
		require.NoError(t, err)
		assert.Equal(t, Meta{PubKey: m.PubKey, AllowedIPs: m.AllowedIPs, Signature: m.Signature}, decoded,
			"the two the wire leaves out are the verifier's to fill in")
	}
}

// A node is persisted with its metadata decoded, as one flat object.
func Test_Node_JSON(t *testing.T) {
	node := Node{Name: "n", Addr: netip.MustParseAddr("192.0.2.1"), Port: 7946, Meta: Meta{OverlayAddr: netip.MustParseAddr("10.0.0.1"), PubKey: "k", Identity: trust.PublicKey{1}}}
	b, err := json.Marshal(node)
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"n","addr":"192.0.2.1","port":7946,"overlay":"10.0.0.1","wg":"k","id":"`+trust.PublicKey{1}.String()+`","sig":null}`, string(b))
	var back Node
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, node, back)
}

// A peer is rejoined at the port it was last reached at, which need not be ours.
func Test_Node_GossipAddr(t *testing.T) {
	assert.Equal(t, "192.0.2.1:7946", Node{Addr: netip.MustParseAddr("192.0.2.1"), Port: 7946}.GossipAddr())
	assert.Equal(t, "[2001:db8::1]:7947", Node{Addr: netip.MustParseAddr("2001:db8::1"), Port: 7947}.GossipAddr())
}

func Test_Meta_Encode_limit(t *testing.T) {
	m := Meta{OverlayAddr: netip.MustParseAddr("10.0.0.1"), PubKey: "abcdefghijklmnopkqstuvwxyzABCDEF"}
	_, err := m.Encode(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not fit node metadata")
}

func Test_DecodeMeta_garbage(t *testing.T) {
	for _, meta := range [][]byte{nil, {}, []byte("not json"), []byte(`{"sig":"!!!"}`)} {
		_, err := DecodeMeta(meta)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding node meta")
	}
}
