package cluster

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_assignedAddr_and_verifyMeta(t *testing.T) {
	root, a, b, stranger := testIdentity(t), testIdentity(t), testIdentity(t), testIdentity(t)
	t0 := time.Unix(1_700_000_000, 0)
	set := trust.NewSet(root.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(root, "root", t0),
		trust.Admit(root, a.Public(), "a", 2, 2, t0),
		trust.Admit(root, b.Public(), "b", 2, 3, t0.Add(time.Second)), // same slot, later
	}})

	addr, err := assignedAddr(set, testOverlay, root.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", addr.String())
	addr, err = assignedAddr(set, testOverlay, a.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", addr.String())
	_, err = assignedAddr(set, testOverlay, b.Public())
	assert.ErrorContains(t, err, "collides with a")
	_, err = assignedAddr(set, testOverlay, stranger.Public())
	assert.ErrorContains(t, err, "not a member")
	_, err = assignedAddr(set, netip.MustParsePrefix("10.0.0.0/31"), a.Public())
	assert.ErrorContains(t, err, "does not fit")
	_, err = assignedAddr(set, testOverlay, trust.PublicKey{})
	assert.ErrorContains(t, err, "not a member")

	// metadata must claim the assigned address, signed by the identity
	meta := func(id *trust.Identity, name, overlayAddr string) *overlay.Node {
		n := &overlay.Node{Name: name}
		n.OverlayAddr = netip.MustParseAddr(overlayAddr)
		n.PubKey = testKey
		n.Identity = id.Public()
		n.Signature = id.Sign(trust.MetaDigest(n.Name, n.OverlayAddr, n.PubKey, nil))
		return n
	}
	require.NoError(t, verifyMeta(set, testOverlay, meta(a, "a", "10.0.0.2")))
	err = verifyMeta(set, testOverlay, meta(a, "a", "10.0.0.9"))
	assert.ErrorContains(t, err, "is assigned 10.0.0.2")
	err = verifyMeta(set, testOverlay, meta(b, "b", "10.0.0.2"))
	assert.ErrorContains(t, err, "collides")
	forged := meta(a, "a", "10.0.0.2")
	forged.Signature[0] ^= 1
	assert.ErrorContains(t, verifyMeta(set, testOverlay, forged), "signature", "metadata not signed by the identity is refused")

	bad := meta(a, "a", "10.0.0.2")
	bad.PubKey = "not a wireguard key"
	bad.Signature = a.Sign(trust.MetaDigest("a", bad.OverlayAddr, bad.PubKey, nil))
	err = verifyMeta(set, testOverlay, bad)
	assert.ErrorContains(t, err, "wireguard key")

	// what memberlist carries is the encoded form, and it round-trips
	encoded, err := meta(a, "a", "10.0.0.2").Encode(512)
	require.NoError(t, err)
	decoded, err := overlay.DecodeMeta(encoded)
	require.NoError(t, err)
	require.NoError(t, verifyMeta(set, testOverlay, &overlay.Node{Name: "a", Meta: decoded}))
}

// testKey is a syntactically valid wireguard public key.
const testKey = "gm/3EV7bl46Z2QPUa5CppLUjwoL45BwHO1nrEgIFsFA="
