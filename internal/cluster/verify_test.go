package cluster

import (
	"net/netip"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// What a node is entitled to comes from the agreed membership alone. There is
// no contest to settle here: a membership the cluster has agreed on cannot name
// two members sharing a name or a slot, so a joiner that would have made one is
// left out before it is ever a member. That is trust's to decide, and is tested
// there.
func Test_assigned_and_verifyMeta(t *testing.T) {
	root, a, stranger := testIdentity(t), testIdentity(t), testIdentity(t)
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(root, "root", "1")))
	_, err := set.AddAdmission(trust.Admit(root, a.Public(), "a", 2))
	require.NoError(t, err)
	settle(t, set, root)
	require.True(t, set.Valid(a.Public()))

	adm, addr, err := assigned(set, testOverlay, root.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", addr.String())
	assert.Equal(t, "root", adm.Name)
	_, addr, err = assigned(set, testOverlay, a.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", addr.String())
	_, _, err = assigned(set, testOverlay, stranger.Public())
	assert.ErrorContains(t, err, "not a member")
	_, _, err = assigned(set, netip.MustParsePrefix("10.0.0.0/31"), a.Public())
	assert.ErrorContains(t, err, "does not fit")
	_, _, err = assigned(set, testOverlay, trust.PublicKey{})
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

	// a member's own signature says nothing about whose name it may use: the
	// membership does, and a name is what every node writes to its hosts file
	err = verifyMeta(set, testOverlay, meta(a, "root", "10.0.0.2"))
	assert.ErrorContains(t, err, `goes by "root" but is admitted as "a"`)
	err = verifyMeta(set, testOverlay, meta(a, "nobody", "10.0.0.2"))
	assert.ErrorContains(t, err, "but is admitted as")

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
