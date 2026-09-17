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
	require.NoError(t, set.Adopt(trust.Found(root, "root", "1", 0)))
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

	// Metadata reaches a peer with no identity and no overlay address on it:
	// the name says which member, and the signature has to be that member's
	// over the address the membership gives it.
	meta := func(id *trust.Identity, name, signedAddr string) *overlay.Node {
		n := &overlay.Node{Name: name}
		n.PubKey = testKey
		n.Signature = id.Sign(trust.MetaDigest(name, netip.MustParseAddr(signedAddr), n.PubKey, nil))
		return n
	}
	// what verifies is also what fills in the two the wire left out
	good := meta(a, "a", "10.0.0.2")
	require.NoError(t, verifyMeta(set, testOverlay, good))
	assert.Equal(t, a.Public(), good.Identity, "the identity comes from the membership")
	assert.Equal(t, "10.0.0.2", good.OverlayAddr.String(), "and so does the overlay address")
	require.NoError(t, verifyMeta(set, testOverlay, meta(root, "root", "10.0.0.1")))

	// a member that signed for an address the membership does not give it
	err = verifyMeta(set, testOverlay, meta(a, "a", "10.0.0.9"))
	assert.ErrorContains(t, err, "does not verify")

	// A member's own signature says nothing about whose name it may use: the
	// membership does, and a name is what every node writes to its hosts file.
	// Metadata under root's name has to carry root's signature, and only root
	// can produce one.
	err = verifyMeta(set, testOverlay, meta(a, "root", "10.0.0.1"))
	assert.ErrorContains(t, err, "metadata signature of root does not verify")
	err = verifyMeta(set, testOverlay, meta(a, "nobody", "10.0.0.2"))
	assert.ErrorContains(t, err, `no member of this cluster goes by "nobody"`)

	forged := meta(a, "a", "10.0.0.2")
	forged.Signature[0] ^= 1
	assert.ErrorContains(t, verifyMeta(set, testOverlay, forged), "signature", "metadata not signed by the identity is refused")

	bad := meta(a, "a", "10.0.0.2")
	bad.PubKey = "not a wireguard key"
	bad.Signature = a.Sign(trust.MetaDigest("a", netip.MustParseAddr("10.0.0.2"), bad.PubKey, nil))
	err = verifyMeta(set, testOverlay, bad)
	assert.ErrorContains(t, err, "wireguard key")

	// what memberlist carries is the encoded form, and a peer verifies that
	encoded, err := meta(a, "a", "10.0.0.2").Encode(512)
	require.NoError(t, err)
	decoded, err := overlay.DecodeMeta(encoded)
	require.NoError(t, err)
	require.NoError(t, verifyMeta(set, testOverlay, &overlay.Node{Name: "a", Meta: decoded}))
}

// testKey is a syntactically valid wireguard public key.
const testKey = "gm/3EV7bl46Z2QPUa5CppLUjwoL45BwHO1nrEgIFsFA="
