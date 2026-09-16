package cluster

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_assigned_and_verifyMeta(t *testing.T) {
	root, stranger := testIdentity(t), testIdentity(t)
	// Two newcomers contest one slot or one name. The smaller identity keeps
	// it, which is arbitrary on purpose: both were admitted moments ago, so
	// there is no established node to prefer. The tests pick which is which so
	// that the assertions read, not because the order means anything.
	a, b := ordered(t)
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(root, "root", trust.QuorumMajority)))
	set.Merge(trust.Records{Admissions: []trust.Admission{
		trust.Admit(root, a.Public(), "a", 2),
		trust.Admit(root, b.Public(), "b", 2), // same slot
	}})

	adm, addr, err := assignedIn(set, testOverlay, root.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", addr.String())
	assert.Equal(t, "root", adm.Name)
	_, addr, err = assignedIn(set, testOverlay, a.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", addr.String())
	_, _, err = assignedIn(set, testOverlay, b.Public())
	assert.ErrorContains(t, err, "collides with a")
	_, _, err = assignedIn(set, testOverlay, stranger.Public())
	assert.ErrorContains(t, err, "not a member")
	_, _, err = assignedIn(set, netip.MustParsePrefix("10.0.0.0/31"), a.Public())
	assert.ErrorContains(t, err, "does not fit")
	_, _, err = assignedIn(set, testOverlay, trust.PublicKey{})
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
	require.NoError(t, verifiedIn(set, testOverlay, meta(a, "a", "10.0.0.2")))
	err = verifiedIn(set, testOverlay, meta(a, "a", "10.0.0.9"))
	assert.ErrorContains(t, err, "is assigned 10.0.0.2")
	err = verifiedIn(set, testOverlay, meta(b, "b", "10.0.0.2"))
	assert.ErrorContains(t, err, "collides")
	// two members admitted with one name at once: one yields, the same way it
	// would over a slot, and every node decides that alike
	twin := after(t, a)
	set.Merge(trust.Records{Admissions: []trust.Admission{
		trust.Admit(root, twin.Public(), "a", 9),
	}})
	require.NoError(t, verifiedIn(set, testOverlay, meta(a, "a", "10.0.0.2")), "the smaller identity keeps the name")
	twinAddr, ok := overlay.Addr(testOverlay, 9)
	require.True(t, ok)
	err = verifiedIn(set, testOverlay, meta(twin, "a", twinAddr.String()))
	assert.ErrorContains(t, err, `the name "a" is held by two members`)
	assert.ErrorContains(t, err, "must be renamed and enrolled again")

	// a member's own signature says nothing about whose name it may use: the
	// admission does, and a name is what every node writes to its hosts file
	err = verifiedIn(set, testOverlay, meta(a, "root", "10.0.0.2"))
	assert.ErrorContains(t, err, `goes by "root" but is admitted as "a"`)
	err = verifiedIn(set, testOverlay, meta(a, "nobody", "10.0.0.2"))
	assert.ErrorContains(t, err, "but is admitted as")

	forged := meta(a, "a", "10.0.0.2")
	forged.Signature[0] ^= 1
	assert.ErrorContains(t, verifiedIn(set, testOverlay, forged), "signature", "metadata not signed by the identity is refused")

	bad := meta(a, "a", "10.0.0.2")
	bad.PubKey = "not a wireguard key"
	bad.Signature = a.Sign(trust.MetaDigest("a", bad.OverlayAddr, bad.PubKey, nil))
	err = verifiedIn(set, testOverlay, bad)
	assert.ErrorContains(t, err, "wireguard key")

	// what memberlist carries is the encoded form, and it round-trips
	encoded, err := meta(a, "a", "10.0.0.2").Encode(512)
	require.NoError(t, err)
	decoded, err := overlay.DecodeMeta(encoded)
	require.NoError(t, err)
	require.NoError(t, verifiedIn(set, testOverlay, &overlay.Node{Name: "a", Meta: decoded}))
}

// testKey is a syntactically valid wireguard public key.
const testKey = "gm/3EV7bl46Z2QPUa5CppLUjwoL45BwHO1nrEgIFsFA="

// ordered is two identities, smaller first.
func ordered(t *testing.T) (*trust.Identity, *trust.Identity) {
	t.Helper()
	x, y := testIdentity(t), testIdentity(t)
	if xk, yk := x.Public(), y.Public(); bytes.Compare(xk[:], yk[:]) > 0 {
		return y, x
	}
	return x, y
}

// after is an identity that sorts above id, so that a test can say which of two
// newcomers yields.
func after(t *testing.T, id *trust.Identity) *trust.Identity {
	t.Helper()
	for range 1000 {
		c := testIdentity(t)
		if ck, idk := c.Public(), id.Public(); bytes.Compare(ck[:], idk[:]) > 0 {
			return c
		}
	}
	t.Fatal("no identity above the given one in a thousand tries")
	return nil
}

// assignedIn and verifiedIn ask the set for its conflicts as they go, which is
// what a caller checking a single node does; a caller with a whole membership
// to check asks once and hands the same answer to each.
func assignedIn(set *trust.Set, prefix netip.Prefix, id trust.PublicKey) (trust.Member, netip.Addr, error) {
	return assigned(set, prefix, id, set.Conflicts())
}

func verifiedIn(set *trust.Set, prefix netip.Prefix, n *overlay.Node) error {
	return verifyMeta(set, prefix, n, set.Conflicts())
}
