package trust

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Admission_Validate(t *testing.T) {
	root, a := newID(t), newID(t)
	adm := Admit(root, a.Public(), "a", 2, 1, t0)
	require.NoError(t, adm.Validate())

	for name, mutate := range map[string]func(*Admission){
		"name":      func(x *Admission) { x.Name = "b" },
		"host":      func(x *Admission) { x.Host = 3 },
		"identity":  func(x *Admission) { x.Identity = root.Public() },
		"issued":    func(x *Admission) { x.IssuedAt++ },
		"seq":       func(x *Admission) { x.Seq++ },
		"admitter":  func(x *Admission) { x.Admitter = a.Public() },
		"signature": func(x *Admission) { x.Signature[0] ^= 1 },
	} {
		x := adm
		x.Signature = append([]byte(nil), adm.Signature...)
		mutate(&x)
		assert.Error(t, x.Validate(), name)
	}
	x := adm
	x.Name = ""
	assert.ErrorContains(t, x.Validate(), "node name is empty")
	x = adm
	x.Host = 0
	assert.ErrorContains(t, x.Validate(), "without an overlay slot")
	x = adm
	x.Seq = 0
	assert.ErrorContains(t, x.Validate(), "without a sequence number")
}

func Test_Revocation_Validate(t *testing.T) {
	root, a := newID(t), newID(t)
	rev := Revoke(root, a.Public(), 1, 7, t0)
	require.NoError(t, rev.Validate())
	for name, mutate := range map[string]func(*Revocation){
		"issued":    func(x *Revocation) { x.IssuedAt++ },
		"seq":       func(x *Revocation) { x.Seq++ },
		"raised":    func(x *Revocation) { x.UpTo++ },
		"lowered":   func(x *Revocation) { x.UpTo-- },
		"revoker":   func(x *Revocation) { x.Revoker = a.Public() },
		"signature": func(x *Revocation) { x.Signature[0] ^= 1 },
	} {
		x := rev
		x.Signature = append([]byte(nil), rev.Signature...)
		mutate(&x)
		assert.Error(t, x.Validate(), name)
	}
	x := rev
	x.Seq = 0
	assert.ErrorContains(t, x.Validate(), "without a sequence number")

	// a revocation that keeps nothing is signed the same way as any other
	bare := Revoke(root, a.Public(), 1, 0, t0)
	require.NoError(t, bare.Validate())
	assert.Zero(t, bare.UpTo)
}

func Test_MetaDigest(t *testing.T) {
	id := newID(t)
	routes := []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}
	d := MetaDigest("node", netip.MustParseAddr("10.0.0.1"), "wgkey", routes)
	sig := id.Sign(d)
	assert.True(t, Verify(id.Public(), d, sig))
	assert.False(t, Verify(id.Public(), MetaDigest("node", netip.MustParseAddr("10.0.0.2"), "wgkey", routes), sig))
	assert.False(t, Verify(id.Public(), MetaDigest("other", netip.MustParseAddr("10.0.0.1"), "wgkey", routes), sig))
	assert.False(t, Verify(id.Public(), MetaDigest("node", netip.MustParseAddr("10.0.0.1"), "wgkey", nil), sig))
	assert.False(t, Verify(id.Public(), MetaDigest("node", netip.MustParseAddr("10.0.0.1"), "wgkey", []netip.Prefix{netip.MustParsePrefix("192.168.7.0/23")}), sig))
	// length-prefixing: moving bytes between fields changes the digest
	assert.NotEqual(t, MetaDigest("ab", netip.MustParseAddr("10.0.0.1"), "c", nil), MetaDigest("a", netip.MustParseAddr("10.0.0.1"), "bc", nil))
}
