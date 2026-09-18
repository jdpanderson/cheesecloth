package wire

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Canonical(t *testing.T) {
	assert.Equal(t, []byte("d\x00\x00\x00\x00\x02ab\x00\x00\x00\x00"), Canonical("d", []byte("ab"), nil))
	assert.Equal(t, []byte("d\x00"), Canonical("d"))
	assert.NotEqual(t, Canonical("d", []byte("ab"), []byte("c")), Canonical("d", []byte("a"), []byte("bc")), "boundaries are unambiguous")
	assert.NotEqual(t, Canonical("d", []byte("a")), Canonical("e", []byte("a")), "domain separation")
}

// netip's types carry their own binary form, which the codec uses: an IPv4
// address travels as four bytes rather than as the text of it. The saving is
// worth nothing if it loses the zone or the family, so this checks it does not.
func Test_Marshal_netip(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "2001:db8::1", "255.255.255.255", "::", "fe80::1%eth0"} {
		addr := netip.MustParseAddr(s)
		b, err := Marshal(addr)
		require.NoError(t, err)
		var back netip.Addr
		require.NoError(t, Unmarshal(b, &back), s)
		assert.Equal(t, addr, back, "%s in %d bytes", s, len(b))
	}
	for _, s := range []string{"192.168.7.0/24", "2001:db8:1::/48", "0.0.0.0/0"} {
		p := netip.MustParsePrefix(s)
		b, err := Marshal(p)
		require.NoError(t, err)
		var back netip.Prefix
		require.NoError(t, Unmarshal(b, &back), s)
		assert.Equal(t, p, back, "%s in %d bytes", s, len(b))
	}
	var zero netip.Addr
	b, err := Marshal(zero)
	require.NoError(t, err)
	var backZero netip.Addr
	require.NoError(t, Unmarshal(b, &backZero))
	assert.Equal(t, zero, backZero, "the zero address survives")
}

// A message that is not a message is refused rather than decoded into nothing.
func Test_Unmarshal_garbage(t *testing.T) {
	for _, junk := range [][]byte{nil, {}, {0xc1}, []byte("not a message")} {
		var v struct {
			N int `json:"n"`
		}
		assert.Error(t, Unmarshal(junk, &v), "%q", junk)
	}
}
