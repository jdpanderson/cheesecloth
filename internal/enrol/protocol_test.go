package enrol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_frames(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeFrame(&buf, proof{MAC: []byte{1, 2, 3}}))
	require.NoError(t, writeFrame(&buf, hello{Name: "n"}))
	var p proof
	require.NoError(t, readFrame(&buf, &p, maxShortFrame))
	assert.Equal(t, []byte{1, 2, 3}, p.MAC)
	var h hello
	require.NoError(t, readFrame(&buf, &h, maxShortFrame))
	assert.Equal(t, "n", h.Name)
	assert.Zero(t, buf.Len())

	assert.Error(t, writeFrame(&buf, func() {}), "not JSON")
	assert.ErrorContains(t, writeFrame(&buf, strings.Repeat("x", maxFrame)), "frame too large")

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxFrame+1)
	assert.ErrorContains(t, readFrame(bytes.NewReader(hdr[:]), &h, maxShortFrame), "frame too large")
	binary.BigEndian.PutUint32(hdr[:], 10)
	assert.Error(t, readFrame(bytes.NewReader(append(hdr[:], 1, 2)), &h, maxShortFrame), "truncated body")
	assert.Error(t, readFrame(bytes.NewReader(hdr[:2]), &h, maxShortFrame), "truncated header")
}

// The body is allocated from the header, so a message read before the peer has
// proved anything is held to what that message can be, not to what the welcome
// can be. Otherwise four bytes buy a megabyte.
func Test_readFrame_holdsEachMessageToItsOwnLimit(t *testing.T) {
	id, err := trust.NewIdentity()
	require.NoError(t, err)
	var buf bytes.Buffer
	longest := hello{Version: protocolVersion, TokenID: make([]byte, tokenIDLen), Identity: id.Public(),
		Nonce: make([]byte, nonceLen), Name: strings.Repeat("n", trust.NameMax)}
	require.NoError(t, writeFrame(&buf, longest))
	assert.Less(t, buf.Len(), maxShortFrame, "the largest hello there can be fits with room to spare")

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxShortFrame+1)
	var h hello
	assert.ErrorContains(t, readFrame(bytes.NewReader(hdr[:]), &h, maxShortFrame), "frame too large")

	// the welcome is the one message that may be large
	binary.BigEndian.PutUint32(hdr[:], maxShortFrame+1)
	var w Welcome
	assert.NotErrorIs(t, readFrame(bytes.NewReader(hdr[:]), &w, maxFrame), errFrameTooLarge)
}

func Test_randomNonce(t *testing.T) {
	a, err := randomNonce()
	require.NoError(t, err)
	b, err := randomNonce()
	require.NoError(t, err)
	assert.Len(t, a, nonceLen)
	assert.NotEqual(t, a, b)
}

func Test_mac_labels(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	tr := []byte("transcript")
	assert.NotEqual(t, mac(key, labelMember, tr), mac(key, labelJoiner, tr), "each side proves with its own label")
	assert.Equal(t, mac(key, labelMember, tr), mac(key, labelMember, tr))
	// the label is terminated, so it cannot bleed into the transcript
	assert.NotEqual(t, mac(key, "ab", []byte("c")), mac(key, "a", []byte("bc")))
}
