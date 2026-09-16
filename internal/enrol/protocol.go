package enrol

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/jdpanderson/cheesecloth/internal/wire"
)

// protocolVersion identifies this exchange format; a mismatch fails closed.
const protocolVersion = 1

const (
	nonceLen = 32
	// maxFrame bounds the welcome, which carries the whole record set: records
	// for a large cluster fit comfortably.
	maxFrame = 1 << 20
	// maxShortFrame bounds every other message, which is a few hundred bytes.
	// The reader allocates what a header claims before any of the body arrives,
	// and a member reads its first two messages from a peer that has proved
	// nothing, so what such a peer can ask it to hold is what this limits.
	maxShortFrame    = 4096
	exchangeTime     = 15 * time.Second
	kdfInfo          = "cheesecloth/enrol/v1"
	transcriptDomain = "cheesecloth/enrol/transcript/v1"
	labelMember      = "member"
	labelJoiner      = "joiner"
)

// hello is the joiner's first message, in the clear.
type hello struct {
	Version  int             `json:"version"`
	TokenID  []byte          `json:"tokenId"`
	Identity trust.PublicKey `json:"identity"`
	Nonce    []byte          `json:"nonce"`
	Name     string          `json:"name"`
}

// challenge is the member's reply: its identity, nonce and proof of token knowledge.
type challenge struct {
	Identity trust.PublicKey `json:"identity"`
	Nonce    []byte          `json:"nonce"`
	MAC      []byte          `json:"mac"`
}

// proof is the joiner's proof of token knowledge.
type proof struct {
	MAC []byte `json:"mac"`
}

// ack is the joiner's last word: it has the welcome, the member may hang up.
type ack struct{}

// Welcome is what an admitted joiner receives; the transport's TLS protects it.
// The member asserts the overlay network, as it asserts the slot it assigned
// and the records. Error instead carries the reason a joiner that proved the
// token was not admitted after all, so it is told rather than left with a
// closed connection.
type Welcome struct {
	Root trust.PublicKey `json:"root"`
	// Anchor is the membership the cluster has agreed on, which the joiner
	// takes as given: it has no way to check it and no need to, since the token
	// exchange is what established that this member speaks for the cluster. It
	// is what lets a joiner start without the whole history.
	Anchor     *trust.Checkpoint `json:"anchor,omitempty"`
	Records    trust.Records     `json:"records"`
	Admission  trust.Admission   `json:"admission"`       // the joiner's own
	GossipAddr string            `json:"gossipAddr"`      // member's ip:port for memberlist
	OverlayNet netip.Prefix      `json:"overlayNet"`      // the network the cluster allocates addresses in
	Error      string            `json:"error,omitempty"` // set instead of everything else when the joiner was refused
}

// deriveKey derives the exchange's MAC key from the token, bound to this
// exchange by both nonces.
func deriveKey(token, nJ, nM []byte) []byte {
	salt := append(append([]byte(nil), nJ...), nM...)
	k, err := hkdf.Key(sha256.New, token, salt, kdfInfo, 32)
	if err != nil {
		panic("hkdf: " + err.Error()) // only for absurd output lengths
	}
	return k
}

// transcript binds both identities, both nonces and the name, under its own
// domain like every other signed or authenticated message. The identities are
// the ones the transport verified, so a relay cannot put itself in the middle
// with its own.
func transcript(j, m trust.PublicKey, nJ, nM []byte, name string) []byte {
	return wire.Canonical(transcriptDomain, j[:], m[:], nJ, nM, []byte(name))
}

func mac(key []byte, label string, transcript []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(transcript)
	return h.Sum(nil)
}

// errFrameTooLarge is returned for a message, or a header claiming a message,
// larger than that message is allowed to be.
var errFrameTooLarge = errors.New("frame too large")

// writeFrame sends a length-prefixed JSON message.
func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return errFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err = w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// readFrame receives a length-prefixed JSON message of at most limit bytes.
// The limit is what the message being read can be, not what any message can
// be: the body is allocated from the header, so a reader that allows the
// largest message of the exchange for the smallest one lets whoever sent the
// header decide how much to hold.
func readFrame(r io.Reader, v any, limit uint32) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > limit {
		return errFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func randomNonce() ([]byte, error) {
	n := make([]byte, nonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("reading random source: %w", err)
	}
	return n, nil
}

// setDeadline bounds the whole exchange.
func setDeadline(conn net.Conn) { _ = conn.SetDeadline(time.Now().Add(exchangeTime)) }
