package enrol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// fuzzConn feeds the member's side of an exchange from a fixed slice and
// throws away what it writes. Reads end at EOF rather than at the deadline,
// so an input that stops mid-message costs nothing to try; a socket would
// make every such input wait out exchangeTime.
type fuzzConn struct {
	r    *bytes.Reader
	peer trust.PublicKey
}

func (c *fuzzConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fuzzConn) Close() error                     { return nil }
func (c *fuzzConn) LocalAddr() net.Addr              { return fuzzAddr{} }
func (c *fuzzConn) RemoteAddr() net.Addr             { return fuzzAddr{} }
func (c *fuzzConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fuzzConn) PeerIdentity() trust.PublicKey    { return c.peer }

type fuzzAddr struct{}

func (fuzzAddr) Network() string { return "fuzz" }
func (fuzzAddr) String() string  { return "fuzz" }

// FuzzServerHandle drives the member's side of enrolment with arbitrary bytes.
// Enrolment accepts a connection from anyone — a joiner is not a member yet,
// and only the token exchange decides — so everything up to the proof is
// parsed on behalf of a peer that has proved nothing.
func FuzzServerHandle(f *testing.F) {
	id, err := trust.NewIdentity()
	if err != nil {
		f.Fatal(err)
	}
	frame := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			f.Fatal(err)
		}
		out := make([]byte, 4, 4+len(b))
		binary.BigEndian.PutUint32(out, uint32(len(b)))
		return append(out, b...)
	}
	f.Add(frame(hello{Version: protocolVersion, TokenID: make([]byte, tokenIDLen),
		Identity: id.Public(), Nonce: make([]byte, nonceLen), Name: "joiner"}))
	f.Add(frame(hello{Version: 999, Name: "joiner"}))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x00, 0x00, 0x10, 0x00}) // a header and nothing behind it
	f.Add([]byte("not a frame at all"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, wire []byte) {
		srv := &Server{
			Identity: id, Tokens: NewTokenStore(nil), Root: id.Public(), GossipAddr: "192.0.2.1:7946",
			OverlayNet: netip.MustParsePrefix("10.0.0.0/8"),
			Records:    func() trust.Records { return trust.Records{} },
			Admit: func(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
				return trust.Admit(id, joiner, name, 2), trust.Records{}, nil
			},
		}
		if _, err := srv.Tokens.Mint(time.Minute, 1); err != nil {
			t.Fatal(err)
		}
		srv.Handle(&fuzzConn{r: bytes.NewReader(wire), peer: id.Public()})
	})
}
