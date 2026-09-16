package enrol

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newID(t *testing.T) *trust.Identity {
	t.Helper()
	id, err := trust.NewIdentity()
	require.NoError(t, err)
	return id
}

// identified is a conn whose peer the transport has authenticated.
type identified struct {
	net.Conn
	peer trust.PublicKey
}

func (c identified) PeerIdentity() trust.PublicKey { return c.peer }

// pipeTo runs the member's side of one exchange on srv for a joiner with the
// given identity and returns the joiner's end, each end knowing its peer the
// way the transport's TLS would tell it.
func pipeTo(t *testing.T, srv *Server, joiner trust.PublicKey) Conn {
	t.Helper()
	c1, c2 := net.Pipe()
	go srv.Handle(identified{c2, joiner})
	t.Cleanup(func() { _ = c1.Close() })
	return identified{c1, srv.Identity.Public()}
}

// join runs the joiner's side of the exchange against srv.
func join(t *testing.T, srv *Server, token string, id *trust.Identity, name string) (*Welcome, trust.PublicKey, error) {
	t.Helper()
	conn := pipeTo(t, srv, id.Public())
	defer func() { _ = conn.Close() }()
	return Join(conn, token, id, name)
}

// noRecords is for servers whose Admit hands back nothing, so there is no set
// to ask; the size check has nothing to measure but still runs.
func noRecords() trust.Records { return trust.Records{} }

// member is an enrolment server for a one-node cluster rooted at its identity.
func member(t *testing.T) (*Server, *trust.Set) {
	t.Helper()
	id := newID(t)
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(id, "root", trust.QuorumMajority)))
	srv := &Server{
		Identity: id, Tokens: NewTokenStore(nil), GossipAddr: "192.0.2.1:7946",
		OverlayNet: netip.MustParsePrefix("10.42.0.0/16"), Records: set.Records, Anchor: anchorOf(set),
		Admit: func(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			a := trust.Admit(id, joiner, name, 2)
			if _, aerr := set.AddAdmission(a); aerr != nil {
				return trust.Admission{}, trust.Records{}, aerr
			}
			return a, set.Records(), nil
		},
	}
	return srv, set
}

func Test_Join_happyPath(t *testing.T) {
	srv, set := member(t)
	token, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	joiner := newID(t)
	w, member, err := join(t, srv, token, joiner, "joiner")
	require.NoError(t, err)
	assert.Equal(t, srv.Identity.Public(), member)
	assert.Equal(t, "192.0.2.1:7946", w.GossipAddr)
	assert.Equal(t, netip.MustParsePrefix("10.42.0.0/16"), w.OverlayNet, "the joiner needs no overlay net of its own")
	assert.Equal(t, joiner.Public(), w.Admission.Identity)
	assert.Equal(t, "joiner", w.Admission.Name)
	assert.True(t, set.Valid(joiner.Public()), "member's set now includes the joiner")
	assert.NotNil(t, w.Anchor, "the joiner is handed the membership the cluster agreed on")
	assert.Len(t, w.Records.Admissions, 1, "and only what has been signed since")
	assert.Equal(t, 0, srv.Tokens.pending(), "single-use token is consumed")

	// the token cannot be reused
	_, _, err = join(t, srv, token, newID(t), "again")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed the connection")
}

func Test_Join_multiUseAndExpiry(t *testing.T) {
	srv, _ := member(t)
	token, err := srv.Tokens.Mint(time.Minute, 2)
	require.NoError(t, err)
	_, _, err = join(t, srv, token, newID(t), "one")
	require.NoError(t, err)
	assert.Equal(t, 1, srv.Tokens.pending())
	_, _, err = join(t, srv, token, newID(t), "two")
	require.NoError(t, err)
	assert.Equal(t, 0, srv.Tokens.pending())

	// expiry
	now := time.Now()
	srv.Tokens = NewTokenStore(func() time.Time { return now })
	token, err = srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	now = now.Add(2 * time.Minute)
	_, _, err = join(t, srv, token, newID(t), "late")
	require.Error(t, err)
	assert.Equal(t, 0, srv.Tokens.pending())
}

func Test_Join_wrongToken(t *testing.T) {
	srv, _ := member(t)
	_, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	// a different, well-formed token: unknown id, silent close
	other, err := NewTokenStore(nil).Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = join(t, srv, other, newID(t), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed the connection")
	assert.Equal(t, 1, srv.Tokens.pending(), "a failed attempt does not consume the token")

	// malformed token
	_, _, err = join(t, srv, "nope", newID(t), "x")
	assert.ErrorContains(t, err, "join key")
}

// A man in the middle who knows the token id but not the token cannot pass as the member.
func Test_Join_memberMustProveToken(t *testing.T) {
	srv, _ := member(t)
	real, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	key, _ := decodeToken(real)

	// impostor: same token id (it saw the hello), different key
	impostor := &Server{Identity: newID(t), Tokens: NewTokenStore(nil), GossipAddr: "x", Records: noRecords,
		Admit: func(trust.PublicKey, string) (trust.Admission, trust.Records, error) {
			return trust.Admission{}, trust.Records{}, nil
		}}
	wrong := make([]byte, len(key))
	copy(wrong, key)
	wrong[0] ^= 1
	impostor.Tokens.tokens[idOf(key)] = &token{key: wrong, expires: time.Now().Add(time.Minute), uses: 1}

	_, _, err = join(t, impostor, real, newID(t), "victim")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "member could not prove knowledge")
}

func Test_Join_welcomeMustBeConsistent(t *testing.T) {
	// a server whose Admit does not actually make the joiner a member of the described cluster
	id := newID(t)
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), GossipAddr: "x", Records: noRecords,
		Admit: func(trust.PublicKey, string) (trust.Admission, trust.Records, error) {
			return trust.Admission{}, trust.Records{}, nil
		}}
	token, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	_, _, err = join(t, srv, token, newID(t), "j")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid member")
}

func Test_transcriptAndKeys(t *testing.T) {
	a, b := newID(t), newID(t)
	nJ, nM := []byte("nJ"), []byte("nM")
	t1 := transcript(a.Public(), b.Public(), nJ, nM, "n")
	t2 := transcript(a.Public(), b.Public(), nJ, nM, "m")
	assert.NotEqual(t, t1, t2)
	assert.True(t, bytes.HasPrefix(t1, []byte(transcriptDomain+"\x00")), "domain-separated from the signed records")
	assert.NotEqual(t, mac([]byte("k"), labelMember, t1), mac([]byte("k"), labelJoiner, t1), "direction labels differ")

	k1 := deriveKey([]byte("token"), nJ, nM)
	k2 := deriveKey([]byte("other"), nJ, nM)
	assert.NotEqual(t, k1, k2, "the token is mixed into the keys")
	assert.Len(t, k1, 32)
}

// anchorOf hands a joiner the membership a set has agreed on, which is what a
// running member's server does.
func anchorOf(set *trust.Set) func() *trust.Checkpoint {
	return func() *trust.Checkpoint {
		if c, ok := set.Anchor(); ok {
			return &c
		}
		return nil
	}
}
