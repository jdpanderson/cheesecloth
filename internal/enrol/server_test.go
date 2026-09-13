package enrol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Failure paths of the exchange; the successful and token-related paths are in enrol_test.go.

func Test_handle_malformedHello(t *testing.T) {
	srv, _ := member(t)
	joiner := newID(t)
	conn := pipeTo(t, srv, joiner.Public())
	setDeadline(conn)
	require.NoError(t, writeFrame(conn, hello{Version: protocolVersion + 1, TokenID: make([]byte, tokenIDLen), Identity: joiner.Public(), Nonce: make([]byte, nonceLen), Name: "j"}))
	var c challenge
	assert.Error(t, readFrame(conn, &c, maxShortFrame), "the member hangs up without a challenge")
}

func Test_handle_badProof(t *testing.T) {
	srv, _ := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	key, err := decodeToken(tok)
	require.NoError(t, err)
	joiner := newID(t)

	conn := pipeTo(t, srv, joiner.Public())
	setDeadline(conn)
	tid := idOf(key)
	nJ, _ := randomNonce()
	require.NoError(t, writeFrame(conn, hello{Version: protocolVersion, TokenID: tid[:], Identity: joiner.Public(), Nonce: nJ, Name: "j"}))
	var c challenge
	require.NoError(t, readFrame(conn, &c, maxShortFrame), "a known token id gets a challenge")

	// prove with the wrong key: knowing the id is not knowing the token
	k := deriveKey(append([]byte{0}, key[1:]...), nJ, c.Nonce)
	tr := transcript(joiner.Public(), c.Identity, nJ, c.Nonce, "j")
	require.NoError(t, writeFrame(conn, proof{MAC: mac(k, labelJoiner, tr)}))
	var sealed []byte
	assert.Error(t, readFrame(conn, &sealed, maxFrame), "no welcome")
	assert.Equal(t, 1, srv.Tokens.pending(), "a failed proof does not spend the token")
}

// A name no node may hold is refused at the door, before the token is looked
// at, and the joiner does not get as far as sending one.
func Test_handle_refusesABadName(t *testing.T) {
	srv, _ := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	joiner := newID(t)

	conn := pipeTo(t, srv, joiner.Public())
	setDeadline(conn)
	tid := idOf(mustKey(t, tok))
	require.NoError(t, writeFrame(conn, hello{Version: protocolVersion, TokenID: tid[:], Identity: joiner.Public(),
		Nonce: make([]byte, nonceLen), Name: "web1\n10.0.0.9 other"}))
	var c challenge
	assert.Error(t, readFrame(conn, &c, maxShortFrame), "the member hangs up without a challenge")
	assert.Equal(t, 1, srv.Tokens.pending(), "and the token is untouched")

	// the joiner checks its own name before it says anything
	_, _, err = Join(pipeTo(t, srv, joiner.Public()), tok, joiner, "Web1")
	assert.ErrorContains(t, err, "not a hostname")
}

func Test_Join_errors(t *testing.T) {
	id, other := newID(t), newID(t)
	tok, _ := NewTokenStore(nil).Mint(time.Minute, 1)

	// answers runs a member that replies to the hello with c, and returns the joiner's end
	answers := func(c challenge) Conn {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { _ = c1.Close() })
		go func() {
			var h hello
			_ = readFrame(c2, &h, maxShortFrame)
			_ = writeFrame(c2, c)
			_ = c2.Close()
		}()
		return identified{c1, other.Public()}
	}

	_, _, err := Join(answers(challenge{}), "not base64!", id, "j")
	assert.ErrorContains(t, err, "join key")

	_, _, err = Join(answers(challenge{Nonce: []byte{1}}), tok, id, "j")
	assert.ErrorContains(t, err, "malformed challenge")

	// a member that cannot prove it holds the token is refused
	_, _, err = Join(answers(challenge{Identity: other.Public(), Nonce: make([]byte, nonceLen)}), tok, id, "j")
	assert.ErrorContains(t, err, "could not prove knowledge of the join key")
}

// Two joiners may both be challenged on a single-use token; only the first to
// prove it is admitted.
func Test_handle_singleUseTokenTwoJoiners(t *testing.T) {
	srv, _ := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	key := mustKey(t, tok)

	type joiner struct {
		conn Conn
		id   *trust.Identity
		nJ   []byte
		c    challenge
	}
	start := func(name string) *joiner {
		j := &joiner{id: newID(t)}
		j.conn = pipeTo(t, srv, j.id.Public())
		setDeadline(j.conn)
		j.nJ, err = randomNonce()
		require.NoError(t, err)
		tid := idOf(key)
		require.NoError(t, writeFrame(j.conn, hello{Version: protocolVersion, TokenID: tid[:], Identity: j.id.Public(), Nonce: j.nJ, Name: name}))
		require.NoError(t, readFrame(j.conn, &j.c, maxShortFrame), "%s is challenged", name)
		return j
	}
	prove := func(j *joiner, name string) error {
		k := deriveKey(key, j.nJ, j.c.Nonce)
		tr := transcript(j.id.Public(), j.c.Identity, j.nJ, j.c.Nonce, name)
		require.NoError(t, writeFrame(j.conn, proof{MAC: mac(k, labelJoiner, tr)}))
		var w Welcome
		return readFrame(j.conn, &w, maxFrame)
	}

	one, two := start("one"), start("two")
	require.NoError(t, prove(one, "one"), "the first proof is admitted")
	assert.Error(t, prove(two, "two"), "the second finds the token spent")
	assert.Equal(t, 0, srv.Tokens.pending())
}

// On an authenticated connection the identities in the messages must be the peer's.
func Test_identityBinding(t *testing.T) {
	srv, _ := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	joiner, other := newID(t), newID(t)

	// server side: hello claims joiner but the connection belongs to other
	c1 := pipeTo(t, srv, other.Public())
	setDeadline(c1)
	tid := idOf(mustKey(t, tok))
	require.NoError(t, writeFrame(c1, hello{Version: protocolVersion, TokenID: tid[:], Identity: joiner.Public(), Nonce: make([]byte, nonceLen), Name: "j"}))
	var c challenge
	assert.Error(t, readFrame(c1, &c, maxShortFrame), "server hangs up on a mismatch")
	assert.Equal(t, 1, srv.Tokens.pending())

	// joiner side: the challenge claims the member but the connection belongs to other
	_, _, err = Join(identified{pipeTo(t, srv, joiner.Public()), other.Public()}, tok, joiner, "j")
	assert.ErrorContains(t, err, "does not match the connection")

	// and with matching identities the exchange succeeds
	w, member, err := Join(pipeTo(t, srv, joiner.Public()), tok, joiner, "j")
	require.NoError(t, err)
	assert.Equal(t, srv.Identity.Public(), member)
	assert.Equal(t, joiner.Public(), w.Admission.Identity)
}

func mustKey(t *testing.T, tok string) []byte {
	t.Helper()
	key, err := decodeToken(tok)
	require.NoError(t, err)
	return key
}

// A peer that has proved nothing announces a message far larger than the one
// it is sending, which the reader would otherwise allocate before any of the
// body arrived. The member turns it away at the header instead of holding the
// space and the enrolment slot until the exchange times out.
func Test_Server_refusesAnOversizedHeaderAtOnce(t *testing.T) {
	srv, _ := member(t)
	conn := pipeTo(t, srv, newID(t).Public())
	defer func() { _ = conn.Close() }()

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxFrame) // what the welcome may be, not the hello
	_, err := conn.Write(hdr[:])
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var c challenge
		_ = readFrame(conn, &c, maxShortFrame) // errors when the member hangs up
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the member held the connection instead of refusing the header")
	}
}

func Test_Join_rejectsForeignAdmission(t *testing.T) {
	// the member hands back an admission for someone else
	id := newID(t)
	set := trust.NewSet(id.Public())
	_, err := set.AddAdmission(trust.SelfAdmit(id, "root", time.Now()))
	require.NoError(t, err)
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), Root: id.Public(), GossipAddr: "x", Records: set.Records,
		Admit: func(trust.PublicKey, string) (trust.Admission, trust.Records, error) {
			other := newID(t)
			return trust.Admit(id, other.Public(), "other", 2, set.NextSeq(id.Public()), time.Now()), set.Records(), nil
		}}
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = join(t, srv, tok, newID(t), "j")
	assert.ErrorContains(t, err, "someone else")
}

// The joiner checks the admission it is handed, not just who it is for.
func Test_Join_rejectsForgedAdmission(t *testing.T) {
	id := newID(t)
	set := trust.NewSet(id.Public())
	_, err := set.AddAdmission(trust.SelfAdmit(id, "root", time.Now()))
	require.NoError(t, err)
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), Root: id.Public(), GossipAddr: "x", Records: set.Records,
		Admit: func(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			a := trust.Admit(id, joiner, name, 2, set.NextSeq(id.Public()), time.Now())
			a.Signature[0] ^= 1
			return a, set.Records(), nil
		}}
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = join(t, srv, tok, newID(t), "j")
	assert.ErrorContains(t, err, "signature")
}

// A cluster whose records no longer fit in a frame stops admitting nodes, and
// says so, rather than signing an admission it cannot deliver: every such
// attempt would add another record and make the overflow worse.
func Test_Join_refusedWhenRecordsOutgrowTheFrame(t *testing.T) {
	id := newID(t)
	set := trust.NewSet(id.Public())
	_, err := set.AddAdmission(trust.SelfAdmit(id, "root", time.Now()))
	require.NoError(t, err)
	for host := uint64(2); len(mustJSON(t, set.Records())) <= maxFrame; { // in batches: the set is marshalled to measure it
		for range 500 {
			other := newID(t)
			_, aerr := set.AddAdmission(trust.Admit(id, other.Public(), "n", host, set.NextSeq(id.Public()), time.Now()))
			require.NoError(t, aerr)
			host++
		}
	}
	admitted := 0
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), Root: id.Public(), GossipAddr: "x", Records: set.Records,
		Admit: func(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			admitted++
			a := trust.Admit(id, joiner, name, 2, set.NextSeq(id.Public()), time.Now())
			return a, set.Records(), nil
		}}
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	_, _, err = join(t, srv, tok, newID(t), "j")
	assert.ErrorContains(t, err, "the member refused to admit this node")
	assert.ErrorContains(t, err, "no longer fit in an enrolment message")
	assert.Zero(t, admitted, "nothing was signed, so the records did not grow")
}

// A joiner refused for any reason it could not otherwise know is told why,
// once it has proved the token.
func Test_Join_refusalReachesTheJoiner(t *testing.T) {
	id := newID(t)
	set := trust.NewSet(id.Public())
	_, err := set.AddAdmission(trust.SelfAdmit(id, "root", time.Now()))
	require.NoError(t, err)
	refuse := true
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), Root: id.Public(), GossipAddr: "x", Records: set.Records,
		Admit: func(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			if refuse {
				return trust.Admission{}, trust.Records{}, errors.New(`a member named "j" is already in the cluster`)
			}
			a := trust.Admit(id, joiner, name, 2, set.NextSeq(id.Public()), time.Now())
			_, aerr := set.AddAdmission(a)
			return a, set.Records(), aerr
		}}
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	_, _, err = join(t, srv, tok, newID(t), "j")
	assert.ErrorContains(t, err, `already in the cluster`)

	// nothing was signed, so the invitation was not spent either
	assert.Equal(t, 1, srv.Tokens.pending(), "a refusal gives the token use back")
	refuse = false
	_, _, err = join(t, srv, tok, newID(t), "j2")
	require.NoError(t, err, "the returned use enrols the next joiner")
	assert.Equal(t, 0, srv.Tokens.pending())
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
