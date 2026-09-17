package enrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
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

// A name no node may hold is refused once the joiner has proved the token, and
// the joiner is told why rather than left with a closed connection to read as a
// bad token. The token is not spent on an enrolment that did not happen.
func Test_handle_refusesABadName(t *testing.T) {
	srv, _ := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	joiner := newID(t)

	// a name carrying a line of its own, which is what the check is guarding
	bad := "web1\n10.0.0.9 other"
	conn := pipeTo(t, srv, joiner.Public())
	setDeadline(conn)
	key := mustKey(t, tok)
	tid := idOf(key)
	nJ := make([]byte, nonceLen)
	require.NoError(t, writeFrame(conn, hello{Version: protocolVersion, TokenID: tid[:], Identity: joiner.Public(),
		Nonce: nJ, Name: bad}))

	var c challenge
	require.NoError(t, readFrame(conn, &c, maxShortFrame), "the joiner proved nothing yet, but it gets its challenge")
	k := deriveKey(key, nJ, c.Nonce)
	tr := transcript(joiner.Public(), c.Identity, nJ, c.Nonce, bad)
	require.NoError(t, writeFrame(conn, proof{MAC: mac(k, labelJoiner, tr)}))

	var w Welcome
	require.NoError(t, readFrame(conn, &w, maxFrame))
	assert.Contains(t, w.Error, "not a hostname", "the joiner is told what is wrong with its name")
	assert.Empty(t, w.Admission.Signature, "and nothing was signed for it")
	assert.Equal(t, 1, srv.Tokens.pending(), "the token is not spent on a name that cannot be admitted")

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
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(id, "root", "1", 0)))
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), GossipAddr: "x", Records: set.Records, Anchor: anchorOf(set),
		Admit: func(context.Context, trust.PublicKey, string) (trust.Admission, trust.Records, error) {
			other := newID(t)
			return trust.Admit(id, other.Public(), "other", 2), set.Records(), nil
		}}
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = join(t, srv, tok, newID(t), "j")
	assert.ErrorContains(t, err, "someone else")
}

// Every cluster has an overlay network, so a welcome without one is not a
// welcome: the joiner would have no address to derive from its slot.
func Test_Join_rejectsAWelcomeWithoutTheOverlayNetwork(t *testing.T) {
	id := newID(t)
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(id, "root", "1", 0)))
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), GossipAddr: "x", Records: set.Records, Anchor: anchorOf(set),
		Admit: func(_ context.Context, joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			a := trust.Admit(id, joiner, name, 2)
			if _, aerr := set.AddAdmission(a); aerr != nil {
				return trust.Admission{}, trust.Records{}, aerr
			}
			settle(t, set, id) // the joiner is a member; the welcome is still missing a network
			return a, set.Records(), nil
		}}
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = join(t, srv, tok, newID(t), "j")
	assert.ErrorContains(t, err, "no overlay network")
}

// The joiner checks the admission it is handed, not just who it is for.
func Test_Join_rejectsForgedAdmission(t *testing.T) {
	id := newID(t)
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(id, "root", "1", 0)))
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), GossipAddr: "x", Records: set.Records, Anchor: anchorOf(set),
		Admit: func(_ context.Context, joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			a := trust.Admit(id, joiner, name, 2)
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
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(id, "root", "1", 0)))
	for host := uint64(2); len(mustJSON(t, set.Records())) <= maxFrame; { // in batches: the set is marshalled to measure it
		for range 500 {
			other := newID(t)
			_, aerr := set.AddAdmission(trust.Admit(id, other.Public(), "n", host))
			require.NoError(t, aerr)
			host++
		}
	}
	admitted := 0
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), GossipAddr: "x", Records: set.Records, Anchor: anchorOf(set),
		Admit: func(_ context.Context, joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			admitted++
			a := trust.Admit(id, joiner, name, 2)
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
	set := trust.NewSet()
	require.NoError(t, set.Adopt(trust.Found(id, "root", "1", 0)))
	refuse := true
	srv := &Server{Identity: id, Tokens: NewTokenStore(nil), GossipAddr: "x", Records: set.Records, Anchor: anchorOf(set), OverlayNet: netip.MustParsePrefix("10.42.0.0/16"),
		Admit: func(_ context.Context, joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error) {
			if refuse {
				return trust.Admission{}, trust.Records{}, errors.New(`a member named "j" is already in the cluster`)
			}
			host, herr := set.FreeHost(1 << 16)
			if herr != nil {
				return trust.Admission{}, trust.Records{}, herr
			}
			a := trust.Admit(id, joiner, name, host)
			if _, aerr := set.AddAdmission(a); aerr != nil {
				return trust.Admission{}, trust.Records{}, aerr
			}
			settle(t, set, id)
			return a, set.Records(), nil
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

// syncBuffer is a log sink a test can read while the server is still writing.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

// captureWarnings sends the default logger's warnings to a buffer for the rest
// of the test.
func captureWarnings(t *testing.T) *syncBuffer {
	t.Helper()
	log := &syncBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return log
}

// A peer that has proved nothing must not be able to decide how much a member
// writes to disk: those failures are counted rather than written out one each.
// How the counting paces itself is the tally package's business and is tested
// there; what matters here is which failures go that way.
func Test_Server_unprovenFailuresAreCountedNotLoggedEach(t *testing.T) {
	log := captureWarnings(t)
	srv, _ := member(t)
	joiner := newID(t)

	for range 50 {
		conn := pipeTo(t, srv, joiner.Public())
		setDeadline(conn)
		require.NoError(t, writeFrame(conn, hello{Version: protocolVersion + 1})) // nothing here proves anything
		var c challenge
		assert.Error(t, readFrame(conn, &c, maxShortFrame), "the member hangs up without a challenge")
		_ = conn.Close()
	}
	lines := strings.Count(log.String(), "proved nothing")
	assert.Less(t, lines, 5, "fifty attempts, a handful of lines")
	assert.Positive(t, lines, "but the condition is reported")
	assert.Contains(t, log.String(), "count=10", "and the count shows the size of the burst")
	assert.Contains(t, log.String(), "malformed hello", "and it carries the reason")
}

// A failure by a peer that held a valid token is news and is logged as it
// happens: the uses the token had bound how many there can be.
func Test_Server_provenFailuresAreLoggedEach(t *testing.T) {
	log := captureWarnings(t)
	srv, _ := member(t)
	srv.Admit = func(context.Context, trust.PublicKey, string) (trust.Admission, trust.Records, error) {
		return trust.Admission{}, trust.Records{}, errors.New("no room in the overlay")
	}
	tok, err := srv.Tokens.Mint(time.Minute, 3)
	require.NoError(t, err)

	for range 2 {
		_, _, jerr := join(t, srv, tok, newID(t), "web1")
		assert.ErrorContains(t, jerr, "no room in the overlay", "and the joiner is told")
	}
	// the member logs after it has answered the joiner, so the joiner returning
	// does not mean the line is written yet
	assert.Eventually(t, func() bool {
		return strings.Count(log.String(), "enrolment failed") == 2
	}, time.Second, 5*time.Millisecond, "one line each")
	assert.NotContains(t, log.String(), "proved nothing")
}

// The name in a hello has passed no check when an unknown token is logged, so
// what reaches the log is bounded: a peer that has proved nothing must not
// decide how much a member writes to disk.
func Test_Server_logsABoundedNameForAnUnknownToken(t *testing.T) {
	var log syncBuffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	srv, _ := member(t)
	joiner := newID(t)
	bad := "web1\nFAKE level=ERROR msg=forged\n" + strings.Repeat("A", 3000)

	conn := pipeTo(t, srv, joiner.Public())
	setDeadline(conn)
	require.NoError(t, writeFrame(conn, hello{
		Version: protocolVersion, TokenID: make([]byte, tokenIDLen),
		Identity: joiner.Public(), Nonce: make([]byte, nonceLen), Name: bad,
	}))
	var c challenge
	assert.Error(t, readFrame(conn, &c, maxShortFrame), "the member hangs up without a challenge")
	_ = conn.Close()

	assert.Eventually(t, func() bool { return strings.Contains(log.String(), "unknown or expired token") },
		time.Second, 5*time.Millisecond)
	assert.Less(t, len(log.String()), 600, "a 3000-byte name does not become a 3000-byte log line")
	assert.Contains(t, log.String(), "truncated")
	assert.Contains(t, log.String(), "web1", "what the joiner asked for is still recognisable")
	// the handler escapes the newlines the name carried, so what it sent cannot
	// become a record of its own: two log records here, two lines
	assert.Equal(t, 2, strings.Count(log.String(), "\n"), "the name did not become lines of its own")
}

func Test_shortName(t *testing.T) {
	assert.Equal(t, "web1", shortName("web1"))
	assert.Equal(t, strings.Repeat("a", trust.NameMax), shortName(strings.Repeat("a", trust.NameMax)))
	assert.Equal(t, strings.Repeat("a", trust.NameMax)+"... (truncated)", shortName(strings.Repeat("a", 500)))
}
