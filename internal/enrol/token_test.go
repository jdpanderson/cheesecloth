package enrol

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pending is the number of tokens a node could still enrol with. A spent
// token is kept until it expires, so that a use can be given back, and does
// not count here.
func (s *TokenStore) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	return len(s.tokens)
}

func Test_token_codec(t *testing.T) {
	key := make([]byte, tokenLen)
	for i := range key {
		key[i] = byte(i)
	}
	got, err := decodeToken(encodeToken(key))
	require.NoError(t, err)
	assert.Equal(t, key, got)

	_, err = decodeToken("not a token!")
	assert.ErrorContains(t, err, "join key")
	upper, err := decodeToken(strings.ToUpper(encodeToken(key)))
	require.NoError(t, err)
	assert.Equal(t, key, upper, "case and surrounding whitespace do not matter")
	_, err = decodeToken(" " + encodeToken(key) + "\n")
	require.NoError(t, err)
	_, err = decodeToken(encodeToken(key[:5]))
	assert.ErrorContains(t, err, "want 32 bytes")

	assert.NotEqual(t, idOf(key), idOf(append([]byte{1}, key[1:]...)), "the public id depends on the whole key")
}

// A token is pasted after --join-key on a command line, so it must never look like a flag.
func Test_token_isPlainWord(t *testing.T) {
	s := NewTokenStore(nil)
	for i := 0; i < 200; i++ {
		tok, err := s.Mint(time.Minute)
		require.NoError(t, err)
		assert.Regexp(t, `^[a-z2-7]{52}$`, tok)
	}
}

func Test_TokenStore_expiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewTokenStore(func() time.Time { return now })

	tok, err := s.Mint(time.Minute)
	require.NoError(t, err)
	key, err := decodeToken(tok)
	require.NoError(t, err)
	assert.Equal(t, 1, s.pending())

	now = now.Add(59 * time.Second)
	_, ok := s.lookup(idOf(key))
	assert.True(t, ok)
	now = now.Add(time.Second)
	_, ok = s.lookup(idOf(key))
	assert.False(t, ok, "expired at exactly ttl")
	assert.Equal(t, 0, s.pending())
}

// A token admits one node and is gone once spent: nothing gives it back, so a
// refused enrolment costs the invitation and the operator issues another.
func Test_TokenStore_oneNodePerToken(t *testing.T) {
	s := NewTokenStore(nil)
	_, err := s.Mint(0)
	assert.Error(t, err, "a token must last")
	tok, err := s.Mint(time.Minute)
	require.NoError(t, err)
	key, _ := decodeToken(tok)
	id := idOf(key)

	assert.False(t, s.consume(tokenID{9}), "unknown token")
	_, ok := s.lookup(id)
	assert.True(t, ok, "not spent yet")
	assert.True(t, s.consume(id))
	_, ok = s.lookup(id)
	assert.False(t, ok, "and gone once it is")
	assert.False(t, s.consume(id), "spent")
}

// Two joiners may both look a single-use token up before either has proven
// it; consuming decides who gets the one use.
func Test_TokenStore_concurrentJoiners(t *testing.T) {
	s := NewTokenStore(nil)
	tok, err := s.Mint(time.Minute)
	require.NoError(t, err)
	key, _ := decodeToken(tok)
	id := idOf(key)

	_, ok := s.lookup(id)
	require.True(t, ok)
	_, ok = s.lookup(id)
	require.True(t, ok, "both joiners see the token")
	assert.True(t, s.consume(id), "the first proof spends it")
	assert.False(t, s.consume(id), "the second is refused")

	now := time.Now()
	s = NewTokenStore(func() time.Time { return now })
	tok, err = s.Mint(time.Minute)
	require.NoError(t, err)
	key, _ = decodeToken(tok)
	now = now.Add(2 * time.Minute)
	assert.False(t, s.consume(idOf(key)), "a token that expired mid-exchange is not spent")
}
