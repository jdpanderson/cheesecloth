// Package enrol implements node enrolment: a member mints a short-lived token,
// the joiner proves knowledge of it in a mutual exchange bound to both
// identities, and receives the membership records. See docs/membership.md.
package enrol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// tokenLen is the token length in bytes; 256 bits makes guessing infeasible.
const tokenLen = 32

// tokenIDLen is the length of the public token identifier the joiner sends.
const tokenIDLen = 8

type tokenID [tokenIDLen]byte

func idOf(key []byte) tokenID {
	sum := sha256.Sum256(key)
	var id tokenID
	copy(id[:], sum[:tokenIDLen])
	return id
}

// tokenEncoding is lowercase base32 without padding: letters and digits only,
// so a token never starts with "-" and cannot be mistaken for a flag when
// pasted after --join-key, and a double-click selects the whole of it.
var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// encodeToken is the printable form of a token.
func encodeToken(key []byte) string { return strings.ToLower(tokenEncoding.EncodeToString(key)) }

// decodeToken parses the printable form; case does not matter.
func decodeToken(s string) ([]byte, error) {
	key, err := tokenEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(s)))
	if err != nil {
		return nil, fmt.Errorf("join key: %w", err)
	}
	if len(key) != tokenLen {
		return nil, fmt.Errorf("join key: want %d bytes, got %d", tokenLen, len(key))
	}
	return key, nil
}

type token struct {
	key     []byte
	expires time.Time
}

// TokenStore holds pending invitations in memory only.
type TokenStore struct {
	mu     sync.Mutex
	tokens map[tokenID]*token
	now    func() time.Time
}

// NewTokenStore creates an empty store that reads the clock through now; nil
// means the wall clock.
func NewTokenStore(now func() time.Time) *TokenStore {
	if now == nil {
		now = time.Now
	}
	return &TokenStore{tokens: map[tokenID]*token{}, now: now}
}

// Mint creates a token valid for ttl, returning its printable form. An
// invitation admits one node: a second is a second invitation, so that a token
// that leaks costs one enrolment and a joiner that finds its own spent knows
// somebody else used it.
func (s *TokenStore) Mint(ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", errors.New("token ttl must be positive")
	}
	key := make([]byte, tokenLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("reading random source: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	s.tokens[idOf(key)] = &token{key: key, expires: s.now().Add(ttl)}
	return encodeToken(key), nil
}

// lookup returns the key for a pending token without consuming it.
func (s *TokenStore) lookup(id tokenID) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	t, ok := s.tokens[id]
	if !ok {
		return nil, false
	}
	return t.key, true
}

// consume spends a token after a successful proof and reports whether it was
// still there to spend. Two joiners proving the same token at once both pass
// lookup; this is what decides between them, and the one that loses is told so
// rather than left to guess -- under one use per invitation, a token already
// spent means somebody else used it.
//
// Spending is final. An exchange that gets this far and then cannot be admitted
// costs the invitation, and the operator issues another: giving it back would
// mean a token that outlives the enrolment it was made for.
func (s *TokenStore) consume(id tokenID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok || !s.now().Before(t.expires) {
		return false
	}
	delete(s.tokens, id)
	return true
}

// gc drops expired tokens; callers hold mu.
func (s *TokenStore) gc() {
	now := s.now()
	for id, t := range s.tokens {
		if !now.Before(t.expires) {
			delete(s.tokens, id)
		}
	}
}
