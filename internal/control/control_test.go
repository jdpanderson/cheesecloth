package control

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// key is a stand-in identity, one per byte, so a test can name the one it expects.
func key(b byte) trust.PublicKey {
	var k trust.PublicKey
	k[0] = b
	return k
}

type fakeHandler struct {
	pending   []PendingRecord
	confirmed string
	ttl       time.Duration
	uses      int
	force     bool
	leaveErr  error
	entered   chan struct{} // closed when Leave is called
	block     chan struct{} // when set, Leave waits for it, as a real one waits for the agent
}

func (f *fakeHandler) Invite(ttl time.Duration, uses int) (string, error) {
	f.ttl, f.uses = ttl, uses
	if uses <= 0 {
		return "", errors.New("uses must be positive")
	}
	return "TOKEN", nil
}

func (f *fakeHandler) Leave(force bool) (LeaveResult, error) {
	f.force = force
	if f.entered != nil {
		close(f.entered)
	}
	if f.block != nil {
		<-f.block
	}
	if f.leaveErr != nil {
		return LeaveResult{}, f.leaveErr
	}
	return LeaveResult{Identity: key(1), Revoked: true, Notified: 2}, nil
}

// Revoke answers with an identity derived from the target, so a test can tell
// that the target it asked for is the one that reached the handler.
func (f *fakeHandler) Revoke(target string) (RevokeResult, error) {
	if target == "ghost" {
		return RevokeResult{}, errors.New("no such node")
	}
	return RevokeResult{Identity: key(target[0])}, nil
}

// socketDir is a short-lived directory for sockets. t.TempDir() names the
// test in the path, which pushes a socket past the platform's path limit.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func Test_control_roundTrip(t *testing.T) {
	path := filepath.Join(socketDir(t), "w.sock")
	h := &fakeHandler{}
	srv, err := Listen(path, h)
	require.NoError(t, err)
	defer srv.Close()

	resp, err := Call(path, Request{Op: "invite", TTL: "10m", Uses: 2})
	require.NoError(t, err)
	assert.Equal(t, "TOKEN", resp.Token)
	assert.Equal(t, 10*time.Minute, h.ttl)
	assert.Equal(t, 2, h.uses)

	_, err = Call(path, Request{Op: "invite", TTL: "10m", Uses: 0})
	assert.ErrorContains(t, err, "uses must be positive")
	_, err = Call(path, Request{Op: "invite", TTL: "soon", Uses: 1})
	assert.ErrorContains(t, err, "invalid ttl")

	resp, err = Call(path, Request{Op: "revoke", Target: "node2"})
	require.NoError(t, err)
	assert.Equal(t, key('n'), resp.Revoke.Identity, "the target reached the handler")
	_, err = Call(path, Request{Op: "revoke", Target: "ghost"})
	assert.ErrorContains(t, err, "no such node")

	_, err = Call(path, Request{Op: "dance"})
	assert.ErrorContains(t, err, "unknown operation")

	resp, err = Call(path, Request{Op: OpLeave, Force: true})
	require.NoError(t, err)
	assert.Equal(t, key(1), resp.Leave.Identity)
	assert.True(t, resp.Leave.Revoked)
	assert.Equal(t, 2, resp.Leave.Notified)
	assert.True(t, h.force)
	h.leaveErr = errors.New("signing the revocation failed")
	_, err = Call(path, Request{Op: OpLeave})
	assert.ErrorContains(t, err, "signing the revocation failed")
	assert.False(t, h.force)

	srv.Close()
	_, err = Call(path, Request{Op: "invite", TTL: "1m", Uses: 1})
	assert.ErrorContains(t, err, "is it running")
	assert.ErrorIs(t, err, ErrNoAgent)
}

// The agent closes the control server as it shuts down, which is what a leave
// asked it to do: the reply must still reach the operator.
func Test_Close_waitsForTheRequestInFlight(t *testing.T) {
	path := filepath.Join(socketDir(t), "w.sock")
	h := &fakeHandler{entered: make(chan struct{}), block: make(chan struct{})}
	srv, err := Listen(path, h)
	require.NoError(t, err)

	type result struct {
		resp Response
		err  error
	}
	results := make(chan result, 1)
	go func() {
		resp, err := Call(path, Request{Op: OpLeave})
		results <- result{resp, err}
	}()
	<-h.entered

	closed := make(chan struct{})
	go func() {
		srv.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a request was still being answered")
	case <-time.After(50 * time.Millisecond):
	}

	close(h.block)
	got := <-results
	require.NoError(t, got.err)
	assert.Equal(t, key(1), got.resp.Leave.Identity)
	<-closed
	assert.NoFileExists(t, path)
}

func Test_Listen_replacesStaleSocket(t *testing.T) {
	path := filepath.Join(socketDir(t), "w.sock")
	first, err := Listen(path, &fakeHandler{})
	require.NoError(t, err)
	_ = first.ln.Close() // simulate an unclean exit that left the file behind
	second, err := Listen(path, &fakeHandler{})
	require.NoError(t, err)
	defer second.Close()
	_, err = Call(path, Request{Op: "invite", TTL: "1m", Uses: 1})
	assert.NoError(t, err)
}

func Test_Listen_ownerOnly(t *testing.T) {
	dir := socketDir(t)
	path := filepath.Join(dir, "ctl.sock")
	srv, err := Listen(path, &fakeHandler{})
	require.NoError(t, err)
	defer srv.Close()

	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSocket)
	if runtime.GOOS != "windows" { // Windows has no file modes; access there is by ACL
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no staging directory left behind")

	// the renamed socket serves requests
	resp, err := Call(path, Request{Op: OpInvite, TTL: "1m", Uses: 1})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
}

func Test_Listen_refusesToReplaceAFile(t *testing.T) {
	path := filepath.Join(socketDir(t), "notes.txt")
	require.NoError(t, os.WriteFile(path, []byte("keep me"), 0o600))
	_, err := Listen(path, &fakeHandler{})
	assert.ErrorContains(t, err, "not a socket")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "keep me", string(content))
}

func Test_Listen_refusesLongPath(t *testing.T) {
	path := filepath.Join(socketDir(t), strings.Repeat("x", maxSocketPath), "ctl.sock")
	_, err := Listen(path, &fakeHandler{})
	assert.ErrorContains(t, err, "too long")
}

func Test_DefaultSocket(t *testing.T) {
	assert.Equal(t, filepath.Join(DefaultDir, "wgcloth.sock"), DefaultSocket("wgcloth"))
	assert.True(t, filepath.IsAbs(DefaultDir))
}

func Test_Listen_badDirectory(t *testing.T) {
	file := filepath.Join(socketDir(t), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err := Listen(filepath.Join(file, "ctl.sock"), &fakeHandler{})
	assert.ErrorContains(t, err, "creating control socket directory")
}

// A request that is not JSON gets an error response, not silence.
func Test_serve_malformedRequest(t *testing.T) {
	path := filepath.Join(socketDir(t), "w.sock")
	srv, err := Listen(path, &fakeHandler{})
	require.NoError(t, err)
	defer srv.Close()

	conn, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("not json\n"))
	require.NoError(t, err)
	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))
	assert.Equal(t, "malformed request", resp.Error)
}

// An agent that hangs up without answering is reported as such.
func Test_Call_noReply(t *testing.T) {
	path := filepath.Join(socketDir(t), "mute.sock")
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		if conn, aerr := ln.Accept(); aerr == nil {
			_, _ = conn.Read(make([]byte, 1024)) // take the request, answer nothing
			_ = conn.Close()
		}
	}()
	_, err = Call(path, Request{Op: OpInvite, TTL: "1m", Uses: 1})
	assert.ErrorContains(t, err, "reading the agent's reply")
}

func (f *fakeHandler) Pending() ([]PendingRecord, error) { return f.pending, nil }

func (f *fakeHandler) Confirm(target string) (PendingRecord, error) {
	f.confirmed = target
	if len(f.pending) == 0 {
		return PendingRecord{}, errors.New("nothing is waiting to be confirmed")
	}
	return f.pending[0], nil
}
