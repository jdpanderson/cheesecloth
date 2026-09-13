// Package control is the local operator interface to a running agent: a unix
// socket carrying one JSON request and one JSON response per connection.
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/paths"
)

// DefaultDir is where the control sockets live; DefaultSocket is the one for iface.
var DefaultDir = paths.RunDir

func DefaultSocket(iface string) string { return filepath.Join(DefaultDir, iface+".sock") }

// Operations a Request may ask for.
const (
	OpInvite = "invite"
	OpRevoke = "revoke"
	OpLeave  = "leave"
	OpPrune  = "prune"
)

// deadline is how long one request may take. A leave revokes this node, tells
// the members, tears the interface down and stops the agent, and a prune walks
// and rewrites the whole record set; the others are answered immediately.
func deadline(op string) time.Duration {
	if op == OpLeave || op == OpPrune {
		return time.Minute
	}
	return 10 * time.Second
}

// Request is an operator command.
type Request struct {
	Op     string `json:"op"`               // OpInvite, OpRevoke, OpLeave or OpPrune
	TTL    string `json:"ttl,omitempty"`    // invite: token lifetime, a Go duration
	Uses   int    `json:"uses,omitempty"`   // invite: how many nodes may enrol with it
	Target string `json:"target,omitempty"` // revoke: node name or identity
	Force  bool   `json:"force,omitempty"`  // leave: leave even if this node cannot revoke itself
	DryRun bool   `json:"dryRun,omitempty"` // prune: report what would go, sign nothing
}

// Response carries the result or an error message.
type Response struct {
	Token    string   `json:"token,omitempty"`
	Identity string   `json:"identity,omitempty"` // revoke: the identity that was revoked; leave: this node's
	Revoked  bool     `json:"revoked,omitempty"`  // leave: whether the identity was revoked
	Notified int      `json:"notified,omitempty"` // leave: members handed the revocation
	Pruned   []string `json:"pruned,omitempty"`   // prune: the identities removed
	Before   int      `json:"before,omitempty"`   // prune: records held before and after
	After    int      `json:"after,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// LeaveResult is what a leave did: this node's identity, whether it managed
// to revoke it, and how many members were handed the revocation. A node that
// could not revoke itself is still a member as far as the cluster knows, so
// the operator is given the identity to revoke from a member.
type LeaveResult struct {
	Identity string
	Revoked  bool
	Notified int
}

// Handler performs the operations on behalf of the agent.
type Handler interface {
	Invite(ttl time.Duration, uses int) (string, error)
	// Revoke resolves target to an identity, revokes it and returns the identity.
	Revoke(target string) (string, error)
	// Leave revokes this node and stops the agent once it has torn the
	// interface down and forgotten the cluster. With force it leaves even when
	// it cannot revoke itself.
	Leave(force bool) (LeaveResult, error)
	// Prune removes the admissions of identities that have been revoked and that
	// no member's chain runs through. With dry it signs nothing and only reports
	// what would go.
	Prune(dry bool) (PruneResult, error)
}

// PruneResult is what a prune did, or would do.
type PruneResult struct {
	Identities []string
	Before     int
	After      int
}

// Server answers requests on a unix socket.
type Server struct {
	handler Handler
	ln      net.Listener
	path    string
	mu      sync.Mutex
	closed  bool
	conns   sync.WaitGroup // requests being answered; Close waits for them
}

// maxSocketPath is the longest path a unix socket address can hold on this
// platform: 107 bytes on Linux, 103 on macOS and the BSDs.
var maxSocketPath = len(syscall.RawSockaddrUnix{}.Path) - 1

// Listen creates the socket at path (owner-only) and starts serving. The
// socket is created in a private directory and renamed into place once its
// mode is set, so it is never reachable by anyone else, not even briefly.
func Listen(path string, h Handler) (*Server, error) {
	dir := filepath.Dir(path)
	// the staging path is the final one plus a directory of this length
	if n := len(path) + len("/.control-0000000000"); n > maxSocketPath {
		return nil, fmt.Errorf("control socket path %s is too long: %d bytes with its staging directory, at most %d", path, n, maxSocketPath)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating control socket directory: %w", err)
	}
	// a stale socket from an unclean exit is replaced; anything else at the path is not ours to remove
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("control socket path %s exists and is not a socket", path)
	}
	staging, err := os.MkdirTemp(dir, ".control-*") // 0700
	if err != nil {
		return nil, fmt.Errorf("creating control socket: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	tmp := filepath.Join(staging, filepath.Base(path))
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("listening on control socket %s: %w", path, err)
	}
	if err = os.Chmod(tmp, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("securing control socket: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("placing control socket at %s: %w", path, err)
	}
	s := &Server{handler: h, ln: ln, path: path}
	go s.serve()
	return s, nil
}

// Close stops serving, waits for the requests in flight to be answered and
// removes the socket. A leave is answered from the agent's own shutdown, so
// the reply must outlive it.
func (s *Server) Close() {
	s.mu.Lock()
	first := !s.closed
	s.closed = true
	s.mu.Unlock()
	if first {
		_ = s.ln.Close()
	}
	s.conns.Wait()
	_ = os.Remove(s.path)
}

// track registers a request being answered, unless the server is closing.
func (s *Server) track() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns.Add(1)
	return true
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !s.track() {
			_ = conn.Close()
			return
		}
		go func() {
			defer s.conns.Done()
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(deadline("")))
			var req Request
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = json.NewEncoder(conn).Encode(Response{Error: "malformed request"})
				return
			}
			_ = conn.SetDeadline(time.Now().Add(deadline(req.Op)))
			_ = json.NewEncoder(conn).Encode(s.handle(req))
		}()
	}
}

func (s *Server) handle(req Request) Response {
	switch req.Op {
	case OpInvite:
		ttl, err := time.ParseDuration(req.TTL)
		if err != nil {
			return Response{Error: "invalid ttl: " + err.Error()}
		}
		token, err := s.handler.Invite(ttl, req.Uses)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Token: token}
	case OpRevoke:
		id, err := s.handler.Revoke(req.Target)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Identity: id}
	case OpLeave:
		left, err := s.handler.Leave(req.Force)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Identity: left.Identity, Revoked: left.Revoked, Notified: left.Notified}
	case OpPrune:
		res, err := s.handler.Prune(req.DryRun)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Pruned: res.Identities, Before: res.Before, After: res.After}
	default:
		return Response{Error: "unknown operation " + req.Op}
	}
}

// ErrNoAgent means nothing is listening on the control socket, which the
// leave command tells apart from an agent that answered with an error.
var ErrNoAgent = errors.New("no agent is listening")

// Call sends one request to the agent listening at path.
func Call(path string, req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("%w at %s (is it running, and are you root?): %w", ErrNoAgent, path, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(deadline(req.Op)))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("reading the agent's reply: %w", err)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
