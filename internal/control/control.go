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
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// DefaultDir is where the control sockets live; DefaultSocket is the one for iface.
var DefaultDir = paths.RunDir

func DefaultSocket(iface string) string { return filepath.Join(DefaultDir, iface+".sock") }

// Operations a Request may ask for.
const (
	OpInvite = "invite"
	OpRevoke = "revoke"
	OpLeave  = "leave"
)

// readDeadline is how long the agent waits for a request to arrive, before it
// knows which operation the request asks for.
const readDeadline = 10 * time.Second

// deadline is how long one request may take. A leave revokes this node, tells
// the members, tears the interface down and stops the agent; the others are
// answered immediately.
func deadline(op string) time.Duration {
	if op == OpLeave {
		return time.Minute
	}
	return readDeadline
}

// Request is an operator command.
type Request struct {
	Op     string `json:"op"`               // OpInvite, OpRevoke or OpLeave
	TTL    string `json:"ttl,omitempty"`    // invite: token lifetime, a Go duration
	Uses   int    `json:"uses,omitempty"`   // invite: how many nodes may enrol with it
	Target string `json:"target,omitempty"` // revoke: node name or identity
	// Disown names the nodes the subject admitted that the operator does not
	// recognise, by name or identity. They go out with it, identity, name and
	// slot alike. Empty takes the subject alone.
	Disown []string `json:"disown,omitempty"`
	// DisownAll takes every node the agent still holds a record of the subject
	// admitting, which means those admitted since the cluster last agreed a
	// membership. It is what a node that was never to be trusted gets.
	DisownAll bool `json:"disownAll,omitempty"`
	Force     bool `json:"force,omitempty"` // leave: leave even if this node cannot revoke itself
}

// Response carries what one operation produced, or an error message. Each
// operation fills in its own part and leaves the rest empty.
type Response struct {
	Token  string       `json:"token,omitempty"` // invite: the enrolment token
	Revoke RevokeResult `json:"revoke,omitzero"`
	Leave  LeaveResult  `json:"leave,omitzero"`
	Error  string       `json:"error,omitempty"`
}

// RevokeResult is what a revocation did: the identity it named, and the
// members the record takes out along with it, which are the ones the operator
// disowned. They are reported because a revocation cannot be undone and
// nobody asked for those to go.
type RevokeResult struct {
	Identity  trust.PublicKey `json:"identity,omitzero"`
	Withdrawn []Member        `json:"withdrawn,omitempty"`
}

// Member is a node as the records name it, for an operator to read.
type Member struct {
	Identity trust.PublicKey `json:"identity"`
	Name     string          `json:"name"`
}

// LeaveResult is what a leave did: this node's identity, whether it managed
// to revoke it, and how many members were handed the revocation. A node that
// could not revoke itself is still a member as far as the cluster knows, so
// the operator is given the identity to revoke from a member.
type LeaveResult struct {
	Identity trust.PublicKey `json:"identity,omitzero"`
	Revoked  bool            `json:"revoked,omitempty"`
	Notified int             `json:"notified,omitempty"`
}

// Handler performs the operations on behalf of the agent.
type Handler interface {
	Invite(ttl time.Duration, uses int) (string, error)
	// Revoke resolves target to an identity and revokes it. disown names the
	// nodes it admitted that are to go with it, by name or identity. all takes
	// every node the agent still holds a record of it admitting. It returns the
	// identity revoked and the members that went with it.
	Revoke(target string, disown []string, all bool) (RevokeResult, error)
	// Leave revokes this node and stops the agent once it has torn the
	// interface down and forgotten the cluster. With force it leaves even when
	// it cannot revoke itself.
	Leave(force bool) (LeaveResult, error)
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
			_ = conn.SetDeadline(time.Now().Add(readDeadline))
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
		revoked, err := s.handler.Revoke(req.Target, req.Disown, req.DisownAll)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Revoke: revoked}
	case OpLeave:
		left, err := s.handler.Leave(req.Force)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Leave: left}
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
