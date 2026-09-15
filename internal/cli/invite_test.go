package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/control"
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

// fakeAgent answers on a control socket the way a running agent would.
type fakeAgent struct {
	ttl    time.Duration
	uses   int
	target string
	force  bool
	left   control.LeaveResult
	err    error
}

func (f *fakeAgent) Invite(ttl time.Duration, uses int) (string, error) {
	f.ttl, f.uses = ttl, uses
	return "TOKEN", f.err
}

func (f *fakeAgent) Revoke(target string) (trust.PublicKey, error) {
	f.target = target
	return key(1), f.err
}

func (f *fakeAgent) Leave(force bool) (control.LeaveResult, error) {
	f.force = force
	switch {
	case f.err != nil:
		return control.LeaveResult{}, f.err
	case f.left != (control.LeaveResult{}):
		return f.left, nil
	}
	return control.LeaveResult{Identity: key(1), Revoked: true, Notified: 3}, nil
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

// listenFakeAgent serves a fake agent on a temp socket and returns its path.
func listenFakeAgent(t *testing.T, agent *fakeAgent) string {
	t.Helper()
	path := filepath.Join(socketDir(t), "ctl.sock")
	srv, err := control.Listen(path, agent)
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	return path
}

// captureOutput runs fn with os.Stdout and os.Stderr redirected.
func captureOutput(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	capture := func(f **os.File) func() string {
		r, w, perr := os.Pipe()
		require.NoError(t, perr)
		orig := *f
		*f = w
		return func() string {
			*f = orig
			_ = w.Close()
			b, _ := io.ReadAll(r)
			return string(b)
		}
	}
	doneOut, doneErr := capture(&os.Stdout), capture(&os.Stderr)
	err = fn()
	return doneOut(), doneErr(), err
}

func Test_InviteCmd_Run(t *testing.T) {
	agent := &fakeAgent{}
	cmd := &InviteCmd{controlFlags: controlFlags{ControlSocket: listenFakeAgent(t, agent)}, TTL: 5 * time.Minute, Uses: 2}
	stdout, stderr, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Equal(t, "TOKEN\n", stdout, "only the token on stdout, for scripts")
	assert.Contains(t, stderr, "valid for 5m0s, 2 use(s)")
	assert.Contains(t, stderr, "--join-key TOKEN")
	assert.Equal(t, 5*time.Minute, agent.ttl)
	assert.Equal(t, 2, agent.uses)

	agent.err = errors.New("no more tokens")
	_, _, err = captureOutput(t, cmd.Run)
	assert.ErrorContains(t, err, "no more tokens")

	cmd.ControlSocket = filepath.Join(t.TempDir(), "absent.sock")
	_, _, err = captureOutput(t, cmd.Run)
	assert.Error(t, err, "no agent running")
}
