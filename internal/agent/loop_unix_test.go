//go:build unix

package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// socketDir is a short-lived directory for sockets. t.TempDir() names the
// test in the path, which pushes a socket past the platform's path limit.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func Test_agent_loop_notifiesSystemd(t *testing.T) {
	path := filepath.Join(socketDir(t), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	t.Setenv("NOTIFY_SOCKET", path)
	read := func() string {
		buf := make([]byte, 1024)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, rerr := conn.Read(buf)
		require.NoError(t, rerr)
		return string(buf[:n])
	}

	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	cancel, errc := runLoop(t, &agent{Config: Config{OverlayNet: testOverlay, NoEtcHosts: true}}, cl, &fakeWG{}, &fakeHosts{}, notify.Systemd{})

	cl.ch <- nil // a lone node: ready with no peers
	assert.Equal(t, "READY=1\nSTATUS=0 peers", read())
	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	assert.Equal(t, "STATUS=1 peers", read())
	cancel()
	assert.Equal(t, "STOPPING=1", read())
	require.NoError(t, waitErr(t, errc))
}
