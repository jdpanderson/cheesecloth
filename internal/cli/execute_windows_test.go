//go:build windows

package cli

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc"
)

// serviceResult is what svc.Run is told when the handler returns.
type serviceResult struct {
	specific bool
	code     uint32
}

// runService starts the handler with channels of the test's own, as the
// service manager would.
func runService(t *testing.T, s *service) (chan<- svc.ChangeRequest, <-chan svc.Status, <-chan serviceResult) {
	t.Helper()
	requests := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status, 16)
	done := make(chan serviceResult, 1)
	go func() {
		specific, code := s.Execute(nil, requests, changes)
		done <- serviceResult{specific, code}
	}()
	return requests, changes, done
}

// nextStatus is the next state reported to the manager.
func nextStatus(t *testing.T, changes <-chan svc.Status) svc.Status {
	t.Helper()
	select {
	case s := <-changes:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the service reported nothing to the manager")
		return svc.Status{}
	}
}

func waitResult(t *testing.T, done <-chan serviceResult) serviceResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the service did not return")
		return serviceResult{}
	}
}

// The whole exchange with the service manager: the agent reports it is
// starting, then running once it is up, and a stop request cancels its
// context so it can tear down before the service reports itself stopped.
func Test_service_Execute_startsAndStops(t *testing.T) {
	running := make(chan struct{})
	s := &service{run: func(ctx context.Context, n notify.Notifier) error {
		assert.NoError(t, n.Ready("up"))
		close(running)
		<-ctx.Done() // the stop request reaches the agent as a cancelled context
		return n.Stopping()
	}}
	requests, changes, done := runService(t, s)

	assert.Equal(t, svc.StartPending, nextStatus(t, changes).State)
	<-running
	up := nextStatus(t, changes)
	assert.Equal(t, svc.Running, up.State)
	assert.Equal(t, svc.AcceptStop|svc.AcceptShutdown, up.Accepts, "the manager is told it may stop the service")

	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	assert.Equal(t, svc.StopPending, nextStatus(t, changes).State)
	assert.Equal(t, svc.Stopped, nextStatus(t, changes).State)
	assert.Equal(t, serviceResult{false, 0}, waitResult(t, done), "a clean stop is not a service failure")
}

// Shutdown is a stop like any other: the machine is going down and the agent
// still has an interface to take with it.
func Test_service_Execute_shutdown(t *testing.T) {
	s := &service{run: func(ctx context.Context, _ notify.Notifier) error {
		<-ctx.Done()
		return nil
	}}
	requests, changes, done := runService(t, s)

	assert.Equal(t, svc.StartPending, nextStatus(t, changes).State)
	requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
	assert.Equal(t, svc.Stopped, nextStatus(t, changes).State)
	assert.Equal(t, serviceResult{false, 0}, waitResult(t, done))
}

// The manager asks what the state is from time to time; the answer is the
// state it was last told, and the service carries on.
func Test_service_Execute_interrogate(t *testing.T) {
	s := &service{run: func(ctx context.Context, _ notify.Notifier) error {
		<-ctx.Done()
		return nil
	}}
	requests, changes, done := runService(t, s)
	assert.Equal(t, svc.StartPending, nextStatus(t, changes).State)

	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop}
	requests <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: current}
	assert.Equal(t, current, nextStatus(t, changes), "the state is echoed back unchanged")

	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	assert.Equal(t, svc.Stopped, nextStatus(t, changes).State)
	assert.Equal(t, serviceResult{false, 0}, waitResult(t, done))
}

// A command that is not a stop request leaves the service where it is.
func Test_service_Execute_ignoresOtherCommands(t *testing.T) {
	s := &service{run: func(ctx context.Context, _ notify.Notifier) error {
		<-ctx.Done()
		return nil
	}}
	requests, changes, done := runService(t, s)
	assert.Equal(t, svc.StartPending, nextStatus(t, changes).State)

	requests <- svc.ChangeRequest{Cmd: svc.Pause}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	assert.Equal(t, svc.Stopped, nextStatus(t, changes).State, "the pause was ignored, the stop was not")
	assert.Equal(t, serviceResult{false, 0}, waitResult(t, done))
}

// An agent that fails reports the service as failed, so the manager can
// restart it or say so, rather than looking as though it stopped on purpose.
func Test_service_Execute_reportsAFailedAgent(t *testing.T) {
	s := &service{run: func(context.Context, notify.Notifier) error {
		return errors.New("no wireguard")
	}}
	_, changes, done := runService(t, s)

	assert.Equal(t, svc.StartPending, nextStatus(t, changes).State)
	assert.Equal(t, svc.Stopped, nextStatus(t, changes).State)
	assert.Equal(t, serviceResult{true, 1}, waitResult(t, done))
}

// A service has no console, so the log goes to a file in the state
// directory, which is made if it is not there.
func Test_openLog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	defer swapStateDir(t, dir)()
	defer swapDefaultLogger(t)()

	f, err := openLog(slog.LevelWarn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	path := filepath.Join(dir, "agent.log")
	require.FileExists(t, path)
	slog.Warn("a message", "key", "value")
	slog.Debug("below the level")
	require.NoError(t, f.Sync())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "a message")
	assert.Contains(t, string(content), "key=value")
	assert.NotContains(t, string(content), "below the level", "the level given is the one the file is written at")
}

// A second start appends rather than starting the file over, so what the
// last run logged before it failed is still there.
func Test_openLog_appends(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	defer swapStateDir(t, dir)()
	defer swapDefaultLogger(t)()

	first, err := openLog(slog.LevelInfo)
	require.NoError(t, err)
	slog.Info("from the first run")
	require.NoError(t, first.Close())

	second, err := openLog(slog.LevelInfo)
	require.NoError(t, err)
	slog.Info("from the second run")
	require.NoError(t, second.Close())

	content, err := os.ReadFile(filepath.Join(dir, "agent.log"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "from the first run")
	assert.Contains(t, string(content), "from the second run")
}

func Test_openLog_reportsAnUnusableDirectory(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	defer swapStateDir(t, filepath.Join(blocker, "state"))()

	_, err := openLog(slog.LevelWarn)
	assert.Error(t, err, "a file where the state directory should be")
}

// swapStateDir points the state directory at dir until the returned function
// puts it back.
func swapStateDir(t *testing.T, dir string) func() {
	t.Helper()
	was := paths.StateDir
	paths.StateDir = dir
	return func() { paths.StateDir = was }
}

// swapDefaultLogger restores the default logger, which openLog replaces.
func swapDefaultLogger(t *testing.T) func() {
	t.Helper()
	was := slog.Default()
	return func() { slog.SetDefault(was) }
}
