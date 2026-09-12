//go:build windows

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/paths"
	"golang.org/x/sys/windows/svc"
)

// Execute runs the parsed command. Under the Service Control Manager the
// agent runs as a service: it reports its state to the manager, stops when
// the manager says so, and logs to a file, since a service has no console.
// Started from a console it behaves as on any other platform.
func Execute(c *CLI, ktx *kong.Context) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("asking whether this is a service: %w", err)
	}
	if !isService {
		return run(ktx, context.Background(), notify.Default())
	}
	level, err := c.LogLevel.Level()
	if err != nil {
		return err
	}
	logFile, err := openLog(level)
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()
	return svc.Run(ServiceName, &service{run: func(ctx context.Context, n notify.Notifier) error {
		return run(ktx, ctx, n)
	}})
}

// openLog sends the default logger to the agent's log file in the state directory.
func openLog(level slog.Level) (*os.File, error) {
	if err := os.MkdirAll(paths.StateDir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(paths.StateDir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening the log file: %w", err)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: level})))
	return f, nil
}

// service is the svc.Handler: it runs the command with an SCM notifier and a
// context the manager's stop request cancels. The command is held as a
// function rather than as the parsed context it comes from, so that the
// exchange with the manager can be driven by a test.
type service struct {
	run func(ctx context.Context, n notify.Notifier) error
}

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, notify.SCM{Changes: changes}) }()
	for {
		select {
		case err := <-done:
			changes <- svc.Status{State: svc.Stopped}
			if err != nil {
				slog.Error("the service failed", "err", err)
				return true, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				changes <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
			}
		}
	}
}
