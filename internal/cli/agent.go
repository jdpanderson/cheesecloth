package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jdpanderson/cheesecloth/internal/agent"
	"github.com/jdpanderson/cheesecloth/internal/notify"
)

// AgentCmd is the long-running daemon: it joins the cluster and keeps the
// wireguard interface and /etc/hosts in step with the membership.
type AgentCmd struct {
	settings `embed:""`
	JoinKey  string `help:"invitation token from 'cheesecloth invite' on a member, needed only the first time this node joins"`
}

func (a *AgentCmd) Validate() error { return a.config().Check() }

// config is what the agent runs with: the settings, and the join key that
// is given on the command line alone.
func (a *AgentCmd) config() agent.Config {
	cfg := a.settings.config()
	cfg.JoinKey = a.JoinKey
	return cfg
}

// Run runs the agent until SIGTERM/SIGINT or ctx is done, reporting to the
// service manager through n.
func (a *AgentCmd) Run(ctx context.Context, n notify.Notifier) error {
	ctx, cancelSignals := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer cancelSignals()
	return agent.Run(ctx, a.config(), n)
}
