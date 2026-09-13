package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// interfaceFlag names the agent a command addresses, by its wireguard interface.
type interfaceFlag struct {
	Interface string `help:"wireguard interface of the agent" default:"${default_interface}"`
}

// controlFlags are shared by the commands that talk to a running agent.
type controlFlags struct {
	interfaceFlag
	ControlSocket string `help:"agent control socket (default /run/cheesecloth/<interface>.sock)"`
}

func (c *controlFlags) socket() string { return socketFor(c.Interface, c.ControlSocket) }

// socketFor is the control socket of the agent for iface, unless one is given explicitly.
func socketFor(iface, explicit string) string {
	if explicit != "" {
		return explicit
	}
	return control.DefaultSocket(iface)
}

// membership is what agentControl needs from a *cluster.Cluster.
type membership interface {
	Invite(ttl time.Duration, uses int) (string, error)
	Revoke(id trust.PublicKey) error
	RevokeSelf() (int, error)
	Prune(dry bool) (cluster.PruneResult, error)
	Trust() *trust.Set
	Identity() trust.PublicKey
}

var _ membership = (*cluster.Cluster)(nil)

// leaving carries a leave request from the control socket into the agent's
// shutdown: the handler stops the agent and waits for it to have torn the
// interface down and forgotten the cluster before the operator is told.
type leaving struct {
	stop      func()        // stops the agent, as a signal does
	done      chan struct{} // closed once the agent has torn down and forgotten the cluster
	requested atomic.Bool
	err       error // what forgetting the cluster ran into; written before done is closed
}

// agentControl adapts a Cluster to the control.Handler interface.
type agentControl struct {
	cluster membership
	leaving *leaving
}

func (a agentControl) Invite(ttl time.Duration, uses int) (string, error) {
	return a.cluster.Invite(ttl, uses)
}

// Leave revokes this node and stops the agent. Without force a node that
// cannot revoke itself stays where it is, rather than leaving a member the
// cluster still trusts without saying so.
func (a agentControl) Leave(force bool) (control.LeaveResult, error) {
	left := control.LeaveResult{Identity: a.cluster.Identity()}
	notified, err := a.cluster.RevokeSelf()
	if err != nil {
		if !force {
			return control.LeaveResult{}, err
		}
		slog.Warn("leaving the cluster without revoking this node", "err", err)
	} else {
		left.Revoked, left.Notified = true, notified
	}
	a.leaving.requested.Store(true)
	a.leaving.stop()
	<-a.leaving.done
	return left, a.leaving.err
}

// Prune removes the admissions of revoked identities no member's chain runs
// through. The two result types have the same fields, so one becomes the other.
func (a agentControl) Prune(dry bool) (control.PruneResult, error) {
	res, err := a.cluster.Prune(dry)
	return control.PruneResult(res), err
}

func (a agentControl) Revoke(target string) (trust.PublicKey, error) {
	id, err := trust.ParsePublicKey(target)
	if err != nil {
		adm, ok := a.cluster.Trust().ByName(target)
		if !ok {
			return trust.PublicKey{}, fmt.Errorf("no member named %q (give the identity instead if names are ambiguous)", target)
		}
		id = adm.Identity
	}
	if id == a.cluster.Identity() {
		return trust.PublicKey{}, errors.New("refusing to revoke this node itself")
	}
	if err := a.cluster.Revoke(id); err != nil {
		return trust.PublicKey{}, err
	}
	return id, nil
}
