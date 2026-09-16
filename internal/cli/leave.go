package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/agent"
	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/jdpanderson/cheesecloth/internal/wg"
)

// LeaveCmd takes this node out of its cluster for good: the running agent
// revokes this node's identity, hands the revocation to the members, tears
// the interface down and deletes the state file. Any node may leave this way,
// the root included. With --force it leaves without telling the cluster, which
// is the only way out for a node whose agent is no longer running.
type LeaveCmd struct {
	controlFlags
	Force bool `help:"leave even when the cluster cannot be told, such as when no agent is running to sign the revocation"`

	stateDir string      // where the agent keeps its state; empty means cluster.DefaultDir
	hosts    hostsWriter // this interface's hosts entries; nil means the hosts file
}

// hostsWriter is the part of the hosts file a leave uses.
type hostsWriter interface {
	WriteEntries(map[string][]string) error
}

func (c *LeaveCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpLeave, Force: c.Force})
	switch {
	case err == nil:
		return c.report(resp)
	case !errors.Is(err, control.ErrNoAgent):
		if !c.Force {
			return fmt.Errorf("%w\nthe agent stays where it is; --force leaves without telling the cluster", err)
		}
		// --force is "take this node out without telling the cluster", so an
		// agent that answered and could not do it is no more a reason to stop
		// than one that did not answer at all. An agent that is a member of
		// nothing refuses, and this is the command that gets such a node back
		// to a state it can enrol from.
		fmt.Fprintf(os.Stderr, "the agent did not take this node out of the cluster: %v\nleaving anyway, since --force was given\n", err)
	case !c.Force:
		return fmt.Errorf("%w\nstart it so the cluster can be told this node is leaving, or use --force to remove this node's state without telling it", err)
	}
	return c.forced()
}

// report says what the agent did. A node the cluster was not told about is
// still a member as far as every peer is concerned, so the operator is given
// the identity and how to get rid of it.
func (c *LeaveCmd) report(resp control.Response) error {
	left := resp.Leave
	switch {
	case left.Revoked && left.Notified > 0:
		fmt.Fprintf(os.Stderr, "left the cluster: revoked %s, %d member(s) told\n", left.Identity, left.Notified)
	case left.Revoked:
		fmt.Fprintf(os.Stderr, "left the cluster: revoked %s, but no member could be reached\n", left.Identity)
		c.stillTrusted(left.Identity)
	default:
		fmt.Fprintf(os.Stderr, "left the cluster without revoking %s\n", left.Identity)
		c.stillTrusted(left.Identity)
	}
	fmt.Fprintf(os.Stderr, "the agent has stopped and its state for %s is gone\n", c.Interface)
	return nil
}

// forced removes what a stopped agent left behind. Nothing is told to the
// cluster: there is no agent to tell it with.
func (c *LeaveCmd) forced() error {
	identity, known := cluster.LocalIdentity(c.state(), c.Interface)
	if err := c.removeLeftovers(); err != nil {
		return err
	}
	if !known {
		fmt.Fprintf(os.Stderr, "no state for %s; removed the interface and hosts entries, if any\n", c.Interface)
		return nil
	}
	fmt.Fprintf(os.Stderr, "removed this node's state for %s\n", c.Interface)
	c.stillTrusted(identity)
	return nil
}

// removeLeftovers deletes the interface, the hosts entries and the state of an
// interface whose agent is not running.
func (c *LeaveCmd) removeLeftovers() error {
	if err := wg.Remove(c.Interface); err != nil {
		return err
	}
	hosts := c.hosts
	if hosts == nil {
		hosts = agent.HostsFor(c.Interface)
	}
	if err := hosts.WriteEntries(map[string][]string{}); err != nil {
		return fmt.Errorf("removing hosts entries: %w", err)
	}
	return cluster.Forget(c.state(), c.Interface)
}

func (c *LeaveCmd) state() string { return stateDirOr(c.stateDir) }

func (c *LeaveCmd) stillTrusted(identity trust.PublicKey) {
	fmt.Fprintf(os.Stderr, "the cluster still trusts this node: run 'cheesecloth revoke %s' on a member\n", identity)
}
