package cli

import (
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// RevokeCmd removes a node from the membership. One record takes out one
// member: the nodes it admitted are members in their own right and keep their
// place, so removing several of them is several revocations. A joiner the
// cluster has not yet agreed on is the exception, and goes with the node that
// vouched for it -- the agent says so before it signs.
type RevokeCmd struct {
	controlFlags
	Target string `arg:"" help:"node name or identity to revoke"`
}

func (c *RevokeCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpRevoke, Target: c.Target})
	if err != nil {
		return err
	}
	revoked := resp.Revoke
	fmt.Fprintf(os.Stderr, "revoked %s (%s)\n", c.Target, revoked.Identity)
	if len(revoked.Withdrawn) == 0 {
		return nil
	}
	// joiners this node vouched for that the cluster had not agreed on yet:
	// nothing else holds them in, so they go with it
	fmt.Fprintf(os.Stderr, "%d node(s) it admitted are withdrawn with it and have to enrol again:\n", len(revoked.Withdrawn))
	for _, w := range revoked.Withdrawn {
		fmt.Fprintf(os.Stderr, "  %s (%s)\n", w.Name, w.Identity)
	}
	return nil
}
