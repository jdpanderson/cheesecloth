package cli

import (
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// RevokeCmd removes a node from the membership.
type RevokeCmd struct {
	controlFlags
	Target string `arg:"" help:"node name or identity to revoke"`
}

func (c *RevokeCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpRevoke, Target: c.Target})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "revoked %s (%s)\n", c.Target, resp.Revoked)
	return nil
}
