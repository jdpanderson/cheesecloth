package cli

import (
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// RevokeCmd removes a node from the membership.
type RevokeCmd struct {
	controlFlags
	Target string  `arg:"" help:"node name or identity to revoke"`
	UpTo   *uint64 `help:"keep only the records this node signed up to and including this sequence number; the default keeps everything it signed, and a lower number undoes what it signed after that point"`
}

func (c *RevokeCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpRevoke, Target: c.Target, UpTo: c.UpTo})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "revoked %s (%s)\n", c.Target, resp.Revoked)
	if c.UpTo != nil {
		fmt.Fprintf(os.Stderr, "its records above %d are withdrawn; any node they admitted has to enrol again\n", *c.UpTo)
	}
	return nil
}
