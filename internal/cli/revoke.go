package cli

import (
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// RevokeCmd removes a node from the membership. The nodes the revoked node
// admitted keep their place unless the operator names them: the record carries
// the identities that go with its subject, so naming one reaches it whatever
// else vouches for it. --disown-all names every node this agent still holds a
// record of the subject admitting.
type RevokeCmd struct {
	controlFlags
	Target    string   `arg:"" help:"node name or identity to revoke"`
	Disown    []string `help:"nodes admitted by the revoked node that should go with it, by name or identity"`
	DisownAll bool     `help:"take out every node this agent still holds a record of the revoked node admitting"`
}

func (c *RevokeCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpRevoke, Target: c.Target, Disown: c.Disown, DisownAll: c.DisownAll})
	if err != nil {
		return err
	}
	revoked := resp.Revoke
	fmt.Fprintf(os.Stderr, "revoked %s (%s)\n", c.Target, revoked.Identity)
	if len(revoked.Withdrawn) == 0 {
		return nil
	}
	// what the mark took besides the node named: the operator asked for some of
	// them and the cluster worked out the rest, so all of them are listed
	fmt.Fprintf(os.Stderr, "%d node(s) it admitted are withdrawn with it and have to enrol again:\n", len(revoked.Withdrawn))
	for _, w := range revoked.Withdrawn {
		fmt.Fprintf(os.Stderr, "  %s (%s)\n", w.Name, w.Identity)
	}
	return nil
}
