package cli

import (
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// RevokeCmd removes a node from the membership. The nodes the revoked node
// admitted keep their place unless the operator names them: a revocation marks
// where its subject's records stop, --disown moves that mark below the first
// record that admitted one of the named nodes, and --disown-all moves it below
// everything the node ever signed.
type RevokeCmd struct {
	controlFlags
	Target    string   `arg:"" help:"node name or identity to revoke"`
	Disown    []string `help:"nodes the revoked node admitted that should go with it, by name or identity; everything it signed from the first of them onwards is withdrawn"`
	DisownAll bool     `help:"withdraw everything the revoked node ever signed: every node it admitted goes with it and every revocation it made stops counting"`
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
