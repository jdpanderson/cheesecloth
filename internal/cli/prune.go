package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// PruneCmd removes the records of identities the cluster no longer needs.
type PruneCmd struct {
	controlFlags
	DryRun bool `help:"report what would be removed without signing anything"`
}

func (c *PruneCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpPrune, DryRun: c.DryRun})
	if err != nil {
		return err
	}
	if len(resp.Pruned) == 0 {
		fmt.Fprintf(os.Stderr, "nothing to prune: every record the cluster holds is still needed\n")
		return nil
	}
	// the identities go to stdout, so they can be piped somewhere
	if _, err := io.WriteString(os.Stdout, strings.Join(resp.Pruned, "\n")+"\n"); err != nil {
		return err
	}
	if c.DryRun {
		fmt.Fprintf(os.Stderr, "%d identities would be pruned from %d records; run without --dry-run to do it\n",
			len(resp.Pruned), resp.Before)
		return nil
	}
	fmt.Fprintf(os.Stderr, "pruned %d identities: %d records, down from %d\n", len(resp.Pruned), resp.After, resp.Before)
	return nil
}
