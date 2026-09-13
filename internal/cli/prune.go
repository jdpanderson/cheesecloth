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
	pruned := resp.Prune
	if len(pruned.Identities) == 0 {
		fmt.Fprintf(os.Stderr, "nothing to prune: every record the cluster holds is still needed\n")
		return nil
	}
	// the identities go to stdout, so they can be piped somewhere
	lines := make([]string, len(pruned.Identities))
	for i, id := range pruned.Identities {
		lines[i] = id.String()
	}
	if _, err := io.WriteString(os.Stdout, strings.Join(lines, "\n")+"\n"); err != nil {
		return err
	}
	if c.DryRun {
		fmt.Fprintf(os.Stderr, "%d identities would be pruned from %d records; run without --dry-run to do it\n",
			len(lines), pruned.Before)
		return nil
	}
	fmt.Fprintf(os.Stderr, "pruned %d identities: %d records, down from %d\n", len(lines), pruned.After, pruned.Before)
	return nil
}
