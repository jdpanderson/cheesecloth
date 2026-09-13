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
	behind(pruned)
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

// behind says so when the agent could not see the whole cluster while it
// decided what to remove. A prune acts on the records the agent holds, so one
// run from a node that is out of touch can drop records another node still
// needs, and the two then disagree about who is a member.
func behind(p control.PruneResult) {
	if p.Members == 0 || p.Seen >= p.Members {
		return
	}
	fmt.Fprintf(os.Stderr,
		"warning: this node can reach %d of %d members. Pruning from a node that is out of touch "+
			"can remove records the rest of the cluster still needs; bring it back into contact first, "+
			"or make sure the members it cannot see are gone for good.\n", p.Seen, p.Members)
}
