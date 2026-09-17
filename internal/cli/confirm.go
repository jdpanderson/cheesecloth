package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// ConfirmCmd agrees that a record the cluster is holding should count. Where
// the cluster asks for confirmations, an admission or a revocation does nothing
// until enough members have agreed with it, and this is how a member agrees.
// With no target it lists what is waiting, which is what an operator reads
// before deciding.
type ConfirmCmd struct {
	controlFlags
	Target string `arg:"" optional:"" help:"node name, identity or record id to confirm; omit to list what is waiting"`
}

func (c *ConfirmCmd) Run() error {
	op := control.OpPending
	if c.Target != "" {
		op = control.OpConfirm
	}
	resp, err := control.Call(c.socket(), control.Request{Op: op, Target: c.Target})
	if err != nil {
		return err
	}
	if c.Target != "" {
		for _, p := range resp.Pending {
			fmt.Fprintf(os.Stderr, "confirmed the %s of %s (%s); it had %d of the %d it needs, and now has %d\n",
				p.Kind, p.Name, p.Identity.Short(), p.Have, p.Need, p.Have+1)
		}
		return nil
	}
	if len(resp.Pending) == 0 {
		fmt.Fprintln(os.Stderr, "nothing is waiting to be confirmed")
		return nil
	}
	// The record id is what names one unambiguously, so it is what the operator
	// is shown to type back. tabwriter reports write errors from Flush, so the
	// per-row results are dropped.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "RECORD\tWHAT\tNODE\tIDENTITY\tSIGNED BY\tCONFIRMED")
	for _, p := range resp.Pending {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d of %d\n",
			p.Record[:8], p.Kind, p.Name, p.Identity.Short(), p.Signer.Short(), p.Have, p.Need)
	}
	return w.Flush()
}
