package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// InviteCmd mints an enrolment token on the running agent. One invitation
// admits one node; adding another node means another invitation.
type InviteCmd struct {
	controlFlags
	TTL time.Duration `help:"how long the token stays valid" default:"10m"`
}

func (c *InviteCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpInvite, TTL: c.TTL.String()})
	if err != nil {
		return err
	}
	fmt.Println(resp.Token)
	fmt.Fprintf(os.Stderr, "valid for %s, and admits one node. On the new node:\n  cheesecloth --join <this host> --join-key %s\n", c.TTL, resp.Token)
	return nil
}
