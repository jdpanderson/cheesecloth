package cli

import "github.com/jdpanderson/cheesecloth/internal/control"

// interfaceFlag names the agent a command addresses, by its wireguard interface.
type interfaceFlag struct {
	Interface string `help:"wireguard interface of the agent" default:"${default_interface}"`
}

// controlFlags are shared by the commands that talk to a running agent.
type controlFlags struct {
	interfaceFlag
	ControlSocket string `help:"agent control socket (default /run/cheesecloth/<interface>.sock)"`
}

func (c *controlFlags) socket() string { return socketFor(c.Interface, c.ControlSocket) }

// socketFor is the control socket of the agent for iface, unless one is given explicitly.
func socketFor(iface, explicit string) string {
	if explicit != "" {
		return explicit
	}
	return control.DefaultSocket(iface)
}
