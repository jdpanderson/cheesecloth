package cli

import (
	"net/netip"
	"os"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/jdpanderson/cheesecloth/internal/wg"
)

// StatusCmd shows the live wireguard state of a cheesecloth interface, naming peers
// from the persisted cluster state. Needs the same privileges as the agent.
type StatusCmd struct {
	interfaceFlag
	JSON bool `help:"print the report as JSON"`

	status   func(iface string) (*wg.Report, error) // reports on the interface; nil means wg.Status
	stateDir string                                 // where the agent keeps its state; empty means cluster.DefaultDir
}

func (c *StatusCmd) Run() error {
	status := c.status
	if status == nil {
		status = wg.Status
	}
	report, err := status(c.Interface)
	if err != nil {
		return err
	}
	names := make(map[string]peerInfo) // wireguard public key -> node
	for _, n := range cluster.KnownNodes(c.state(), c.Interface) {
		id := n.Identity
		names[n.PubKey] = peerInfo{Name: n.Name, Identity: &id, Overlay: n.OverlayAddr}
	}
	local, _ := cluster.LocalIdentity(c.state(), c.Interface)
	if c.JSON {
		return renderStatusJSON(os.Stdout, report, local, names)
	}
	return renderStatus(os.Stdout, report, local, names, time.Now())
}

func (c *StatusCmd) state() string { return stateDirOr(c.stateDir) }

// peerInfo is what the cluster state knows about a wireguard peer.
type peerInfo struct {
	Name     string           `json:"name,omitempty"`
	Identity *trust.PublicKey `json:"identity,omitempty"`
	Overlay  netip.Addr       `json:"overlay,omitzero"`
}
