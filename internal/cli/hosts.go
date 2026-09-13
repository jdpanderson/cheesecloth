package cli

import (
	"github.com/jdpanderson/cheesecloth/internal/etchosts"
)

// hostsFor writes the hosts entries of one interface. The banner marks the
// block as that interface's, so agents for different clusters, and a leave,
// only ever touch their own entries.
func hostsFor(iface string) *etchosts.EtcHosts {
	return &etchosts.EtcHosts{
		Banner: "# ! managed automatically by cheesecloth interface " + iface,
	}
}
