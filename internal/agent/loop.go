package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
)

// clusterController, wgController and hostsWriter are the parts of the
// cluster, wg and etchosts packages the agent loop drives; they exist so the
// loop can be tested with fakes.
type clusterController interface {
	Members() <-chan []overlay.Node
	Stranded() bool
	Leave()
}

type wgController interface {
	SetUpInterface([]overlay.Node) error
	DownInterface() error
}

type hostsWriter interface {
	WriteEntries(map[string][]string) error
}

// loop applies each membership update until ctx is done, then leaves and
// tears down. The service manager is told the service is ready once the
// interface has been configured from the first snapshot, and kept posted on
// the peer count.
func (a *agent) loop(ctx context.Context, peerc <-chan []overlay.Node, cl clusterController, wgstate wgController, hosts hostsWriter, n notify.Notifier) error {
	slog.Debug("waiting for cluster events")
	report := n.Ready
	for {
		select {
		case peers, ok := <-peerc:
			if !ok {
				return errors.New("cluster membership channel closed")
			}
			// The service manager's line is where an operator looks first, so
			// a node that cannot catch up says so there as well as in the log.
			status := fmt.Sprintf("%d peers", a.apply(peers, wgstate, hosts))
			if cl.Stranded() {
				status += "; offered a membership this node cannot verify, see the log"
			}
			if err := report(status); err != nil {
				slog.Warn("could not notify the service manager", "err", err)
			}
			report = n.Status
		case <-ctx.Done():
			slog.Info("terminating")
			if err := n.Stopping(); err != nil {
				slog.Warn("could not notify the service manager", "err", err)
			}
			cl.Leave()
			if !a.NoEtcHosts {
				if err := hosts.WriteEntries(map[string][]string{}); err != nil {
					slog.Error("could not remove stale hosts entries", "err", err)
				}
			}
			if err := wgstate.DownInterface(); err != nil {
				return fmt.Errorf("downing interface: %w", err)
			}
			return nil
		}
	}
}

// apply pushes one membership snapshot, already verified by the cluster, to
// wireguard and /etc/hosts and returns the number of peers installed. A
// network advertised by more than one node goes to the first by name, so
// every snapshot resolves the same way; sorted here rather than assumed. The
// nodes' route slices are shared with the cluster, which persists them, so
// they are filtered into new slices rather than in place.
func (a *agent) apply(peers []overlay.Node, wgstate wgController, hosts hostsWriter) int {
	hostEntries := make(map[string][]string, len(peers))
	routedBy := map[netip.Prefix]string{}
	slices.SortFunc(peers, func(x, y overlay.Node) int { return strings.Compare(x.Name, y.Name) })
	for i := range peers {
		node := &peers[i]
		var routes []netip.Prefix
		for _, p := range node.AllowedIPs {
			switch by, taken := routedBy[p]; {
			case p.Overlaps(a.OverlayNet):
				slog.Warn("ignoring advertised network inside the overlay net", "name", node.Name, "net", p)
			case taken:
				slog.Warn("network advertised by two nodes, keeping the first", "net", p, "kept", by, "ignored", node.Name)
			default:
				routedBy[p] = node.Name
				routes = append(routes, p)
			}
		}
		node.AllowedIPs = routes
		slog.Info("cluster member", "addr", node.Addr, "overlay", node.OverlayAddr, "pubkey", node.PubKey, "routes", node.AllowedIPs)
		hostEntries[node.OverlayAddr.String()] = []string{node.Name}
	}
	if err := wgstate.SetUpInterface(peers); err != nil {
		slog.Error("could not up interface", "err", err)
		if err := wgstate.DownInterface(); err != nil {
			slog.Warn("could not down interface after failed setup", "err", err)
		}
	}
	if !a.NoEtcHosts {
		if err := hosts.WriteEntries(hostEntries); err != nil {
			slog.Error("could not write hosts entries", "err", err)
		}
	}
	return len(peers)
}
