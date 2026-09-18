package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/tally"
)

// retryEvery is how often a snapshot the interface would not take is stated
// again. Nothing else would state it: a membership that does not change
// produces no further snapshots, and the cluster's own syncs signal only when
// they carry something new, so a node that failed once would stay off the mesh
// until the membership happened to change.
const retryEvery = 30 * time.Second

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
// tears down. The service manager is told the service is ready once the first
// snapshot has been acted on, and kept posted on the peer count and on
// anything an operator would want to know about.
func (a *agent) loop(ctx context.Context, peerc <-chan []overlay.Node, cl clusterController, wgstate wgController, hosts hostsWriter, n notify.Notifier) error {
	slog.Debug("waiting for cluster events")
	report := n.Ready
	// A snapshot the interface would not take is held and stated again until
	// it does: the interface goes on carrying what it last took, so the node
	// keeps the peers it had rather than losing them to a fault in one of
	// them.
	var held []overlay.Node
	var retry <-chan time.Time
	// The same failure for as long as its cause lasts, so it is written at
	// this node's rate rather than once per attempt.
	var refused tally.Counter
	settle := func() {
		peers, err := a.apply(held, wgstate, hosts)
		// The service manager's line is where an operator looks first, so what
		// is wrong is said there as well as in the log.
		status := fmt.Sprintf("%d peers", peers)
		if err != nil {
			refused.Note("the wireguard interface would not take this membership; it keeps the one it last "+
				"took, and this node states it again until it does", "iface", a.Interface, "every", a.retry(), "err", err)
			status += "; the interface could not be configured, see the log"
			retry = time.After(a.retry())
		} else {
			retry = nil
		}
		if cl.Stranded() {
			status += "; offered a membership this node cannot verify, see the log"
		}
		if nerr := report(status); nerr != nil {
			slog.Warn("could not notify the service manager", "err", nerr)
		}
		report = n.Status
	}
	for {
		select {
		case peers, ok := <-peerc:
			if !ok {
				return errors.New("cluster membership channel closed")
			}
			held = peers
			settle()
		case <-retry:
			settle()
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
// wireguard and /etc/hosts. It returns the number of peers in the snapshot and
// what the interface made of it; a snapshot it would not take is the caller's
// to state again. A network advertised by more than one node goes to the first
// by name, so every snapshot resolves the same way; sorted here rather than
// assumed. The nodes' route slices are shared with the cluster, which persists
// them, so they are filtered into new slices rather than in place.
func (a *agent) apply(peers []overlay.Node, wgstate wgController, hosts hostsWriter) (int, error) {
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
	// A refused snapshot costs the snapshot, not the interface: removing it
	// would take every peer's tunnel down over a fault that may be in one of
	// them, or in one attribute of the device, and there would be nothing to
	// route over while the node waited to be told the membership again. It is
	// the same answer the routes take one step further in.
	err := wgstate.SetUpInterface(peers)
	if !a.NoEtcHosts {
		if werr := hosts.WriteEntries(hostEntries); werr != nil {
			slog.Error("could not write hosts entries", "err", werr)
		}
	}
	return len(peers), err
}
