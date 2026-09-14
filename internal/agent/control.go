package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// membership is what the control socket needs from a *cluster.Cluster.
type membership interface {
	Invite(ttl time.Duration, uses int) (string, error)
	Revoke(id trust.PublicKey) error
	RevokeSelf() (int, error)
	Prune(dry bool) (cluster.PruneResult, error)
	Trust() *trust.Set
	Identity() trust.PublicKey
}

var _ membership = (*cluster.Cluster)(nil)

// leaving carries a leave request from the control socket into the agent's
// shutdown: the handler stops the agent and waits for it to have torn the
// interface down and forgotten the cluster before the operator is told.
type leaving struct {
	stop      func()        // stops the agent, as a signal does
	done      chan struct{} // closed once the agent has torn down and forgotten the cluster
	requested atomic.Bool
	err       error // what forgetting the cluster ran into; written before done is closed
}

// controlHandler answers the control socket with the cluster, and carries a
// leave into the agent's shutdown.
type controlHandler struct {
	cluster membership
	leaving *leaving
}

func (h controlHandler) Invite(ttl time.Duration, uses int) (string, error) {
	return h.cluster.Invite(ttl, uses)
}

// Leave revokes this node and stops the agent. Without force a node that
// cannot revoke itself stays where it is, rather than leaving a member the
// cluster still trusts without saying so.
func (h controlHandler) Leave(force bool) (control.LeaveResult, error) {
	left := control.LeaveResult{Identity: h.cluster.Identity()}
	notified, err := h.cluster.RevokeSelf()
	if err != nil {
		if !force {
			return control.LeaveResult{}, err
		}
		slog.Warn("leaving the cluster without revoking this node", "err", err)
	} else {
		left.Revoked, left.Notified = true, notified
	}
	h.leaving.requested.Store(true)
	h.leaving.stop()
	<-h.leaving.done
	return left, h.leaving.err
}

// Prune removes the admissions of revoked identities no member's chain runs
// through. The two result types have the same fields, so one becomes the other.
func (h controlHandler) Prune(dry bool) (control.PruneResult, error) {
	res, err := h.cluster.Prune(dry)
	return control.PruneResult(res), err
}

func (h controlHandler) Revoke(target string) (trust.PublicKey, error) {
	id, err := trust.ParsePublicKey(target)
	if err != nil {
		adm, ok := h.cluster.Trust().ByName(target)
		if !ok {
			return trust.PublicKey{}, fmt.Errorf("no member named %q (give the identity instead if names are ambiguous)", target)
		}
		id = adm.Identity
	}
	if id == h.cluster.Identity() {
		return trust.PublicKey{}, errors.New("refusing to revoke this node itself")
	}
	// A second revocation of one identity keeps only what this node has seen it
	// sign, which is no more than the first kept and may be less, so it can take
	// out members the first one left alone. It also costs a record the cluster
	// never gets back.
	if !h.cluster.Trust().Valid(id) {
		return trust.PublicKey{}, fmt.Errorf("%s is not a member: it has been revoked already, or was never admitted", id.Short())
	}
	if err := h.cluster.Revoke(id); err != nil {
		return trust.PublicKey{}, err
	}
	return id, nil
}
