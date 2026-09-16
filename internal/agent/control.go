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
	Revoke(id trust.PublicKey, disown []trust.PublicKey) ([]trust.Member, error)
	RevokeSelf() (int, error)
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

// Revoke resolves the target and the nodes to go with it, and signs the
// revocation. Everything named goes out entirely: the identity, the name and
// the overlay slot, and once a checkpoint has ratified it, the records too.
//
// The operator names nodes rather than numbers. What they can see is the nodes
// the cluster is carrying, so that is what the command takes; the identities go
// into the record itself rather than a rule for finding them, because a rule
// would have each node work out its own list and no two of them would then
// attest to the same membership.
//
// A node may be disowned only while this node still holds the record of the
// subject admitting it, which means since the last checkpoint. Once a
// checkpoint has ratified, the membership is stated rather than derived and the
// cluster no longer records who admitted whom, so there is nothing left to
// disown by: that node is revoked in its own right instead. This is the case
// --disown is for anyway -- a member that has just minted identities has just
// admitted them -- and refusing is better than a flag that silently reaches
// less than it did last week.
func (h controlHandler) Revoke(target string, disown []string, all bool) (control.RevokeResult, error) {
	set := h.cluster.Trust()
	id, err := resolve(set, target)
	if err != nil {
		return control.RevokeResult{}, err
	}
	if id == h.cluster.Identity() {
		return control.RevokeResult{}, errors.New("refusing to revoke this node itself")
	}
	if !set.Valid(id) {
		return control.RevokeResult{}, fmt.Errorf("%s is not a member: it has been revoked already, or was never admitted", id.Short())
	}
	admitted := map[trust.PublicKey]bool{}
	for _, other := range set.AdmittedBy(id) {
		admitted[other] = true
	}
	var disowned []trust.PublicKey
	if all {
		if len(disown) > 0 {
			return control.RevokeResult{}, errors.New("disowning everything withdraws every node the subject admitted, so there is nothing left to name")
		}
		for other := range admitted {
			if set.Valid(other) {
				disowned = append(disowned, other)
			}
		}
		slog.Info("disowning every node this agent still holds a record of the subject admitting; "+
			"anything it admitted before the last checkpoint is revoked in its own right",
			"subject", target, "nodes", len(disowned))
	}
	for _, name := range disown {
		other, resErr := resolve(set, name)
		if resErr != nil {
			return control.RevokeResult{}, resErr
		}
		if other == h.cluster.Identity() {
			return control.RevokeResult{}, errors.New("refusing to disown this node itself")
		}
		if !admitted[other] {
			return control.RevokeResult{}, fmt.Errorf("this node holds no record of %s admitting %s, so there is "+
				"nothing to disown it by: either it was admitted by somebody else, or the cluster has agreed on a "+
				"membership since and no longer records who admitted whom. Revoke %s in its own right instead",
				target, name, name)
		}
		disowned = append(disowned, other)
	}
	withdrawn, err := h.cluster.Revoke(id, disowned)
	if err != nil {
		return control.RevokeResult{}, err
	}
	res := control.RevokeResult{Identity: id}
	for _, m := range withdrawn {
		res.Withdrawn = append(res.Withdrawn, control.Member{Identity: m.Identity, Name: m.Name})
	}
	return res, nil
}

// resolve turns what the operator typed into an identity: a name a member goes
// by, or the identity itself.
func resolve(set *trust.Set, target string) (trust.PublicKey, error) {
	if id, err := trust.ParsePublicKey(target); err == nil {
		return id, nil
	}
	m, ok := set.ByName(target)
	if !ok {
		return trust.PublicKey{}, fmt.Errorf("no member named %q (give the identity instead if names are ambiguous)", target)
	}
	return m.Identity, nil
}
