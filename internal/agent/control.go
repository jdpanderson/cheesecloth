package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// membership is what the control socket needs from a *cluster.Cluster.
type membership interface {
	Invite(ttl time.Duration) (string, error)
	Revoke(id trust.PublicKey) ([]trust.Member, error)
	Awaiting() []trust.Awaiting
	Confirm(record trust.Digest) error
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

func (h controlHandler) Invite(ttl time.Duration) (string, error) {
	return h.cluster.Invite(ttl)
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

// Revoke resolves the target and signs the revocation. The subject goes out
// entirely: the identity, the name and the overlay slot, and once a checkpoint
// has ratified it, the records too.
//
// The operator names nodes rather than numbers. What they can see is the nodes
// the cluster is carrying, so that is what the command takes; the identity goes
// into the record itself rather than a rule for finding it, because a rule
// would have each node work out its own answer and no two of them would then
// attest to the same membership. For the same reason one record takes out one
// member: the nodes the subject admitted are members the cluster agreed to in
// their own right, and each is revoked in its own right too.
//
// What does go with the subject is a joiner it vouched for that the cluster has
// not agreed on yet, since nothing else holds that joiner in. The result names
// them, so the operator is told before the signature is spent.
func (h controlHandler) Revoke(target string) (control.RevokeResult, error) {
	set := h.cluster.Trust()
	id, err := resolve(set, target)
	if err != nil {
		return control.RevokeResult{}, err
	}
	if id == h.cluster.Identity() {
		return control.RevokeResult{}, errors.New("refusing to revoke this node itself")
	}
	if set.Revoked(id) {
		return control.RevokeResult{}, fmt.Errorf("%s is not a member for much longer: it has been revoked already, "+
			"and goes as soon as the cluster agrees a membership without it. Revoking it again would cost a record "+
			"the cluster never gets back and change nothing", id.Short())
	}
	if !set.Valid(id) {
		if _, proposed := set.Proposal().Holds(id); !proposed {
			return control.RevokeResult{}, fmt.Errorf("%s is not a member and was never admitted", id.Short())
		}
	}
	withdrawn, err := h.cluster.Revoke(id)
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
	if m, ok := set.ByName(target); ok {
		return m.Identity, nil
	}
	// A node the cluster has agreed to admit but not yet agreed on has a name
	// and no membership to look it up in. It can still be revoked, which is
	// what stops it becoming a member at all.
	for _, m := range set.Proposal().Members {
		if m.Name == target {
			return m.Identity, nil
		}
	}
	return trust.PublicKey{}, fmt.Errorf("no member named %q (give the identity instead)", target)
}

// Pending is the records the cluster is holding until enough members confirm
// them. It is the list an operator reads before deciding to.
func (h controlHandler) Pending() ([]control.PendingRecord, error) {
	return pendingRecords(h.cluster.Awaiting(), h.cluster.Identity()), nil
}

// Confirm signs this node's agreement with one waiting record, named by the
// subject's name, its identity, or the record's own digest.
func (h controlHandler) Confirm(target string) (control.PendingRecord, error) {
	waiting := h.cluster.Awaiting()
	var match []trust.Awaiting
	for _, w := range waiting {
		if w.Name == target || w.Identity.String() == target ||
			strings.HasPrefix(w.Record.String(), target) {
			match = append(match, w)
		}
	}
	switch len(match) {
	case 1:
	case 0:
		if len(waiting) == 0 {
			return control.PendingRecord{}, errors.New("nothing is waiting to be confirmed")
		}
		return control.PendingRecord{}, fmt.Errorf("nothing waiting matches %q; "+
			"'cheesecloth confirm' with no argument lists what is", target)
	default:
		return control.PendingRecord{}, fmt.Errorf("%q matches %d waiting records; name one by its record id, "+
			"which 'cheesecloth confirm' with no argument lists", target, len(match))
	}
	if err := h.cluster.Confirm(match[0].Record); err != nil {
		return control.PendingRecord{}, err
	}
	// What the record has now, rather than one more than it had: this node's
	// confirmation may have been the last one it needed, and another member's
	// may have arrived while this one was being signed.
	self := h.cluster.Identity()
	for _, w := range h.cluster.Awaiting() {
		if w.Record == match[0].Record {
			return pendingRecords([]trust.Awaiting{w}, self)[0], nil
		}
	}
	done := pendingRecords(match, self)[0]
	done.Waiting = false
	return done, nil
}

// pendingRecords is the wire form of what is waiting.
func pendingRecords(waiting []trust.Awaiting, self trust.PublicKey) []control.PendingRecord {
	out := make([]control.PendingRecord, 0, len(waiting))
	for _, w := range waiting {
		out = append(out, control.PendingRecord{
			Record: w.Record.String(), Kind: w.Kind, Identity: w.Identity,
			Name: w.Name, Signer: w.Signer, Have: w.Have, Need: w.Need,
			SignedHere: w.Signer == self, Waiting: true,
		})
	}
	return out
}
