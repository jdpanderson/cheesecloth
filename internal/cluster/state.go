package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/paths"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// state is what a node persists: its identity seed, the membership it trusts
// and the peers it last saw, so it can restart unattended.
type state struct {
	Seed       []byte       `json:"seed"`
	OverlayNet netip.Prefix `json:"overlayNet,omitzero"` // the cluster's, so no flag is needed to restart
	// Anchor is the deepest checkpoint this node has verified. A restart starts
	// there rather than walking the whole history again, which is what lets the
	// history be thrown away; see trust.Set.Anchor.
	Anchor  *trust.Checkpoint `json:"anchor,omitempty"`
	Records trust.Records     `json:"records"`
	Peers   []overlay.Node    `json:"peers"`
}

// DefaultDir is where the agent keeps state unless told otherwise.
var DefaultDir = paths.StateDir

// statePath is where the state named name is kept under dir.
func statePath(dir, name string) string { return filepath.Join(dir, name+".json") }

// save writes the state atomically: a reader (the status command, or a
// restart after a crash mid-write) sees the old file or the new one, never a
// truncated one.
func (s *state) save(statePath string) error {
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}

	stateOut, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(statePath), filepath.Base(statePath)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone already once renamed
	if _, err = tmp.Write(stateOut); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return replace(tmp.Name(), statePath) // CreateTemp made it 0600
}

// loadState reads the persisted state at statePath. A missing file is an
// empty state; a file that cannot be read or decoded is an error, so that a
// damaged state is never mistaken for a node that has not started before.
func loadState(statePath string) (*state, error) {
	content, err := readFile(statePath)
	if os.IsNotExist(err) {
		return &state{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state %s: %w", statePath, err)
	}
	s := &state{}
	if err := json.Unmarshal(content, s); err != nil {
		return nil, fmt.Errorf("decoding state %s: %w", statePath, err)
	}
	return s, nil
}

// KnownNodes returns the peers persisted under dir for name; an unusable
// state file yields none.
func KnownNodes(dir, name string) []overlay.Node {
	st, err := loadState(statePath(dir, name))
	if err != nil {
		slog.Warn("could not load cluster state", "err", err)
		return nil
	}
	return st.Peers
}

// KnownOverlayNet returns the overlay network the cluster told this node,
// from the state persisted under dir for name. Unlike Load it creates
// nothing, so a command that only reports settings leaves no state behind.
func KnownOverlayNet(dir, name string) (netip.Prefix, bool) {
	st, err := loadState(statePath(dir, name))
	if err != nil || !st.OverlayNet.IsValid() {
		return netip.Prefix{}, false
	}
	return st.OverlayNet, true
}

// LocalIdentity returns the identity persisted under dir for name, if any.
func LocalIdentity(dir, name string) (trust.PublicKey, bool) {
	st, err := loadState(statePath(dir, name))
	if err != nil || len(st.Seed) == 0 {
		return trust.PublicKey{}, false
	}
	id, err := trust.IdentityFromSeed(st.Seed)
	if err != nil {
		return trust.PublicKey{}, false
	}
	return id.Public(), true
}

// Forget deletes the state kept under dir for name, so the node keeps nothing
// of the cluster it has left. A missing file is not an error.
func Forget(dir, name string) error {
	path := statePath(dir, name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing state %s: %w", path, err)
	}
	return nil
}

// Bootstrap is the persisted knowledge a node starts from. Load fills it; the
// agent then either makes the node a root, enrols it, or finds it already
// enrolled, and hands it to New, which keeps it up to date and saves it.
type Bootstrap struct {
	Identity   *trust.Identity
	OverlayNet netip.Prefix      // the cluster's; known whenever Anchor is
	Anchor     *trust.Checkpoint // the membership this node has satisfied itself of
	Records    trust.Records
	Peers      []overlay.Node // last known peers, with metadata

	// set is the membership Records describe, built on demand by Set and
	// dropped whenever Records is replaced.
	set *trust.Set
}

// Set is the membership the records describe. It is built once and kept: the
// agent asks it which admission this node holds before it can create the
// interface, and the cluster then runs on the same set, rather than verifying
// every signature a second time. It is built before the cluster starts, so
// nothing else is reading it yet.
func (b *Bootstrap) Set() *trust.Set {
	if b.set == nil {
		b.set = trust.NewSet()
		if b.Anchor != nil {
			if err := b.set.Adopt(*b.Anchor); err != nil {
				slog.Warn("could not start from the membership this node last verified; it has none, and "+
					"nothing it holds can give it one. Enrol this node again", "err", err)
			}
		}
		if res := b.set.Merge(b.Records); res.Refused > 0 {
			slog.Warn("some persisted membership records could not be loaded; this node may not agree "+
				"with its peers about who is a member until the next state sync",
				"records", res.Refused, "of", res.Judged, "recent", res.Reason)
		}
	}
	return b.set
}

// Load reads the state kept under dir for name and makes sure the node has an
// identity. The identity is persisted immediately.
func Load(dir, name string) (*Bootstrap, error) {
	path := statePath(dir, name)
	st, err := loadState(path)
	if err != nil {
		return nil, err
	}
	if len(st.Seed) == 0 {
		var id *trust.Identity
		if id, err = trust.NewIdentity(); err != nil {
			return nil, err
		}
		st = &state{Seed: id.Seed()}
		if err = st.save(path); err != nil {
			return nil, fmt.Errorf("saving new identity: %w", err)
		}
		slog.Info("generated node identity", "identity", id.Public().Short(), "path", path)
	}
	id, err := trust.IdentityFromSeed(st.Seed)
	if err != nil {
		return nil, fmt.Errorf("loading identity from %s: %w", path, err)
	}
	// every member has the cluster's network, settled when it was enrolled or
	// when it started the cluster, so a member without one is damaged state
	if st.Anchor != nil && !st.OverlayNet.IsValid() {
		return nil, fmt.Errorf("decoding state %s: a member with no overlay network", path)
	}
	return &Bootstrap{Identity: id, OverlayNet: st.OverlayNet, Anchor: st.Anchor, Records: st.Records, Peers: st.Peers}, nil
}

// Enrolled reports whether the node already belongs to a cluster: it holds a
// membership it has satisfied itself of.
func (b *Bootstrap) Enrolled() bool { return b.Anchor != nil }

// Save persists the bootstrap under dir for name, where Load reads it back.
// The agent calls it as soon as a node has enrolled, rather than leaving it to
// New: by then the invitation is spent and the cluster has agreed a membership
// holding the node, so an enrolment kept only in memory is one the node would
// have to be invited for a second time.
func (b *Bootstrap) Save(dir, name string) error { return b.save(statePath(dir, name)) }

// save persists the bootstrap at statePath.
func (b *Bootstrap) save(statePath string) error {
	st := &state{Seed: b.Identity.Seed(), OverlayNet: b.OverlayNet, Anchor: b.Anchor, Records: b.Records, Peers: b.Peers}
	return st.save(statePath)
}

// Assigned is the admission that says who this node is: the name it goes by
// and the overlay slot it holds. It is decided from the records the way the
// cluster decides it rather than from the first record that happens to name
// this node: several may, and only the ones the root vouches for count.
func (b *Bootstrap) Assigned() (trust.Member, error) {
	m, ok := b.Set().Lookup(b.Identity.Public())
	if !ok {
		return trust.Member{}, fmt.Errorf("this node (%s) is not a member of the cluster it holds records for", b.Identity.Public().Short())
	}
	return m, nil
}

// InitRoot makes this node the root of a new cluster allocating addresses in
// overlayNet. The membership it starts from is itself, agreed by the only
// member there is.
func (b *Bootstrap) InitRoot(nodeName string, overlayNet netip.Prefix, quorum trust.QuorumRule, confirmations int) {
	b.OverlayNet = overlayNet
	founding := trust.Found(b.Identity, nodeName, quorum, confirmations)
	b.Anchor = &founding
	b.Records, b.Peers, b.set = trust.Records{}, nil, nil
}

// Enrol records the outcome of an enrolment exchange. The overlay network is
// the cluster's, as the admitting member stated it.
func (b *Bootstrap) Enrol(records trust.Records, overlayNet netip.Prefix, anchor *trust.Checkpoint) {
	b.Records = records
	b.OverlayNet = overlayNet
	b.Anchor = anchor
	b.Peers, b.set = nil, nil
}
