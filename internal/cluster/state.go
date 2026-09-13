package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/paths"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// state is what a node persists: its identity seed, the membership it trusts
// and the peers it last saw, so it can restart unattended.
type state struct {
	Seed       []byte           `json:"seed"`
	Root       *trust.PublicKey `json:"root,omitempty"`
	OverlayNet netip.Prefix     `json:"overlayNet,omitzero"` // the cluster's, so no flag is needed to restart
	Records    trust.Records    `json:"records"`
	Peers      []overlay.Node   `json:"peers"`
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
	Root       trust.PublicKey // zero until enrolled or initialised
	OverlayNet netip.Prefix    // the cluster's; zero until enrolled, initialised or read from state
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
		b.set = trust.NewSet(b.Root)
		b.set.Merge(b.Records)
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
	b := &Bootstrap{Identity: id, OverlayNet: st.OverlayNet, Records: st.Records, Peers: st.Peers}
	if st.Root != nil {
		b.Root = *st.Root
	}
	return b, nil
}

// Enrolled reports whether the node already belongs to a cluster: it knows a root.
func (b *Bootstrap) Enrolled() bool { return b.Root != (trust.PublicKey{}) }

// save persists the bootstrap at statePath.
func (b *Bootstrap) save(statePath string) error {
	st := &state{Seed: b.Identity.Seed(), OverlayNet: b.OverlayNet, Records: b.Records, Peers: b.Peers}
	if b.Enrolled() {
		root := b.Root
		st.Root = &root
	}
	return st.save(statePath)
}

// Assigned is the admission that says who this node is: the name it goes by
// and the overlay slot it holds. It is decided from the records the way the
// cluster decides it rather than from the first record that happens to name
// this node: several may, and only the ones the root vouches for count.
func (b *Bootstrap) Assigned() (trust.Admission, error) {
	a, ok := b.Set().Lookup(b.Identity.Public())
	if !ok {
		return trust.Admission{}, fmt.Errorf("no admission record for this node (%s)", b.Identity.Public().Short())
	}
	return a, nil
}

// InitRoot makes this node the root of a new cluster.
func (b *Bootstrap) InitRoot(nodeName string) {
	b.Root = b.Identity.Public()
	adm := trust.SelfAdmit(b.Identity, nodeName, time.Now())
	b.Records = trust.Records{Admissions: []trust.Admission{adm}}
	b.Peers, b.set = nil, nil
}

// Enrol records the outcome of an enrolment exchange. The overlay network is
// the cluster's, as the admitting member stated it; a member too old to say
// leaves it zero and the node falls back to its own setting.
func (b *Bootstrap) Enrol(root trust.PublicKey, records trust.Records, overlayNet netip.Prefix) {
	b.Root = root
	b.Records = records
	b.OverlayNet = overlayNet
	b.Peers, b.set = nil, nil
}
