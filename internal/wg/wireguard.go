// Package wg keeps one WireGuard interface in step with the cluster: the
// device itself, its key and peers, and the address, MTU and routes the
// operating system needs around it.
package wg

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgClient is the subset of *wgctrl.Client used by State.
type wgClient interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

// device is where a WireGuard interface comes from: the kernel module, or an
// implementation running in this process. Its methods take the name the
// agent knows the interface by, which is also the name wgctrl configures it
// under.
type device interface {
	// Create makes the interface exist, with the MTU where that is fixed at
	// creation; an interface that already exists is fine. It returns the
	// name the operating system gave the interface, which the linker uses.
	Create(name string, mtu int) (string, error)
	// Delete removes the interface; a missing one is not an error.
	Delete(name string) error
	// Kind names the implementation for the log: "kernel" or "userspace".
	Kind() string
}

// linker is what the agent needs from the operating system's network stack
// for one interface, named as the operating system knows it. Every method
// is idempotent: setting what is set, adding what exists and removing what
// is missing all succeed.
type linker interface {
	SetAddr(iface string, addr netip.Prefix) error
	SetMTU(iface string, mtu int) error
	Up(iface string) error
	Addrs(iface string) ([]netip.Prefix, error)
	// Routes lists the destinations routed through the interface.
	Routes(iface string) ([]netip.Prefix, error)
	AddRoute(iface string, dst netip.Prefix) error
	DelRoute(iface string, dst netip.Prefix) error
}

// Config describes the wireguard interface a State manages.
type Config struct {
	Interface   string     // name of the wireguard interface to create
	Port        int        // wireguard listen port, also used as the peers' port
	OverlayAddr netip.Addr // this node's address in the overlay network
	MTU         int        // interface MTU
	// PersistentKeepalive, when non-zero, makes every peer send keepalives at this
	// interval so NAT mappings stay open.
	PersistentKeepalive time.Duration
	// Userspace runs wireguard in this process even where the kernel could do
	// it. Where it cannot (no module, macOS, Windows) that is the way regardless.
	Userspace bool
}

// State holds the configured state of a cheesecloth WireGuard interface.
type State struct {
	iface       string
	mtu         int
	keepalive   time.Duration
	client      wgClient
	dev         device
	link        linker
	osName      string // what the operating system calls the interface, once created
	privKey     wgtypes.Key
	overlayAddr netip.Addr
	port        int
	PubKey      wgtypes.Key // fresh on every start; gossiped to peers
}

// New creates a new cheesecloth WireGuard state with a fresh key pair.
// The interface must later be set up using SetUpInterface.
func New(cfg Config) (*State, error) {
	dev, link, err := platform(cfg)
	if err != nil {
		return nil, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("instantiating wireguard client: %w", err)
	}
	return newState(cfg, client, dev, link)
}

func newState(cfg Config, client wgClient, dev device, link linker) (*State, error) {
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}
	return &State{
		iface:       cfg.Interface,
		mtu:         cfg.MTU,
		keepalive:   cfg.PersistentKeepalive,
		client:      client,
		dev:         dev,
		link:        link,
		privKey:     privKey,
		overlayAddr: cfg.OverlayAddr,
		port:        cfg.Port,
		PubKey:      privKey.PublicKey(),
	}, nil
}

// Remove deletes an interface that an agent which is no longer running left
// behind; a missing interface is not an error. Only a kernel interface
// outlives its agent: everywhere else the device runs inside the agent and
// goes with it.
func Remove(iface string) error {
	if err := remove(iface); err != nil {
		return fmt.Errorf("removing interface %s: %w", iface, err)
	}
	return nil
}

// PublicKey is this node's wireguard public key as peers learn it, in the
// textual form the metadata carries.
func (s *State) PublicKey() string { return s.PubKey.String() }

// DownInterface deletes the associated network interface; a missing interface is not an error.
func (s *State) DownInterface() error {
	if err := s.dev.Delete(s.iface); err != nil {
		return fmt.Errorf("removing interface %s: %w", s.iface, err)
	}
	s.osName = ""
	return nil
}

// SetUpInterface creates and sets up the associated network interface.
func (s *State) SetUpInterface(nodes []overlay.Node) error {
	osName, err := s.dev.Create(s.iface, s.mtu)
	if err != nil {
		return fmt.Errorf("creating interface %s: %w", s.iface, err)
	}
	if osName != s.osName {
		slog.Info("wireguard interface", "iface", s.iface, "os", osName, "device", s.dev.Kind())
		s.osName = osName
	}

	peerCfgs, err := s.nodesToPeerConfigs(nodes)
	if err != nil {
		return fmt.Errorf("converting received node information to wireguard format: %w", err)
	}
	if err = s.client.ConfigureDevice(s.iface, wgtypes.Config{
		PrivateKey:   &s.privKey,
		ListenPort:   &s.port,
		ReplacePeers: true,
		Peers:        peerCfgs,
	}); err != nil {
		return fmt.Errorf("setting wireguard configuration for %s: %w", s.iface, err)
	}

	if err := s.link.SetAddr(osName, hostPrefix(s.overlayAddr)); err != nil {
		return fmt.Errorf("setting address for %s: %w", osName, err)
	}
	if err := s.link.SetMTU(osName, s.mtu); err != nil {
		return fmt.Errorf("setting MTU for %s: %w", osName, err)
	}
	if err := s.link.Up(osName); err != nil {
		return fmt.Errorf("enabling interface %s: %w", osName, err)
	}
	wanted := make(map[netip.Prefix]bool, len(nodes))
	for _, node := range nodes {
		for _, dst := range peerPrefixes(node) {
			wanted[dst] = true
			if err := s.link.AddRoute(osName, dst); err != nil {
				return fmt.Errorf("adding route %s to %s: %w", dst, osName, err)
			}
		}
	}
	return s.removeStaleRoutes(osName, wanted)
}

// peerPrefixes lists what is reachable through node: its overlay address and
// the extra networks it advertises.
func peerPrefixes(node overlay.Node) []netip.Prefix {
	out := make([]netip.Prefix, 0, 1+len(node.AllowedIPs))
	out = append(out, hostPrefix(node.OverlayAddr))
	return append(out, node.AllowedIPs...)
}

// hostPrefix is the single-address prefix for addr.
func hostPrefix(addr netip.Addr) netip.Prefix { return netip.PrefixFrom(addr, addr.BitLen()) }

// removeStaleRoutes deletes the routes on the interface that no current peer
// owns; the interface is ours, so every route on it is. The route to our own
// address (the kernel adds one for IPv6 /128 addresses) is left alone.
func (s *State) removeStaleRoutes(osName string, wanted map[netip.Prefix]bool) error {
	wanted[hostPrefix(s.overlayAddr)] = true
	routes, err := s.link.Routes(osName)
	if err != nil {
		return fmt.Errorf("listing routes on %s: %w", osName, err)
	}
	for _, dst := range routes {
		if wanted[dst] {
			continue
		}
		slog.Debug("removing stale route", "dst", dst, "iface", osName)
		if err := s.link.DelRoute(osName, dst); err != nil {
			return fmt.Errorf("removing route %s from %s: %w", dst, osName, err)
		}
	}
	return nil
}

// prefixFromIPNet converts a *net.IPNet to a netip.Prefix, unmapping IPv4-in-IPv6.
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 128 && addr.Is4In6() {
		ones -= 96
	}
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

func (s *State) nodesToPeerConfigs(nodes []overlay.Node) ([]wgtypes.PeerConfig, error) {
	peerCfgs := make([]wgtypes.PeerConfig, len(nodes))
	for i, node := range nodes {
		pubKey, err := wgtypes.ParseKey(node.PubKey)
		if err != nil {
			return nil, fmt.Errorf("parsing wireguard key: %w", err)
		}
		var keepalive *time.Duration
		if s.keepalive > 0 {
			keepalive = &s.keepalive
		}
		prefixes := peerPrefixes(node)
		allowed := make([]net.IPNet, len(prefixes))
		for j, p := range prefixes {
			allowed[j] = *prefixToIPNet(p)
		}
		peerCfgs[i] = wgtypes.PeerConfig{
			PublicKey:                   pubKey,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: keepalive,
			Endpoint:                    net.UDPAddrFromAddrPort(netip.AddrPortFrom(node.Addr, uint16(s.port))),
			AllowedIPs:                  allowed,
		}
	}
	return peerCfgs, nil
}
