package agent

import (
	"fmt"
	"net"
	"net/netip"
)

// Bind and advertise address selection for cluster gossip.

// advertiseAddr is the address peers use to reach this node for cluster
// membership: the bind address itself, or, for a wildcard, an address of the
// same family on one of this host's interfaces other than the overlay one.
func (a *agent) advertiseAddr() (netip.Addr, error) {
	if !a.BindAddr.IsUnspecified() {
		return a.BindAddr, nil
	}
	list := a.addrs
	if list == nil {
		list = upInterfaceAddrs
	}
	addr, ok := pickAdvertiseAddr(a.BindAddr, list(a.Interface))
	if !ok {
		family := "IPv4"
		if a.BindAddr.Is6() {
			family = "IPv6"
		}
		return netip.Addr{}, fmt.Errorf("no %s address found to advertise for cluster membership; set --bind-addr to a specific address", family)
	}
	return addr, nil
}

// pickAdvertiseAddr chooses, among addrs, an address in the family of wildcard:
// public first, then any global unicast (private ranges included).
func pickAdvertiseAddr(wildcard netip.Addr, addrs []net.Addr) (netip.Addr, bool) {
	inFamily := func(want func(netip.Addr) bool) func(netip.Addr) bool {
		return func(x netip.Addr) bool { return x.Is4() == wildcard.Is4() && want(x) }
	}
	if addr, ok := firstAddr(addrs, inFamily(isPublic)); ok {
		return addr, true
	}
	return firstAddr(addrs, inFamily(netip.Addr.IsGlobalUnicast))
}

// firstAddr returns the first address in addrs accepted by want, with IPv4-mapped addresses unmapped.
func firstAddr(addrs []net.Addr, want func(netip.Addr) bool) (netip.Addr, bool) {
	for _, na := range addrs {
		var ip net.IP
		switch v := na.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if want(addr) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// sharedAddressSpace is RFC 6598 carrier-grade NAT space, private for our purposes.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// isPublic reports whether addr is a globally routable unicast address
// (excludes RFC 1918, RFC 6598 and IPv6 unique local addresses).
func isPublic(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddressSpace.Contains(addr)
}

// upInterfaceAddrs returns the addresses of all up, non-loopback interfaces
// except the one named skip, in interface order.
func upInterfaceAddrs(skip string) []net.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []net.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == skip {
			continue
		}
		if ifAddrs, err := iface.Addrs(); err == nil {
			addrs = append(addrs, ifAddrs...)
		}
	}
	return addrs
}
