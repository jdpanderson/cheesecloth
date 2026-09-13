package trust

import (
	"fmt"
	"regexp"
	"strings"
)

// A node's name is what every other node calls it: it goes in the hosts file
// of every member, in their logs, and in what the operator is shown. So it is
// held to what a hostname may be rather than to anything this program happens
// to cope with, and it is checked wherever one arrives from outside, not only
// where one is made.

// NameMax is the longest a node name may be: one DNS label.
const NameMax = 63

// nameLabel is one lowercase DNS label (RFC 1123): letters, digits and
// hyphens, starting and ending with a letter or digit.
var nameLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// CheckName reports whether name may be a node's. One label, not a dotted
// name: the cluster's names are flat, so no member can hold a name that
// belongs somewhere else in the DNS.
func CheckName(name string) error {
	if name == "" {
		return fmt.Errorf("node name is empty")
	}
	// the length is checked before the name is quoted into a message, since a
	// name that got this far may be anything at all
	if len(name) > NameMax {
		return fmt.Errorf("node name is %d characters, and the most is %d", len(name), NameMax)
	}
	if !nameLabel.MatchString(name) {
		return fmt.Errorf("node name %q is not a hostname: it must be lowercase letters, digits and hyphens, "+
			"starting and ending with a letter or digit, with no dots", name)
	}
	if strings.IndexFunc(name, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return fmt.Errorf("node name %q is all digits, which a resolver reads as an address", name)
	}
	return nil
}
