package cli

import (
	"path/filepath"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/stretchr/testify/assert"
)

func Test_controlFlags_socket(t *testing.T) {
	f := controlFlags{interfaceFlag: interfaceFlag{Interface: "wg1"}}
	assert.Equal(t, control.DefaultSocket("wg1"), f.socket())
	f.ControlSocket = "/tmp/x.sock"
	assert.Equal(t, "/tmp/x.sock", f.socket())
}

// Every command that names an interface refuses a name an interface cannot
// have. The check is on the shared flag rather than on each command, so this
// covers the ones that only talk to a running agent as well as the agent
// itself: they name the control socket, the state file and the hosts block
// after it just the same.
func Test_interfaceFlag_everyCommandChecksTheName(t *testing.T) {
	// the arguments each command needs besides --interface
	commands := map[string][]string{
		"agent":   nil,
		"config":  nil,
		"status":  nil,
		"invite":  nil,
		"revoke":  {"somenode"},
		"confirm": nil,
		"leave":   nil,
	}
	bad := []string{"../secrets", "wg 0", ".wg0", "wg0\nevil", "wgcloth0123456789", ""}

	for name, extra := range commands {
		for _, iface := range bad {
			args := append([]string{name, "--interface", iface}, extra...)
			_, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), args...)
			assert.Error(t, err, "%s --interface %q", name, iface)
			if err != nil {
				assert.Contains(t, err.Error(), "interface name", "%s --interface %q", name, iface)
			}
		}
		// and the name it runs with every day is accepted
		args := append([]string{name, "--interface", "wgcloth"}, extra...)
		_, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), args...)
		assert.NoError(t, err, name)
	}
}
