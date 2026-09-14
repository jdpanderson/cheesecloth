package cli

import (
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
