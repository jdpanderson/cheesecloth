package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The banner marks the block as one interface's, so two agents on the same
// host, and a leave, only ever touch their own entries.
func Test_HostsFor_banner(t *testing.T) {
	assert.Equal(t, "# ! managed automatically by cheesecloth interface wg1", HostsFor("wg1").Banner)
	assert.NotEqual(t, HostsFor("wg1").Banner, HostsFor("wg2").Banner)
}
