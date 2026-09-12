package cli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two interfaces being configured at the same moment each append their
// section to the file as they found it. Appending is safe on its own; what is
// not is the check that the interface has no section yet, which both would
// pass, leaving a file with the same key twice that YAML then refuses to
// read. Exactly one of them may write.
func Test_ConfigCmd_write_concurrentInit(t *testing.T) {
	const writers = 8
	path := filepath.Join(t.TempDir(), "config.yaml")

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &ConfigCmd{settings: settings{Interface: "wg1", MTU: 9000}}
			errs <- c.write(path, []byte("wg1:\n  mtu: 9000\n"))
		}()
	}
	wg.Wait()
	close(errs)

	var wrote int
	for err := range errs {
		if err == nil {
			wrote++
			continue
		}
		assert.ErrorContains(t, err, `already has a section for "wg1"`)
	}
	assert.Equal(t, 1, wrote, "one writer creates the section, the rest are told it is there")

	sections, err := readSections(path)
	require.NoError(t, err, "the file is still readable")
	assert.Len(t, sections, 1)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(content), "wg1:"), "the section is written once:\n"+string(content))
}

// Sections for different interfaces all survive being written at once.
func Test_ConfigCmd_write_concurrentInterfaces(t *testing.T) {
	ifaces := []string{"wg1", "wg2", "wg3", "wg4"}
	path := filepath.Join(t.TempDir(), "config.yaml")

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &ConfigCmd{settings: settings{Interface: iface}}
			assert.NoError(t, c.write(path, []byte(iface+":\n  mtu: 9000\n")))
		}()
	}
	wg.Wait()

	sections, err := readSections(path)
	require.NoError(t, err)
	assert.Len(t, sections, len(ifaces), "every section is there")
}
