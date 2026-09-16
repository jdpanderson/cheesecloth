package cli

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One file describes one interface, so creating it is the whole of the write
// and the file system settles two of these racing: exactly one creates it and
// the rest are told it is there.
func Test_ConfigCmd_write_concurrentInit(t *testing.T) {
	const writers = 8
	path := filepath.Join(t.TempDir(), "config.yaml")
	rendered := []byte("interface: wg1\nmtu: 9000\n")

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- (&ConfigCmd{settings: settings{Interface: "wg1", MTU: 9000}}).write(path, rendered)
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
		assert.ErrorContains(t, err, "already exists")
	}
	assert.Equal(t, 1, wrote, "one writer creates the file, the rest are told it is there")

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(rendered), string(content), "and it holds exactly what was written")
}
