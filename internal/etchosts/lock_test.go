package etchosts

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A host in several clusters runs an agent for each of them, and they write
// this file at the same moment: at a restart every one of them settles its
// membership at once. Each rewrites the file whole, keeping the lines it does
// not manage, so a writer that reads the file before another's block is there
// and writes it back afterwards drops that block, and the cluster it belongs
// to has no hosts entries until its membership next changes.
//
// The slow rename holds the file open for as long as the second writer needs
// to read it, which is the window the lock has to close.
func TestEtcHosts_WriteEntries_concurrentAgents(t *testing.T) {
	path := writeTempHosts(t, "127.0.0.1 localhost\n", 0o600)
	slow := &EtcHosts{Banner: "# ! managed by wg1", Path: path, rename: func(old, new string) error {
		time.Sleep(200 * time.Millisecond)
		return os.Rename(old, new)
	}}
	quick := &EtcHosts{Banner: "# ! managed by wg2", Path: path}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, slow.WriteEntries(map[string][]string{"10.1.0.1": {"wg1-peer"}}))
	}()

	time.Sleep(50 * time.Millisecond) // while the slow writer is between reading and renaming
	require.NoError(t, quick.WriteEntries(map[string][]string{"10.2.0.1": {"wg2-peer"}}))
	wg.Wait()

	got := readHosts(t, path)
	assert.Contains(t, got, "127.0.0.1 localhost", "the unmanaged line is kept")
	assert.Contains(t, got, "wg1-peer", "the first agent's entries survived the second's write")
	assert.Contains(t, got, "wg2-peer", "the second agent's entries are there")
}

// Repeated writes from several agents leave one line each and no temp files.
func TestEtcHosts_WriteEntries_concurrentAgents_repeated(t *testing.T) {
	const rounds = 40
	agents := []string{"wg1", "wg2", "wg3"}
	path := writeTempHosts(t, "127.0.0.1 localhost\n", 0o600)

	var wg sync.WaitGroup
	for _, agent := range agents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eh := &EtcHosts{Banner: "# ! managed by " + agent, Path: path}
			entries := map[string][]string{"10.0.0." + agent[2:]: {agent + "-peer"}}
			for range rounds {
				assert.NoError(t, eh.WriteEntries(entries))
			}
		}()
	}
	wg.Wait()

	got := readHosts(t, path)
	for _, agent := range agents {
		assert.Contains(t, got, agent+"-peer", "the entries of "+agent+" survived the others' writes")
	}
	assert.Equal(t, len(agents)+1, strings.Count(got, "\n"), "one line each and no duplicates:\n"+got)

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	var leftover []string
	for _, e := range entries {
		if name := e.Name(); name != "hosts" && !strings.HasSuffix(name, ".lock") {
			leftover = append(leftover, name)
		}
	}
	assert.Empty(t, leftover, "no temp files left behind")
}

func readHosts(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}
