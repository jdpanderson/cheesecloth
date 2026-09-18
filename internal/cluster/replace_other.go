//go:build !windows

package cluster

import (
	"os"
	"path/filepath"
)

// replace moves tmp over dst atomically and durably: a reader sees the old
// file or the new one, never a mix, and the move outlives the power going out.
// The rename itself is a change to the directory, so syncing the file writes
// the contents to the disk and leaves the name of them in the journal, where a
// cut seconds later still loses it -- and the state would be the one from
// before, which for a node that has just enrolled is a node that has not.
func replace(tmp, dst string) error {
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

// readFile reads the state file.
func readFile(path string) ([]byte, error) { return os.ReadFile(path) }
