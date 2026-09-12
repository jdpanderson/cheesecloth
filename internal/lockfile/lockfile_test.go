package lockfile

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// target is a file to be protected, in a directory of the test's own.
func target(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "shared")
}

// The lock belongs to the open file rather than to the process, so two in one
// process exclude each other exactly as two processes do.
func Test_Acquire_excludesASecondHolder(t *testing.T) {
	path := target(t)
	held, err := Acquire(path, Wait)
	require.NoError(t, err)
	assert.FileExists(t, path+".lock")
	assert.NoFileExists(t, path, "the file itself is neither read nor created")

	_, err = Acquire(path, 50*time.Millisecond)
	require.Error(t, err)
	assert.ErrorContains(t, err, "another cheesecloth process is holding it")

	require.NoError(t, held.Release())
	next, err := Acquire(path, Wait)
	require.NoError(t, err, "released, so the next writer gets in")
	require.NoError(t, next.Release())
}

// Two files in a directory are locked apart from each other.
func Test_Acquire_isPerFile(t *testing.T) {
	dir := t.TempDir()
	a, err := Acquire(filepath.Join(dir, "a"), Wait)
	require.NoError(t, err)
	b, err := Acquire(filepath.Join(dir, "b"), Wait)
	require.NoError(t, err)
	require.NoError(t, a.Release())
	require.NoError(t, b.Release())
}

// A writer that has to wait gets the lock once the holder is done, rather
// than failing or going ahead anyway.
func Test_Acquire_waitsForTheHolder(t *testing.T) {
	path := target(t)
	held, err := Acquire(path, Wait)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	var waited *Lock
	var waitErr error
	go func() {
		defer wg.Done()
		waited, waitErr = Acquire(path, Wait)
	}()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, held.Release())
	wg.Wait()
	require.NoError(t, waitErr)
	require.NoError(t, waited.Release())
}

func Test_Acquire_reportsAnUnusablePath(t *testing.T) {
	_, err := Acquire(filepath.Join(t.TempDir(), "no-such-dir", "f"), Wait)
	assert.ErrorContains(t, err, "opening lock file")
}

// Releasing twice, or releasing nothing, is not an error: the agent releases
// on its way out of paths that may not have taken the lock.
func Test_Release_twice(t *testing.T) {
	l, err := Acquire(target(t), Wait)
	require.NoError(t, err)
	require.NoError(t, l.Release())
	assert.NoError(t, l.Release())
	assert.NoError(t, (*Lock)(nil).Release())
}
