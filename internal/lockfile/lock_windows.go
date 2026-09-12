//go:build windows

package lockfile

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// the whole file, however long it turns out to be
const lockLow, lockHigh = ^uint32(0), ^uint32(0)

// tryLock takes the lock if it is free, and reports whether it did. The lock
// belongs to the open handle, not to the process, so two of these in one
// process exclude each other as two processes would.
func tryLock(f *os.File) (bool, error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, lockLow, lockHigh, &overlapped)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION): // somebody else holds it
		return false, nil
	default:
		return false, err
	}
}

func unlock(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, lockLow, lockHigh, &overlapped)
}
