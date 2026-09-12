//go:build !windows

package lockfile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryLock takes the lock if it is free, and reports whether it did. The lock
// belongs to the open file, not to the process, so two of these in one
// process exclude each other as two processes would.
func tryLock(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK): // EAGAIN: somebody else holds it
		return false, nil
	default:
		return false, err
	}
}

func unlock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
