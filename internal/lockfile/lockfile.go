// Package lockfile serialises the updates that several cheesecloth processes
// can make to one file at the same time. One process serves one interface, so
// a host running several clusters runs several agents, and the hosts file is
// read, changed and written back by each of them.
//
// The lock is taken on a file beside the one it protects, named <path>.lock,
// rather than on that file itself: an update that ends in a rename replaces
// the file, so a lock held on it would be a lock on the inode the rename
// throws away, and the next writer would lock the new one and proceed.
package lockfile

import (
	"fmt"
	"os"
	"time"
)

// suffix names a file's lock beside it.
const suffix = ".lock"

// Wait is how long to wait for another process before giving up. Waiting
// rather than failing at once covers the ordinary case of two agents writing
// at the same moment; giving up covers the one where a process is wedged
// while holding the lock, which must not stop an agent from shutting down.
const Wait = 5 * time.Second

// retry is how often the lock is tried again while another process holds it.
// Neither flock nor LockFileEx will wait for a bounded time, so the wait is
// made of short attempts.
const retry = 10 * time.Millisecond

// Lock is a held file lock. It is released by Release, and by the process
// exiting however it does: neither platform leaves the lock behind.
type Lock struct {
	f *os.File
}

// Acquire takes the exclusive lock for path, waiting up to wait for whoever
// holds it. Nothing about path itself is read, written or created; the lock
// is a file of its own, in the same directory.
func Acquire(path string, wait time.Duration) (*Lock, error) {
	lockPath := path + suffix
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file %s: %w", lockPath, err)
	}
	deadline := time.Now().Add(wait)
	for {
		locked, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("locking %s: %w", lockPath, err)
		}
		if locked {
			return &Lock{f: f}, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("waited %s for the lock on %s; another cheesecloth process is holding it", wait, path)
		}
		time.Sleep(retry)
	}
}

// Release gives the lock up. The lock file is left behind: deleting it would
// race with the next process to open it, which would then lock a file that is
// no longer the one anybody else has.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlock(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}
