//go:build windows

package cluster

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// busyWait is how long a file operation keeps trying while the file is in
// use by another process.
const busyWait = 2 * time.Second

// busy reports whether err is Windows refusing access to a file that another
// process has open or is replacing.
func busy(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

// retryBusy runs op until it succeeds, fails for another reason, or busyWait
// has passed.
func retryBusy(op func() error) error {
	deadline := time.Now().Add(busyWait)
	for {
		err := op()
		if err == nil || !busy(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// replace moves tmp over dst. Windows refuses to replace a file another
// process has open, and `cheesecloth status` reads the state file, so the
// move is retried while the file is busy. There is no directory to sync
// afterwards as there is elsewhere: a directory is not a file to open here,
// and NTFS journals the rename itself.
func replace(tmp, dst string) error {
	return retryBusy(func() error { return os.Rename(tmp, dst) })
}

// readFile reads the state file, waiting out a replacement in progress.
func readFile(path string) (b []byte, err error) {
	err = retryBusy(func() error {
		b, err = os.ReadFile(path)
		return err
	})
	return b, err
}
