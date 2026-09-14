// Package etchosts keeps a block of managed entries in an /etc/hosts file,
// each line marked with a banner comment, without touching the rest of the file.
package etchosts

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jdpanderson/cheesecloth/internal/lockfile"
	"github.com/jdpanderson/cheesecloth/internal/paths"
)

// defaultBanner is the comment that marks a line as managed by this package.
const defaultBanner = "# ! MANAGED AUTOMATICALLY !"

// defaultPath is the hosts file written unless Path says otherwise.
var defaultPath = paths.HostsFile

// EtcHosts writes managed entries to a hosts file. The zero value writes to
// defaultPath and marks its lines with defaultBanner.
type EtcHosts struct {
	// Banner marks the lines this instance manages; defaultBanner when empty.
	// It must start with "#" so the resolver reads it as a comment.
	Banner string
	// Path is the hosts file; defaultPath when empty.
	Path string
	// rename replaces the hosts file with the temp file; nil means os.Rename.
	rename func(oldpath, newpath string) error
}

// WriteEntries makes the managed block of the hosts file exactly ipsToNames:
// one banner-marked line per address with its names. Lines without the banner
// are kept as they are.
func (eh *EtcHosts) WriteEntries(ipsToNames map[string][]string) error {
	hostsPath := eh.Path
	if hostsPath == "" {
		hostsPath = defaultPath
	}

	// A host in several clusters runs an agent per cluster, each of them
	// rewriting this file whole; without the lock the slower one would write
	// back what it read before the other's block was added, dropping it.
	lock, err := lockfile.Acquire(hostsPath, lockfile.Wait)
	if err != nil {
		return err
	}
	defer func() {
		if rerr := lock.Release(); rerr != nil {
			slog.Warn("could not release the hosts file lock", "path", hostsPath, "err", rerr)
		}
	}()

	// the hosts file is never created: a missing one means the wrong path
	etcHosts, err := os.OpenFile(hostsPath, os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("could not open %s for reading: %w", hostsPath, err)
	}
	defer func() { _ = etcHosts.Close() }()

	// Temp file in the same directory so the rename is atomic. A library like renameio
	// would not do: /etc/hosts is a bind mount in containers and needs the copy fallback below.
	tmp, err := os.CreateTemp(filepath.Dir(hostsPath), "etchosts")
	if err != nil {
		return fmt.Errorf("could not create tempfile: %w", err)
	}

	// the temp file is gone already once renamed into place
	defer func(file *os.File) {
		_ = file.Close()
		if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
			slog.Warn("could not remove temp file", "path", file.Name(), "err", err)
		}
	}(tmp)

	if err := eh.writeEntries(etcHosts, tmp, ipsToNames); err != nil {
		return err
	}

	return eh.movePreservePerms(tmp, etcHosts)
}

// writeEntries copies orig to dest, rewriting managed lines whose IP is in
// ipsToNames, dropping the other managed lines, and appending new entries.
// Write errors surface once, on the final Flush.
func (eh *EtcHosts) writeEntries(orig io.Reader, dest io.Writer, ipsToNames map[string][]string) error {
	banner := eh.Banner
	if banner == "" {
		banner = defaultBanner
	}
	w := bufio.NewWriter(dest)
	written := make(map[string]bool, len(ipsToNames))

	scanner := bufio.NewScanner(orig)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasSuffix(strings.TrimSpace(line), strings.TrimSpace(banner)) {
			_, _ = fmt.Fprintln(w, line) // unmanaged line, keep as is; w keeps the error for Flush
			continue
		}
		ip := strings.Fields(line)[0] // the line ends with the banner, so it has fields
		if names, ok := ipsToNames[ip]; ok && !written[ip] {
			writeEntryWithBanner(w, banner, ip, names)
			written[ip] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading hosts file: %w", err)
	}

	for ip, names := range ipsToNames {
		if !written[ip] {
			writeEntryWithBanner(w, banner, ip, names)
		}
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("error writing hosts file: %w", err)
	}
	return nil
}

func writeEntryWithBanner(w *bufio.Writer, banner, ip string, names []string) {
	if !writable(ip) || len(names) == 0 {
		slog.Warn("not writing a hosts entry for an address this file cannot hold", "ip", ip)
		return
	}
	for _, name := range names {
		if !writable(name) {
			slog.Warn("not writing a hosts entry with a name this file cannot hold", "ip", ip, "name", name)
			return
		}
	}
	slog.Debug("writing hosts entry", "ip", ip, "names", names)
	_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", ip, strings.Join(names, " "), banner) // w keeps the error for Flush
}

// writable reports whether a field can be written as one field of one line.
// The cluster holds names to more than this, but a name that ended a line
// early would put content of its own in a file the resolver reads, with no
// banner marking it as ours to remove, so it is checked again here, where the
// writing happens.
func writable(field string) bool {
	return field != "" && strings.IndexFunc(field, func(r rune) bool {
		return r <= ' ' || r >= 0x7f || r == '#'
	}) < 0
}

func (eh *EtcHosts) movePreservePerms(src, dst *os.File) error {
	if err := src.Sync(); err != nil {
		return fmt.Errorf("could not sync changes to %s: %w", src.Name(), err)
	}

	etcHostsInfo, err := dst.Stat()
	if err != nil {
		return fmt.Errorf("could not stat %s: %w", dst.Name(), err)
	}
	// CreateTemp made src 0600 and ours; match the hosts file before it becomes the hosts file
	if err = src.Chmod(etcHostsInfo.Mode()); err != nil {
		return fmt.Errorf("could not chmod %s: %w", src.Name(), err)
	}
	if err = keepOwner(src, etcHostsInfo); err != nil {
		slog.Warn("could not keep the owner of the hosts file", "path", dst.Name(), "err", err)
	}

	rename := eh.rename
	if rename == nil {
		rename = os.Rename
	}
	if err = rename(src.Name(), dst.Name()); err != nil {
		slog.Info("could not rename over hosts file, falling back to copy", "path", dst.Name(), "err", err)

		if _, err = src.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err = dst.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err = dst.Truncate(0); err != nil {
			return err
		}
		if _, err = io.Copy(dst, src); err != nil {
			return err
		}
		return dst.Sync()
	}
	return nil
}
