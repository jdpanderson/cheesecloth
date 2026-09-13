package etchosts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEtcHosts_writeEntryWithBanner(t *testing.T) {
	type args struct {
		banner string
		ip     string
		names  []string
	}

	tests := []struct {
		name    string
		args    args
		wantTmp string
	}{
		{"do not write empty ip", args{defaultBanner, "", []string{"somename", "someothername"}}, ""},
		{"do not write empty names", args{defaultBanner, "1.2.3.4", []string{}}, ""},
		{"complete entry", args{defaultBanner, "1.2.3.4", []string{"somename", "someothername"}}, fmt.Sprintf("1.2.3.4\tsomename someothername\t%s\n", defaultBanner)},
		{"custom banner", args{"# somebanner", "1.2.3.4", []string{"somename", "someothername"}}, fmt.Sprintf("1.2.3.4\tsomename someothername\t%s\n", "# somebanner")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := &bytes.Buffer{}
			w := bufio.NewWriter(tmp)
			writeEntryWithBanner(w, tt.args.banner, tt.args.ip, tt.args.names)
			require.NoError(t, w.Flush())
			assert.Equal(t, tt.wantTmp, tmp.String())
		})
	}
}

func TestEtcHosts_writeEntries(t *testing.T) {
	type fields struct {
		Banner string
		Path   string
	}
	type args struct {
		orig       io.Reader
		ipsToNames map[string][]string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantDest string
	}{
		{
			"simple empty write",
			fields{},
			args{strings.NewReader(""), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
		},
		{
			"do not touch comments",
			fields{},
			args{strings.NewReader("# some comment\n"), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"# some comment\n1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
		},
		{
			"do not touch existing entries",
			fields{},
			args{strings.NewReader("4.3.2.1 hostname1 hostname2\n"), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"4.3.2.1 hostname1 hostname2\n1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
		},
		{
			"remove managed entry not in map",
			fields{},
			args{strings.NewReader("4.3.2.1 fooz baarz # ! MANAGED AUTOMATICALLY !\n"), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"1.2.3.4\tfoo bar\t# ! MANAGED AUTOMATICALLY !\n",
		},
		{
			"custom banner",
			fields{Banner: "# somebanner"},
			args{strings.NewReader(""), map[string][]string{"1.2.3.4": {"foo", "bar"}}},
			"1.2.3.4\tfoo bar\t# somebanner\n",
		},
		{
			"a managed ip listed twice is written once, in place of its first line",
			fields{},
			args{strings.NewReader("1.2.3.4 old # ! MANAGED AUTOMATICALLY !\n# between\n1.2.3.4 older # ! MANAGED AUTOMATICALLY !\n"), map[string][]string{"1.2.3.4": {"foo"}}},
			"1.2.3.4\tfoo\t# ! MANAGED AUTOMATICALLY !\n# between\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eh := &EtcHosts{Banner: tt.fields.Banner, Path: tt.fields.Path}
			dest := &bytes.Buffer{}
			wantLen := len(tt.args.ipsToNames)
			require.NoError(t, eh.writeEntries(tt.args.orig, dest, tt.args.ipsToNames))
			assert.Len(t, tt.args.ipsToNames, wantLen, "caller's map must not be modified")
			assert.Equal(t, tt.wantDest, dest.String())
		})
	}
}

func writeTempHosts(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts")
	require.NoError(t, os.WriteFile(p, []byte(content), mode))
	return p
}

func TestEtcHosts_WriteEntries(t *testing.T) {
	const banner = "# ! test banner"
	tests := []struct {
		name string
		orig string
		ips  map[string][]string
		want string
	}{
		{
			"add to empty file",
			"",
			map[string][]string{"10.0.0.1": {"a"}},
			"10.0.0.1\ta\t" + banner + "\n",
		},
		{
			"preserve unmanaged and update managed",
			"127.0.0.1 localhost\n10.0.0.1\told\t" + banner + "\n",
			map[string][]string{"10.0.0.1": {"new"}},
			"127.0.0.1 localhost\n10.0.0.1\tnew\t" + banner + "\n",
		},
		{
			"remove managed entries with empty map",
			"127.0.0.1 localhost\n10.0.0.1\ta\t" + banner + "\n",
			map[string][]string{},
			"127.0.0.1 localhost\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeTempHosts(t, tt.orig, 0o600)
			eh := &EtcHosts{Banner: banner, Path: p}
			require.NoError(t, eh.WriteEntries(tt.ips))

			got, err := os.ReadFile(p)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestEtcHosts_WriteEntries_missingFile(t *testing.T) {
	eh := &EtcHosts{Path: filepath.Join(t.TempDir(), "nonexistent")}
	err := eh.WriteEntries(map[string][]string{"10.0.0.1": {"a"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not open")
}

func TestEtcHosts_WriteEntries_noLeftoverTempFile(t *testing.T) {
	p := writeTempHosts(t, "", 0o600)
	eh := &EtcHosts{Path: p}
	entries := map[string][]string{"10.0.0.1": {"a"}}
	require.NoError(t, eh.WriteEntries(entries))

	// no leftover tempfiles next to the hosts file
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(p), "etchosts*"))
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestEtcHosts_WriteEntries_renameFallback(t *testing.T) {
	orig := "127.0.0.1 localhost\n10.0.0.1\told\t" + defaultBanner + "\n"
	p := writeTempHosts(t, orig, 0o600)
	eh := &EtcHosts{Path: p, rename: func(_, _ string) error {
		return errors.New("cross-device link")
	}}
	require.NoError(t, eh.WriteEntries(map[string][]string{}))

	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1 localhost\n", string(got), "copy fallback must truncate")
}

// errWriter fails every write.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestEtcHosts_writeEntries_ioErrors(t *testing.T) {
	eh := &EtcHosts{}
	err := eh.writeEntries(strings.NewReader(""), errWriter{}, map[string][]string{"10.0.0.1": {"a"}})
	assert.ErrorContains(t, err, "error writing hosts file")

	// the scanner's line limit is the one limit on the hosts file
	long := strings.Repeat("x", bufio.MaxScanTokenSize+1) + "\n"
	err = eh.writeEntries(strings.NewReader(long), &bytes.Buffer{}, map[string][]string{})
	assert.ErrorContains(t, err, "error reading hosts file")
}

// A name that could end the line early would write content of its own into a
// file the resolver reads, and without the banner nothing would ever take it
// out again. The cluster refuses such names; this is the gate at the file.
func Test_WriteEntries_refusesAnUnwritableName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	require.NoError(t, os.WriteFile(path, []byte("127.0.0.1\tlocalhost\n"), 0o644))

	eh := &EtcHosts{Path: path}
	require.NoError(t, eh.WriteEntries(map[string][]string{
		"10.0.0.2": {"web1\n192.0.2.66\tbank.example.com\n"},
		"10.0.0.3": {"ok"},
		"10.0.0.4": {"has space"},
		"10.0.0.5": {"hash#comment"},
	}))

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(after), "bank.example.com", "nothing of the name reached the file")
	assert.NotContains(t, string(after), "has space")
	assert.NotContains(t, string(after), "hash#comment")
	assert.Contains(t, string(after), "10.0.0.3\tok", "the entries beside it are still written")
	assert.Contains(t, string(after), "127.0.0.1\tlocalhost", "and so is what was already there")
	assert.Len(t, strings.Split(strings.TrimSpace(string(after)), "\n"), 2)
}
