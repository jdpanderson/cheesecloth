package cli

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/lockfile"
	"go.yaml.in/yaml/v3"
)

// configCmdName is the command that prints settings rather than acting on a
// single interface, which is why it alone survives an ambiguous config file.
const configCmdName = "config"

// ConfigCmd reports the settings an interface runs with, as config file
// sections. Printed, they can be redirected somewhere; with --init they are
// written to the config file, which is how a node is set up before its agent
// is started for the first time.
type ConfigCmd struct {
	settings `embed:""`
	Init     bool `help:"write the settings to the config file as a new section for this interface, instead of printing them"`
}

func (c *ConfigCmd) Validate() error { return c.check() }

func (c *ConfigCmd) Run(cli *CLI) error {
	if c.Init {
		rendered, err := c.render(cli.LogLevel)
		if err != nil {
			return err
		}
		return c.write(cli.ConfigPath(), rendered)
	}
	rendered, err := c.dump(cli)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(rendered)
	return err
}

// dump is what the command prints. One interface, named or the only one there
// is, reports its settings as the agent would settle them, the command line
// included. Several sections and nothing to choose between them reports each
// as the file holds it, since there is no one section for a setting given here
// to belong to; giving one anyway is refused rather than quietly dropped.
func (c *ConfigCmd) dump(cli *CLI) ([]byte, error) {
	if cli.ifaceArg != "" {
		return c.render(cli.LogLevel)
	}
	sections, err := readSections(cli.ConfigPath())
	if err != nil {
		return nil, err
	}
	if len(sections) <= 1 {
		return c.render(cli.LogLevel)
	}
	given, err := c.givenHere(cli.LogLevel)
	if err != nil {
		return nil, err
	}
	if given {
		return nil, fmt.Errorf("the settings given here belong to one interface, and the config file has sections for %s; name the one they apply to with --interface",
			strings.Join(slices.Sorted(maps.Keys(sections)), ", "))
	}
	return c.renderAll(sections)
}

// givenHere reports whether any setting was given on this command line. It is
// asked only of a file with several sections, which resolves none of them, so
// anything that differs from the flag defaults came from here.
func (c *ConfigCmd) givenHere(logLevel LogLevelFlag) (bool, error) {
	s, err := c.sectionFor(logLevel)
	if err != nil {
		return false, err
	}
	return len(s) > 0, nil
}

// renderAll is every section of the config file, each with the overlay network
// the cluster told that interface where the file does not say it itself.
func (c *ConfigCmd) renderAll(sections map[string]map[string]any) ([]byte, error) {
	flags, err := c.flags()
	if err != nil {
		return nil, err
	}
	out := map[string][]setting{}
	for name, values := range sections {
		// in the order the settings are declared, so that what is printed
		// keeps the shape of what 'cheesecloth config' writes
		var s []setting
		for _, f := range flags {
			v, ok := values[f.Name]
			if !ok && f.Name == "overlay-net" {
				if net, known := cluster.KnownOverlayNet(c.state(), name); known {
					v, ok = net.String(), true
				}
			}
			if ok {
				s = append(s, setting{f.Name, v})
			}
		}
		if v, ok := values["log-level"]; ok {
			s = append(s, setting{"log-level", v})
		}
		out[name] = s
	}
	return encode(out)
}

// readSections is the config file's sections, none when it is not there.
func readSections(path string) (map[string]map[string]any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return parseSections(bytes.NewReader(content))
}

// render is this interface's section as it goes into a config file, with the
// overlay network the cluster told this node where nothing else says it, the
// same way every section of a whole-file dump is filled in.
func (c *ConfigCmd) render(logLevel LogLevelFlag) ([]byte, error) {
	if !c.OverlayNet.IsValid() {
		if net, ok := cluster.KnownOverlayNet(c.state(), c.Interface); ok {
			c.OverlayNet = net
		}
	}
	s, err := c.sectionFor(logLevel)
	if err != nil {
		return nil, err
	}
	return encode(map[string][]setting{c.Interface: s})
}

// sectionFor is what the command line and the config file say, and nothing
// else: only what differs from the flag defaults is worth writing down. The
// log level is a global flag rather than one of an interface's settings, but
// it belongs to a section all the same, since the agent runs one interface.
func (c *ConfigCmd) sectionFor(logLevel LogLevelFlag) ([]setting, error) {
	s, err := c.entries()
	if err != nil {
		return nil, err
	}
	if string(logLevel) != DefaultLogLevel {
		s = append(s, setting{"log-level", string(logLevel)})
	}
	return s, nil
}

// encode writes the sections as the config file spells them: each section
// under its interface name, its settings in the order given.
func encode(sections map[string][]setting) ([]byte, error) {
	scalar := func(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: s} }
	root := &yaml.Node{Kind: yaml.MappingNode}
	for _, name := range slices.Sorted(maps.Keys(sections)) {
		body := &yaml.Node{Kind: yaml.MappingNode}
		for _, s := range sections[name] {
			var value yaml.Node
			if err := value.Encode(s.value); err != nil {
				return nil, fmt.Errorf("rendering the settings: %w", err)
			}
			body.Content = append(body.Content, scalar(s.name), &value)
		}
		root.Content = append(root.Content, scalar(name), body)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("rendering the settings: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("rendering the settings: %w", err)
	}
	return buf.Bytes(), nil
}

// write appends the section to the config file, creating it if it is not
// there. The file is appended to rather than rewritten so that the comments
// of the one the package ships survive.
func (c *ConfigCmd) write(path string, rendered []byte) error {
	// the directory is made before the lock, which is a file in it
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// two interfaces being configured at once would otherwise each append to
	// the file as they found it, and the first section written would be lost
	lock, err := lockfile.Acquire(path, lockfile.Wait)
	if err != nil {
		return err
	}
	defer func() {
		if rerr := lock.Release(); rerr != nil {
			slog.Warn("could not release the config file lock", "path", path, "err", rerr)
		}
	}()

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	sections, err := parseSections(bytes.NewReader(existing))
	if err != nil {
		return err
	}
	if _, taken := sections[c.Interface]; taken {
		return fmt.Errorf("%s already has a section for %q; edit it, or run 'cheesecloth config' to print the settings and redirect them yourself", path, c.Interface)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := appendSection(f, existing, rendered); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote the %s section to %s\n", c.Interface, path)
	return f.Close()
}

// appendSection writes the section after what the file already holds, with a
// blank line between the two so an existing file stays readable.
func appendSection(w io.Writer, existing, rendered []byte) error {
	var lead string
	if n := len(existing); n > 0 {
		lead = "\n"
		if existing[n-1] != '\n' {
			lead = "\n\n"
		}
	}
	_, err := io.WriteString(w, lead+string(rendered))
	return err
}
