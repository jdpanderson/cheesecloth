package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"go.yaml.in/yaml/v3"
)

// ConfigCmd reports the settings this interface runs with, as a config file.
// Printed, they can be redirected somewhere; with --init they are written to
// the config file, which is how a node is set up before its agent is started
// for the first time.
type ConfigCmd struct {
	settings `embed:""`
	Init     bool `help:"write the settings to the config file, instead of printing them"`
}

func (c *ConfigCmd) Validate() error { return c.check() }

func (c *ConfigCmd) Run(cli *CLI) error {
	rendered, err := c.render(cli.LogLevel)
	if err != nil {
		return err
	}
	if c.Init {
		return c.write(cli.ConfigPath(), rendered)
	}
	_, err = os.Stdout.Write(rendered)
	return err
}

// render is the config file as it would be written, with the overlay network
// the cluster told this node where nothing else says it.
func (c *ConfigCmd) render(logLevel LogLevelFlag) ([]byte, error) {
	if !c.OverlayNet.IsValid() {
		if net, ok := cluster.KnownOverlayNet(c.state(), c.Interface); ok {
			c.OverlayNet = net
		}
	}
	s, err := c.entries()
	if err != nil {
		return nil, err
	}
	// The log level is a global flag rather than one of an interface's
	// settings, but it belongs in the file all the same, since the agent runs
	// one interface.
	if string(logLevel) != DefaultLogLevel {
		s = append(s, setting{"log-level", string(logLevel)})
	}
	return encode(s)
}

// encode writes the settings as the config file spells them, in the order the
// flags are declared.
func encode(settings []setting) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode}
	for _, s := range settings {
		var value yaml.Node
		if err := value.Encode(s.value); err != nil {
			return nil, fmt.Errorf("rendering the settings: %w", err)
		}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: s.name}, &value)
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

// write creates the config file with the rendered settings. A file that is
// already there is left alone: one file describes one interface, so there is
// nothing to merge into, and rewriting it would throw away whatever the
// operator had put in it.
func (c *ConfigCmd) write(path string, rendered []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// O_EXCL rather than a lock: creating the file is the whole of the write,
	// so the file system settles two of these racing without any help.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if os.IsExist(err) {
		return fmt.Errorf("%s already exists; edit it, run 'cheesecloth config' to print the settings and "+
			"redirect them yourself, or name another file with --config", path)
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(rendered); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	return f.Close()
}
