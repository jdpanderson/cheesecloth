package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/paths"
	"go.yaml.in/yaml/v3"
)

// Configuration file support: a YAML file of one interface's settings, keyed by
// flag name, applied as kong resolver defaults so command-line flags override
// them.
//
// One file describes one interface. A host running several clusters gives each
// its own file and names it with --config, which is the same thing the agent
// already needs to be told anyway: an agent runs one interface, so a file that
// held several only ever meant "find the part of this that applies to me".

// DefaultConfigPath is read when it exists; --config names another file.
var DefaultConfigPath = paths.ConfigFile

// configFile is the --config flag. It is kong.ConfigFlag with one difference:
// a file that is not there leaves every setting at its default rather than
// failing. That is what the default path already does, and it is what makes
// 'config --init --config PATH' able to create the file it names, which is how
// a second cluster on a host is set up.
type configFile string

func (c configFile) BeforeResolve(k *kong.Kong, ctx *kong.Context, trace *kong.Path) error {
	path := string(ctx.FlagValue(trace.Flag).(configFile))
	if _, err := os.Stat(kong.ExpandPath(path)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	resolver, err := k.LoadConfig(path)
	if err != nil {
		return err
	}
	ctx.AddResolver(resolver)
	return nil
}

// commandLineOnly are flags that must not appear in the config file, with the
// reason the operator is told: --join-key is a one-time secret, --config is
// how the file itself is found.
var commandLineOnly = map[string]string{
	"join-key": "it is a one-time secret; pass it on the command line",
	"config":   "it names the config file itself",
}

// notSettings are flags that are not settings at all, --init among them: it
// tells 'cheesecloth config' to write the file rather than print it. In the
// config file they are unknown keys like any other.
var notSettings = map[string]bool{"help": true, "version": true, "init": true}

// configLoader builds the loader for a config file.
func configLoader() kong.ConfigurationLoader {
	return func(r io.Reader) (kong.Resolver, error) {
		values, err := parseSettings(r)
		if err != nil {
			return nil, err
		}
		return &configResolver{values: values}, nil
	}
}

// parseSettings reads the file as one interface's settings. A value that is
// itself a mapping is the shape of a file keyed by interface name, which is an
// easy thing to write by mistake, so it is named as such.
func parseSettings(r io.Reader) (map[string]any, error) {
	var file map[string]any
	if err := yaml.NewDecoder(r).Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	for name, v := range file {
		if _, nested := v.(map[string]any); nested {
			return nil, fmt.Errorf("config: %q holds settings of its own, but this file holds one interface's "+
				"settings directly, as in %q. Give each interface its own file and name it with --config",
				name, "interface: "+name)
		}
	}
	return file, nil
}

// configResolver is a kong.Resolver over the parsed file.
type configResolver struct{ values map[string]any }

// Validate rejects unknown keys and command-line-only settings, so a typo or a
// misplaced secret is an error rather than silently ignored.
func (c *configResolver) Validate(app *kong.Application) error {
	known := map[string]bool{}
	collectFlags(app.Node, known)
	var bad []string
	for _, key := range slices.Sorted(maps.Keys(c.values)) {
		if reason, only := commandLineOnly[key]; only {
			return fmt.Errorf("config: %q cannot be set in the config file: %s", key, reason)
		}
		if !known[key] || notSettings[key] {
			bad = append(bad, key)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("config: unknown setting(s) %s; keys are flag names such as %q", strings.Join(bad, ", "), "bind-addr")
	}
	return nil
}

func collectFlags(n *kong.Node, into map[string]bool) {
	for _, f := range n.Flags {
		into[f.Name] = true
	}
	for _, child := range n.Children {
		collectFlags(child, into)
	}
}

// Resolve implements kong.Resolver. Command-line-only settings are refused
// here as well as in Validate, because kong resolves values before it
// validates resolvers.
func (c *configResolver) Resolve(_ *kong.Context, _ *kong.Path, flag *kong.Flag) (any, error) {
	v, ok := c.values[flag.Name]
	if !ok {
		return nil, nil
	}
	if reason, only := commandLineOnly[flag.Name]; only {
		return nil, fmt.Errorf("config: %q cannot be set in the config file: %s", flag.Name, reason)
	}
	return v, nil
}
