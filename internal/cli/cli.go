package cli

import (
	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/control"
)

// DefaultInterface is the wireguard interface the commands act on unless told otherwise.
const DefaultInterface = "wgcloth"

// DefaultLogLevel is the verbosity the commands run at unless told otherwise.
const DefaultLogLevel = "warn"

// CLI is the command tree.
type CLI struct {
	Config   configFile       `help:"configuration file to read instead of ${default_config}" placeholder:"PATH"`
	LogLevel LogLevelFlag     `help:"set the verbosity (debug/info/warn/error)" default:"${default_log_level}"`
	Version  kong.VersionFlag `help:"display current version and exit"`

	Agent    AgentCmd  `cmd:"" default:"withargs" help:"start the cheesecloth agent (default when no command specified)"`
	Settings ConfigCmd `cmd:"" name:"config" help:"print the settings this interface runs with, including any given on this command line; --init writes them to the config file instead"`
	Status   StatusCmd `cmd:"" help:"show the wireguard interface and its peers"`
	Invite   InviteCmd `cmd:"" help:"mint an enrolment token for a new node (talks to the running agent)"`
	Revoke   RevokeCmd `cmd:"" help:"revoke a node's membership, permanently (talks to the running agent)"`
	Leave    LeaveCmd  `cmd:"" help:"take this node out of its cluster and remove what it leaves behind"`

	Service ServiceCmd `cmd:"" help:"register or remove the agent as a Windows service"`

	configPath string // the default config file, as Parser was given it
}

// ConfigPath is the config file this run reads and writes: what --config says,
// or the default the parser was built with.
func (c *CLI) ConfigPath() string {
	if c.Config != "" {
		return string(c.Config)
	}
	return c.configPath
}

// varsFor are the values interpolated into the flag tags.
func varsFor(configPath, version string) kong.Vars {
	return kong.Vars{"version": version, "default_config": configPath, "default_interface": DefaultInterface,
		"default_socket_dir": control.DefaultDir, "default_log_level": DefaultLogLevel}
}

// Parser builds the command-line parser; configPath is the file read when
// present and version is what --version prints.
func Parser(c *CLI, configPath, version string) (*kong.Kong, error) {
	c.configPath = configPath
	return kong.New(c,
		kong.Name("cheesecloth"),
		kong.Description("mesh overlay network manager. Settings may come from a YAML config file ("+configPath+
			" or --config) of settings keyed by flag name, one file per interface; command-line flags override it."),
		kong.UsageOnError(),
		varsFor(configPath, version),
		kong.Configuration(configLoader(), configPath),
	)
}
