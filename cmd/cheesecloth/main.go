// Command cheesecloth builds an encrypted wireguard mesh across a cluster of
// nodes whose membership rests on per-node identities and invitation tokens.
package main

import (
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/cli"
)

// version is set by the Makefile from the git tag.
var version = "dev"

func main() {
	c := &cli.CLI{}
	args := os.Args[1:]
	k, err := cli.Parser(c, cli.DefaultConfigPath, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cheesecloth:", err)
		os.Exit(1)
	}
	ktx, err := k.Parse(args)
	k.FatalIfErrorf(err)
	k.FatalIfErrorf(cli.Execute(c, ktx))
}
