// Command basilisk keeps PII and secrets away from coding agents.
// Only the command surface exists so far; every subcommand is a stub.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `basilisk keeps PII and secrets away from coding agents.

Usage:
  basilisk scan [path...]      report PII and secrets found
  basilisk petrify             replace PII and secrets on stdin with placeholders
  basilisk mirror              swap placeholders on stdin back to real values
  basilisk hook <event>        handle a Claude Code or Codex hook payload on stdin
  basilisk version             print the version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "hook":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "basilisk hook: missing event name")
			return 2
		}
		return notImplemented(stderr, "hook "+args[1])
	case "scan", "petrify", "mirror":
		return notImplemented(stderr, args[0])
	default:
		fmt.Fprintf(stderr, "basilisk: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func notImplemented(stderr io.Writer, cmd string) int {
	fmt.Fprintf(stderr, "basilisk %s: not implemented yet\n", cmd)
	return 1
}
