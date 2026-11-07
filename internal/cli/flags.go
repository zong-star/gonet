package cli

import (
	"flag"
	"io"
)

// newFlagSet returns a flag.FlagSet that writes parse errors to w and uses
// ContinueOnError so callers can map failures to the usage exit code.
func newFlagSet(name string, w io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(w)
	return fs
}
