// Package cli implements the gonet command line contract (section 10.2):
// exit codes, flag parsing and JSON output. Logs go to stderr, data to stdout.
package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"strings"

	"gonet/internal/config"
)

// Exit codes per section 10.2.
const (
	ExitOK          = 0
	ExitUsage       = 2
	ExitPartial     = 3
	ExitNoResult    = 4
	ExitLocked      = 5
	ExitInterrupted = 130
)

// Version is the program version; overridable via -ldflags "-X gonet/internal/cli.Version=...".
var Version = "0.21.0-full-probe-snmp-settings-dev"

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "auth":
		return runAuth(args[1:], stdout, stderr)
	case "version":
		return runVersion(args[1:], stdout)
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "collect":
		return runCollect(args[1:], stdout, stderr)
	case "probe":
		return runProbe(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "migrate":
		return runMigrate(args[1:], stdout, stderr)
	case "topology":
		return runTopology(args[1:], stdout, stderr)
	case "history":
		return runHistory(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return ExitUsage
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `usage: gonet <command> [flags]

commands:
  auth hash-password            securely initialize administrator bcrypt hash
  auth generate-agent-token     generate independent topology:read token and digest
  serve --config F --listen 127.0.0.1:8787       local LLDP visual console
  version                       print version, commit and build info
  config validate --config F    strictly validate config and env secrets
  collect --config F --target IP --output SNAP   collect one device (M1)
  probe --config F --target IP                  scalar-only SNMP access facts
  scan --config F --plan                        IPv4 scope count; no network
  scan --config F --dry-run --output RESULT     in-memory discovery (M3)
  scan --config F                               persisted discovery (M4)
  migrate up --config F                         apply PostgreSQL migrations (M4)
  topology export --config F --state active     export persisted topology (M4)
  history prune --config F --output-dir D       keep configured recent history
`)
}

func runVersion(args []string, stdout io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stdout, "version: unexpected argument %q\n", args[0])
		return ExitUsage
	}
	vcsRev := ""
	vcsTime := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				vcsRev = s.Value
			case "vcs.time":
				vcsTime = s.Value
			}
		}
	}
	fmt.Fprintf(stdout, "gonet %s\n", Version)
	fmt.Fprintf(stdout, "go %s\n", biGoVersion())
	if vcsRev != "" {
		fmt.Fprintf(stdout, "commit %s %s\n", vcsRev, vcsTime)
	} else {
		fmt.Fprintln(stdout, "commit unknown")
	}
	return ExitOK
}

func biGoVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		return bi.GoVersion
	}
	return "unknown"
}

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "config: missing subcommand")
		return ExitUsage
	}
	switch args[0] {
	case "validate":
		return runConfigValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "config: unknown subcommand %q\n", args[0])
		return ExitUsage
	}
}

func runConfigValidate(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("config validate", stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "config validate: --config is required")
		return ExitUsage
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "config validate: %v\n", err)
		return ExitUsage
	}
	logger := newLogger(cfg, stderr)
	if _, _, err := resolutionRules(cfg); err != nil {
		fmt.Fprintf(stderr, "config validate: %v\n", err)
		return ExitUsage
	}
	if err := cfg.ResolveAllProfiles(); err != nil {
		logger.Error("config validate failed", "error", err)
		fmt.Fprintf(stderr, "config validate: %v\n", err)
		return ExitUsage
	}
	logger.Info("config valid")
	fmt.Fprintf(stdout, "config %s is valid\n", *configPath)
	return ExitOK
}

func newLogger(cfg *config.Config, w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Logging.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(cfg.Logging.Format) == "json" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

var errUsage = errors.New("usage")
