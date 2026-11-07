package cli

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"gonet/internal/config"
	"gonet/internal/preprobe"
)

// runProbe provides a one-address, scalar-only diagnostic using the same
// configured scope, profile and basic collector as automatic preprobe.
func runProbe(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("probe", stderr)
	path := fs.String("config", "", "configuration path")
	target := fs.String("target", "", "allowed access IP")
	output := fs.String("output", "-", "output path")
	overwrite := fs.Bool("overwrite", false, "overwrite output")
	if fs.Parse(args) != nil {
		return ExitUsage
	}
	if *path == "" || *target == "" {
		fmt.Fprintln(stderr, "probe: --config and --target are required")
		return ExitUsage
	}
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	a, err := netip.ParseAddr(*target)
	if err != nil || !cfg.InManagementScope(a) {
		fmt.Fprintln(stderr, "probe: address outside allowed scope")
		return ExitUsage
	}
	a = a.Unmap()
	allowed, _ := cfg.ManagementCIDRs()
	scope := preprobe.NewRange(allowed, excludedPrefixes(cfg), cfg.Discovery.AllowIPv4LinkLocal)
	if !a.Is4() || !scope.Contains(a) {
		fmt.Fprintln(stderr, "probe: requires an allowed IPv4 host")
		return ExitUsage
	}
	reg, _, err := resolutionRules(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	coll, err := newProfileCollector(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	attempt := coll.Probe(ctx, a)
	record := preprobe.Merge(preprobe.Record{}, attempt, reg)
	if err = writeJSON(*output, *overwrite, map[string]any{"attempt": attempt, "record": record}, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	if ctx.Err() != nil {
		return ExitInterrupted
	}
	if !attempt.Reachable {
		return ExitNoResult
	}
	return ExitOK
}
