package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"

	"gonet/internal/config"
	"gonet/internal/control"
	"gonet/internal/identity"
	"gonet/internal/store/postgres"
)

// runTopology dispatches `gonet topology export`.
func runTopology(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(stderr, "topology: want 'export'")
		return ExitUsage
	}
	fs := newFlagSet("topology export", stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	state := fs.String("state", "active", "active | all")
	output := fs.String("output", "-", "output path ('-' for stdout)")
	overwrite := fs.Bool("overwrite", false, "overwrite an existing output file")
	scopePath := fs.String("scope", "", "optional LLDP console scope JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "topology export: --config is required")
		return ExitUsage
	}
	if *state != "active" && *state != "all" {
		fmt.Fprintln(stderr, "topology export: --state must be 'active' or 'all'")
		return ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "topology export: %v\n", err)
		return ExitUsage
	}
	logger := newLogger(cfg, stderr)
	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		fmt.Fprintf(stderr, "topology export: %v\n", err)
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		logger.Error("database connect failed")
		fmt.Fprintf(stderr, "topology export: connect: %v\n", err)
		return ExitNoResult
	}
	defer conn.Close(ctx)

	exp, err := postgres.ExportTopology(ctx, conn, *state)
	if err != nil {
		logger.Error("topology export failed")
		fmt.Fprintf(stderr, "topology export: %v\n", err)
		return ExitNoResult
	}
	var value any = exp
	if *scopePath != "" {
		scope, e := control.LoadScope(*scopePath)
		if e != nil {
			fmt.Fprintln(stderr, "topology export: invalid scope")
			return ExitUsage
		}
		scope.Migrate(cfg)
		control.PrepareProbeView(exp, cfg, scope.Settings)
		rules, e := identity.LoadRules(cfg.Classification.RulesFile)
		if e != nil {
			fmt.Fprintln(stderr, "topology export: invalid device rules")
			return ExitUsage
		}
		view := control.Project(exp, *scope)
		control.LabelModels(view, rules)
		value = view
	}
	if err := writeJSON(*output, *overwrite, value, stdout); err != nil {
		logger.Error("write output", "error", err)
		fmt.Fprintf(stderr, "topology export: %v\n", err)
		return ExitUsage
	}
	logger.Info("topology exported", "devices", len(exp.Devices), "links", len(exp.Links),
		"fresh", exp.Fresh, "coverage_gap", exp.CoverageGap)
	return ExitOK
}
