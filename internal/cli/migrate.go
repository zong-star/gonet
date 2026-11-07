package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"

	"gonet/internal/config"
	"gonet/internal/store/postgres"
)

// runMigrate applies forward migrations under the shared advisory lock.
func runMigrate(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "migrate: missing subcommand (want 'up')")
		return ExitUsage
	}
	if args[0] != "up" {
		fmt.Fprintf(stderr, "migrate: unknown subcommand %q\n", args[0])
		return ExitUsage
	}
	fs := newFlagSet("migrate up", stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "migrate up: --config is required")
		return ExitUsage
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "migrate: %v\n", err)
		return ExitUsage
	}
	logger := newLogger(cfg, stderr)
	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		fmt.Fprintf(stderr, "migrate: %v\n", err)
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		logger.Error("database connect failed")
		fmt.Fprintf(stderr, "migrate: connect: %v\n", err)
		return ExitNoResult
	}
	defer conn.Close(ctx)

	applied, err := postgres.Migrate(ctx, conn)
	if err != nil {
		if errors.Is(err, postgres.ErrLocked) {
			logger.Error("migration lock held by another process")
			fmt.Fprintf(stderr, "migrate: %v\n", err)
			return ExitLocked
		}
		logger.Error("migration failed")
		fmt.Fprintf(stderr, "migrate: %v\n", err)
		return ExitNoResult
	}
	if len(applied) == 0 {
		logger.Info("migrate up: nothing to do")
		fmt.Fprintln(stdout, "nothing to do")
	} else {
		logger.Info("migrate up applied", "versions", applied)
		fmt.Fprintf(stdout, "applied %v\n", applied)
	}
	return ExitOK
}
