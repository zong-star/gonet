package cli

import (
	"context"
	"errors"
	"fmt"
	"gonet/internal/config"
	"gonet/internal/history"
	"gonet/internal/store/postgres"
	"io"
	"time"
)

func pruneOutputFiles(directory string, keep int, stderr io.Writer) {
	if _, err := history.PruneOutputs(directory, keep); err != nil {
		fmt.Fprintln(stderr, "history: output cleanup incomplete; current topology remains available")
	}
}
func runHistory(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "prune" {
		fmt.Fprintln(stderr, "history: want prune --config F --output-dir D")
		return ExitUsage
	}
	fs := newFlagSet("history prune", stderr)
	path := fs.String("config", "", "configuration path")
	dir := fs.String("output-dir", "outputs", "generated history directory")
	filesOnly := fs.Bool("files-only", false, "prune generated files without database access")
	if fs.Parse(args[1:]) != nil || *path == "" {
		return ExitUsage
	}
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, "history: configuration could not be loaded")
		return ExitUsage
	}
	var database postgres.PrunedHistory
	if !*filesOnly {
		dsn, err := cfg.DatabaseDSN()
		if err != nil {
			fmt.Fprintln(stderr, "history: database environment variable is missing")
			return ExitUsage
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		store, err := postgres.Open(ctx, dsn)
		if err != nil {
			fmt.Fprintln(stderr, "history: database could not be connected")
			return ExitNoResult
		}
		defer store.Close(context.Background())
		database, err = store.PruneHistory(ctx, cfg.History.KeepScans)
		if errors.Is(err, postgres.ErrLocked) {
			fmt.Fprintln(stderr, "history: scan or migration is running; cleanup skipped")
			return ExitLocked
		}
		if err != nil {
			fmt.Fprintln(stderr, "history: database cleanup failed")
			return ExitNoResult
		}
	}
	files, err := history.PruneOutputs(*dir, cfg.History.KeepScans)
	if err != nil {
		fmt.Fprintln(stderr, "history: generated file cleanup incomplete")
		return ExitNoResult
	}
	if err = writeJSON("-", false, map[string]any{"keep_scans": cfg.History.KeepScans, "database": database, "files": files}, stdout); err != nil {
		return ExitNoResult
	}
	return ExitOK
}
