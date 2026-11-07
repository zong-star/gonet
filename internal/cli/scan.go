package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gonet/internal/config"
	"gonet/internal/discovery"
	"gonet/internal/model"
	"gonet/internal/preprobe"
	"gonet/internal/store/postgres"
)

// scanSummary is the persistent-mode output: the committed scan id and coverage.
type scanSummary struct {
	Preprobe          preprobe.Summary `json:"preprobe"`
	ScanID            int64            `json:"scan_id"`
	Status            string           `json:"status"`
	TerminationReason string           `json:"termination_reason"`
	Counts            discovery.Counts `json:"counts"`
	Issues            []model.Issue    `json:"issues"`
}

// runScan runs in-memory discovery (--dry-run) or persists a full round.
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan", stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	dryRun := fs.Bool("dry-run", false, "in-memory discovery (no database)")
	planOnly := fs.Bool("plan", false, "calculate effective IPv4 scope without network or database")
	output := fs.String("output", "-", "output path ('-' for stdout)")
	overwrite := fs.Bool("overwrite", false, "overwrite an existing output file")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "scan: --config is required")
		return ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return ExitUsage
	}
	logger := newLogger(cfg, stderr)
	if *planOnly {
		allowed, _ := cfg.ManagementCIDRs()
		r := preprobe.NewRange(allowed, excludedPrefixes(cfg), cfg.Discovery.AllowIPv4LinkLocal)
		if err := writeJSON(*output, *overwrite, map[string]any{"version": Version, "seeds": cfg.Discovery.Seeds, "allowed_cidrs": cfg.Discovery.ManagementCIDRs, "excluded_cidrs": cfg.Discovery.ExcludedCIDRs, "range_hosts": r.Count, "scope_digest": r.Digest, "max_targets": cfg.Discovery.MaxTargets, "preprobe": cfg.Discovery.Preprobe, "preprobe_mode": "full_range"}, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return ExitUsage
		}
		return ExitOK
	}
	if !*dryRun && *output != "-" {
		defer pruneOutputFiles(filepath.Dir(*output), cfg.History.KeepScans, stderr)
	}

	coord, seeds, err := newScanCoordinator(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *dryRun {
		coord.SetEventHandler(discoveryLogger(logger, 0))
		coord.SetProbeHandler(probeLogger(logger, 0))
		result := coord.Run(ctx)
		if err := writeJSON(*output, *overwrite, result, stdout); err != nil {
			logger.Error("write output", "error", err)
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return ExitUsage
		}
		logger.Info("scan finished (dry-run)", "status", result.Status,
			"devices", len(result.Devices), "links", len(result.Links), "termination", result.Termination)
		return scanExitCode(result.Status)
	}

	// Persistent mode: one dedicated session holds the advisory lock for the round.
	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return ExitUsage
	}
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		logger.Error("database connect failed")
		fmt.Fprintf(stderr, "scan: connect: %v\n", err)
		return ExitNoResult
	}
	defer store.Close(ctx)

	digest, err := cfg.ConfigDigest()
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return ExitUsage
	}
	summary, err := json.Marshal(cfg.SanitizedSummary())
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return ExitUsage
	}
	scanID, err := store.BeginScan(ctx, postgres.ScanInput{
		StartedAt:     time.Now().UTC(),
		Seeds:         seeds,
		ConfigDigest:  digest,
		ConfigSummary: summary,
		KeepScans:     cfg.History.KeepScans,
	})
	if err != nil {
		if errors.Is(err, postgres.ErrLocked) {
			logger.Error("scan lock held by another process")
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return ExitLocked
		}
		logger.Error("begin scan failed")
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return ExitNoResult
	}

	err = restoreScanContext(ctx, store, coord, cfg)
	if err != nil {
		_ = store.MarkFailed(ctx, scanID, "DB_CONTEXT_FAILED", "resolution context could not be loaded")
		fmt.Fprintln(stderr, "scan: resolution context could not be loaded")
		return ExitNoResult
	}
	coord.SetEventHandler(discoveryLogger(logger, scanID))
	coord.SetProbeHandler(probeLogger(logger, scanID))
	result := coord.Run(ctx)
	commitTimeout := cfg.Database.StatementTimeout.Duration
	if commitTimeout <= 0 {
		commitTimeout = 30 * time.Second
	}
	if result.Status == "aborted" && commitTimeout > 10*time.Second {
		commitTimeout = 10 * time.Second
	}
	commitCtx, cancelCommit := context.WithTimeout(context.WithoutCancel(ctx), commitTimeout)
	defer cancelCommit()
	if err := store.CommitResult(commitCtx, scanID, result); err != nil {
		failureCtx, cancelFailure := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelFailure()
		if merr := store.MarkFailed(failureCtx, scanID, "DB_COMMIT_FAILED", "result transaction failed"); merr != nil {
			logger.Error("mark failed", "error", merr)
		}
		logger.Error("result commit failed")
		fmt.Fprintf(stderr, "scan: commit: %v\n", err)
		return ExitNoResult
	}

	logCommittedNeighbors(logger, scanID, store, result)
	out := scanSummary{
		Preprobe:          result.Preprobe.Summary,
		ScanID:            scanID,
		Status:            result.Status,
		TerminationReason: result.Termination,
		Counts:            result.Counts,
		Issues:            result.Issues,
	}
	if err := writeJSON(*output, *overwrite, out, stdout); err != nil {
		logger.Error("write output", "error", err)
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return ExitUsage
	}
	logger.Info("scan committed", "scan_id", scanID, "status", result.Status,
		"devices", len(result.Devices), "links", len(result.Links))
	return scanExitCode(result.Status)
}

// newScanCoordinator builds the registry, resolver, collector and coordinator.
func newScanCoordinator(cfg *config.Config) (*discovery.Coordinator, []netip.Addr, error) {
	coll, err := newProfileCollector(cfg)
	if err != nil {
		return nil, nil, err
	}
	reg, resolver, err := resolutionRules(cfg)
	if err != nil {
		return nil, nil, err
	}
	seeds, err := cfg.Seeds()
	if err != nil {
		return nil, nil, err
	}
	cidrs, err := cfg.ManagementCIDRs()
	if err != nil {
		return nil, nil, err
	}
	addressOverrides := map[string][]netip.Addr{}
	for _, o := range cfg.Identity.AddressOverrides {
		if o.IdentityKey == "" || o.Reason == "" {
			return nil, nil, fmt.Errorf("address override requires identity and reason")
		}
		for _, text := range o.Addresses {
			a, err := netip.ParseAddr(text)
			if err != nil || !cfg.InManagementScope(a) {
				return nil, nil, fmt.Errorf("address override must be inside management_cidrs")
			}
			addressOverrides[o.IdentityKey] = append(addressOverrides[o.IdentityKey], a.Unmap())
		}
	}
	coord, err := discovery.New(discovery.Options{
		Preprobe:              preprobe.Options{Enabled: cfg.Discovery.Preprobe.Enabled, FullRange: true, Workers: cfg.Discovery.Preprobe.Workers, MaxHosts: cfg.Discovery.Preprobe.MaxHostsPerRun, KnownHosts: cfg.Discovery.Preprobe.KnownHostsPerRun, PhaseTimeout: cfg.Discovery.Preprobe.PhaseTimeout.Duration, RefreshInterval: cfg.Discovery.Preprobe.RefreshInterval.Duration, Prober: coll},
		AllowIPv4LinkLocal:    cfg.Discovery.AllowIPv4LinkLocal,
		Seeds:                 seeds,
		ManagementCIDRs:       cidrs,
		ExcludedCIDRs:         excludedPrefixes(cfg),
		MaxDepth:              cfg.Discovery.MaxDepth,
		MaxDevices:            cfg.Discovery.MaxDevices,
		MaxTargets:            cfg.Discovery.MaxTargets,
		Workers:               cfg.Discovery.Workers,
		RunTimeout:            cfg.Discovery.RunTimeout.Duration,
		MaxAddressesPerDevice: cfg.Discovery.MaxAddressesPerDevice,
		Profile:               cfg.SNMP.DefaultProfile,
		AddressOverrides:      addressOverrides,
		Collector:             coll,
		Registry:              reg,
		Resolver:              resolver,
	})
	if err != nil {
		return nil, nil, err
	}
	return coord, seeds, nil
}

// scanExitCode maps the discovery status to the CLI contract: completed 0,
// partial 3, failed 4, aborted 130.
func scanExitCode(status string) int {
	switch status {
	case "completed":
		return ExitOK
	case "partial":
		return ExitPartial
	case "aborted":
		return ExitInterrupted
	default:
		return ExitNoResult
	}
}
