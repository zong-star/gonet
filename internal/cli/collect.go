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

	"gonet/internal/collector"
	"gonet/internal/collector/snmp"
	"gonet/internal/config"
	"gonet/internal/model"
)

func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("collect", stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	targetStr := fs.String("target", "", "target IP address")
	output := fs.String("output", "-", "output path ('-' for stdout)")
	overwrite := fs.Bool("overwrite", false, "overwrite an existing output file")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *configPath == "" || *targetStr == "" {
		fmt.Fprintln(stderr, "collect: --config and --target are required")
		return ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		return ExitUsage
	}
	logger := newLogger(cfg, stderr)

	target, err := netip.ParseAddr(*targetStr)
	if err != nil {
		fmt.Fprintf(stderr, "collect: invalid --target %q: %v\n", *targetStr, err)
		return ExitUsage
	}
	if !cfg.InManagementScope(target) {
		fmt.Fprintf(stderr, "collect: target %s is outside management_cidrs\n", target)
		return ExitUsage
	}

	profName, err := cfg.ResolveProfileForAddr(target)
	if err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		return ExitUsage
	}
	prof, err := cfg.ResolveProfile(profName)
	if err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	coll := collector.New(collector.Options{
		LAGTimeout: cfg.SNMP.LAGTimeout.Duration, LAGMaxPDUs: cfg.SNMP.LAGMaxPDUs,
		CollectManagementAddresses: cfg.SNMP.CollectManagementAddresses, Adapters: cfg.SNMP.Adapters,
		Params:             snmpParams(cfg, prof),
		MaxNeighbors:       cfg.SNMP.MaxNeighborsPerDevice,
		ConsistencyRetries: cfg.SNMP.ConsistencyRetries,
		ViewVerified:       cfg.SNMP.ViewVerified,
		DeviceTimeout:      cfg.SNMP.DeviceTimeout.Duration,
		StartupGrace:       cfg.SNMP.StartupGrace.Duration,
	})
	dt := model.DiscoveryTarget{Address: target.Unmap(), Profile: profName}
	snap, err := coll.Collect(ctx, dt)

	if ctx.Err() != nil {
		logger.Error("collect interrupted")
		return ExitInterrupted
	}
	if snap == nil {
		if err != nil {
			logger.Error("collect failed", "target", target.String(), "error", err)
		} else {
			logger.Error("collect failed", "target", target.String())
		}
		fmt.Fprintf(stderr, "collect: no usable snapshot\n")
		return ExitNoResult
	}

	if err := writeJSON(*output, *overwrite, snap, stdout); err != nil {
		logger.Error("write output", "error", err)
		fmt.Fprintf(stderr, "collect: %v\n", err)
		return ExitUsage
	}

	if !snap.SnapshotStable || len(snap.Issues) > 0 {
		logger.Warn("collect produced warnings", "issues", len(snap.Issues), "stable", snap.SnapshotStable)
	}
	code := collectExitCode(snap)
	if code == ExitOK {
		logger.Info("collect complete", "target", target.String(), "neighbors", len(snap.Neighbors))
	} else {
		logger.Warn("collect partial", "target", target.String(), "collection_complete", snap.CollectionComplete)
	}
	return code
}

// collectExitCode maps a collected snapshot to the CLI contract: a complete
// necessary collection is 0; a usable but partial result is 3; no snapshot is 4.
func collectExitCode(snap *model.DeviceSnapshot) int {
	if snap == nil {
		return ExitNoResult
	}
	if snap.CollectionComplete && snap.SnapshotStable {
		return ExitOK
	}
	return ExitPartial
}

// snmpParams maps resolved config/profile into transport parameters.
func snmpParams(cfg *config.Config, prof *config.SNMPProfile) snmp.Params {
	p := snmp.Params{
		Port:           cfg.SNMP.Port,
		Timeout:        cfg.SNMP.Timeout.Duration,
		Retries:        cfg.SNMP.Retries,
		MaxRepetitions: cfg.SNMP.MaxRepetitions,
		MaxPDUs:        cfg.SNMP.MaxPDUsPerDevice,
		Version:        prof.Version,
		Community:      prof.Community,
	}
	if prof.Version == "3" {
		p.V3 = &snmp.V3Params{
			SecurityLevel:  prof.SecurityLevel,
			Username:       prof.Username,
			AuthProtocol:   prof.AuthProtocol,
			AuthPassphrase: prof.AuthPassphrase,
			PrivProtocol:   prof.PrivProtocol,
			PrivPassphrase: prof.PrivPassphrase,
			ContextName:    prof.ContextName,
		}
	}
	return p
}

// writeJSON emits a stable, indented snapshot to stdout or an atomically
// replaced file. Existing files are refused unless overwrite is set.
func writeJSON(path string, overwrite bool, v any, stdout io.Writer) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	data = append(data, '\n')

	if path == "-" {
		_, err := stdout.Write(data)
		return err
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output %s exists (use --overwrite to replace)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gonet-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !overwrite {
		return os.Link(tmpName, path)
	}
	return os.Rename(tmpName, path)
}
