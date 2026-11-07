package cli

import (
	"context"
	"gonet/internal/config"
	"gonet/internal/discovery"
	"gonet/internal/store/postgres"
)

// Both console and CLI (including scheduled scans) restore the same state and
// run the same coordinator stages. Dry-run simply uses its empty in-memory pool.
func restoreScanContext(ctx context.Context, store *postgres.Store, coord *discovery.Coordinator, cfg *config.Config) error {
	devices, ports, err := store.LoadContext(ctx)
	if err != nil {
		return err
	}
	if err = coord.RestoreContext(devices, ports); err != nil {
		return err
	}
	if cfg.Discovery.Preprobe.Enabled {
		pool, cursor, e := store.LoadProbeContext(ctx)
		if e != nil {
			return e
		}
		coord.SetProbeContext(pool, cursor)
	}
	return nil
}
