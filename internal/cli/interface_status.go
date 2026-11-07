package cli

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"gonet/internal/collector"
	"gonet/internal/config"
	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"net/netip"
	"slices"
	"sync"
	"time"
)

func applyInterfacePolicy(view *control.View, cfg *config.Config) {
	now := time.Now().UTC()
	// Cache timestamps are evaluated on every read, never only during a poll.
	for i := range view.Links {
		l := &view.Links[i]
		l.LinkInterfaceStatus = model.LinkStatus(l.SourceInterfaceStatus, l.TargetInterfaceStatus, now, cfg.InterfaceStatus.StaleAfter.Duration)
	}
	for d := range view.Devices {
		for i := range view.Devices[d].Interfaces {
			x := &view.Devices[d].Interfaces[i]
			if x.StatusCollectedAt != nil && (now.Before(*x.StatusCollectedAt) || now.Sub(*x.StatusCollectedAt) >= cfg.InterfaceStatus.StaleAfter.Duration) && x.StatusCollectionState == "success" {
				x.StatusCollectionState = "stale"
			}
		}
	}
	view.InferenceStaleAfter = cfg.InterfaceStatus.InferenceStaleAfter.Duration
}
func (b *consoleBackend) runInterfaceStatus(ctx context.Context) {
	for ctx.Err() == nil {
		cycleStarted := time.Now()
		cfg, err := config.Load(b.configPath)
		interval := 4 * time.Minute
		if err == nil {
			interval = cfg.InterfaceStatus.Interval.Duration
			if !cfg.InterfaceStatus.Disabled {
				if err = b.collectInterfaceStatuses(ctx, cfg); err != nil && ctx.Err() == nil {
					fmt.Fprintln(b.log, "interface-status: collection cycle failed:", err)
				}
			}
		}
		if !b.waitInterfaceStatus(ctx, cycleStarted, interval) {
			return
		}
	}
}
func (b *consoleBackend) collectInterfaceStatuses(ctx context.Context, cfg *config.Config) error {
	view, err := b.Read(ctx)
	if err != nil {
		return err
	}
	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		return err
	}
	leader, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer leader.Close(context.Background())
	var elected bool
	if err = leader.QueryRow(ctx, `SELECT pg_try_advisory_lock(207026,2)`).Scan(&elected); err != nil {
		return err
	}
	if !elected {
		return nil
	}
	defer leader.Exec(context.Background(), `SELECT pg_advisory_unlock(207026,2)`)
	// The whole cycle is bounded; each worker owns its network and DB sessions.
	ctx, cancel := context.WithTimeout(ctx, cfg.InterfaceStatus.Interval.Duration)
	defer cancel()
	jobs := make(chan control.Device)
	var wg sync.WaitGroup
	for w := 0; w < cfg.InterfaceStatus.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				if ctx.Err() != nil {
					return
				}
				attempt := time.Now().UTC()
				var result []model.Interface
				var collectErr error
				for _, raw := range d.AccessAddresses {
					addr, e := netip.ParseAddr(raw)
					if e != nil || !cfg.InManagementScope(addr) {
						continue
					}
					name, e := cfg.ResolveProfileForAddr(addr)
					if e != nil {
						collectErr = e
						continue
					}
					prof, e := cfg.ResolveProfile(name)
					if e != nil {
						collectErr = e
						continue
					}
					params := snmpParams(cfg, prof)
					params.Target = addr.String()
					deviceCtx, stop := context.WithTimeout(ctx, cfg.SNMP.DeviceTimeout.Duration)
					result, collectErr = collector.CollectInterfaceStatus(deviceCtx, params)
					stop()
					if collectErr == nil {
						break
					}
				}
				if result == nil && collectErr == nil {
					collectErr = fmt.Errorf("no verified SNMP access address")
				}
				conn, e := pgx.Connect(ctx, dsn)
				if e != nil {
					fmt.Fprintln(b.log, "interface-status: database unavailable")
					continue
				}
				// Retain physical Ethernet and logical LAG interfaces already identified
				// by the existing native membership collector (including Huawei ifType 53).
				if collectErr == nil {
					known := map[string]bool{}
					rows, e := conn.Query(ctx, `SELECT DISTINCT f.if_name FROM scan_interface_facts f JOIN scan_lag_members m ON (f.scan_id,f.device_id,f.if_index)=(m.scan_id,m.device_id,m.aggregate_if_index) WHERE f.device_id=$1`, d.ID)
					if e == nil {
						for rows.Next() {
							var n string
							if e = rows.Scan(&n); e != nil {
								break
							}
							known[n] = true
						}
						if e == nil {
							e = rows.Err()
						}
						rows.Close()
					}
					if e != nil {
						collectErr = e
					} else {
						result = slices.DeleteFunc(result, func(i model.Interface) bool { return i.Type != 6 && i.Type != 161 && !known[i.Name] })
					}
				}
				e = postgres.SaveInterfaceStatus(ctx, conn, d.ID, result, attempt, collectErr)
				conn.Close(ctx)
				if e != nil {
					fmt.Fprintln(b.log, "interface-status: cache write failed for device", d.ID, ":", e)
				} else if collectErr != nil {
					fmt.Fprintln(b.log, "interface-status: SNMP collection failed for device", d.ID)
				}
			}
		}()
	}
	defer wg.Wait()
	for _, d := range view.Devices {
		if d.IdentityState != "verified" || d.Kind != "switch" {
			continue
		}
		select {
		case jobs <- d:
		case <-ctx.Done():
			close(jobs)
			return ctx.Err()
		}
	}
	close(jobs)
	return nil
}

// Recalculate the next due time on a successful settings save, even when the
// previous interval was measured in days. Running collections finish normally.
func (b *consoleBackend) waitInterfaceStatus(ctx context.Context, started time.Time, interval time.Duration) bool {
	for {
		delay := interval - time.Since(started)
		if delay < time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-b.intervalChanged:
			timer.Stop()
			if cfg, err := config.Load(b.configPath); err == nil {
				interval = cfg.InterfaceStatus.Interval.Duration
			}
		case <-timer.C:
			return true
		}
	}
}
