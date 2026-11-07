package cli

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"gonet/internal/auth"
	"gonet/internal/config"
	"gonet/internal/control"
	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/store/postgres"
	"gonet/internal/webui"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type consoleBackend struct {
	intervalChanged                  chan struct{}
	mu                               sync.RWMutex
	configPath, scopePath, outputDir string
	log                              io.Writer
	scope                            control.Scope
}

func (b *consoleBackend) Settings() control.Settings {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s := b.scope.Settings
	s.Seeds = append([]string{}, s.Seeds...)
	s.AllowedCIDRs = append([]string{}, s.AllowedCIDRs...)
	s.ExcludedCIDRs = append([]string{}, s.ExcludedCIDRs...)
	s.BootstrapCIDRs = append([]string{}, s.BootstrapCIDRs...)
	if s.CollectionInterval != nil {
		v := *s.CollectionInterval
		s.CollectionInterval = &v
	}
	if s.TopologyScanInterval != nil {
		v := *s.TopologyScanInterval
		s.TopologyScanInterval = &v
	}
	if cfg, err := config.Load(b.configPath); err == nil {
		control.SyncSNMPSettings(&s, cfg)
		control.SyncTopologyScanInterval(&s, cfg.TopologyScan.Interval.Duration)
		control.SyncCollectionInterval(&s, cfg.InterfaceStatus.Interval.Duration)
	}
	return s
}
func (b *consoleBackend) SaveSettings(s control.Settings) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, err := config.Load(b.configPath)
	if err != nil {
		return fmt.Errorf("无法读取配置")
	}
	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		return fmt.Errorf("数据库配置缺失")
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("无法连接 PostgreSQL，暂时不能确认是否有扫描正在运行")
	}
	defer conn.Close(context.Background())
	var locked bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(207026,1)`).Scan(&locked); err != nil || !locked {
		return fmt.Errorf("另一个扫描或迁移正在运行，请完成后再保存范围")
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(207026,1)`)
	copy := b.scope
	copy.Settings = s
	if copy.Settings.CollectionInterval == nil {
		control.SyncCollectionInterval(&copy.Settings, cfg.InterfaceStatus.Interval.Duration)
	}
	if copy.Settings.TopologyScanInterval == nil {
		control.SyncTopologyScanInterval(&copy.Settings, cfg.TopologyScan.Interval.Duration)
	}
	// Console discovery always accepts in-scope LLDP management address hints.
	copy.Settings.ReadManagement = true
	// The console normalization entry also covers the startup auto-save, so a
	// legacy address-supplement value can neither resurface in the API nor block
	// validation with an invisible field. SavePolicy keeps the backups.
	retired := control.RetireBootstrap(&copy.Settings)
	if err := control.SavePolicy(b.configPath, b.scopePath, &copy); err != nil {
		return err
	}
	// Never retain the submitted secret in the long-lived console model.
	if copy.Settings.SNMP != nil {
		public := *copy.Settings.SNMP
		public.Community = ""
		copy.Settings.SNMP = &public
	}
	b.scope = copy
	if b.intervalChanged != nil {
		select {
		case b.intervalChanged <- struct{}{}:
		default:
		}
	}
	if len(retired) > 0 {
		b.recordRetiredBootstrap(retired, copy.Settings.ReadManagement)
	}
	return nil
}

// recordRetiredBootstrap writes an explicit record of a deprecated-field
// retirement. Recording is best effort: the settings were already saved, so a
// failed record must not turn a successful save into an error.
func (b *consoleBackend) recordRetiredBootstrap(entries []string, readManagement bool) {
	log := b.log
	if log == nil {
		log = io.Discard
	}
	fmt.Fprintf(log, "serve: 已退役 bootstrap_cidrs（旧地址补全，共 %d 项）: %s\n", len(entries), strings.Join(entries, ", "))
	record := struct {
		RetiredAt      string   `json:"retired_at"`
		Reason         string   `json:"reason"`
		Entries        []string `json:"entries"`
		ReadManagement bool     `json:"read_management_addresses"`
	}{
		RetiredAt:      time.Now().Format(time.RFC3339),
		Reason:         "新版控制台不再提供地址补全，规范化入口将 discovery bootstrap 字段置空；read_management_addresses 固定启用",
		Entries:        entries,
		ReadManagement: readManagement,
	}
	dir := filepath.Join(filepath.Dir(b.configPath), "outputs", "backups")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(log, "serve: 无法创建退役记录目录 %s: %v\n", dir, err)
		return
	}
	if err := control.WriteJSON(filepath.Join(dir, "bootstrap-retired.json"), record); err != nil {
		fmt.Fprintf(log, "serve: 无法写入退役记录: %v\n", err)
	}
}
func (b *consoleBackend) Read(ctx context.Context) (*control.View, error) {
	return b.readTopology(ctx, false)
}

func (b *consoleBackend) ReadTopologyEvidence(ctx context.Context) (*control.View, error) {
	return b.readTopology(ctx, true)
}

func (b *consoleBackend) readTopology(ctx context.Context, evidence bool) (*control.View, error) {
	cfg, e := config.Load(b.configPath)
	if e != nil {
		return nil, e
	}
	dsn, e := cfg.DatabaseDSN()
	if e != nil {
		return nil, e
	}
	conn, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return nil, e
	}
	defer conn.Close(ctx)
	read := postgres.ExportTopology
	if evidence {
		read = postgres.ExportTopologyWithEvidence
	}
	exp, e := read(ctx, conn, "all")
	if e != nil {
		return nil, e
	}
	b.mu.RLock()
	scope := b.scope
	b.mu.RUnlock()
	rules, e := identity.LoadRules(cfg.Classification.RulesFile)
	if e != nil {
		return nil, e
	}
	control.PrepareProbeView(exp, cfg, scope.Settings)
	view := control.Project(exp, scope)
	control.LabelModels(view, rules)
	applyInterfacePolicy(view, cfg)
	return view, nil
}
func (b *consoleBackend) Scan(ctx context.Context, supplement bool, progress func(webui.Progress)) (webui.RunResult, error) {
	b.mu.RLock()
	scope := b.scope
	b.mu.RUnlock()
	return scanConsole(ctx, b.configPath, b.outputDir, scope, supplement, progress)
}
func runServe(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	path := fs.String("config", "config.yaml", "configuration path")
	scopePath := fs.String("scope", "config/scan-scope.json", "inventory/scope JSON")
	output := fs.String("output-dir", "outputs", "output directory")
	listen := fs.String("listen", "127.0.0.1:8787", "explicit loopback or private listen address")
	sources := fs.String("allow-sources", "", "comma-separated client IP addresses or CIDRs for direct LAN access")
	tlsCert := fs.String("tls-cert", "", "PEM TLS server certificate")
	tlsKey := fs.String("tls-key", "", "PEM TLS server private key")
	agentPath := fs.String("agent-api-config", "", "legacy Agent API state file for one-time import")
	if fs.Parse(args) != nil {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "serve: unexpected arguments")
		return ExitUsage
	}
	if *agentPath == "" {
		*agentPath = filepath.Join(filepath.Dir(*scopePath), "agent-api.json")
	}
	authConfig, err := auth.LoadConfig()
	if err != nil {
		fmt.Fprintln(stderr, "serve:", err)
		return ExitUsage
	}
	// Relative rule paths keep the same semantics as CLI scanning. The launcher
	// sets the workspace root; paths themselves are never accepted via HTTP.
	cfg, e := config.Load(*path)
	if e != nil {
		fmt.Fprintln(stderr, "serve: configuration could not be loaded")
		return ExitUsage
	}
	if _, _, e = resolutionRules(cfg); e != nil {
		fmt.Fprintln(stderr, "serve:", e)
		return ExitUsage
	}
	if e = cfg.ResolveAllProfiles(); e != nil {
		fmt.Fprintln(stderr, "serve: SNMP credentials are missing or unavailable")
		return ExitUsage
	}
	dsn, e := cfg.DatabaseDSN()
	if e != nil {
		fmt.Fprintln(stderr, "serve: database environment variable is missing")
		return ExitUsage
	}
	var allowedSources []netip.Prefix
	if strings.TrimSpace(*sources) != "" {
		allowedSources, e = auth.ParseIPNetworks(strings.Split(*sources, ","))
		if e != nil {
			fmt.Fprintln(stderr, "serve: invalid --allow-sources:", e)
			return ExitUsage
		}
	}
	var tlsConfig *tls.Config
	if *tlsCert != "" || *tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil || !authConfig.CookieSecure {
			fmt.Fprintln(stderr, "serve: HTTPS requires a valid TLS certificate/key and GONET_COOKIE_SECURE=true")
			return ExitUsage
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	listener, e := webui.ListenAddress(*listen, allowedSources, tlsConfig != nil)
	if e != nil {
		fmt.Fprintln(stderr, "serve:", e)
		return ExitUsage
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startupCtx, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStartup()
	keys, err := postgres.OpenAPIKeys(startupCtx, dsn)
	if err != nil {
		fmt.Fprintln(stderr, "serve: API Key storage configuration is invalid")
		return ExitUsage
	}
	defer keys.Close()
	var legacyErr error
	err = keys.ImportLegacyAPIKey(startupCtx, func() ([]byte, *time.Time, *time.Time, error) {
		hash, created, updated, err := auth.ReadLegacyAPIKey(*agentPath, os.Getenv)
		legacyErr = err
		return hash, created, updated, err
	})
	cancelStartup()
	if err != nil {
		if legacyErr != nil {
			fmt.Fprintln(stderr, "serve:", legacyErr)
		} else {
			fmt.Fprintln(stderr, "serve: API Key storage could not be initialized; check PostgreSQL and run migrate up")
		}
		return ExitNoResult
	}
	scope, e := control.LoadScope(*scopePath)
	if e != nil {
		fmt.Fprintln(stderr, "serve: scope could not be loaded")
		return ExitUsage
	}
	scope.Migrate(cfg)
	// Persisted SNMP settings are public display metadata, never a request to
	// overwrite the authoritative profile when starting or normalizing scope.
	scope.Settings.SNMP = nil
	control.SyncCollectionInterval(&scope.Settings, cfg.InterfaceStatus.Interval.Duration)
	control.SyncTopologyScanInterval(&scope.Settings, cfg.TopologyScan.Interval.Duration)
	b := &consoleBackend{configPath: *path, scopePath: *scopePath, outputDir: *output, log: stderr, scope: *scope, intervalChanged: make(chan struct{}, 1)}
	if e = b.SaveSettings(scope.Settings); e != nil {
		fmt.Fprintln(stderr, "serve:", e)
		return ExitUsage
	}
	if len(allowedSources) != 0 {
		// A local request to the bound interface uses that interface as its source.
		ip := listener.Addr().(*net.TCPAddr).AddrPort().Addr().Unmap()
		authConfig.AllowedSources = append(allowedSources, netip.PrefixFrom(ip, ip.BitLen()))
	}
	app, err := webui.New(ctx, b, authConfig, keys)
	if err != nil {
		fmt.Fprintln(stderr, "serve: authentication initialization failed")
		return ExitUsage
	}
	defer app.Close()
	go b.runInterfaceStatus(ctx)
	server := &http.Server{Handler: app.Handler(listener.Addr().String()), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	scheme := "http"
	if tlsConfig != nil {
		scheme = "https"
	}
	fmt.Fprintln(stdout, "GoNet 控制台："+scheme+"://"+listener.Addr().String())
	fmt.Fprintln(stdout, "发现方式：从核心沿 LLDP 递归；管理地址只用于访问，排除范围优先。")
	if tlsConfig != nil {
		e = server.ServeTLS(listener, "", "")
	} else {
		e = server.Serve(listener)
	}
	if e != nil && !errors.Is(e, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "serve: local web server failed")
		return ExitNoResult
	}
	return ExitOK
}
func scanConsole(ctx context.Context, configPath, outputDir string, scope control.Scope, supplement bool, progress func(webui.Progress)) (webui.RunResult, error) {
	cfg, e := config.Load(configPath)
	if e != nil {
		return webui.RunResult{}, fmt.Errorf("配置无法读取")
	}
	defer pruneOutputFiles(outputDir, cfg.History.KeepScans, os.Stderr)
	// The saved console policy is authoritative for this job, even if a CLI
	// configuration editor changes the file between the UI request and load.
	cfg.Discovery.Seeds = append([]string{}, scope.Settings.Seeds...)
	cfg.Discovery.ManagementCIDRs = append([]string{}, scope.Settings.AllowedCIDRs...)
	cfg.Discovery.ExcludedCIDRs = append([]string{}, scope.Settings.ExcludedCIDRs...)
	cfg.SNMP.CollectManagementAddresses = true
	ctx, cancel := context.WithTimeout(ctx, cfg.Discovery.RunTimeout.Duration)
	defer cancel()
	dsn, e := cfg.DatabaseDSN()
	if e != nil {
		return webui.RunResult{}, fmt.Errorf("数据库连接配置缺失")
	}
	store, e := postgres.Open(ctx, dsn)
	if e != nil {
		return webui.RunResult{}, fmt.Errorf("无法连接 PostgreSQL 服务")
	}
	defer store.Close(context.Background())
	seeds, e := cfg.Seeds()
	if e != nil {
		return webui.RunResult{}, e
	}
	var supplementTargets []netip.Addr
	if supplement {
		supplementTargets, e = scope.Settings.BootstrapAddresses(cfg.Discovery.MaxTargets - len(seeds))
		if e != nil {
			return webui.RunResult{}, e
		}
		if len(supplementTargets) == 0 {
			return webui.RunResult{}, fmt.Errorf("请先在扫描设置中指定允许范围内的地址补全 IP/IP 段")
		}
	}
	configSummary := cfg.SanitizedSummary()
	configSummary["console_address_supplement"] = map[string]any{"requested": supplement, "ranges": scope.Settings.BootstrapCIDRs, "targets": len(supplementTargets)}
	summary, e := json.Marshal(configSummary)
	if e != nil {
		return webui.RunResult{}, fmt.Errorf("配置摘要生成失败")
	}
	hash := sha256.Sum256(summary)
	digest := hex.EncodeToString(hash[:])
	id, e := store.BeginScan(ctx, postgres.ScanInput{StartedAt: time.Now(), Seeds: seeds, ConfigDigest: digest, ConfigSummary: summary, KeepScans: cfg.History.KeepScans})
	if errors.Is(e, postgres.ErrLocked) {
		return webui.RunResult{}, fmt.Errorf("另一个扫描或迁移正在运行，请稍后更新")
	}
	if e != nil {
		return webui.RunResult{}, fmt.Errorf("无法创建扫描轮次")
	}
	result := webui.RunResult{ScanID: id}
	fail := func(message string) (webui.RunResult, error) {
		cleanup, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = store.MarkFailed(cleanup, id, "CONSOLE_SCAN_FAILED", message)
		return result, fmt.Errorf("%s", message)
	}
	coord, _, e := newScanCoordinator(cfg)
	if e != nil {
		return fail("发现配置或型号规则无效")
	}
	coord.SetProgress(func(p discovery.Progress) { progress(webui.FromDiscovery(p)) })
	logger := newLogger(cfg, os.Stderr)
	coord.SetEventHandler(discoveryLogger(logger, id))
	coord.SetProbeHandler(probeLogger(logger, id))
	if e = restoreScanContext(ctx, store, coord, cfg); e != nil {
		return fail("历史身份、端口或探测池读取失败；请先运行 migrate up")
	}
	if supplement {
		targets := coord.PrepareSupplement(supplementTargets)
		phaseCtx, cancelPhase := context.WithTimeout(ctx, min(time.Minute, cfg.Discovery.RunTimeout.Duration/3))
		hints := supplementAddresses(phaseCtx, cfg, targets, progress)
		cancelPhase()
		coord.SetSupplementHints(hints)
	}
	r := coord.Run(ctx)
	progress(webui.Progress{Stage: "saving", Completed: r.Counts.DevicesCollected, Scheduled: r.Counts.AdmittedCandidates})
	commitTimeout := cfg.Database.StatementTimeout.Duration
	if commitTimeout <= 0 {
		commitTimeout = 30 * time.Second
	}
	if r.Status == "aborted" && commitTimeout > 10*time.Second {
		commitTimeout = 10 * time.Second
	}
	commitCtx, c := context.WithTimeout(context.WithoutCancel(ctx), commitTimeout)
	defer c()
	if e = store.CommitResult(commitCtx, id, r); e != nil {
		newLogger(cfg, os.Stderr).Error("result commit failed", "scan_id", id, "code", "DATABASE_WRITE_FAILED", "error", e)
		return fail("扫描结果提交失败，原有已提交拓扑仍保留")
	}
	logCommittedNeighbors(newLogger(cfg, os.Stderr), id, store, r)
	result.Status = r.Status
	// Publishing uses the same projection as the browser and scoped CLI export.
	exportCtx, ec := context.WithTimeout(context.Background(), 15*time.Second)
	defer ec()
	conn, e := pgx.Connect(exportCtx, dsn)
	if e != nil {
		return result, fmt.Errorf("扫描已提交，结果导出暂时失败")
	}
	defer conn.Close(exportCtx)
	exp, e := postgres.ExportTopology(exportCtx, conn, "all")
	if e != nil {
		return result, fmt.Errorf("扫描已提交，结果导出暂时失败")
	}
	control.PrepareProbeView(exp, cfg, scope.Settings)
	view := control.Project(exp, scope)
	if rules, err := identity.LoadRules(cfg.Classification.RulesFile); err == nil {
		control.LabelModels(view, rules)
		applyInterfacePolicy(view, cfg)
	}
	if e = control.WriteJSON(filepath.Join(outputDir, "topology-latest.json"), view); e != nil {
		return result, fmt.Errorf("扫描已提交，本机输出文件写入失败")
	}
	_ = control.WriteJSON(filepath.Join(outputDir, fmt.Sprintf("scan-ui-%d.json", id)), map[string]any{"scan_id": id, "status": r.Status, "counts": r.Counts, "preprobe": r.Preprobe.Summary, "issues": r.Issues})
	_ = control.WriteJSON(filepath.Join(outputDir, "latest-status.json"), map[string]any{"scan_id": id, "status": r.Status, "devices": len(view.Devices), "links": len(view.Links), "device_counts": view.Counts, "updated_at": time.Now(), "source": "console", "termination_reason": r.Termination})
	progress(webui.Progress{Stage: "finished", Completed: r.Counts.DevicesCollected, Scheduled: r.Counts.AdmittedCandidates})
	return result, nil
}
