package webui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"gonet/internal/auth"
	"gonet/internal/control"
	"gonet/internal/discovery"
	"gonet/internal/preprobe"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed assets/*
var assets embed.FS

type Progress struct {
	Probe     *preprobe.Summary `json:"probe,omitempty"`
	Stage     string            `json:"stage"`
	Target    string            `json:"target,omitempty"`
	Completed int               `json:"completed"`
	Scheduled int               `json:"scheduled"`
	Depth     int               `json:"depth"`
}
type Job struct {
	Running    bool       `json:"running"`
	ID         string     `json:"id"`
	State      string     `json:"state"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Progress   Progress   `json:"progress"`
	Message    string     `json:"message"`
	ScanID     int64      `json:"scan_id"`
}
type RunResult struct {
	ScanID int64
	Status string
}
type Backend interface {
	Read(context.Context) (*control.View, error)
	Settings() control.Settings
	SaveSettings(control.Settings) error
	Scan(context.Context, bool, func(Progress)) (RunResult, error)
}
type Server struct {
	topologyChanged    chan struct{}
	topologyInterval   time.Duration
	topologyNextAt     time.Time
	stop               context.CancelFunc
	closed             bool
	cursorKey          [32]byte
	backend            Backend
	authConfig         auth.Config
	sessions           *auth.Store
	loginLimiter       *auth.LoginLimiter
	apiKeys            APIKeyStore
	apiReadTimeout     time.Duration
	topologyStaleAfter time.Duration
	auditLogger        *slog.Logger
	host               string
	mu                 sync.Mutex
	job                Job
	cancel             context.CancelFunc
	ctx                context.Context
	wg                 sync.WaitGroup
}

// servedAssets is the complete allow-list of frontend files; every other path
// stays 404 so the embedded filesystem cannot be walked for arbitrary files.
var servedAssets = map[string]bool{
	"/":                      true,
	"/app.js":                true,
	"/style.css":             true,
	"/tokens.css":            true,
	"/login":                 true,
	"/login.css":             true,
	"/login.js":              true,
	"/ui-pagination.js":      true,
	"/ui-settings.js":        true,
	"/ui-region.js":          true,
	"/ui-topology-layout.js": true,
	"/ui-topology-render.js": true,
	"/ui-topology.css":       true,
	"/ui-api.js":             true,
	"/ui-api.css":            true,
	"/ui-uplink.js":          true,
	"/ui-uplink.css":         true,
	"/docs/api.html":         true,
	"/docs/api.css":          true,
	"/docs/api.js":           true,
}

func servedAsset(path string) bool { return servedAssets[path] }

type APIKeyStore interface {
	ListAPIKeys(context.Context) ([]postgres.APIKey, error)
	CreateAPIKey(context.Context, postgres.APIKey, [32]byte) (postgres.APIKey, error)
	UpdateAPIKey(context.Context, int64, postgres.APIKeyUpdate) (postgres.APIKey, time.Time, error)
	DeleteAPIKey(context.Context, int64) error
	LookupAPIKey(context.Context, [32]byte) (postgres.APIKeyGrant, error)
}

func New(ctx context.Context, b Backend, cfg auth.Config, keys APIKeyStore) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, errors.New("API Key store is required")
	}
	staleAfter, err := parseTopologyStaleAfter(os.Getenv("GONET_TOPOLOGY_STALE_AFTER"))
	if err != nil {
		return nil, err
	}
	var cursorKey [32]byte
	if _, err := rand.Read(cursorKey[:]); err != nil {
		return nil, err
	}
	runCtx, stop := context.WithCancel(ctx)
	server := &Server{stop: stop, topologyChanged: make(chan struct{}, 1), cursorKey: cursorKey, backend: b, authConfig: cfg, sessions: auth.NewStore(cfg.SessionTTL), loginLimiter: auth.NewLoginLimiter(), apiKeys: keys, apiReadTimeout: 10 * time.Second, topologyStaleAfter: staleAfter, auditLogger: slog.Default(), ctx: runCtx, job: Job{State: "idle", Message: "等待更新"}}
	server.wg.Add(1)
	go server.runTopologySchedule()
	return server, nil
}
func (s *Server) Handler(host string) http.Handler {
	s.host = host
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("GET /api/v1/auth/me", s.me)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("GET /api/devices.csv", s.devicesCSV)
	mux.HandleFunc("PUT /api/settings", s.settings)
	mux.HandleFunc("POST /api/scan", s.scan)
	mux.HandleFunc("POST /api/cancel", s.cancelScan)
	mux.HandleFunc("GET "+apiKeyPath, s.listAPIKeys)
	mux.HandleFunc("POST "+apiKeyPath, s.saveAPIKey)
	mux.HandleFunc("PATCH "+apiKeyPath+"/{id}", s.saveAPIKey)
	mux.HandleFunc("DELETE "+apiKeyPath+"/{id}", s.deleteAPIKey)
	mux.HandleFunc("GET "+legacyOpenAPIPath, downloadOpenAPI)
	mux.HandleFunc("GET /docs/openapi.yaml", downloadOpenAPI)
	mux.HandleFunc("GET /docs/agent-openapi.yaml", downloadAgentOpenAPI)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	static, _ := fs.Sub(assets, "assets")
	files := http.FileServer(http.FS(static))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if !servedAsset(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/login" {
			if _, ok := s.session(r); ok {
				http.Redirect(w, r, auth.SafeNext(r.URL.Query().Get("next")), http.StatusFound)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/login.html"
		}
		files.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w = headResponse{w}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if len(s.authConfig.AllowedSources) != 0 && !containsIP(s.authConfig.AllowedSources, peerIP(r.RemoteAddr)) {
			s.requestForbidden(w, r, "请求来源不在控制台访问范围内")
			return
		}
		if r.Host != s.host {
			s.requestForbidden(w, r, "请求地址与控制台监听地址不符")
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != scheme+"://"+s.host {
			s.requestForbidden(w, r, "拒绝跨站请求")
			return
		}
		if kind, id, ok := topologyRoute(r.URL.Path); ok {
			s.topologyAPI(w, r, kind, id)
			return
		}
		if !s.authorize(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	read := s.backend.Read
	if backend, ok := s.backend.(interface {
		ReadTopologyEvidence(context.Context) (*control.View, error)
	}); ok {
		read = backend.ReadTopologyEvidence
	}
	data, err := read(ctx)
	s.mu.Lock()
	job := s.job
	s.mu.Unlock()
	session, _ := s.session(r)
	response := map[string]any{"token": session.CSRFToken, "settings": s.backend.Settings(), "job": job, "topology": data, "error": ""}
	if data != nil {
		graph := projectCurrentTopologyGraph(data)
		response["topology"] = topologyStateV4{View: data, InferencePolicyVersion: topology.AggregationInferencePolicy, AggregateConnections: graph.AggregateConnections, Graph: graph}
	}
	if err != nil {
		response["error"] = "暂时无法读取数据库，请检查 PostgreSQL 服务及本机连接配置。"
	}
	writeJSON(w, 200, response)
}

// A regular HTTP attachment also works in browsers that do not download blob URLs.
// IDs only select rows already visible under the current access policy.
func (s *Server) devicesCSV(w http.ResponseWriter, r *http.Request) {
	selected := map[int64]bool{}
	values, filtered := r.URL.Query()["ids"]
	if filtered {
		for _, value := range values {
			if value == "" {
				continue
			}
			for _, raw := range strings.Split(value, ",") {
				id, err := strconv.ParseInt(raw, 10, 64)
				if err != nil || id <= 0 {
					writeJSON(w, 400, map[string]string{"error": "导出设备选择无效"})
					return
				}
				selected[id] = true
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	view, err := s.backend.Read(ctx)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "暂时无法读取数据库，请稍后导出"})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="gonet-devices.csv"`)
	_, _ = io.WriteString(w, "\ufeff")
	writer := csv.NewWriter(w)
	writer.UseCRLF = true
	_ = writer.Write([]string{"设备", "区域", "厂商", "型号", "管理地址", "Chassis MAC", "采集状态", "物理链路数", "设备类型"})
	for _, d := range view.Devices {
		if filtered && !selected[d.ID] {
			continue
		}
		status := "仅有历史记录"
		if d.Status == "collected" {
			status = "本轮已采集"
		}
		row := []string{d.Name, d.Area, d.Vendor, d.Model, strings.Join(d.AccessAddresses, ", "), d.MAC, status, strconv.Itoa(d.LinkCount), control.KindLabel(d.Kind)}
		for i, value := range row {
			trimmed := strings.TrimLeft(value, " \t\r\n")
			if trimmed != "" && strings.ContainsAny(trimmed[:1], "=+@-") {
				row[i] = "'" + value
			}
		}
		_ = writer.Write(row)
	}
	writer.Flush()
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	var settings control.Settings
	if err := decode(w, r, &settings); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job.Running {
		writeJSON(w, 409, map[string]string{"error": "扫描期间不能修改范围，请等待完成或停止扫描。"})
		return
	}
	if err := s.backend.SaveSettings(settings); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	select {
	case s.topologyChanged <- struct{}{}:
	default:
	}
	writeJSON(w, 200, map[string]any{"settings": s.backend.Settings()})
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Supplement bool `json:"supplement"`
	}
	if err := decode(w, r, &request); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	job, err := s.startScanLocked(request.Supplement)
	s.mu.Unlock()
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 202, job)
}

// startScanLocked is the common manual/automatic job entry point. The caller
// owns s.mu; all progress, cancellation and database scan locking stay shared.
func (s *Server) startScanLocked(supplement bool) (Job, error) {
	if s.closed || s.ctx.Err() != nil {
		return Job{}, errors.New("服务正在停止")
	}
	if s.job.Running {
		return Job{}, errors.New("已有更新任务正在运行。")
	}
	now := time.Now()
	ctx, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	s.job = Job{Running: true, ID: fmt.Sprint(now.UnixNano()), State: "running", StartedAt: &now, Message: "正在准备 LLDP 递归发现", Progress: Progress{Stage: "preparing"}}
	job := s.job
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		result, err := s.backend.Scan(ctx, supplement, func(p Progress) { s.mu.Lock(); s.job.Progress = p; s.mu.Unlock() })
		end := time.Now()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.job.Running = false
		s.job.FinishedAt = &end
		s.job.ScanID = result.ScanID
		s.cancel = nil
		if err != nil {
			s.job.State = "failed"
			s.job.Message = err.Error()
			return
		}
		s.job.State = result.Status
		s.job.Message = "更新已提交"
		if result.Status == "partial" {
			s.job.Message = "更新完成，部分邻居或端口仍待核验"
		}
		if result.Status == "aborted" {
			s.job.Message = "已停止扫描，保留已确认结果"
		}
	}()
	return job, nil
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.job.Message = "正在停止并保存结果"
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) Close() {
	s.sessions.Close()
	s.mu.Lock()
	s.closed = true
	if s.stop != nil {
		s.stop()
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return fmt.Errorf("请求格式无效")
	}
	if e := d.Decode(&struct{}{}); !errors.Is(e, io.EOF) {
		return fmt.Errorf("请求只能包含一个 JSON 对象")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func ListenAddress(address string, allowedSources []netip.Prefix, tlsEnabled bool) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || (!ip.IsLoopback() && !ip.IsPrivate()) {
		return nil, fmt.Errorf("控制台必须监听明确的回环或内网地址")
	}
	if ip.IsPrivate() && (!tlsEnabled || len(allowedSources) == 0) {
		return nil, fmt.Errorf("监听内网时必须配置 TLS 证书及 --allow-sources")
	}
	return net.Listen("tcp", address)
}
func FromDiscovery(p discovery.Progress) Progress {
	return Progress{Stage: p.Stage, Target: p.Target, Completed: p.Completed, Scheduled: p.Scheduled, Depth: p.Depth, Probe: p.Probe}
}
