package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	"gonet/internal/auth"
	"gonet/internal/control"
	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
	"gonet/internal/webui"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCurrentTopologyDualUplinkPostgreSQLHTTPS(t *testing.T) {
	rawDSN := os.Getenv("GONET_ISOLATED_TEST_DATABASE_URL")
	if rawDSN == "" {
		t.Skip("isolated schema database URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, rawDSN)
	if err != nil {
		t.Fatal("could not connect to isolated PostgreSQL")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("gonet_test_current_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	dsn, err := url.Parse(rawDSN)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	params := dsn.Query()
	params.Set("search_path", schema)
	dsn.RawQuery = params.Encode()
	t.Setenv("GONET_CURRENT_TEST_DSN", dsn.String())

	conn, err := pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal("could not connect to test schema")
	}
	defer conn.Close(context.Background())
	if _, err := postgres.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../testdata/adapters/current-topology-dual-uplink/pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ Core, Peer model.DeviceSnapshot }
	if err = json.Unmarshal(fixture, &pair); err != nil {
		t.Fatal(err)
	}
	rules, err := identity.LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts := identity.Options{Rules: rules, Overrides: []identity.Override{
		{Subtype: pair.Core.Device.Chassis.Subtype, RawHex: hex.EncodeToString(pair.Core.Device.Chassis.Raw), CanonicalKey: "manual:ts7914-lab-core"},
		{Subtype: pair.Peer.Neighbors[0].Chassis.Subtype, RawHex: hex.EncodeToString(pair.Peer.Neighbors[0].Chassis.Raw), CanonicalKey: "manual:ts7914-lab-core"},
		{Subtype: pair.Peer.Device.Chassis.Subtype, RawHex: hex.EncodeToString(pair.Peer.Device.Chassis.Raw), CanonicalKey: "manual:lab-peer"},
		{Subtype: pair.Core.Neighbors[0].Chassis.Subtype, RawHex: hex.EncodeToString(pair.Core.Neighbors[0].Chassis.Raw), CanonicalKey: "manual:lab-peer"},
	}, ClassificationOverrides: []identity.ClassificationOverride{{IdentityKey: "manual:ts7914-lab-core", Result: "switch", Reason: "verified pair"}}}
	store, err := postgres.Open(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(context.Background())
	var firstLink, firstPortA, firstPortB int64
	buildRound := func(round int) int64 {
		t.Helper()
		id, err := store.BeginScan(ctx, postgres.ScanInput{Seeds: []netip.Addr{pair.Core.Device.Target}, ConfigDigest: "current-uplink-fixture"})
		if err != nil {
			t.Fatal(err)
		}
		registry, err := identity.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		resolver := topology.NewResolver(nil)
		if round > 1 {
			devices, ports, err := store.LoadContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = registry.Restore(devices); err != nil {
				t.Fatal(err)
			}
			if err = resolver.Ports().Restore(ports); err != nil {
				t.Fatal(err)
			}
		}
		builder := topology.NewBuilder(registry, resolver)
		builder.AddSnapshot(&pair.Core)
		builder.AddSnapshot(&pair.Peer)
		g := builder.Build()
		result := &discovery.Result{SchemaVersion: model.SchemaVersion, Status: "partial", Ports: g.Ports, Links: g.Links, Observations: g.Observations, Unresolved: g.Unresolved}
		for _, d := range g.Devices {
			if !registry.Matches(d.Ref, pair.Core.Device.Chassis) && !registry.Matches(d.Ref, pair.Peer.Device.Chassis) {
				continue
			}
			result.Devices = append(result.Devices, d)
			snap := &pair.Peer
			depth := 1
			if registry.Matches(d.Ref, pair.Core.Device.Chassis) {
				snap = &pair.Core
				depth = 0
			}
			result.Outcomes = append(result.Outcomes, model.ScanOutcome{Device: d.Ref, Target: model.DiscoveryTarget{Address: snap.Device.Target, Depth: depth}, Snapshot: snap})
		}
		if len(result.Links) != 2 || len(result.Observations) != 4 {
			t.Fatalf("fixture resolution: links=%d obs=%d unresolved=%+v", len(result.Links), len(result.Observations), result.Unresolved)
		}
		if round == 1 {
			// Freeze an earlier round with only the already-known second uplink.
			var keep []model.LinkEvidence
			var observations []model.LinkObservation
			for _, l := range result.Links {
				for _, p := range result.Ports {
					if (p.Ref == l.Key.PA || p.Ref == l.Key.PB) && p.IfIndex != nil && *p.IfIndex == 28 {
						keep = append(keep, l)
					}
				}
			}
			for _, o := range result.Observations {
				if o.Row.LocalPortNum == 28 || o.Row.LocalPortNum == 131347 {
					observations = append(observations, o)
				}
			}
			result.Links, result.Observations = keep, observations
			for _, p := range result.Ports {
				if p.IfIndex != nil && *p.IfIndex == 81 {
					p.Aliases = []topology.PortKey{p.Key}
					p.MappingRule = "ifname-exact"
				}
			}
		}
		if err = store.CommitResult(ctx, id, result); err != nil {
			t.Fatalf("commit round %d: %v devices=%+v ports=%+v links=%+v", round, err, result.Devices, result.Ports, result.Links)
		}
		if err = store.CommitResult(ctx, id, result); err != nil {
			t.Fatal("idempotent commit:", err)
		}
		return id
	}
	if _, err = conn.Exec(ctx, `ALTER SEQUENCE links_id_seq RESTART WITH 249`); err != nil {
		t.Fatal(err)
	}
	buildRound(1)
	oldEvidenceHash := func() string {
		t.Helper()
		var hash string
		if err := conn.QueryRow(ctx, `SELECT md5(COALESCE((SELECT jsonb_agg(to_jsonb(o) ORDER BY id)::text FROM observations o WHERE scan_id=1),'[]') || COALESCE((SELECT jsonb_agg(to_jsonb(f) ORDER BY device_id,if_index)::text FROM scan_interface_facts f WHERE scan_id=1),'[]'))`).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	frozenEvidence := oldEvidenceHash()

	if err = conn.QueryRow(ctx, `SELECT id,port_a_id,port_b_id FROM links`).Scan(&firstLink, &firstPortA, &firstPortB); err != nil {
		t.Fatal(err)
	}
	if firstLink != 249 {
		t.Fatal("baseline physical ID not frozen")
	}
	// The old provisional alias is not a physical endpoint and must be retired safely.
	_, err = conn.Exec(ctx, `INSERT INTO ports(device_id,port_key,subtype,raw_id,display_name,resolution,is_physical,mapping_rule)
 SELECT id,'lldp:5:4769312f312f3139',5,'Gi1/1/19','Gi1/1/19','provisional',false,'provisional-ifname' FROM devices WHERE sys_name='lab-core';
 INSERT INTO devices(identity_state,classification_rule,sys_name,device_kind) VALUES ('verified','fixture','history-only','switch');
 INSERT INTO ports(device_id,port_key,subtype,raw_id,display_name,if_index,resolution,is_physical,mapping_rule)
 VALUES (1,'lldp:5:4f',5,'O','old-core',900,'verified',true,'fixture'),(3,'lldp:5:48',5,'H','old-edge',901,'verified',true,'fixture');
 INSERT INTO device_addresses(device_id,address,state,source,verified_at) VALUES (3,'192.0.2.3','verified','manual',now());
 INSERT INTO links(id,device_a_id,port_a_id,device_b_id,port_b_id,confidence,first_seen_at,last_seen_at,last_seen_scan_id,last_evaluated_scan_id)
 OVERRIDING SYSTEM VALUE SELECT 2308,1,a.id,3,b.id,'bidirectional',now(),now(),1,1 FROM ports a,ports b WHERE a.port_key='lldp:5:4f' AND b.port_key='lldp:5:48';
 SELECT setval('links_id_seq',2308);`)
	if err != nil {
		t.Fatal(err)
	}
	scan := buildRound(2)
	var stableA, stableB int64
	if err = conn.QueryRow(ctx, `SELECT port_a_id,port_b_id FROM links WHERE id=249`).Scan(&stableA, &stableB); err != nil || stableA != firstPortA || stableB != firstPortB {
		t.Fatal("existing physical link identity changed", err)
	}
	var count int
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM links`).Scan(&count); err != nil || count != 3 {
		t.Fatal("history or independent physical links lost", count, err)
	}
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM scan_interface_facts WHERE scan_id=$1 AND if_index IN (27,28) AND port_id IS NOT NULL`, scan).Scan(&count); err != nil || count != 2 {
		t.Fatal("member interface port references missing", count, err)
	}
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM ports WHERE port_key='lldp:5:4769312f312f3139'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("provisional alias persisted", count, err)
	}
	// A fresh context round simulates service restart and must reuse both link IDs.
	scan = buildRound(3)
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM links`).Scan(&count); err != nil || count != 3 {
		t.Fatal("restart duplicated links", count, err)
	}

	if oldEvidenceHash() != frozenEvidence {
		t.Fatal("old scan observations or interface facts were rewritten")
	}

	configData, err := os.ReadFile("../../config/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rulesDir, err := filepath.Abs("../../config")
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.NewReplacer("GONET_DATABASE_URL", "GONET_CURRENT_TEST_DSN", "10.201.109.0/24", "192.0.2.0/24",
		"10.201.109.1]", "192.0.2.1]", "rules_file: config/", "rules_file: "+filepath.ToSlash(rulesDir)+"/").Replace(string(configData))
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err := postgres.OpenAPIKeys(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	backend := &consoleBackend{configPath: configPath, scope: control.Scope{Version: 1, Settings: control.Settings{
		Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"},
	}}}
	app, err := webui.New(ctx, backend, auth.Config{Username: "test-admin", PasswordHash: string(hash), SessionTTL: time.Hour, CookieSecure: true}, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = app.Handler(server.Listener.Addr().String())
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	login, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"test-admin","password":"fixture-password"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("X-GoNet-Login", "1")
	response, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("fixture login", response.StatusCode)
	}
	getState := func() map[string]any {
		t.Helper()
		response, err := client.Get(server.URL + "/api/state")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != 200 {
			t.Fatal("state read", response.StatusCode, err)
		}
		var state map[string]any
		if err = json.Unmarshal(body, &state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	state := getState()
	view := state["topology"].(map[string]any)
	graph := view["graph"].(map[string]any)
	if len(view["links"].([]any)) != 3 || len(graph["links"].([]any)) != 2 || len(graph["device_ids"].([]any)) != 2 {
		t.Fatalf("true backend current/history mixed: %+v", graph)
	}
	groups := graph["aggregate_connections"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["status"] != "partial_lag" || len(groups[0].(map[string]any)["member_link_ids"].([]any)) != 2 {
		t.Fatalf("true state read lost member evidence: %+v", groups)
	}
	output := os.Getenv("GONET_CURRENT_BROWSER_OUTPUT")
	if output != "" {
		if err = os.MkdirAll(output, 0755); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.MarshalIndent(state, "", "  ")
		if err = os.WriteFile(filepath.Join(output, "api-state.json"), encoded, 0644); err != nil {
			t.Fatal(err)
		}
		script, _ := filepath.Abs("../../docs/acceptance/gonet-current-topology/verify-browser.cjs")
		command := exec.CommandContext(ctx, "node", script)
		command.Env = append(os.Environ(), "GONET_CURRENT_TEST_URL="+server.URL)
		result, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("browser acceptance: %v\n%s", err, result)
		}
		t.Log(string(result))
	}
	// Latest attempts cannot replace the committed snapshot or inject old edges.
	for _, status := range []string{"running", "failed", "aborted"} {
		_, err = conn.Exec(ctx, `INSERT INTO scan_runs(seed_ips,config_digest,status,finished_at) VALUES ('{}','attempt',$1,CASE WHEN $1='running' THEN NULL ELSE now() END)`, status)
		if err != nil {
			t.Fatal(err)
		}
		state = getState()
		graph = state["topology"].(map[string]any)["graph"].(map[string]any)
		if graph["snapshot_id"] != float64(scan) || len(graph["links"].([]any)) != 2 || graph["latest_attempt"].(map[string]any)["status"] != status {
			t.Fatalf("attempt mixed into committed graph: %+v", graph)
		}
	}
	// A committed zero-link scan must never backfill previous physical edges.
	_, err = conn.Exec(ctx, `INSERT INTO scan_runs(seed_ips,config_digest,status,finished_at) VALUES ('{}','empty','partial',now())`)
	if err != nil {
		t.Fatal(err)
	}
	graph = getState()["topology"].(map[string]any)["graph"].(map[string]any)
	if len(graph["links"].([]any)) != 0 || len(graph["aggregate_connections"].([]any)) != 0 {
		t.Fatalf("empty scan backfilled history: %+v", graph)
	}
}
