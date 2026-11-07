package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"gonet/internal/auth"
	"gonet/internal/control"
	"gonet/internal/store/postgres"
	"gonet/internal/webui"
)

func TestPreciseTopologyPostgreSQLHTTPS(t *testing.T) {
	rawDSN := os.Getenv("GONET_ISOLATED_TEST_DATABASE_URL")
	if rawDSN == "" {
		t.Skip("isolated schema database URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, rawDSN)
	if err != nil {
		t.Fatal("could not connect to isolated PostgreSQL")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("gonet_test_precise_%d", time.Now().UnixNano())
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
	t.Setenv("GONET_PRECISE_TEST_DSN", dsn.String())

	conn, err := pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal("could not connect to test schema")
	}
	defer conn.Close(context.Background())
	if _, err := postgres.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(ctx, `
		INSERT INTO scan_runs(seed_ips,config_digest,status,finished_at) VALUES ('{192.0.2.1}','fixture','partial',now());
		INSERT INTO devices(identity_state,classification_rule,sys_name,device_kind)
		VALUES ('verified','fixture','Core-01','switch'), ('verified','fixture','Edge-02','switch');
		INSERT INTO device_addresses(device_id,address,state,source,verified_at)
		VALUES (1,'192.0.2.1','verified','seed',now()), (2,'192.0.2.2','verified','lldp',now());
		INSERT INTO scan_devices(scan_id,device_id,depth,outcome) VALUES (1,1,0,'success'), (1,2,1,'success');
		INSERT INTO ports(device_id,port_key,subtype,raw_id,display_name,if_index,resolution,is_physical,mapping_rule)
		VALUES (1,'lldp:5:41',5,'A','core-port',101,'verified',true,'fixture'),
		       (2,'lldp:5:42',5,'B','edge-port',201,'verified',true,'fixture');
		INSERT INTO links(device_a_id,port_a_id,device_b_id,port_b_id,confidence,first_seen_at,last_seen_at,last_seen_scan_id,last_evaluated_scan_id)
		VALUES (1,1,2,2,'bidirectional',now(),now(),1,1);
		INSERT INTO scan_interface_facts(scan_id,device_id,if_index,if_name,if_descr,if_alias,if_type,port_id,collected_at)
		VALUES (1,1,101,'core-port','','',6,1,now()), (1,2,201,'edge-port','','',6,2,now());
	`)
	if err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile("../../config/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := filepath.Abs("../../config")
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.NewReplacer("GONET_DATABASE_URL", "GONET_PRECISE_TEST_DSN", "10.201.109.0/24", "192.0.2.0/24",
		"10.201.109.1]", "192.0.2.1]", "rules_file: config/", "rules_file: "+filepath.ToSlash(rules)+"/").Replace(string(configData))
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err := postgres.OpenAPIKeys(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	token, preview, digest, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.CreateAPIKey(ctx, postgres.APIKey{Name: "HTTPS fixture", Preview: preview,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Profile: auth.APITopologyCompact}, digest); err != nil {
		t.Fatal(err)
	}
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
	get := func(path string, status int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status {
			t.Fatalf("%s got HTTP %d: %s", path, response.StatusCode, body)
		}
		return body
	}
	for _, check := range []struct{ route, contains string }{
		{"/api/v1/devices?query=192.0.2.2", `"device_id":"2"`},
		{"/api/v1/devices/2", `"id":"2"`},
		{"/api/v1/devices/2/neighbors", `"if_index":201`},
		{"/api/v1/topology/summary", `"link_count":1`},
		{"/docs/agent-openapi.yaml", "openapi: 3.0.3"},
	} {
		if body := get(check.route, 200); !strings.Contains(string(body), check.contains) {
			t.Fatalf("%s unexpected response: %s", check.route, body)
		}
	}
	if body := get("/api/v1/topology", 403); !strings.Contains(string(body), "API_ROUTE_NOT_ALLOWED") {
		t.Fatal("compact Key did not receive the route restriction")
	}
	pathRoute := "/api/v1/devices/2/uplink-path"
	checkBatch := func() string {
		t.Helper()
		var result struct {
			Meta struct {
				Scan        string `json:"latest_scan_id"`
				CoverageGap bool   `json:"coverage_gap"`
			} `json:"meta"`
		}
		body := get(pathRoute, 200)
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{`"path_found":true`, `"role":"core"`, `"scan_id":"` + result.Meta.Scan + `"`} {
			if !strings.Contains(string(body), required) {
				t.Fatalf("inconsistent path: %s", body)
			}
		}
		if result.Meta.Scan == "1" {
			if !result.Meta.CoverageGap || !strings.Contains(string(body), `"if_index":201`) {
				t.Fatalf("batch 1: %s", body)
			}
		} else if result.Meta.Scan != "2" || !strings.Contains(string(body), `"if_index":202`) {
			t.Fatalf("batch 2: %s", body)
		}
		return result.Meta.Scan
	}
	if checkBatch() != "1" {
		t.Fatal("first committed scan was not visible")
	}
	if _, err := conn.Exec(ctx, `INSERT INTO scan_runs(seed_ips,config_digest) VALUES ('{192.0.2.1}','fixture2')`); err != nil {
		t.Fatal(err)
	}
	neighborsV2 := "/api/v1/devices/2/neighbors?schema_version=2"
	checkV2 := func() string {
		t.Helper()
		last := ""
		for _, route := range []string{neighborsV2, pathRoute + "?schema_version=2"} {
			body := string(get(route, 200))
			switch {
			case strings.Contains(body, `"snapshot_id":"1"`) && strings.Contains(body, `"latest_scan":{"scan_id":"2","status":"running"}`) && strings.Contains(body, `"if_index":201`):
				last = "1"
			case strings.Contains(body, `"snapshot_id":"2"`) && strings.Contains(body, `"latest_scan":{"scan_id":"2","status":"partial"}`) && strings.Contains(body, `"if_index":202`):
				last = "2"
			default:
				t.Fatalf("v2 snapshot, running scan and endpoint inconsistent: %s", body)
			}
		}
		return last
	}
	if checkV2() != "1" {
		t.Fatal("running scan replaced the committed snapshot")
	}
	committed := make(chan error, 1)
	go func() {
		_, err := conn.Exec(ctx, `
			UPDATE scan_runs SET status='partial', finished_at=now() WHERE id=2;
			INSERT INTO scan_devices(scan_id,device_id,depth,outcome) VALUES (2,1,0,'success'), (2,2,1,'success');
			INSERT INTO scan_interface_facts(scan_id,device_id,if_index,if_name,if_descr,if_alias,if_type,port_id,collected_at)
			VALUES (2,1,101,'core-port','','',6,1,now()), (2,2,202,'edge-port','','',6,2,now());
			UPDATE links SET last_seen_scan_id=2,last_evaluated_scan_id=2;
		`)
		committed <- err
	}()
	for i := 0; i < 5; i++ {
		checkBatch()
		checkV2()
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if checkBatch() != "2" {
		t.Fatal("newly committed scan was not visible")
	}
	if checkV2() != "2" {
		t.Fatal("committed partial scan was not visible to v2")
	}
}
