package webui

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"gonet/internal/auth"
	"gonet/internal/store/postgres"
)

// The test uses a private schema and never touches business tables in public.
func TestAPIKeysPostgreSQLIntegration(t *testing.T) {
	dsn := os.Getenv("GONET_ISOLATED_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated schema database URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("could not connect to integration PostgreSQL")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("gonet_test_keys_%d", time.Now().UnixNano())
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+ident+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("integration DSN must be a PostgreSQL URL")
	}
	params := u.Query()
	params.Set("search_path", schema)
	u.RawQuery = params.Encode()
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal("could not connect to the test schema")
	}
	defer conn.Close(context.Background())
	if versions, err := postgres.Migrate(ctx, conn); err != nil || len(versions) != 12 || versions[11] != 12 {
		t.Fatalf("migration: %v, %v", versions, err)
	}
	if versions, err := postgres.Migrate(ctx, conn); err != nil || len(versions) != 0 {
		t.Fatalf("repeated migration: %v, %v", versions, err)
	}

	store, err := postgres.OpenAPIKeys(ctx, u.String())
	if err != nil {
		t.Fatal("could not open the key store")
	}
	defer store.Close()
	legacy, _, err := auth.GenerateAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(legacy))
	oldTime := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	imports := 0
	importer := func() ([]byte, *time.Time, *time.Time, error) {
		imports++
		return hash[:], &oldTime, nil, nil
	}
	if err := store.ImportLegacyAPIKey(ctx, importer); err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListAPIKeys(ctx)
	if err != nil || len(keys) != 1 || !keys[0].CreatedAt.Equal(oldTime) {
		t.Fatal("legacy metadata missing")
	}

	s := newTestServer(t, &countingBackend{view: apiFixture()})
	defer s.Close()
	s.apiKeys = store
	if w := callAuth(s.Handler(testHost), "GET", "/api/v1/topology", "", nil, map[string]string{"Authorization": "Bearer " + legacy}); w.Code != 200 {
		t.Fatalf("legacy credential no longer works (HTTP %d)", w.Code)
	}
	cookie, csrf := testSession(t, s)
	path := apiKeyPath + "/" + strconv.FormatInt(keys[0].ID, 10)
	if w := callAuth(s.Handler(testHost), "DELETE", path, "", cookie, map[string]string{"X-GoNet-Token": csrf}); w.Code != 204 {
		t.Fatalf("legacy key deletion failed (HTTP %d)", w.Code)
	}
	if err := store.ImportLegacyAPIKey(ctx, importer); err != nil || imports != 1 {
		t.Fatalf("legacy import was repeated: %v", err)
	}
	if w := callAuth(s.Handler(testHost), "GET", "/api/v1/topology", "", nil, map[string]string{"Authorization": "Bearer " + legacy}); w.Code != 401 {
		t.Fatalf("deleted legacy credential regained access (HTTP %d)", w.Code)
	}

	checkAPIKeysManagementAndAccess(t, s)
	checkCompactAPIKey(t, s)
	var records, validDigests int
	if err := conn.QueryRow(ctx, "SELECT count(*), count(*) FILTER (WHERE octet_length(key_hash)=32) FROM agent_api_keys").Scan(&records, &validDigests); err != nil || records != 1 || validDigests != 1 {
		t.Fatal("deletion did not leave exactly one stored SHA-256 digest")
	}

	// A partial edit leaves omitted columns untouched.
	name := "LangBot edited"
	keys, err = store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current := keys[0]
	key, _, err := store.UpdateAPIKey(ctx, current.ID, postgres.APIKeyUpdate{Name: &name})
	if err != nil || key.Name != name || len(key.AllowedIPs) != 1 || key.AllowedIPs[0] != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("partial update changed the allowlist: %v", err)
	}
}
