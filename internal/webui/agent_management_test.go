package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	apidocs "gonet/docs/api"
	"gonet/internal/auth"
	"gonet/internal/store/postgres"
)

type testAPIKeyStore struct {
	mu     sync.Mutex
	keys   []postgres.APIKey
	hashes map[[32]byte]int64
	lastID int64
}

func (s *testAPIKeyStore) ListAPIKeys(context.Context) ([]postgres.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := append([]postgres.APIKey{}, s.keys...)
	slices.Reverse(keys)
	return keys, nil
}

func (s *testAPIKeyStore) CreateAPIKey(_ context.Context, key postgres.APIKey, hash [32]byte) (postgres.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, old := range s.keys {
		if old.Name == key.Name {
			return postgres.APIKey{}, postgres.ErrAPIKeyName
		}
	}
	s.lastID++
	key.ID, key.CreatedAt = s.lastID, time.Now().UTC()
	s.keys = append(s.keys, key)
	if s.hashes == nil {
		s.hashes = map[[32]byte]int64{}
	}
	s.hashes[hash] = key.ID
	return key, nil
}

func (s *testAPIKeyStore) UpdateAPIKey(_ context.Context, id int64, change postgres.APIKeyUpdate) (postgres.APIKey, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := slices.IndexFunc(s.keys, func(key postgres.APIKey) bool { return key.ID == id })
	if index < 0 {
		return postgres.APIKey{}, time.Time{}, pgx.ErrNoRows
	}
	key := &s.keys[index]
	if change.Name != nil {
		for _, old := range s.keys {
			if old.ID != id && old.Name == *change.Name {
				return postgres.APIKey{}, time.Time{}, postgres.ErrAPIKeyName
			}
		}
		key.Name = *change.Name
	}
	if change.Description != nil {
		key.Description = *change.Description
	}
	if change.AllowedIPs != nil {
		key.AllowedIPs = change.AllowedIPs
	}
	if change.Profile != nil {
		key.Profile = *change.Profile
	}
	return *key, time.Now().UTC(), nil
}

func (s *testAPIKeyStore) DeleteAPIKey(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := slices.IndexFunc(s.keys, func(key postgres.APIKey) bool { return key.ID == id })
	if index < 0 {
		return pgx.ErrNoRows
	}
	s.keys = slices.Delete(s.keys, index, index+1)
	for hash, keyID := range s.hashes {
		if keyID == id {
			delete(s.hashes, hash)
			break
		}
	}
	return nil
}

func (s *testAPIKeyStore) LookupAPIKey(_ context.Context, hash [32]byte) (postgres.APIKeyGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.keys {
		if key.ID == s.hashes[hash] {
			profile := key.Profile
			if profile == "" {
				profile = auth.APITopologyRead
			}
			return postgres.APIKeyGrant{ID: key.ID, AllowedIPs: key.AllowedIPs, Profile: profile}, nil
		}
	}
	return postgres.APIKeyGrant{}, pgx.ErrNoRows
}

func seedTestKey(t *testing.T, s *Server, token string) {
	t.Helper()
	hash, ok := auth.BearerDigest([]string{"Bearer " + token})
	if !ok {
		t.Fatal("invalid fixture token")
	}
	_, err := s.apiKeys.CreateAPIKey(context.Background(), postgres.APIKey{Name: "fixture", AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	}}, hash)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAPIKeysManagementAndAccess(t *testing.T) {
	s := newTestServer(t, &countingBackend{view: apiFixture()})
	t.Cleanup(s.Close)
	checkAPIKeysManagementAndAccess(t, s)
}

func checkAPIKeysManagementAndAccess(t *testing.T, s *Server) {
	t.Helper()
	h := s.Handler(testHost)
	cookie, csrf := testSession(t, s)
	headers := map[string]string{"Content-Type": "application/json", "X-GoNet-Token": csrf}
	input := `{"name":"Dify","description":"workflow","allowed_ips":["192.0.2.1","2001:db8:1::1/64"]}`
	if w := callAuth(h, "POST", apiKeyPath, input, cookie, nil); w.Code != 403 {
		t.Fatal("creation bypassed CSRF")
	}
	if w := callAuth(h, "POST", apiKeyPath, input, cookie, map[string]string{"Origin": "https://evil.invalid", "X-GoNet-Token": csrf}); w.Code != 403 {
		t.Fatal("creation bypassed origin restriction")
	}
	for _, invalid := range []string{`{}`, `{"name":"a","allowed_ips":[]}`, `{"name":"a","allowed_ips":["1.2.3.999"]}`, `{"name":"a","allowed_ips":["::/129"]}`, `{"name":"a","allowed_ips":["::1"],"enabled":true}`} {
		if w := callAuth(h, "POST", apiKeyPath, invalid, cookie, headers); w.Code != 400 {
			t.Fatal("invalid request accepted")
		}
	}
	create := func(body string) (postgres.APIKey, string) {
		t.Helper()
		w := callAuth(h, "POST", apiKeyPath, body, cookie, headers)
		var response struct {
			postgres.APIKey
			Key string `json:"key"`
		}
		if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" ||
			json.Unmarshal(w.Body.Bytes(), &response) != nil || !strings.HasPrefix(response.Key, "gonet_sk_") || response.Preview == response.Key {
			t.Fatalf("creation failed (HTTP %d)", w.Code)
		}
		return response.APIKey, response.Key
	}
	first, key1 := create(input)
	second, key2 := create(`{"name":"LangBot","allowed_ips":["198.51.100.0/24"]}`)
	if key1 == key2 || first.ID == second.ID {
		t.Fatal("keys are not independent")
	}
	if w := callAuth(h, "POST", apiKeyPath, input, cookie, headers); w.Code != 409 {
		t.Fatal("duplicate key name accepted")
	}
	if w := callAuth(h, "GET", apiKeyPath, "", cookie, nil); w.Code != 200 ||
		strings.Contains(w.Body.String(), key1) || strings.Contains(w.Body.String(), key2) ||
		strings.Contains(w.Body.String(), "key_hash") || strings.Contains(w.Body.String(), "updated_at") ||
		strings.Index(w.Body.String(), second.Name) > strings.Index(w.Body.String(), first.Name) {
		t.Fatal("list exposed private data or lost sort order")
	}
	query := "/api/v1/topology"
	bearer1 := map[string]string{"Authorization": "Bearer " + key1}
	bearer2 := map[string]string{"Authorization": "Bearer " + key2, "X-Forwarded-For": "198.51.100.5"}
	if w := callAuth(h, "GET", apiKeyPath, "", nil, bearer1); w.Code != 401 {
		t.Fatal("API Key accessed management")
	}
	if w := callAuth(h, "GET", query, "", nil, bearer1); w.Code != 200 {
		t.Fatal("matching IPv4 key was rejected")
	}
	if w := callAuth(h, "GET", query, "", nil, bearer2); w.Code != 403 || !strings.Contains(w.Body.String(), "IP_NOT_ALLOWED") {
		t.Fatal("untrusted client spoofed its source")
	}
	s.authConfig.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
	if w := callAuth(h, "GET", query, "", nil, bearer2); w.Code != 200 {
		t.Fatal("trusted proxy client was rejected")
	}
	bearer1["X-Forwarded-For"] = "2001:db8:1::42"
	if w := callAuth(h, "GET", query, "", nil, bearer1); w.Code != 200 {
		t.Fatal("matching IPv6 client was rejected")
	}
	bearer1["X-Forwarded-For"] = "2001:db8:1::42, 192.0.2.1"
	if w := callAuth(h, "GET", query, "", nil, bearer1); w.Code != 403 {
		t.Fatal("malformed forwarded client accepted")
	}
	delete(bearer1, "X-Forwarded-For")
	url := apiKeyPath + "/" + strconv.FormatInt(first.ID, 10)
	change := `{"name":"Dify edited","description":"","allowed_ips":["198.51.100.5"]}`
	w := callAuth(h, "PATCH", url, change, cookie, headers)
	var updated postgres.APIKey
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &updated) != nil || !updated.CreatedAt.Equal(first.CreatedAt) ||
		updated.Preview != first.Preview || updated.Name != "Dify edited" || strings.Contains(w.Body.String(), key1) {
		t.Fatalf("edit contract failed (HTTP %d)", w.Code)
	}
	if w := callAuth(h, "GET", query, "", nil, bearer1); w.Code != 403 {
		t.Fatal("updated whitelist did not take effect")
	}
	bearer1["X-Forwarded-For"] = "198.51.100.5"
	if w := callAuth(h, "GET", query, "", nil, bearer1); w.Code != 200 {
		t.Fatal("existing key stopped working after edit")
	}
	if w := callAuth(h, "DELETE", url, "", nil, bearer1); w.Code != 401 {
		t.Fatal("API Key accessed deletion")
	}
	if w := callAuth(h, "DELETE", url, "", cookie, nil); w.Code != 403 {
		t.Fatal("deletion bypassed CSRF")
	}
	if w := callAuth(h, "DELETE", apiKeyPath+"/0", "", cookie, headers); w.Code != 400 {
		t.Fatal("deletion accepted an invalid ID")
	}
	if w := callAuth(h, "DELETE", url, "", cookie, headers); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("deletion failed (HTTP %d)", w.Code)
	}
	if w := callAuth(h, "DELETE", url, "", cookie, headers); w.Code != 404 {
		t.Fatal("deleted key still exists")
	}
	if w := callAuth(h, "GET", query, "", nil, bearer1); w.Code != 401 {
		t.Fatal("deleted key still works")
	}
	if w := callAuth(h, "GET", query, "", nil, bearer2); w.Code != 200 {
		t.Fatal("deletion affected a different key")
	}
	if w := callAuth(h, "GET", apiKeyPath, "", cookie, nil); w.Code != 200 || strings.Contains(w.Body.String(), updated.Name) || !strings.Contains(w.Body.String(), second.Name) {
		t.Fatal("list did not reflect deletion")
	}
	if w := callAuth(h, "GET", "/docs/api.html", "", nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "GoNet API 使用说明") {
		t.Fatal("static guide unavailable")
	}
	for _, url := range []string{"/docs/openapi.yaml", legacyOpenAPIPath} {
		if w := callAuth(h, http.MethodGet, url, "", cookie, nil); w.Code != 200 || w.Body.String() != string(apidocs.OpenAPI) {
			t.Fatal("canonical OpenAPI download mismatch")
		}
	}
}
