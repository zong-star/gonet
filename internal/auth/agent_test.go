package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAgentKeyFormats(t *testing.T) {
	key, preview, digest, err := GenerateAPIKey()
	if err != nil || !strings.HasPrefix(key, "gonet_sk_") || len(key) != 52 || strings.Contains(preview, key) ||
		digest != sha256.Sum256([]byte(key)) {
		t.Fatal("invalid key generation")
	}
	legacy, hexDigest, err := GenerateAgentToken()
	if err != nil || len(legacy) != 43 {
		t.Fatal("invalid legacy CLI key")
	}
	for _, token := range []string{key, legacy} {
		if hash, ok := BearerDigest([]string{"bEaReR " + token}); !ok || hash != sha256.Sum256([]byte(token)) {
			t.Fatal("valid Bearer rejected")
		}
		for _, headers := range [][]string{nil, {""}, {"Bearer invalid"}, {"Basic " + token}, {"Bearer  " + token}, {"Bearer " + token + " "}, {"Bearer " + token, "Bearer " + token}} {
			if _, ok := BearerDigest(headers); ok {
				t.Fatal("invalid Bearer accepted")
			}
		}
	}
	if hash := sha256.Sum256([]byte(legacy)); hex.EncodeToString(hash[:]) != hexDigest {
		t.Fatal("legacy digest mismatch")
	}
}

func TestReadLegacyAPIKey(t *testing.T) {
	_, digest, _ := GenerateAgentToken()
	path := filepath.Join(t.TempDir(), "agent-api.json")
	env := map[string]string{"GONET_AGENT_API_ENABLED": "true", "GONET_AGENT_READ_TOKEN_SHA256": digest}
	get := func(name string) string { return env[name] }
	hash, _, _, err := ReadLegacyAPIKey(path, get)
	if err != nil || hex.EncodeToString(hash) != digest {
		t.Fatal("environment bootstrap digest lost")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"revision":"r","enabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	hash, _, _, err = ReadLegacyAPIKey(path, get)
	if err != nil || len(hash) != 0 {
		t.Fatal("disabled credential was imported from fallback")
	}
	active := `{"version":1,"revision":"r","enabled":true,"token_sha256":"` + digest + `","token_created_at":"2026-11-02T08:00:00Z"}`
	if err := os.WriteFile(path, []byte(active), 0600); err != nil {
		t.Fatal(err)
	}
	hash, created, _, err := ReadLegacyAPIKey(path, get)
	if err != nil || hex.EncodeToString(hash) != digest || created == nil {
		t.Fatal("saved digest or creation time lost")
	}
	for _, invalid := range []string{"{}", `{"version":1,"enabled":null,"revision":"r"}`, strings.Repeat("x", 17000)} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := ReadLegacyAPIKey(path, get); err == nil {
			t.Fatal("malformed legacy file accepted")
		}
	}
}

func TestParseIPNetworks(t *testing.T) {
	prefixes, err := ParseIPNetworks([]string{"192.0.2.3", "192.0.2.3/32", "2001:db8::7/64", "::ffff:198.51.100.7/120"})
	var actual []string
	for _, prefix := range prefixes {
		actual = append(actual, prefix.String())
	}
	if err != nil || !slices.Equal(actual, []string{"192.0.2.3/32", "2001:db8::/64", "198.51.100.0/24"}) {
		t.Fatalf("unexpected networks: %v, %v", actual, err)
	}
}
