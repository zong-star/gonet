package cli

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gonet/internal/auth"
)

func TestHashPasswordPrompt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		fail   bool
	}{{"valid", []string{"  fixture-password-2026  ", "  fixture-password-2026  "}, false}, {"mismatch", []string{"fixture-password-2026", "different-password"}, true}, {"short", []string{"short"}, true}, {"bytes", []string{strings.Repeat("字", 25)}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errout bytes.Buffer
			i := 0
			result := hashPasswordPrompt(&out, &errout, func() ([]byte, error) {
				if i >= len(tc.values) {
					return nil, errors.New("input failed")
				}
				v := tc.values[i]
				i++
				return []byte(v), nil
			})
			if tc.fail {
				if result == 0 || out.Len() != 0 {
					t.Fatal("invalid password produced hash")
				}
			} else if result != 0 || bcrypt.CompareHashAndPassword([]byte(strings.TrimSpace(out.String())), []byte(tc.values[0])) != nil {
				t.Fatal("hash failed")
			}
			for _, v := range tc.values {
				if len(v) > 10 && strings.Contains(errout.String(), v) {
					t.Fatal("password leaked")
				}
			}
		})
	}
}

func TestGenerateAgentTokenCommand(t *testing.T) {
	var out, errout bytes.Buffer
	if Run([]string{"auth", "generate-agent-token"}, &out, &errout) != ExitOK {
		t.Fatal("token generation failed")
	}
	lines := strings.Fields(out.String())
	if len(lines) != 2 {
		t.Fatal("token output contract")
	}
	token := strings.TrimPrefix(lines[0], "GONET_AGENT_TOKEN=")
	digest := strings.TrimPrefix(lines[1], "GONET_AGENT_READ_TOKEN_SHA256=")
	hash, valid := auth.BearerDigest([]string{"Bearer " + token})
	if !valid || hex.EncodeToString(hash[:]) != digest || strings.Contains(errout.String(), token) {
		t.Fatal("token output invalid or logged")
	}
}
func TestAuthCommandRejectsPlaintextArguments(t *testing.T) {
	var out, errout bytes.Buffer
	if Run([]string{"auth", "hash-password", "secret"}, &out, &errout) != ExitUsage || strings.Contains(errout.String(), "secret") {
		t.Fatal("accepted or logged password argument")
	}
}
func TestServeRequiresAuthBeforeConfigurationIO(t *testing.T) {
	t.Setenv("GONET_ADMIN_USERNAME", "")
	t.Setenv("GONET_ADMIN_PASSWORD_HASH", "")
	var out, errout bytes.Buffer
	if Run([]string{"serve", "--config", "nonexistent.yaml"}, &out, &errout) != ExitUsage || !strings.Contains(errout.String(), "GONET_ADMIN_USERNAME") {
		t.Fatal("serve failed open or read config first")
	}
}
