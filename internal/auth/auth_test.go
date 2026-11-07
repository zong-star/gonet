package auth

import (
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(" test-password-123 "), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Username: "admin", PasswordHash: string(h), SessionTTL: 8 * time.Hour, CookieSecure: true}
}
func TestConfigFailClosed(t *testing.T) {
	c := testConfig(t)
	env := map[string]string{"GONET_ADMIN_USERNAME": c.Username, "GONET_ADMIN_PASSWORD_HASH": c.PasswordHash}
	cfg, err := ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil || !cfg.CookieSecure || cfg.SessionTTL != 8*time.Hour {
		t.Fatal("invalid defaults", err)
	}
	for _, tc := range []struct{ key, value string }{{"GONET_ADMIN_USERNAME", ""}, {"GONET_ADMIN_PASSWORD_HASH", "plaintext"}, {"GONET_ADMIN_PASSWORD_HASH", strings.Repeat("$", 60)}, {"GONET_SESSION_TTL", "0"}, {"GONET_SESSION_TTL", "25h"}, {"GONET_SESSION_TTL", "-1s"}, {"GONET_COOKIE_SECURE", "invalid"}} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			copy := map[string]string{}
			for k, v := range env {
				copy[k] = v
			}
			copy[tc.key] = tc.value
			if _, err := ConfigFromEnv(func(k string) string { return copy[k] }); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if !c.Verify("admin", " test-password-123 ") || c.Verify("missing", " test-password-123 ") || c.Verify("admin", "test-password-123") || c.Verify("admin", strings.Repeat("x", 73)) {
		t.Fatal("password or username normalization violated")
	}
}
func TestPasswordBounds(t *testing.T) {
	for _, s := range []string{"short", strings.Repeat("字", 25), strings.Repeat("x", 73), string([]byte{0xff})} {
		if ValidatePassword([]byte(s)) == nil {
			t.Fatal("invalid password accepted")
		}
	}
	for _, s := range []string{strings.Repeat("字", 12), strings.Repeat("x", 72), "  password1234  "} {
		if err := ValidatePassword([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := HashPassword([]byte("password-for-tests"))
	if err != nil {
		t.Fatal(err)
	}
	cost, _ := bcrypt.Cost(hash)
	if cost != 12 {
		t.Fatal("wrong cost")
	}
}
func TestSafeNext(t *testing.T) {
	for _, s := range []string{"https://evil.invalid", "//evil.invalid", "/\\evil", "/login", "/api/state", "/%2f%2fevil", "/?page=%74opology", "/?page=topology&x=1", "/?page=topology&page=settings", "/?page=unknown", "/\n", "/?page=topology#evil"} {
		if SafeNext(s) != "/" {
			t.Fatal("unsafe next", s)
		}
	}
	if SafeNext("/?page=topology") != "/?page=topology" {
		t.Fatal("valid next rejected")
	}
}
func TestStoreRotationExpiryCapacityAndClose(t *testing.T) {
	store := NewStore(time.Hour)
	defer store.Close()
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	id, session, err := store.Create("admin", "attacker-chosen-id")
	if err != nil || len(id) != 43 || session.CSRFToken == id {
		t.Fatal("bad session")
	}
	other, _, _ := store.Create("admin", "")
	next, newSession, err := store.Create("admin", id)
	if err != nil || next == id || newSession.CSRFToken == session.CSRFToken {
		t.Fatal("rotation failed")
	}
	if _, ok := store.Get(id); ok {
		t.Fatal("old session valid")
	}
	if _, ok := store.Get(other); !ok {
		t.Fatal("other browser was invalidated")
	}
	store.Delete(next)
	if _, ok := store.Get(next); ok {
		t.Fatal("logout replay valid")
	}
	now = now.Add(time.Hour)
	if _, ok := store.Get(other); ok {
		t.Fatal("absolute expiry not enforced")
	}
	store.Cleanup()
	if len(store.sessions) != 0 {
		t.Fatal("expired entry retained")
	}
	for range maxSessions {
		if _, _, err := store.Create("admin", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.Create("admin", ""); err == nil {
		t.Fatal("capacity not enforced")
	}
	now = now.Add(time.Hour)
	store.Cleanup()
	if len(store.sessions) != 0 {
		t.Fatal("cleanup failed")
	}
	store.Close()
	if _, ok := store.Get(other); ok {
		t.Fatal("closed store kept sessions")
	}
}
func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore(time.Hour)
	defer s.Close()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _, err := s.Create("admin", "")
			if err != nil {
				t.Error(err)
				return
			}
			s.Get(id)
			s.Cleanup()
			s.Delete(id)
		}()
	}
	wg.Wait()
}
func TestLoginLimiterWindowAndConcurrency(t *testing.T) {
	l := NewLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	for range 5 {
		finish, retry := l.Begin("peer")
		if finish == nil || retry != 0 {
			t.Fatal("early rate limit")
		}
		finish(true)
		finish(true)
	}
	if finish, retry := l.Begin("peer"); finish != nil || retry <= 0 {
		t.Fatal("not rate limited")
	}
	now = now.Add(time.Minute)
	if finish, _ := l.Begin("peer"); finish == nil {
		t.Fatal("did not expire")
	} else {
		finish(false)
	}
	pending := []func(bool){}
	for range 5 {
		finish, _ := l.Begin("parallel")
		if finish == nil {
			t.Fatal("early limit")
		}
		pending = append(pending, finish)
	}
	if finish, _ := l.Begin("parallel"); finish != nil {
		t.Fatal("concurrent bypass")
	}
	for _, finish := range pending {
		finish(true)
	}
	for i := 0; i < 4096; i++ {
		l.entries["capacity-"+strings.Repeat("x", i)] = &attempts{started: now}
	}
	if finish, _ := l.Begin("new peer"); finish != nil {
		t.Fatal("limiter unbounded")
	}
	now = now.Add(time.Minute)
	if finish, _ := l.Begin("new peer"); finish == nil {
		t.Fatal("capacity did not recover")
	} else {
		finish(false)
	}
}

func TestSafeNextAPIManagement(t *testing.T) {
	if SafeNext("/?page=api") != "/?page=api" {
		t.Fatal("API management login destination rejected")
	}
}
