package webui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gonet/internal/auth"
	"gonet/internal/control"
)

const testHost = "127.0.0.1:8787"
const testPassword = "fixture-password-2026"

var testHashOnce sync.Once
var testHash string

func newTestServer(t *testing.T, b Backend) *Server {
	t.Helper()
	testHashOnce.Do(func() {
		h, e := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
		if e != nil {
			panic(e)
		}
		testHash = string(h)
	})
	s, e := New(context.Background(), b, auth.Config{Username: "admin", PasswordHash: testHash, SessionTTL: 8 * time.Hour, CookieSecure: true}, &testAPIKeyStore{})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func testSession(t *testing.T, s *Server) (*http.Cookie, string) {
	t.Helper()
	id, session, e := s.sessions.Create("admin", "")
	if e != nil {
		t.Fatal(e)
	}
	return &http.Cookie{Name: auth.CookieName, Value: id}, session.CSRFToken
}
func callAuth(h http.Handler, method, path, body string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = testHost
	r.RemoteAddr = "192.0.2.1:1234"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func loginRequest(h http.Handler, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	return callAuth(h, "POST", "/api/v1/auth/login", body, cookie, map[string]string{"Content-Type": "application/json", "X-GoNet-Login": "1"})
}
func validLogin(next string) string {
	b, _ := json.Marshal(map[string]string{"username": " admin ", "password": testPassword, "next": next})
	return string(b)
}

type countingBackend struct {
	reads, writes, scans atomic.Int64
	view                 *control.View
}

func (b *countingBackend) Read(context.Context) (*control.View, error) {
	b.reads.Add(1)
	if b.view != nil {
		return b.view, nil
	}
	return &control.View{Devices: []control.Device{}, Candidates: []control.Candidate{}}, nil
}
func (b *countingBackend) Settings() control.Settings {
	return control.Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ExcludedCIDRs: []string{}, BootstrapCIDRs: []string{}, ReadManagement: true}
}
func (b *countingBackend) SaveSettings(control.Settings) error { b.writes.Add(1); return nil }
func (b *countingBackend) Scan(context.Context, bool, func(Progress)) (RunResult, error) {
	b.scans.Add(1)
	return RunResult{}, nil
}

func TestUnauthenticatedRoutesNeverReadBusinessData(t *testing.T) {
	b := &countingBackend{}
	s := newTestServer(t, b)
	defer s.Close()
	h := s.Handler(testHost)
	for _, tc := range []struct {
		method, path string
		code         int
	}{{"GET", "/", 302}, {"GET", "/?page=topology", 302}, {"HEAD", "/", 302}, {"GET", "/api/state", 401}, {"HEAD", "/api/devices.csv", 401}, {"PUT", "/api/settings", 401}, {"POST", "/api/scan", 401}, {"POST", "/api/cancel", 401}, {"GET", "/app.js", 401}, {"GET", "/style.css", 401}, {"GET", "/api/v1/auth/me", 401}, {"POST", "/api/v1/auth/logout", 401}, {"GET", "/login", 200}, {"GET", "/login.js", 200}, {"GET", "/login.css", 200}, {"GET", "/tokens.css", 200}, {"GET", "/health", 200}, {"GET", "/index.html", 404}, {"GET", "/unknown", 404}} {
		w := callAuth(h, tc.method, tc.path, "{}", nil, map[string]string{"Authorization": "Bearer invalid"})
		if w.Code != tc.code {
			t.Errorf("%s %s: %d", tc.method, tc.path, w.Code)
		}
		if tc.method == "HEAD" && w.Body.Len() != 0 {
			t.Error("HEAD has body")
		}
		if tc.path == "/?page=topology" && w.Header().Get("Location") != "/login?next=%2F%3Fpage%3Dtopology" {
			t.Error("destination lost")
		}
	}
	if b.reads.Load() != 0 || b.writes.Load() != 0 || b.scans.Load() != 0 {
		t.Fatal("anonymous request reached backend")
	}
}
func TestLoginSessionCSRFLogoutRotation(t *testing.T) {
	b := &countingBackend{}
	s := newTestServer(t, b)
	defer s.Close()
	h := s.Handler(testHost)
	w := loginRequest(h, nil, validLogin("/?page=topology"))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing cookie")
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode || len(cookie.Value) != 43 || cookie.MaxAge != 28800 || cookie.Expires.IsZero() {
		t.Fatal("cookie attributes")
	}
	var result authResponse
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.RedirectTo != "/?page=topology" || result.User.Role != "admin" || strings.Contains(w.Body.String(), cookie.Value) {
		t.Fatal("login contract")
	}
	if w := callAuth(h, "GET", "/api/v1/auth/me", "", cookie, nil); w.Code != 200 || !strings.Contains(w.Body.String(), result.CSRFToken) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("me contract")
	}
	state := callAuth(h, "GET", "/api/state", "", cookie, nil)
	var data map[string]any
	json.Unmarshal(state.Body.Bytes(), &data)
	if data["token"] != result.CSRFToken {
		t.Fatal("state CSRF mismatch")
	}
	other, otherCSRF := testSession(t, s)
	_ = other
	for _, csrf := range []string{"", otherCSRF, "wrong"} {
		if w := callAuth(h, "PUT", "/api/settings", "{}", cookie, map[string]string{"X-GoNet-Token": csrf}); w.Code != 403 {
			t.Fatal("cross-session CSRF accepted")
		}
	}
	if b.writes.Load() != 0 {
		t.Fatal("bad CSRF wrote")
	}
	if w := callAuth(h, "PUT", "/api/settings", "{}", cookie, map[string]string{"X-GoNet-Token": result.CSRFToken}); w.Code != 200 {
		t.Fatal("valid CSRF rejected")
	}
	if w := callAuth(h, "GET", "/login?next=%2F%3Fpage%3Dtopology", "", cookie, nil); w.Code != 302 || w.Header().Get("Location") != "/?page=topology" {
		t.Fatal("authenticated login page")
	}
	rotated := loginRequest(h, cookie, validLogin("//evil.invalid"))
	if rotated.Code != 200 {
		t.Fatal("rotation failed")
	}
	if w := callAuth(h, "GET", "/api/v1/auth/me", "", cookie, nil); w.Code != 401 {
		t.Fatal("rotated session replay")
	}
	if w := callAuth(h, "GET", "/api/v1/auth/me", "", other, nil); w.Code != 200 {
		t.Fatal("other session lost")
	}
	cookie = rotated.Result().Cookies()[0]
	json.Unmarshal(rotated.Body.Bytes(), &result)
	if result.RedirectTo != "/" {
		t.Fatal("open redirect")
	}
	w = callAuth(h, "POST", "/api/v1/auth/logout", "{}", cookie, map[string]string{"X-GoNet-Token": result.CSRFToken})
	if w.Code != 204 || w.Body.Len() != 0 {
		t.Fatal("logout contract")
	}
	removed := w.Result().Cookies()[0]
	if removed.MaxAge != -1 || removed.Expires.After(time.Now()) || !removed.HttpOnly || !removed.Secure {
		t.Fatal("cookie not removed")
	}
	if w := callAuth(h, "GET", "/api/v1/auth/me", "", cookie, nil); w.Code != 401 {
		t.Fatal("logout cookie replay")
	}
	if b.scans.Load() != 0 {
		t.Fatal("auth triggered scan")
	}
}
func TestLoginStrictInputAndRateLimit(t *testing.T) {
	s := newTestServer(t, &countingBackend{})
	defer s.Close()
	h := s.Handler(testHost)
	for _, tc := range []struct {
		body string
		code int
	}{{`{}`, 400}, {`null`, 400}, {`[]`, 400}, {`{"username":null,"password":"x"}`, 400}, {`{"username":1,"password":"x"}`, 400}, {`{"username":"admin","password":"x","unknown":1}`, 400}, {`{"username":"admin","username":"admin","password":"x"}`, 400}, {validLogin("/") + ` {}`, 400}, {`{"username":"admin","password":"` + strings.Repeat("x", 4100) + `"}`, 413}} {
		if w := loginRequest(h, nil, tc.body); w.Code != tc.code {
			t.Errorf("strict JSON got %d want %d", w.Code, tc.code)
		}
	}
	for _, headers := range []map[string]string{{"Content-Type": "application/json"}, {"X-GoNet-Login": "1", "Content-Type": "application/x-www-form-urlencoded"}, {"X-GoNet-Login": "1", "Content-Type": "application/json", "Origin": "https://evil.invalid"}} {
		w := callAuth(h, "POST", "/api/v1/auth/login", validLogin("/"), nil, headers)
		if w.Code != 403 && w.Code != 415 {
			t.Fatal("login CSRF accepted")
		}
	}
	for i := 0; i < 5; i++ {
		body := `{"username":"missing","password":"wrong"}`
		if i%2 == 0 {
			body = `{"username":"admin","password":"wrong"}`
		}
		w := loginRequest(h, nil, body)
		if w.Code != 401 || !strings.Contains(w.Body.String(), "AUTH_INVALID_CREDENTIALS") || len(w.Result().Cookies()) != 0 {
			t.Fatal("credential failure contract")
		}
	}
	w := loginRequest(h, nil, validLogin("/"))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("missing failure limit")
	}
	// Spoofed forwarding headers cannot select another source bucket.
	w = callAuth(h, "POST", "/api/v1/auth/login", validLogin("/"), nil, map[string]string{"Content-Type": "application/json", "X-GoNet-Login": "1", "X-Forwarded-For": "198.51.100.99"})
	if w.Code != 429 {
		t.Fatal("untrusted proxy bypass")
	}
}
func TestHostOriginCookieModesAndRestart(t *testing.T) {
	s := newTestServer(t, &countingBackend{})
	h := s.Handler(testHost)
	for _, origin := range []string{"null", "https://evil.invalid", "http://127.0.0.1:8787/", "http://user@127.0.0.1:8787", "https://127.0.0.1:8787"} {
		if w := callAuth(h, "POST", "/api/v1/auth/login", validLogin("/"), nil, map[string]string{"Origin": origin, "Content-Type": "application/json", "X-GoNet-Login": "1"}); w.Code != 403 {
			t.Fatal("bad origin")
		}
	}
	r := httptest.NewRequest("GET", "/health", nil)
	r.Host = "evil.invalid"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("bad Host accepted")
	}
	s.authConfig.CookieSecure = false
	w = loginRequest(h, nil, validLogin("/"))
	if w.Code != 200 || w.Result().Cookies()[0].Secure {
		t.Fatal("loopback development cookie")
	}
	cookie := w.Result().Cookies()[0]
	s.Close()
	next := newTestServer(t, &countingBackend{})
	defer next.Close()
	if w := callAuth(next.Handler(testHost), "GET", "/api/v1/auth/me", "", cookie, nil); w.Code != 401 {
		t.Fatal("restart kept session")
	}
	if _, err := New(context.Background(), &fakeBackend{}, auth.Config{}, nil); err == nil {
		t.Fatal("anonymous constructor")
	}
}

func TestAuthenticationLeavesOrderedFixtureUnchanged(t *testing.T) {
	view := authFixtureView()
	before, _ := json.Marshal(view)
	baseline := sha256.Sum256(before)
	b := &countingBackend{view: view}
	s := newTestServer(t, b)
	defer s.Close()
	h := s.Handler(testHost)
	logged := loginRequest(h, nil, validLogin("/?page=topology"))
	if logged.Code != 200 {
		t.Fatal("login failed")
	}
	cookie := logged.Result().Cookies()[0]
	for range 3 {
		for _, path := range []string{"/api/v1/auth/me", "/api/state", "/api/devices.csv"} {
			if w := callAuth(h, "GET", path, "", cookie, nil); w.Code != 200 {
				t.Fatal(path, w.Code)
			}
		}
	}
	var login authResponse
	json.Unmarshal(logged.Body.Bytes(), &login)
	if w := callAuth(h, "POST", "/api/v1/auth/logout", "{}", cookie, map[string]string{"X-GoNet-Token": login.CSRFToken}); w.Code != 204 {
		t.Fatal("logout")
	}
	after, _ := json.Marshal(view)
	if sha256.Sum256(after) != baseline || b.writes.Load() != 0 || b.scans.Load() != 0 {
		t.Fatal("authentication changed fixture, settings, or scan count")
	}
	if b.reads.Load() != 6 {
		t.Fatal("me read business backend")
	}
}
