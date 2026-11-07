package webui

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gonet/internal/auth"
)

type headResponse struct{ http.ResponseWriter }

func (w headResponse) Write(p []byte) (int, error) { return len(p), nil }

func authError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func (s *Server) requestForbidden(w http.ResponseWriter, r *http.Request, message string) {
	if route, rawID, ok := topologyRoute(r.URL.Path); ok {
		started := time.Now()
		id, _ := parseDeviceID(rawID, nil)
		apiError(w, 403, "REQUEST_FORBIDDEN", message)
		s.logTopologyRequest(apiRequestID(w), "unauthenticated", route, id, 403, 0, started)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		authError(w, 403, "REQUEST_FORBIDDEN", message)
	} else {
		writeJSON(w, 403, map[string]string{"error": message})
	}
}
func (s *Server) session(r *http.Request) (auth.Session, bool) {
	cookie, err := r.Cookie(auth.CookieName)
	if err != nil {
		return auth.Session{}, false
	}
	return s.sessions.Get(cookie.Value)
}
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path == "/health" || path == "/login" || path == "/login.css" || path == "/login.js" || path == "/tokens.css" || path == "/api/v1/auth/login" {
		return true
	}
	protected := servedAsset(path) && !strings.HasPrefix(path, "/docs/")
	switch path {
	case "/api/state", "/api/devices.csv", "/api/settings", "/api/scan", "/api/cancel", "/api/v1/auth/me", "/api/v1/auth/logout":
		protected = true
	case legacyOpenAPIPath:
		protected = true
	}
	protected = protected || path == apiKeyPath || strings.HasPrefix(path, apiKeyPath+"/")
	if !protected {
		return true
	} // Unknown paths still resolve to 404.
	session, ok := s.session(r)
	if !ok {
		if path == "/" && (r.Method == "GET" || r.Method == "HEAD") {
			next := "/"
			if query, err := url.ParseQuery(r.URL.RawQuery); err == nil && len(query) == 1 && len(query["page"]) == 1 {
				next = auth.SafeNext("/?page=" + query.Get("page"))
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		} else if strings.HasPrefix(path, "/api/v1/") {
			authError(w, 401, "AUTH_UNAUTHENTICATED", "请先登录")
		} else {
			writeJSON(w, 401, map[string]string{"error": "请先登录"})
		}
		return false
	}
	if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-GoNet-Token")), []byte(session.CSRFToken)) != 1 {
		s.requestForbidden(w, r, "页面令牌失效，请刷新页面")
		return false
	}
	return true
}

type authUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}
type authResponse struct {
	User       authUser  `json:"user"`
	ExpiresAt  time.Time `json:"expires_at"`
	CSRFToken  string    `json:"csrf_token"`
	RedirectTo string    `json:"redirect_to,omitempty"`
}

func sessionResponse(session auth.Session) authResponse {
	return authResponse{User: authUser{session.Username, "admin"}, ExpiresAt: session.ExpiresAt.UTC(), CSRFToken: session.CSRFToken}
}
func (s *Server) setCookie(w http.ResponseWriter, id string, session auth.Session, remove bool) {
	c := &http.Cookie{Name: auth.CookieName, Value: id, Path: "/", HttpOnly: true, Secure: s.authConfig.CookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt.UTC(), MaxAge: int(math.Ceil(s.authConfig.SessionTTL.Seconds()))}
	if remove {
		c.Value = ""
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0).UTC()
	}
	http.SetCookie(w, c)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-GoNet-Login") != "1" {
		authError(w, 403, "REQUEST_FORBIDDEN", "登录请求校验失败")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		authError(w, 415, "UNSUPPORTED_MEDIA_TYPE", "请使用 JSON 登录请求")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	defer r.Body.Close()
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			authError(w, 413, "REQUEST_TOO_LARGE", "登录请求过大")
		} else {
			authError(w, 400, "INVALID_ARGUMENT", "登录请求格式无效")
		}
		return
	}
	// A string map rejects numbers, arrays, booleans and nested values. Explicit
	// nulls and duplicate keys are rejected too, rather than becoming zero values.
	fields := map[string]string{}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		authError(w, 400, "INVALID_ARGUMENT", "登录请求格式无效")
		return
	}
	for decoder.More() {
		key, e := decoder.Token()
		if e != nil {
			err = e
			break
		}
		name, ok := key.(string)
		if !ok {
			err = errors.New("invalid field")
			break
		}
		if _, exists := fields[name]; exists || (name != "username" && name != "password" && name != "next") {
			err = errors.New("invalid field")
			break
		}
		var value any
		if e = decoder.Decode(&value); e != nil {
			err = e
			break
		}
		v, ok := value.(string)
		if !ok {
			err = errors.New("invalid string")
			break
		}
		fields[name] = v
	}
	if err == nil {
		_, err = decoder.Token()
	}
	var extra any
	if err == nil && decoder.Decode(&extra) != io.EOF {
		err = errors.New("extra JSON")
	}
	username, password := strings.TrimSpace(fields["username"]), fields["password"]
	if err != nil || username == "" || password == "" {
		authError(w, 400, "INVALID_ARGUMENT", "请输入用户名和密码")
		return
	}
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		source = r.RemoteAddr
	}
	finish, retry := s.loginLimiter.Begin(source)
	if finish == nil {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retry.Seconds()))))
		authError(w, 429, "AUTH_RATE_LIMITED", "登录尝试过于频繁，请稍后重试")
		return
	}
	valid := s.authConfig.Verify(username, password)
	finish(!valid)
	if !valid {
		authError(w, 401, "AUTH_INVALID_CREDENTIALS", "用户名或密码错误")
		return
	}
	oldID := ""
	if c, e := r.Cookie(auth.CookieName); e == nil {
		oldID = c.Value
	}
	id, session, err := s.sessions.Create(username, oldID)
	if err != nil {
		authError(w, 503, "AUTH_UNAVAILABLE", "暂时无法创建登录会话，请稍后重试")
		return
	}
	s.setCookie(w, id, session, false)
	response := sessionResponse(session)
	response.RedirectTo = auth.SafeNext(fields["next"])
	writeJSON(w, 200, response)
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	session, ok := s.session(r)
	if !ok {
		authError(w, 401, "AUTH_UNAUTHENTICATED", "请先登录")
		return
	}
	writeJSON(w, 200, sessionResponse(session))
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := s.session(r)
	if !ok {
		authError(w, 401, "AUTH_UNAUTHENTICATED", "请先登录")
		return
	}
	c, _ := r.Cookie(auth.CookieName)
	s.sessions.Delete(c.Value)
	s.setCookie(w, "", session, true)
	w.WriteHeader(http.StatusNoContent)
}
