package webui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	apidocs "gonet/docs/api"
	"gonet/internal/auth"
	"gonet/internal/store/postgres"
)

const apiKeyPath = "/api/v1/admin/api-keys"
const legacyOpenAPIPath = "/api/v1/admin/agent-api/openapi.yaml"

func downloadOpenAPI(w http.ResponseWriter, _ *http.Request) {
	downloadSpecification(w, "gonet-openapi.yaml", apidocs.OpenAPI)
}

func downloadAgentOpenAPI(w http.ResponseWriter, _ *http.Request) {
	downloadSpecification(w, "gonet-agent-openapi.yaml", apidocs.AgentOpenAPI)
}

func downloadSpecification(w http.ResponseWriter, name string, payload []byte) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		authError(w, 400, "INVALID_ARGUMENT", "管理接口不接受查询参数")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	keys, err := s.apiKeys.ListAPIKeys(ctx)
	if err != nil {
		apiKeyStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

type apiKeyInput struct {
	Name        *string          `json:"name"`
	Description *string          `json:"description"`
	AllowedIPs  []string         `json:"allowed_ips"`
	Profile     *auth.APIProfile `json:"profile"`
}

func (input apiKeyInput) validate(create bool) (postgres.APIKeyUpdate, error) {
	var change postgres.APIKeyUpdate
	if create || input.Name != nil {
		if input.Name == nil {
			return change, errors.New("请填写名称")
		}
		name := strings.TrimSpace(*input.Name)
		if name == "" || utf8.RuneCountInString(name) > 100 || strings.ContainsAny(name, "\r\n\x00") {
			return change, errors.New("名称须为 1 到 100 个字符")
		}
		change.Name = &name
	}
	if input.Description != nil {
		description := strings.TrimSpace(*input.Description)
		if utf8.RuneCountInString(description) > 1000 || strings.ContainsRune(description, 0) {
			return change, errors.New("描述最多 1000 个字符")
		}
		change.Description = &description
	}
	if create || input.AllowedIPs != nil {
		prefixes, err := auth.ParseIPNetworks(input.AllowedIPs)
		if err != nil {
			return change, err
		}
		change.AllowedIPs = prefixes
	}
	if input.Profile != nil {
		if !input.Profile.Valid() {
			return change, errors.New("API Key 权限类型无效")
		}
		change.Profile = input.Profile
	}
	if change.Name == nil && change.Description == nil && change.AllowedIPs == nil && change.Profile == nil {
		return change, errors.New("请至少提交一个要修改的字段")
	}
	return change, nil
}

func (s *Server) saveAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		authError(w, 400, "INVALID_ARGUMENT", "管理接口不接受查询参数")
		return
	}
	create := r.Method == http.MethodPost
	var id int64
	if !create {
		var err error
		id, err = parseDeviceID(r.PathValue("id"), nil)
		if err != nil {
			authError(w, 400, "INVALID_ARGUMENT", "API Key ID 无效")
			return
		}
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		authError(w, 415, "UNSUPPORTED_MEDIA_TYPE", "请使用 JSON 请求")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	var input apiKeyInput
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err == nil {
		if err = decoder.Decode(&struct{}{}); err == io.EOF {
			err = nil
		} else if err == nil {
			err = errors.New("unexpected second JSON value")
		}
	}
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			authError(w, 413, "REQUEST_TOO_LARGE", "请求过大")
		} else {
			authError(w, 400, "INVALID_ARGUMENT", "请求格式无效")
		}
		return
	}
	change, err := input.validate(create)
	if err != nil {
		authError(w, 400, "INVALID_ARGUMENT", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !create {
		key, updated, err := s.apiKeys.UpdateAPIKey(ctx, id, change)
		if err != nil {
			apiKeyStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			postgres.APIKey
			UpdatedAt time.Time `json:"updated_at"`
		}{key, updated})
		return
	}
	token, preview, hash, err := auth.GenerateAPIKey()
	if err != nil {
		authError(w, 500, "INTERNAL_ERROR", "暂时无法生成 API Key")
		return
	}
	key, err := s.apiKeys.CreateAPIKey(ctx, postgres.APIKey{
		Name: *change.Name, Description: valueOrEmpty(change.Description), Preview: preview, AllowedIPs: change.AllowedIPs,
		Profile: apiKeyProfile(change.Profile),
	}, hash)
	if err != nil {
		apiKeyStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		postgres.APIKey
		Key string `json:"key"`
	}{key, token})
}

func apiKeyProfile(profile *auth.APIProfile) auth.APIProfile {
	if profile == nil {
		return auth.APITopologyRead
	}
	return *profile
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		authError(w, 400, "INVALID_ARGUMENT", "管理接口不接受查询参数")
		return
	}
	id, err := parseDeviceID(r.PathValue("id"), nil)
	if err != nil {
		authError(w, 400, "INVALID_ARGUMENT", "API Key ID 无效")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.apiKeys.DeleteAPIKey(ctx, id); err != nil {
		apiKeyStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func apiKeyStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, postgres.ErrAPIKeyName):
		authError(w, 409, "NAME_CONFLICT", "此 API Key 名称已存在")
	case errors.Is(err, pgx.ErrNoRows):
		authError(w, 404, "KEY_NOT_FOUND", "API Key 不存在")
	default:
		authError(w, 503, "DATABASE_UNAVAILABLE", "暂时无法访问 API Key 存储")
	}
}

func containsIP(networks []netip.Prefix, ip netip.Addr) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func peerIP(remoteAddr string) netip.Addr {
	remote, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return remote.Addr().Unmap().WithZone("")
}

func (s *Server) requestIP(r *http.Request) netip.Addr {
	peer := peerIP(r.RemoteAddr)
	if !containsIP(s.authConfig.TrustedProxies, peer) {
		return peer
	}
	forwarded := r.Header.Values("X-Forwarded-For")
	if len(forwarded) == 0 {
		return peer
	}
	// The trusted proxy must overwrite this header with a single client IP.
	if len(forwarded) != 1 {
		return netip.Addr{}
	}
	client, err := netip.ParseAddr(strings.TrimSpace(forwarded[0]))
	if err != nil || client.Zone() != "" {
		return netip.Addr{}
	}
	return client.Unmap()
}
