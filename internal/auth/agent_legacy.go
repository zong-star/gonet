package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"time"
)

// ReadLegacyAPIKey reads the previously active digest for one-time import.
// The saved file takes precedence over the old bootstrap environment.
func ReadLegacyAPIKey(path string, get func(string) string) ([]byte, *time.Time, *time.Time, error) {
	invalid := errors.New("旧版 Agent API 配置无效")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		if raw := get("GONET_AGENT_API_ENABLED"); raw != "" {
			enabled, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, nil, nil, invalid
			}
			if enabled {
				hash, err := hex.DecodeString(get("GONET_AGENT_READ_TOKEN_SHA256"))
				if err != nil || len(hash) != sha256.Size {
					return nil, nil, nil, invalid
				}
				return hash, nil, nil, nil
			}
		}
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, errors.New("无法读取旧版 Agent API 配置")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil || len(body) > 16<<10 {
		return nil, nil, nil, invalid
	}
	var state struct {
		Version        int        `json:"version"`
		Enabled        *bool      `json:"enabled"`
		TokenSHA256    string     `json:"token_sha256"`
		TokenCreatedAt *time.Time `json:"token_created_at"`
		UpdatedAt      *time.Time `json:"updated_at"`
		Revision       string     `json:"revision"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		state.Version != 1 || state.Enabled == nil || state.Revision == "" || len(state.Revision) > 64 {
		return nil, nil, nil, invalid
	}
	if !*state.Enabled {
		return nil, nil, nil, nil
	}
	hash, err := hex.DecodeString(state.TokenSHA256)
	if err != nil || len(hash) != sha256.Size {
		return nil, nil, nil, invalid
	}
	return hash, state.TokenCreatedAt, state.UpdatedAt, nil
}
