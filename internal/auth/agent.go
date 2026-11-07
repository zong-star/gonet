package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type APIProfile string

const (
	APITopologyRead    APIProfile = "topology_read"
	APITopologyCompact APIProfile = "topology_compact"
)

func (p APIProfile) Valid() bool {
	return p == APITopologyRead || p == APITopologyCompact
}

func (p APIProfile) AllowsTopologyRoute(route string) bool {
	switch p {
	case APITopologyRead:
		return true
	case APITopologyCompact:
		switch route {
		case "search", "device", "neighbors", "path", "summary", "interfaces", "collection":
			return true
		}
	}
	return false
}

const apiKeyPrefix = "gonet_sk_"

func GenerateAPIKey() (string, string, [32]byte, error) {
	random, err := randomID()
	if err != nil {
		return "", "", [32]byte{}, err
	}
	key := apiKeyPrefix + random
	preview := apiKeyPrefix + random[:4] + "…" + random[len(random)-4:]
	return key, preview, sha256.Sum256([]byte(key)), nil
}

// BearerDigest accepts both current and legacy token formats. A legacy token
// must still match a stored digest before it can authorize any request.
func BearerDigest(headers []string) ([32]byte, bool) {
	if len(headers) != 1 {
		return [32]byte{}, false
	}
	scheme, token, found := strings.Cut(headers[0], " ")
	random := strings.TrimPrefix(token, apiKeyPrefix)
	if !found || !strings.EqualFold(scheme, "Bearer") || len(random) != 43 {
		return [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(random)
	if err != nil || len(raw) != sha256.Size {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}

// GenerateAgentToken preserves the legacy CLI output for existing scripts.
func GenerateAgentToken() (string, string, error) {
	token, err := randomID()
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:]), nil
}
