// Package auth provides the console's single-administrator, in-memory sessions.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Username       string
	PasswordHash   string
	SessionTTL     time.Duration
	CookieSecure   bool
	TrustedProxies []netip.Prefix
	AllowedSources []netip.Prefix
}

func LoadConfig() (Config, error) { return ConfigFromEnv(os.Getenv) }

func ConfigFromEnv(get func(string) string) (Config, error) {
	c := Config{Username: strings.TrimSpace(get("GONET_ADMIN_USERNAME")), PasswordHash: get("GONET_ADMIN_PASSWORD_HASH"), SessionTTL: 8 * time.Hour, CookieSecure: true}
	if raw := get("GONET_SESSION_TTL"); raw != "" {
		ttl, err := time.ParseDuration(raw)
		if err != nil {
			return c, errors.New("GONET_SESSION_TTL must be a positive duration up to 24h")
		}
		c.SessionTTL = ttl
	}
	if raw := get("GONET_COOKIE_SECURE"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return c, errors.New("GONET_COOKIE_SECURE must be true or false")
		}
		c.CookieSecure = v
	}
	if raw := strings.TrimSpace(get("GONET_TRUSTED_PROXY_CIDRS")); raw != "" {
		prefixes, err := ParseIPNetworks(strings.Split(raw, ","))
		if err != nil {
			return c, errors.New("GONET_TRUSTED_PROXY_CIDRS must contain valid proxy IPs or CIDRs")
		}
		for _, prefix := range prefixes {
			if prefix.Bits() == 0 {
				return c, errors.New("GONET_TRUSTED_PROXY_CIDRS cannot trust all addresses")
			}
		}
		c.TrustedProxies = prefixes
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.Username == "" || len(c.Username) > 256 || strings.TrimSpace(c.Username) != c.Username || strings.ContainsAny(c.Username, "\r\n\x00") {
		return errors.New("GONET_ADMIN_USERNAME is required (maximum 256 bytes)")
	}
	if c.SessionTTL <= 0 || c.SessionTTL > 24*time.Hour {
		return errors.New("GONET_SESSION_TTL must be a positive duration up to 24h")
	}
	h := c.PasswordHash
	if len(h) != 60 || !(strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$")) {
		return errors.New("GONET_ADMIN_PASSWORD_HASH must be a valid bcrypt hash")
	}
	if _, err := bcrypt.Cost([]byte(h)); err != nil {
		return errors.New("GONET_ADMIN_PASSWORD_HASH must be a valid bcrypt hash")
	}
	for _, ch := range h[7:] {
		if !strings.ContainsRune("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", ch) {
			return errors.New("GONET_ADMIN_PASSWORD_HASH must be a valid bcrypt hash")
		}
	}
	return nil
}

func ValidatePassword(password []byte) error {
	if !utf8.Valid(password) || utf8.RuneCount(password) < 12 || len(password) > 72 {
		return errors.New("密码至少 12 个字符，最多 72 个 UTF-8 字节")
	}
	return nil
}

func HashPassword(password []byte) ([]byte, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	return bcrypt.GenerateFromPassword(password, 12)
}

func (c Config) Verify(username, password string) bool {
	// Always compare against the configured hash, including unknown usernames.
	// Overlong passwords must never be silently truncated by bcrypt comparison.
	candidate := []byte(password)
	validLength := len(candidate) <= 72 && utf8.ValidString(password)
	if !validLength {
		candidate = []byte("invalid overlong password")
	}
	err := bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), candidate)
	a, b := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(c.Username))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1 && err == nil && validLength
}

// SafeNext accepts only canonical console destinations, never arbitrary URLs.
func SafeNext(next string) string {
	if next == "/" {
		return next
	}
	for _, page := range []string{"overview", "devices", "topology", "candidates", "probes", "settings", "api"} {
		if next == "/?page="+page {
			return next
		}
	}
	return "/"
}
