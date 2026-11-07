package postgres

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"gonet/internal/auth"
)

var ErrAPIKeyName = errors.New("API Key name already exists")

type APIKey struct {
	ID          int64           `json:"id,string"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Preview     string          `json:"key_preview"`
	AllowedIPs  []netip.Prefix  `json:"allowed_ips"`
	CreatedAt   time.Time       `json:"created_at"`
	Profile     auth.APIProfile `json:"profile,omitempty"`
}

type APIKeyUpdate struct {
	Name        *string
	Description *string
	AllowedIPs  []netip.Prefix
	Profile     *auth.APIProfile
}

type APIKeyGrant struct {
	ID         int64
	AllowedIPs []netip.Prefix
	Profile    auth.APIProfile
}

type APIKeyStore struct{ pool *pgxpool.Pool }

func OpenAPIKeys(ctx context.Context, dsn string) (*APIKeyStore, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return &APIKeyStore{pool}, nil
}

func (s *APIKeyStore) Close() { s.pool.Close() }

const apiKeyColumns = "id, name, description, key_preview, allowed_ips, created_at, profile"

func scanAPIKey(row pgx.Row, updatedAt *time.Time) (APIKey, error) {
	var key APIKey
	values := []any{&key.ID, &key.Name, &key.Description, &key.Preview, &key.AllowedIPs, &key.CreatedAt, &key.Profile}
	if updatedAt != nil {
		values = append(values, updatedAt)
	}
	err := row.Scan(values...)
	if key.Profile == auth.APITopologyRead {
		key.Profile = ""
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "agent_api_keys_name_key" {
		err = ErrAPIKeyName
	}
	return key, err
}

func (s *APIKeyStore) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+apiKeyColumns+" FROM agent_api_keys ORDER BY created_at DESC, id DESC")
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (APIKey, error) {
		return scanAPIKey(row, nil)
	})
	if keys == nil {
		keys = []APIKey{}
	}
	return keys, err
}

func (s *APIKeyStore) CreateAPIKey(ctx context.Context, key APIKey, hash [32]byte) (APIKey, error) {
	return scanAPIKey(s.pool.QueryRow(ctx, "INSERT INTO agent_api_keys (name, description, key_hash, key_preview, allowed_ips, profile) VALUES ($1, $2, $3, $4, $5, COALESCE(NULLIF($6,''),'topology_read')) RETURNING "+apiKeyColumns,
		key.Name, key.Description, hash[:], key.Preview, key.AllowedIPs, key.Profile), nil)
}

func (s *APIKeyStore) UpdateAPIKey(ctx context.Context, id int64, change APIKeyUpdate) (APIKey, time.Time, error) {
	var updated time.Time
	key, err := scanAPIKey(s.pool.QueryRow(ctx, `
		UPDATE agent_api_keys SET name = COALESCE($2, name), description = COALESCE($3, description),
			allowed_ips = COALESCE($4, allowed_ips), profile = COALESCE($5, profile), updated_at = NOW()
		WHERE id = $1 RETURNING `+apiKeyColumns+", updated_at", id, change.Name, change.Description, change.AllowedIPs, change.Profile), &updated)
	return key, updated, err
}

func (s *APIKeyStore) DeleteAPIKey(ctx context.Context, id int64) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM agent_api_keys WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *APIKeyStore) LookupAPIKey(ctx context.Context, hash [32]byte) (APIKeyGrant, error) {
	var grant APIKeyGrant
	err := s.pool.QueryRow(ctx, "SELECT id, allowed_ips, profile FROM agent_api_keys WHERE key_hash = $1", hash[:]).
		Scan(&grant.ID, &grant.AllowedIPs, &grant.Profile)
	return grant, err
}

// ImportLegacyAPIKey atomically records and, if needed, imports the previous
// credential. Reading the old configuration is only necessary on first start.
func (s *APIKeyStore) ImportLegacyAPIKey(ctx context.Context, legacy func() ([]byte, *time.Time, *time.Time, error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var pending bool
	err = tx.QueryRow(ctx, `INSERT INTO agent_api_legacy_import (singleton) VALUES (TRUE)
		ON CONFLICT DO NOTHING RETURNING singleton`).Scan(&pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	hash, created, updated, err := legacy()
	if err != nil {
		return err
	}
	if len(hash) != 0 {
		// The old application had no per-Key source restriction.
		_, err = tx.Exec(ctx, `INSERT INTO agent_api_keys (name, description, key_hash, key_preview, allowed_ips, created_at, updated_at)
			VALUES ('旧版 Agent Key', '从旧版只读 API 迁移，沿用原访问范围。', $1, '旧版 Key · 已隐藏',
				ARRAY['0.0.0.0/0', '::/0']::cidr[], COALESCE($2, NOW()), COALESCE($3, $2, NOW()))
			ON CONFLICT (key_hash) DO NOTHING`, hash, created, updated)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
