// Package postgres implements PostgreSQL migration and storage helpers (M4).
package postgres

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"gonet/migrations"
)

// Advisory lock shared by every migration and scan writer (section 2.2).
const (
	LockClassID = 207026
	LockObjID   = 1
)

// ErrLocked is returned when another process holds the advisory lock.
var ErrLocked = errors.New("DB_LOCKED: another migration or scan holds the advisory lock")

// Migration is one ordered SQL migration.
type Migration struct {
	Version int
	Name    string
	UpSQL   string
}

// LoadMigrations reads the embedded up migrations sorted by version.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		base := strings.TrimSuffix(name, ".up.sql")
		parts := strings.SplitN(base, "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid migration name %q", name)
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid migration version in %q: %w", name, err)
		}
		data, err := migrations.FS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: v, Name: parts[1], UpSQL: string(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// TryLock takes the session advisory lock. It reports false when another
// session already holds it.
func TryLock(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var ok bool
	err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", LockClassID, LockObjID).Scan(&ok)
	return ok, err
}

// Unlock releases the session advisory lock (best effort).
func Unlock(ctx context.Context, conn *pgx.Conn) {
	_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", LockClassID, LockObjID)
}

// Migrate applies pending migrations inside the advisory lock and transaction
// per version, and returns the versions applied this call.
func Migrate(ctx context.Context, conn *pgx.Conn) ([]int, error) {
	locked, err := TryLock(ctx, conn)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrLocked
	}
	defer Unlock(ctx, conn)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		name text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	appliedSet, err := appliedVersions(ctx, conn)
	if err != nil {
		return nil, err
	}
	migs, err := LoadMigrations()
	if err != nil {
		return nil, err
	}

	var applied []int
	for _, m := range migs {
		if appliedSet[m.Version] {
			continue
		}
		if err := applyOne(ctx, conn, m); err != nil {
			return applied, fmt.Errorf("migration %06d_%s: %w", m.Version, m.Name, err)
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

func appliedVersions(ctx context.Context, conn *pgx.Conn) (map[int]bool, error) {
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[int(v)] = true
	}
	return out, rows.Err()
}

func applyOne(ctx context.Context, conn *pgx.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, stmt := range splitSQL(m.UpSQL) {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("exec %.60q: %w", stmt, err)
		}
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations(version, name) VALUES($1, $2)", m.Version, m.Name); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	return tx.Commit(ctx)
}

// splitSQL splits a migration script on statement boundaries, ignoring
// semicolons inside line comments, block comments and single-quoted strings.
func splitSQL(script string) []string {
	var out []string
	var cur strings.Builder
	inLineComment := false
	inBlockComment := false
	inString := false

	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" && !commentOnly(s) {
			out = append(out, s)
		}
		cur.Reset()
	}

	for i := 0; i < len(script); i++ {
		c := script[i]
		switch {
		case inLineComment:
			cur.WriteByte(c)
			if c == '\n' {
				inLineComment = false
			}
		case inBlockComment:
			cur.WriteByte(c)
			if c == '*' && i+1 < len(script) && script[i+1] == '/' {
				cur.WriteByte('/')
				i++
				inBlockComment = false
			}
		case inString:
			cur.WriteByte(c)
			if c == '\'' {
				if i+1 < len(script) && script[i+1] == '\'' {
					cur.WriteByte('\'')
					i++
				} else {
					inString = false
				}
			}
		case c == '-' && i+1 < len(script) && script[i+1] == '-':
			cur.WriteString("--")
			i++
			inLineComment = true
		case c == '/' && i+1 < len(script) && script[i+1] == '*':
			cur.WriteString("/*")
			i++
			inBlockComment = true
		case c == '\'':
			cur.WriteByte(c)
			inString = true
		case c == ';':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func commentOnly(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "--") {
			return false
		}
	}
	return true
}
