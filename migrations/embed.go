// Package migrations embeds the ordered SQL migration files.
package migrations

import "embed"

// FS holds the SQL migration files (000001_init.up.sql, ...).
//
//go:embed *.sql
var FS embed.FS
