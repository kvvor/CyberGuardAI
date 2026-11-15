// Package dbschema verifies that the connected PostgreSQL database has the
// migrations this build of the backend requires. A reachable database with an
// older schema previously produced opaque INTERNAL_ERROR responses.
package dbschema

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Required is the highest migration number in ../migrations that this code
// depends on. Update it together with every new migration.
const Required = 4

var (
	ErrNotMigrated = errors.New("DATABASE_NOT_MIGRATED")
	ErrOutdated    = errors.New("DATABASE_SCHEMA_OUTDATED")
	ErrDirty       = errors.New("DATABASE_MIGRATION_INCOMPLETE")
	ErrNewer       = errors.New("DATABASE_SCHEMA_NEWER")
)

// Querier is satisfied by pgxpool.Pool, pgx.Conn and pgx.Tx.
type Querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Version returns the applied golang-migrate version. A missing bookkeeping
// table means no migration was ever applied.
func Version(ctx context.Context, db Querier) (int, bool, error) {
	var version int64
	var dirty bool
	err := db.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations LIMIT 1`).Scan(&version, &dirty)
	var pg *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pg) && pg.Code == "42P01") {
		return 0, false, ErrNotMigrated
	}
	return int(version), dirty, err
}

// Check returns nil only when the schema exactly matches this build.
func Check(ctx context.Context, db Querier) error {
	version, dirty, err := Version(ctx, db)
	if err != nil {
		return err
	}
	return Evaluate(version, dirty)
}

func Evaluate(version int, dirty bool) error {
	switch {
	case dirty:
		return ErrDirty
	case version < Required:
		return ErrOutdated
	case version > Required:
		return ErrNewer
	}
	return nil
}

// IsSchemaError reports whether err is one of the schema state errors.
func IsSchemaError(err error) bool {
	return errors.Is(err, ErrNotMigrated) || errors.Is(err, ErrOutdated) || errors.Is(err, ErrDirty) || errors.Is(err, ErrNewer)
}

// Explain turns a Check error into an operator instruction without secrets.
func Explain(err error) string {
	switch {
	case errors.Is(err, ErrNotMigrated):
		return "the database has no CyberGuard tables yet; run scripts/setup.ps1 (or `go run ./cmd/cyberguardctl migrate` from backend/)"
	case errors.Is(err, ErrOutdated):
		return fmt.Sprintf("the database schema is older than this backend (required version %d); run scripts/setup.ps1 (or `go run ./cmd/cyberguardctl migrate` from backend/). Existing data is preserved", Required)
	case errors.Is(err, ErrDirty):
		return "a previous migration stopped half-way; inspect the database before retrying, see docs/local-windows.md"
	case errors.Is(err, ErrNewer):
		return fmt.Sprintf("the database schema is newer than this backend (expected version %d); update the application files", Required)
	}
	return "the database schema could not be inspected; check DATABASE_URL and that PostgreSQL is running"
}
