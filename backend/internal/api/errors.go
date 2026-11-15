package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"cyberguard.local/backend/internal/dbschema"
	"github.com/jackc/pgx/v5/pgconn"
)

// classify maps an unexpected storage error to a stable client code. An
// outdated schema and an unreachable database are operator problems with a
// specific fix, so they must not hide behind INTERNAL_ERROR.
func classify(err error) (int, string) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		// Undefined table/column/function and ON CONFLICT without a matching
		// constraint all mean "migrations were not applied to this database".
		case "42P01", "42703", "42P10", "42883":
			return http.StatusServiceUnavailable, "DATABASE_SCHEMA_OUTDATED"
		case "23514":
			// The pre-000003 CHECK(provider='openai') rejects VirusTotal rows.
			if pg.TableName == "provider_settings" {
				return http.StatusServiceUnavailable, "DATABASE_SCHEMA_OUTDATED"
			}
		}
		if len(pg.Code) >= 2 && (pg.Code[:2] == "08" || pg.Code[:2] == "53" || pg.Code[:2] == "57") {
			return http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE"
		}
		return http.StatusInternalServerError, "INTERNAL_ERROR"
	}
	if dbschema.IsSchemaError(err) {
		return http.StatusServiceUnavailable, "DATABASE_SCHEMA_OUTDATED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "REQUEST_TIMEOUT"
	}
	var netErr net.Error
	var connErr *pgconn.ConnectError
	if errors.As(err, &connErr) || errors.As(err, &netErr) {
		return http.StatusServiceUnavailable, "DATABASE_UNAVAILABLE"
	}
	return http.StatusInternalServerError, "INTERNAL_ERROR"
}

// internal logs the cause server-side and returns a classified error. Only the
// SQLSTATE and server message are logged: PostgreSQL DETAIL can echo row values.
func internal(w http.ResponseWriter, r *http.Request, operation string, err error) {
	status, code := classify(err)
	attrs := []any{"operation", operation, "code", code, "request_id", w.Header().Get("X-Request-ID"), "method", r.Method, "path", r.URL.Path}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		attrs = append(attrs, "sqlstate", pg.Code, "error", pg.Message)
	} else if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	if r.Context().Err() != nil && errors.Is(err, context.Canceled) {
		slog.Info("request cancelled by client", attrs...)
	} else {
		slog.Error("request failed", attrs...)
	}
	fail(w, r, status, code)
}
