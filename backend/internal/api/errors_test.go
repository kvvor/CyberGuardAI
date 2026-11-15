package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberguard.local/backend/internal/dbschema"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestClassifyStorageErrors(t *testing.T) {
	cases := map[string]error{
		// The reproduced Settings failure: ON CONFLICT(user_id,provider) against migration 000002.
		"DATABASE_SCHEMA_OUTDATED": &pgconn.PgError{Code: "42P10", Message: "there is no unique or exclusion constraint matching the ON CONFLICT specification"},
		"DATABASE_UNAVAILABLE":     &pgconn.PgError{Code: "57P01", Message: "terminating connection"},
		"REQUEST_TIMEOUT":          context.DeadlineExceeded,
		"INTERNAL_ERROR":           errors.New("unexpected"),
	}
	for want, err := range cases {
		if _, got := classify(err); got != want {
			t.Fatalf("%v: got %s want %s", err, got, want)
		}
	}
	for _, code := range []string{"42P01", "42703"} {
		if _, got := classify(&pgconn.PgError{Code: code}); got != "DATABASE_SCHEMA_OUTDATED" {
			t.Fatalf("%s not treated as outdated schema", code)
		}
	}
	if _, got := classify(&pgconn.PgError{Code: "23514", TableName: "provider_settings"}); got != "DATABASE_SCHEMA_OUTDATED" {
		t.Fatal("old provider CHECK not recognised")
	}
	if _, got := classify(dbschema.ErrOutdated); got != "DATABASE_SCHEMA_OUTDATED" {
		t.Fatal("schema check error not recognised")
	}
}

func TestInternalNeverEchoesRowDetail(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/settings/ai-provider", nil)
	internal(w, r, "test", &pgconn.PgError{Code: "23505", Message: "duplicate", Detail: "Failing row contains (secret-value)"})
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret-value") || !strings.Contains(w.Body.String(), "INTERNAL_ERROR") {
		t.Fatalf("unexpected response %d %s", w.Code, w.Body.String())
	}
}
