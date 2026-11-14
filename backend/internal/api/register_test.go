package api

import (
	"bytes"
	"context"
	"cyberguard.local/backend/internal/auth"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestRegisterGuards(t *testing.T) {
	s := &Server{Origin: "http://localhost:3000"}
	h := s.Router()
	for _, tc := range []struct {
		origin string
		status int
	}{{s.Origin, 403}, {"https://evil.example", 403}} {
		r := httptest.NewRequest("POST", "/api/v1/auth/register", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(w.Code)
		}
	}
	s.PublicRegistration = true
	for i := 0; i < 11; i++ {
		r := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader("{}"))
		r.Header.Set("Origin", s.Origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 415
		if i == 10 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
}
func TestRegisterPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not configured")
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil || cfg.ConnConfig.Database != "cyberguard_test" {
		t.Fatal("isolated cyberguard_test required")
	}
	ctx := context.Background()
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	svc := auth.New(db)
	s := &Server{Auth: svc, Origin: "http://localhost:3000", PublicRegistration: true}
	handler := s.Router()
	email := uuid.NewString() + "@example.test"
	defer db.Exec(ctx, `DELETE FROM users WHERE email=$1`, email)
	pw := "Registration test passphrase"
	input := func() map[string]string {
		return map[string]string{"email": email, "display_name": " Analyst ", "password": pw, "confirm_password": pw}
	}
	call := func(body map[string]string) (int, string) {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(b))
		r.Header.Set("Origin", s.Origin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	for _, field := range []string{"email", "display_name", "password", "confirm_password"} {
		b := input()
		b[field] = ""
		if code, _ := call(b); code != 400 {
			t.Fatalf("invalid %s: %d", field, code)
		}
	}
	b := input()
	b["email"] = " " + strings.ToUpper(email) + " "
	code, body := call(b)
	if code != 202 {
		t.Fatal(code, body)
	}
	v, e := svc.Login(ctx, email, pw)
	if e != nil || v.Setup || v.User.Name != "Analyst" {
		t.Fatal("registered account cannot log in", e)
	}
	duplicate := input()
	duplicate["password"] = "Different valid passphrase"
	duplicate["confirm_password"] = duplicate["password"]
	code, duplicateBody := call(duplicate)
	if code != 202 || body != duplicateBody {
		t.Fatal("duplicate disclosed")
	}
	if _, e = svc.Login(ctx, email, pw); e != nil {
		t.Fatal("duplicate changed password")
	}
	concurrent := uuid.NewString() + "@example.test"
	defer db.Exec(ctx, `DELETE FROM users WHERE email=$1`, concurrent)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- svc.Register(ctx, concurrent, "Analyst", pw, pw) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e = db.QueryRow(ctx, `SELECT count(*) FROM users WHERE email=$1`, concurrent).Scan(&count); e != nil || count != 1 {
		t.Fatal("uniqueness failed", count, e)
	}
}
