package auth

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"sync"
	"testing"
	"time"
)

// TEST_DATABASE_URL must point to an isolated, migrated PostgreSQL test database.
func TestActivationLifecyclePostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; PostgreSQL integration deferred")
	}
	ctx := context.Background()
	cfg, parseErr := pgxpool.ParseConfig(dsn)
	if parseErr != nil || cfg.ConnConfig.Database != "cyberguard_test" {
		t.Fatal("integration tests require isolated cyberguard_test database")
	}
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := New(db)
	email := uuid.NewString() + "@example.test"
	defer db.Exec(ctx, `DELETE FROM users WHERE email=$1`, email)
	pw, e := s.Provision(ctx, email, "Test analyst", "create")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var sessions []Session
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.Login(ctx, email, pw)
			if e == nil {
				mu.Lock()
				sessions = append(sessions, v)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(sessions) != 1 || !sessions[0].Setup {
		t.Fatalf("temporary password redeemed %d times", len(sessions))
	}
	setup := sessions[0]
	if !s.CSRF(ctx, setup.Token, setup.CSRF) || s.CSRF(ctx, setup.Token, "wrong") {
		t.Fatal("csrf")
	}
	regular, e := s.Password(ctx, setup, "", "correct horse battery staple", true)
	if e != nil || regular.Setup || regular.Token == setup.Token {
		t.Fatal("activation", e)
	}
	if _, e = s.Resolve(ctx, setup.Token); e == nil {
		t.Fatal("setup session survived")
	}
	if _, e = s.Login(ctx, email, pw); e == nil {
		t.Fatal("temporary password reused")
	}
	if _, e = s.Login(ctx, email, "incorrect"); e == nil {
		t.Fatal("bad password accepted")
	}
	if _, e = s.Password(ctx, regular, "correct horse battery staple", "another long secure passphrase", false); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Resolve(ctx, regular.Token); e == nil {
		t.Fatal("session survived password change")
	}
	v, e := s.Login(ctx, email, "another long secure passphrase")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Logout(ctx, v.Token); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Resolve(ctx, v.Token); e == nil {
		t.Fatal("logout failed")
	}
	pw, e = s.Provision(ctx, email, "", "reset-password")
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(ctx, `UPDATE users SET temporary_password_expires_at=$2 WHERE email=$1`, email, time.Now().Add(-time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Login(ctx, email, pw); e == nil {
		t.Fatal("expired credential accepted")
	}
	pw, e = s.Provision(ctx, email, "", "reset-password")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Provision(ctx, email, "", "disable"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Login(ctx, email, pw); e == nil {
		t.Fatal("disabled account accepted")
	}
}
