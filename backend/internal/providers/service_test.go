package providers

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
)

func TestEncryption(t *testing.T) {
	s := Service{Master: bytes.Repeat([]byte{7}, 32)}
	b, e := s.Seal("alice", "synthetic-key")
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte("synthetic-key")) {
		t.Fatal("plaintext")
	}
	if _, e = s.Open("bob", b); e == nil {
		t.Fatal("cross-user decrypt")
	}
	p, e := s.Open("alice", b)
	if e != nil || p != "synthetic-key" {
		t.Fatal(e)
	}
	b[len(b)-1] ^= 1
	if _, e = s.Open("alice", b); e == nil {
		t.Fatal("tamper accepted")
	}
}
func TestSettingsPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("test database not configured")
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil || cfg.ConnConfig.Database != "cyberguard_test" {
		t.Fatal("isolated database required")
	}
	ctx := context.Background()
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	id := uuid.NewString()
	_, e = db.Exec(ctx, `INSERT INTO users(id,email,display_name,account_status) VALUES($1,$2,'test','pending_activation')`, id, id+"@example.test")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	s := Service{DB: db, Master: bytes.Repeat([]byte{1}, 32), FallbackEnabled: true, FallbackKey: "operator-key", FallbackModel: "operator-model"}
	if e = s.Save(ctx, id, "openai", "test-model", "synthetic-key", true); e != nil {
		t.Fatal(e)
	}
	c, b, e := s.Read(ctx, id)
	if e != nil || c.Status != "untested" || !c.HasCredential || bytes.Contains(b, []byte("synthetic-key")) {
		t.Fatal(c, e)
	}
	_, client, e := s.Resolve(ctx, id)
	if e != nil || client.Key != "synthetic-key" {
		t.Fatal(e)
	}
	other, _, e := s.Read(ctx, uuid.NewString())
	if e != nil || other.Source != "operator" || other.Model == c.Model {
		t.Fatal("isolation")
	}
	if e = s.Remove(ctx, id); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Resolve(ctx, id); e == nil {
		t.Fatal("removed credential fell back to operator")
	}
}
