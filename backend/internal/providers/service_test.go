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
	if _, e := s.For("virustotal").Open("alice", b); e == nil {
		t.Fatal("cross-provider decrypt")
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
	vt := s.For("virustotal")
	if err := vt.Save(ctx, id, "virustotal", "", "vt-synthetic", true); err != nil {
		t.Fatal(err)
	}
	vc, vb, err := vt.Read(ctx, id)
	if err != nil || !vc.HasCredential || vc.Provider != "virustotal" {
		t.Fatal(vc, err)
	}
	if key, err := vt.Open(id, vb); err != nil || key != "vt-synthetic" {
		t.Fatal("VT decrypt failed")
	}
	if _, err := s.Open(id, vb); err == nil {
		t.Fatal("provider substitution accepted")
	}
	if ok, err := vt.ReserveLookup(ctx, id); err != nil || !ok {
		t.Fatal("first reservation", err)
	}
	if ok, err := vt.ReserveLookup(ctx, id); err != nil || ok {
		t.Fatal("quota bypass", err)
	}
	if err := vt.Save(ctx, id, "virustotal", "", "", false); err != nil {
		t.Fatal(err)
	}
	vc, vb, err = vt.Read(ctx, id)
	if err != nil || vc.Enabled || !vc.HasCredential {
		t.Fatal("disable lost key", err)
	}
	if key, err := vt.Open(id, vb); err != nil || key != "vt-synthetic" {
		t.Fatal("empty save lost key")
	}
	if other, _, err := vt.Read(ctx, uuid.NewString()); err != nil || other.HasCredential {
		t.Fatal("VT user isolation", err)
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
	if vc, _, err := vt.Read(ctx, id); err != nil || !vc.HasCredential {
		t.Fatal("OpenAI delete affected VT")
	}
	if err := vt.Remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if vc, _, err := vt.Read(ctx, id); err != nil || vc.HasCredential || vc.Enabled {
		t.Fatal("VT delete failed")
	}
}
