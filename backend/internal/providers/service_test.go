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
	// Sliding per-minute allowance (default 4) persisted in PostgreSQL.
	for i := 0; i < 4; i++ {
		if ok, err := vt.ReserveLookup(ctx, id); err != nil || !ok {
			t.Fatal("reservation within allowance refused", i, err)
		}
	}
	if ok, err := vt.ReserveLookup(ctx, id); err != nil || ok {
		t.Fatal("per-minute allowance bypassed", err)
	}
	// Entries older than a minute no longer count.
	if _, err := db.Exec(ctx, `UPDATE provider_settings SET lookup_recent=ARRAY[now()-interval '61 seconds',now()-interval '90 seconds',now()-interval '10 seconds']::timestamptz[] WHERE user_id=$1 AND provider='virustotal'`, id); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if ok, err := vt.ReserveLookup(ctx, id); err != nil || !ok {
			t.Fatal("expired entries still counted", i, err)
		}
	}
	if ok, _ := vt.ReserveLookup(ctx, id); ok {
		t.Fatal("window not enforced after expiry")
	}
	// Replacing the credential must not reset the counters.
	if err := vt.Save(ctx, id, "virustotal", "", "vt-replacement", true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := vt.ReserveLookup(ctx, id); ok {
		t.Fatal("credential replacement reset the allowance")
	}
	if err := vt.Save(ctx, id, "virustotal", "", "vt-synthetic", true); err != nil {
		t.Fatal(err)
	}
	// The OpenAI row has no lookup allowance at all.
	if ok, _ := s.ReserveLookup(ctx, uuid.NewString()); ok {
		t.Fatal("reservation for unknown user")
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

func TestKeyNormalizationAndLimits(t *testing.T) {
	if k, e := NormalizeKey("  sk-abc_DEF-123\r\n"); e != nil || k != "sk-abc_DEF-123" {
		t.Fatal(k, e)
	}
	for _, bad := range []string{"sk abc", "sk-\x00abc", "ключ", "a\tb"} {
		if _, e := NormalizeKey(bad); e == nil || e.Error() != "PROVIDER_KEY_MALFORMED" {
			t.Fatalf("%q accepted: %v", bad, e)
		}
	}
	if _, e := NormalizeKey(string(bytes.Repeat([]byte("a"), 5000))); e == nil {
		t.Fatal("oversized key accepted")
	}
	s := Service{}
	if m, d := s.Limits(); m != 4 || d != 500 {
		t.Fatal(m, d)
	}
	s.LookupsPerMinute, s.LookupsPerDay = 240, 20000
	if m, d := s.Limits(); m != 240 || d != 20000 {
		t.Fatal(m, d)
	}
	s.LookupsPerMinute, s.LookupsPerDay = -1, 0
	if m, d := s.Limits(); m != 4 || d != 500 {
		t.Fatal("invalid limits not replaced by defaults")
	}
	// Saving is refused before any database access when encryption is unavailable.
	if e := (&Service{}).Save(context.Background(), "owner", "openai", "model", "key", true); e == nil || e.Error() != "PROVIDER_ENCRYPTION_UNAVAILABLE" {
		t.Fatal(e)
	}
	for want, args := range map[string][3]string{"PROVIDER_UNSUPPORTED": {"other", "m", "k"}, "PROVIDER_MODEL_INVALID": {"openai", "bad model", "k"}, "PROVIDER_KEY_MALFORMED": {"openai", "model", "a b"}} {
		svc := &Service{Master: bytes.Repeat([]byte{1}, 32)}
		if args[0] == "other" {
			svc = svc.For("other")
		}
		if e := svc.Save(context.Background(), "owner", args[0], args[1], args[2], true); e == nil || e.Error() != want {
			t.Fatalf("%s: %v", want, e)
		}
	}
}
