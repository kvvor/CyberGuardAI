package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/mockproviders"
	"cyberguard.local/backend/internal/providers"
	"cyberguard.local/backend/internal/testfixtures"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testPassword = "correct horse battery staple"

// testPool connects only to the isolated cyberguard_test database. The tests
// create random accounts and delete nothing but their own rows.
func testPool(t *testing.T, searchPath string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not configured")
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal("invalid test DSN")
	}
	if cfg.ConnConfig.Database != "cyberguard_test" {
		t.Fatal("integration tests require the isolated cyberguard_test database")
	}
	if searchPath != "" {
		cfg.ConnConfig.RuntimeParams["search_path"] = searchPath
	}
	db, e := pgxpool.NewWithConfig(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Close)
	return db
}

type env struct {
	t      *testing.T
	db     *pgxpool.Pool
	server *Server
	ts     *httptest.Server
	openai *mockproviders.OpenAI
	vt     *mockproviders.VirusTotal
	aiURL  string
}

type client struct {
	env   *env
	http  *http.Client
	csrf  string
	email string
}

func newEnv(t *testing.T) *env {
	db := testPool(t, "")
	e := &env{t: t, db: db, openai: &mockproviders.OpenAI{}, vt: &mockproviders.VirusTotal{Known: map[string]map[string]int{}}}
	aiServer := httptest.NewServer(e.openai)
	vtServer := httptest.NewServer(e.vt)
	e.aiURL = aiServer.URL
	t.Cleanup(aiServer.Close)
	t.Cleanup(vtServer.Close)
	settings := &providers.Service{DB: db, Master: bytes.Repeat([]byte{2}, 32), OpenAIBaseURL: aiServer.URL}
	e.server = &Server{Auth: auth.New(db), Origin: "http://localhost:3000", ProviderSettings: settings, VirusTotalBaseURL: vtServer.URL, PublicRegistration: true}
	e.ts = httptest.NewServer(e.server.Router())
	t.Cleanup(e.ts.Close)
	return e
}

// do sends a request with the trusted Origin and returns status and body.
func (c *client) do(method, path string, body any) (int, []byte) {
	c.env.t.Helper()
	var input io.Reader
	contentType := "application/json"
	switch v := body.(type) {
	case nil:
	case *upload:
		input, contentType = &v.body, v.contentType
	default:
		b, _ := json.Marshal(v)
		input = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, c.env.ts.URL+"/api/v1"+path, input)
	r.Header.Set("Origin", c.env.server.Origin)
	r.Header.Set("Content-Type", contentType)
	if c.csrf != "" && method != "GET" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, e := c.http.Do(r)
	if e != nil {
		c.env.t.Fatal(e)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *client) must(want int, method, path string, body any) []byte {
	c.env.t.Helper()
	status, b := c.do(method, path, body)
	if status != want {
		c.env.t.Fatalf("%s %s: got %d want %d: %s", method, path, status, want, b)
	}
	return b
}

func (c *client) object(want int, method, path string, body any) map[string]any {
	c.env.t.Helper()
	var out map[string]any
	if b := c.must(want, method, path, body); len(b) > 0 && json.Unmarshal(b, &out) != nil {
		c.env.t.Fatalf("%s %s: not JSON: %s", method, path, b)
	}
	return out
}

func errorCode(b []byte) string {
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(b, &v)
	return v.Error.Code
}

// user registers through the public endpoint and signs in, like a browser.
func (e *env) user() *client {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &client{env: e, http: &http.Client{Jar: jar}, email: uuid.NewString() + "@example.test"}
	e.t.Cleanup(func() { e.db.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, c.email) })
	// The registration/sign-in limiter is per address; tests share 127.0.0.1.
	e.server.mu.Lock()
	e.server.attempts = nil
	e.server.mu.Unlock()
	c.must(202, "POST", "/auth/register", map[string]string{"email": c.email, "display_name": "Synthetic analyst", "password": testPassword, "confirm_password": testPassword})
	var session auth.Session
	json.Unmarshal(c.must(200, "POST", "/auth/login", map[string]string{"email": c.email, "password": testPassword}), &session)
	if session.CSRF == "" || session.Setup {
		e.t.Fatal("registration did not produce a usable session")
	}
	c.csrf = session.CSRF
	return c
}

type upload struct {
	body        bytes.Buffer
	contentType string
}

func file(name string, data []byte, fields map[string]string) *upload {
	u := &upload{}
	w := multipart.NewWriter(&u.body)
	part, _ := w.CreateFormFile("file", name)
	part.Write(data)
	for k, v := range fields {
		w.WriteField(k, v)
	}
	w.Close()
	u.contentType = w.FormDataContentType()
	return u
}

var bothConsents = map[string]string{"external_processing_consent": "true", "virustotal_consent": "true"}

func mimeMessage(subject, text string, attachments map[string][]byte) []byte {
	var b strings.Builder
	b.WriteString("From: Sender <sender@example.test>\r\nTo: analyst@example.test\r\nSubject: " + subject + "\r\nDate: Tue, 03 Mar 2026 09:15:00 +0000\r\nMessage-ID: <" + uuid.NewString() + "@example.test>\r\nAuthentication-Results: mx.example.test; spf=pass smtp.mailfrom=example.test; dkim=none\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n--fixture\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + text + "\r\n")
	for name, data := range attachments {
		b.WriteString("--fixture\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data) + "\r\n")
	}
	b.WriteString("--fixture--\r\n")
	return []byte(b.String())
}

func (c *client) configure(openaiKey, vtKey string) {
	c.env.t.Helper()
	if openaiKey != "" {
		c.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "mock-assessment-large", "api_key": openaiKey, "enabled": true})
	}
	if vtKey != "" {
		c.must(200, "POST", "/settings/virustotal", map[string]any{"provider": "virustotal", "api_key": vtKey, "enabled": true})
	}
}

// TestProviderSettingsWorkflow covers the Settings page contract end to end:
// save, reload, model selection, connection test, replace, disable and remove
// for both providers, per-user isolation, encryption at rest and every
// documented negative case.
func TestProviderSettingsWorkflow(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(), e.user()

	// Nothing configured yet.
	initial := a.object(200, "GET", "/settings/ai-provider", nil)
	if initial["has_credential"] != false || initial["connection_status"] != "not_configured" {
		t.Fatal(initial)
	}
	if status, body := a.do("POST", "/settings/ai-provider/test", nil); status != 409 || errorCode(body) != "PROVIDER_NOT_CONFIGURED" {
		t.Fatal(status, string(body))
	}
	// Negative input cases return specific 400 codes, never a server error.
	for want, payload := range map[string]map[string]any{
		"PROVIDER_KEY_REQUIRED":  {"provider": "openai", "model": "mock-assessment-large", "api_key": "   ", "enabled": true},
		"PROVIDER_KEY_MALFORMED": {"provider": "openai", "model": "mock-assessment-large", "api_key": "sk-abc def", "enabled": true},
		"PROVIDER_MODEL_INVALID": {"provider": "openai", "model": "not a model!", "api_key": "sk-abc", "enabled": true},
		"PROVIDER_UNSUPPORTED":   {"provider": "virustotal", "model": "x", "api_key": "sk-abc", "enabled": true},
		"INVALID_REQUEST":        {"provider": "openai", "model": "m", "api_key": "k", "enabled": true, "unexpected": 1},
	} {
		if status, body := a.do("POST", "/settings/ai-provider", payload); status != 400 || errorCode(body) != want {
			t.Fatalf("%s: got %d %s", want, status, body)
		}
	}

	// Save: whitespace from copy/paste is removed, the key is never echoed.
	secret := mockproviders.KeyValid
	saved := a.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "mock-assessment-large", "api_key": "  " + secret + "\r\n", "enabled": true})
	if bytes.Contains(saved, []byte(secret)) || !bytes.Contains(saved, []byte(`"has_credential":true`)) {
		t.Fatalf("unexpected save response: %s", saved)
	}
	// "Reload the page": the configuration is read back from PostgreSQL.
	reloaded := a.object(200, "GET", "/settings/ai-provider", nil)
	if reloaded["has_credential"] != true || reloaded["enabled"] != true || reloaded["model"] != "mock-assessment-large" || reloaded["connection_status"] != "untested" {
		t.Fatal(reloaded)
	}
	// Encrypted at rest: neither plaintext nor a reversible encoding is stored.
	var stored []byte
	if err := e.db.QueryRow(context.Background(), `SELECT p.credential FROM provider_settings p JOIN users u ON u.id=p.user_id WHERE u.email=$1 AND p.provider='openai'`, a.email).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) < 28 || bytes.Contains(stored, []byte(secret)) || bytes.Contains(stored, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) {
		t.Fatal("credential is not encrypted at rest")
	}
	// Per-user isolation.
	if other := b.object(200, "GET", "/settings/ai-provider", nil); other["has_credential"] != false || other["model"] != "" {
		t.Fatal("provider settings leaked across users", other)
	}
	if status, _ := b.do("POST", "/settings/ai-provider/test", nil); status != 409 {
		t.Fatal("other user could use the credential")
	}

	// Model list comes live from the provider and excludes non-text models.
	models := a.object(200, "GET", "/settings/ai-provider/models", nil)
	list, _ := models["models"].([]any)
	if models["success"] != true || len(list) != 2 || list[0].(map[string]any)["id"] != "mock-assessment-large" {
		t.Fatal(models)
	}
	// A key that is not saved yet can list models so that the first save
	// already carries a valid model; the candidate key is not stored.
	if status, body := b.do("GET", "/settings/ai-provider/models", nil); status != 409 || errorCode(body) != "PROVIDER_NOT_CONFIGURED" {
		t.Fatal(status, string(body))
	}
	if preview := b.object(200, "POST", "/settings/ai-provider/models", map[string]any{"api_key": mockproviders.KeyValid}); preview["success"] != true || len(preview["models"].([]any)) != 2 {
		t.Fatal(preview)
	}
	if preview := b.object(200, "POST", "/settings/ai-provider/models", map[string]any{"api_key": mockproviders.KeyInvalid}); preview["success"] != false || preview["failure_code"] != "PROVIDER_INVALID_CREDENTIALS" {
		t.Fatal(preview)
	}
	if still := b.object(200, "GET", "/settings/ai-provider", nil); still["has_credential"] != false {
		t.Fatal("candidate key was stored")
	}
	// Connection test: metadata only, no inference.
	result := a.object(200, "POST", "/settings/ai-provider/test", nil)
	if result["success"] != true || result["inference_performed"] != false || e.openai.Responses.Load() != 0 {
		t.Fatal(result)
	}
	if tested := a.object(200, "GET", "/settings/ai-provider", nil); tested["connection_status"] != "credential_validated" || tested["last_success_at"] == nil {
		t.Fatal(tested)
	}
	// Changing only the model keeps the saved key (empty api_key).
	a.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "model-that-does-not-exist", "api_key": "", "enabled": true})
	if result = a.object(200, "POST", "/settings/ai-provider/test", nil); result["success"] != false || result["failure_code"] != "PROVIDER_UNSUPPORTED_MODEL" {
		t.Fatal(result)
	}
	// Replace the key with one the provider rejects.
	a.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "mock-assessment-large", "api_key": mockproviders.KeyInvalid, "enabled": true})
	if result = a.object(200, "POST", "/settings/ai-provider/test", nil); result["success"] != false || result["failure_code"] != "PROVIDER_INVALID_CREDENTIALS" {
		t.Fatal(result)
	}
	if failed := a.object(200, "GET", "/settings/ai-provider", nil); failed["connection_status"] != "PROVIDER_INVALID_CREDENTIALS" {
		t.Fatal(failed)
	}
	if models = a.object(200, "GET", "/settings/ai-provider/models", nil); models["success"] != false || models["failure_code"] != "PROVIDER_INVALID_CREDENTIALS" {
		t.Fatal(models)
	}
	// Disabled: the key is kept but cannot be used.
	a.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "mock-assessment-large", "api_key": mockproviders.KeyValid, "enabled": false})
	if status, body := a.do("POST", "/settings/ai-provider/test", nil); status != 409 || errorCode(body) != "PROVIDER_DISABLED" {
		t.Fatal(status, string(body))
	}
	// Remove.
	a.must(204, "DELETE", "/settings/ai-provider", nil)
	if removed := a.object(200, "GET", "/settings/ai-provider", nil); removed["has_credential"] != false || removed["enabled"] != false {
		t.Fatal(removed)
	}

	// VirusTotal: independent row, own connection test (public empty-file hash).
	vt := a.object(200, "POST", "/settings/virustotal", map[string]any{"provider": "virustotal", "api_key": mockproviders.KeyValid, "enabled": true})
	if vt["has_credential"] != true || vt["lookups_per_minute"] != float64(4) || vt["lookups_per_day"] != float64(500) {
		t.Fatal(vt)
	}
	if result = a.object(200, "POST", "/settings/virustotal/test", nil); result["success"] != true || result["test_type"] != "public_hash_lookup" || e.vt.Calls.Load() != 1 || e.vt.Uploads.Load() != 0 {
		t.Fatal(result, e.vt.Calls.Load())
	}
	// Disable and re-enable without re-entering the key.
	a.must(200, "POST", "/settings/virustotal", map[string]any{"provider": "virustotal", "api_key": "", "enabled": false})
	if state := a.object(200, "GET", "/settings/virustotal", nil); state["enabled"] != false || state["has_credential"] != true {
		t.Fatal(state)
	}
	a.must(200, "POST", "/settings/virustotal", map[string]any{"provider": "virustotal", "api_key": mockproviders.KeyInvalid, "enabled": true})
	if result = a.object(200, "POST", "/settings/virustotal/test", nil); result["success"] != false || result["failure_code"] != "authentication_failed" {
		t.Fatal(result)
	}
	a.must(200, "POST", "/settings/virustotal", map[string]any{"provider": "virustotal", "api_key": mockproviders.KeyRateLimited, "enabled": true})
	if result = a.object(200, "POST", "/settings/virustotal/test", nil); result["failure_code"] != "rate_limited" {
		t.Fatal(result)
	}
	if other := b.object(200, "GET", "/settings/virustotal", nil); other["has_credential"] != false {
		t.Fatal("VirusTotal settings leaked across users")
	}
	a.must(204, "DELETE", "/settings/virustotal", nil)
	if status, body := a.do("POST", "/settings/virustotal/test", nil); status != 409 || errorCode(body) != "PROVIDER_NOT_CONFIGURED" {
		t.Fatal(status, string(body))
	}

	// Session and request integrity.
	valid := a.csrf
	a.csrf = "forged"
	if status, body := a.do("POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "m", "api_key": "k", "enabled": true}); status != 403 || errorCode(body) != "CSRF_INVALID" {
		t.Fatal(status, string(body))
	}
	a.csrf = valid
	request, _ := http.NewRequest("POST", e.ts.URL+"/api/v1/settings/ai-provider", strings.NewReader(`{}`))
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("X-CSRF-Token", valid)
	if resp, err := a.http.Do(request); err != nil || resp.StatusCode != 403 {
		t.Fatal("foreign origin accepted")
	}
	// Unsupported methods and unknown routes answer in the JSON error format.
	if status, body := a.do("PUT", "/settings/ai-provider", nil); (status != 405 && status != 404) || errorCode(body) == "" || errorCode(body) == "INTERNAL_ERROR" {
		t.Fatal(status, string(body))
	}
	if status, body := a.do("GET", "/settings/unknown", nil); status != 404 || errorCode(body) != "ROUTE_NOT_FOUND" {
		t.Fatal(status, string(body))
	}
	a.must(204, "POST", "/auth/logout", nil)
	if status, body := a.do("GET", "/settings/ai-provider", nil); status != 401 || errorCode(body) != "UNAUTHENTICATED" {
		t.Fatal("expired session accepted", status, string(body))
	}
}

// TestMissingMasterKeyIsReported: saving must fail with a specific code, not a
// generic server error, when PROVIDER_MASTER_KEY is absent or malformed.
func TestMissingMasterKeyIsReported(t *testing.T) {
	e := newEnv(t)
	e.server.ProviderSettings.Master = nil
	a := e.user()
	status, body := a.do("POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "mock-assessment-large", "api_key": "sk-abc", "enabled": true})
	if status != 503 || errorCode(body) != "PROVIDER_ENCRYPTION_UNAVAILABLE" {
		t.Fatal(status, string(body))
	}
	var rows int
	e.db.QueryRow(context.Background(), `SELECT count(*) FROM provider_settings p JOIN users u ON u.id=p.user_id WHERE u.email=$1`, a.email).Scan(&rows)
	if rows != 0 {
		t.Fatal("a row was written without encryption")
	}
}

// TestOutdatedSchemaIsReportedNotInternalError reproduces the reported defect:
// the backend was healthy but the application database was still at migration
// 000002, so saving a provider key failed inside PostgreSQL and the user saw
// "The server could not complete the request." A throw-away schema inside
// cyberguard_test is migrated only to version 2 and dropped afterwards.
func TestOutdatedSchemaIsReportedNotInternalError(t *testing.T) {
	admin := testPool(t, "")
	ctx := context.Background()
	schema := "cg_legacy_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Skip("test role cannot create a temporary schema: " + err.Error())
	}
	t.Cleanup(func() { admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`) })
	db := testPool(t, schema)
	for _, name := range []string{"000001_initial.up.sql", "000002_providers.up.sql"} {
		sql, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(ctx, string(sql)); err != nil {
			t.Fatal(name, err)
		}
	}
	if _, err := db.Exec(ctx, `CREATE TABLE schema_migrations(version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL); INSERT INTO schema_migrations VALUES (2,false)`); err != nil {
		t.Fatal(err)
	}
	settings := &providers.Service{DB: db, Master: bytes.Repeat([]byte{2}, 32)}
	server := &Server{Auth: auth.New(db), Origin: "http://localhost:3000", ProviderSettings: settings, PublicRegistration: true}
	ts := httptest.NewServer(server.Router())
	defer ts.Close()
	e := &env{t: t, db: db, server: server, ts: ts}
	a := e.user()

	// The page loads (the SELECT works on the old table)...
	a.must(200, "GET", "/settings/ai-provider", nil)
	// ...but saving used to return 500 INTERNAL_ERROR with nothing in the log.
	for _, path := range []string{"/settings/ai-provider", "/settings/virustotal"} {
		provider := "openai"
		if strings.Contains(path, "virustotal") {
			provider = "virustotal"
		}
		status, body := a.do("POST", path, map[string]any{"provider": provider, "model": "mock-assessment-large", "api_key": "sk-abc", "enabled": true})
		if status != 503 || errorCode(body) != "DATABASE_SCHEMA_OUTDATED" {
			t.Fatalf("%s: outdated schema not reported: %d %s", path, status, body)
		}
	}
	// Health no longer reports "ok" for a database the application cannot use.
	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	health, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || errorCode(health) != "DATABASE_SCHEMA_OUTDATED" || !bytes.Contains(health, []byte(`"schema_version":2`)) {
		t.Fatalf("health: %d %s", resp.StatusCode, health)
	}
}

func decodeAnalysis(t *testing.T, b []byte) stored {
	t.Helper()
	var s stored
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("invalid analysis: %v: %s", err, b)
	}
	return s
}

// TestAnalysisPipelineWithMockProviders drives upload -> parse -> hash ->
// VirusTotal -> evidence -> OpenAI -> validation -> PostgreSQL -> reopen ->
// history -> dashboard -> PDF/JSON through the real HTTP API.
func TestAnalysisPipelineWithMockProviders(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(), e.user()
	a.configure(mockproviders.KeyValid, mockproviders.KeyValid)
	var requestSeen map[string]any
	e.openai.Inspect = func(r map[string]any) { requestSeen = r }

	message := mimeMessage("Delivery label", "Open the attached label to reschedule delivery.", map[string][]byte{"label.pdf.exe": mockproviders.MaliciousFixture})
	done := decodeAnalysis(t, a.must(201, "POST", "/analyses", file("delivery.eml", message, bothConsents)))
	if done.Status != "complete" || done.AI == nil || done.AI.Verdict != "phishing" || done.Report.Verdict != "phishing" || done.AIExecution.Status != "completed" || done.AIExecution.Final != "phishing" || done.AIExecution.Model != "mock-assessment-large" {
		t.Fatalf("pipeline did not complete: %+v", done.AIExecution)
	}
	if done.Report.Score != 0 || done.Report.Version != "3.0.0" {
		t.Fatal("legacy score present")
	}
	if len(done.Report.Email.Attachments) != 1 || done.Report.Email.Attachments[0].SHA256 != mockproviders.MaliciousSHA256 {
		t.Fatal("attachment hash", done.Report.Email.Attachments)
	}
	rep := done.Report.AttachmentReputation
	if done.Report.VirusTotalStatus != "completed" || len(rep) != 1 || rep[0].Status != "completed" || rep[0].Statistics["malicious"] != 62 || rep[0].Source != "VirusTotal API v3" || rep[0].LastAnalysis == nil || len(rep[0].Engines) != 1 {
		t.Fatalf("reputation: %+v", rep)
	}
	if e.vt.Calls.Load() != 1 || e.vt.Uploads.Load() != 0 || e.openai.Responses.Load() != 1 {
		t.Fatal("unexpected provider traffic", e.vt.Calls.Load(), e.vt.Uploads.Load(), e.openai.Responses.Load())
	}
	// What the provider received: evidence, the reputation finding, no secrets or bytes.
	input, _ := requestSeen["input"].(string)
	if requestSeen["model"] != "mock-assessment-large" || !strings.Contains(input, "reputation-1") || !strings.Contains(input, "detections_reported") || !strings.Contains(input, "attachment-1") {
		t.Fatal("provider input incomplete")
	}
	for _, leaked := range []string{mockproviders.KeyValid, string(mockproviders.MaliciousFixture), base64.StdEncoding.EncodeToString(mockproviders.MaliciousFixture), a.email} {
		if strings.Contains(input, leaked) {
			t.Fatal("provider input leaks a credential, attachment bytes or the account")
		}
	}
	// Stored assessment: evidence references resolve, backend truth is recorded.
	known := map[string]bool{}
	for _, ev := range done.Report.Evidence {
		known[ev.ID] = true
	}
	if len(done.AI.Supporting) == 0 || done.AI.Attachments != "detections_reported" || done.AI.Authentication.SPF != "reported_pass" || done.AI.Authentication.IndependentlyVerified {
		t.Fatalf("assessment: %+v", done.AI)
	}
	for _, id := range done.AI.Supporting {
		if !known[id] {
			t.Fatal("dangling evidence reference", id)
		}
	}
	// Raw bodies and the header map are not persisted or returned.
	if done.Report.Email.Text != "" || done.Report.Email.HTML != "" || done.Report.Email.Headers != nil {
		t.Fatal("raw content retained")
	}

	// Reopen from PostgreSQL.
	reopened := decodeAnalysis(t, a.must(200, "GET", "/analyses/"+done.ID, nil))
	if reopened.AI == nil || reopened.AI.Verdict != "phishing" || reopened.Report.AttachmentReputation[0].Statistics["malicious"] != 62 || len(reopened.Report.Authentication) != 3 || len(reopened.AI.Findings) == 0 {
		t.Fatal("stored report differs")
	}
	// Exports.
	for _, lang := range []string{"en", "ru", "kk"} {
		pdf := a.must(200, "GET", "/analyses/"+done.ID+"/export?format=pdf&lang="+lang, nil)
		if !bytes.HasPrefix(pdf, []byte("%PDF")) || len(pdf) < 5000 {
			t.Fatal("invalid PDF", lang)
		}
	}
	export := a.must(200, "GET", "/analyses/"+done.ID+"/export?format=json&lang=en", nil)
	var exported struct {
		Export   map[string]any `json:"export"`
		Analysis stored         `json:"analysis"`
	}
	if json.Unmarshal(export, &exported) != nil || exported.Analysis.ID != done.ID || exported.Analysis.AI.Verdict != "phishing" || exported.Export["format_version"] != float64(1) {
		t.Fatalf("JSON export: %s", export[:200])
	}
	for _, secret := range []string{mockproviders.KeyValid, "csrf_token", "password_hash", "cyberguard_session"} {
		if bytes.Contains(bytes.ToLower(export), []byte(strings.ToLower(secret))) {
			t.Fatalf("export contains %q", secret)
		}
	}
	if status, body := a.do("GET", "/analyses/"+done.ID+"/export?format=docx", nil); status != 400 || errorCode(body) != "INVALID_FORMAT" {
		t.Fatal(status)
	}

	// Per-user isolation of analyses.
	for _, path := range []string{"/analyses/" + done.ID, "/analyses/" + done.ID + "/export?format=json", "/analyses/" + done.ID + "/export?format=pdf"} {
		if status, _ := b.do("GET", path, nil); status != 404 {
			t.Fatal("cross-user read", path, status)
		}
	}
	if status, _ := b.do("DELETE", "/analyses/"+done.ID, nil); status != 404 {
		t.Fatal("cross-user delete")
	}
	if status, _ := b.do("POST", "/analyses/"+done.ID+"/virustotal", map[string]any{"virustotal_consent": true}); status != 404 {
		t.Fatal("cross-user recheck")
	}

	// A legitimate message with both providers: unknown hash stays unknown.
	clean := decodeAnalysis(t, a.must(201, "POST", "/analyses", file("report.eml", mimeMessage("Weekly report", "The weekly report is attached.", map[string][]byte{"report.pdf": []byte("%PDF synthetic " + uuid.NewString())}), bothConsents)))
	if clean.AI == nil || clean.AI.Verdict != "legitimate" || clean.Report.AttachmentReputation[0].Status != "not_found" || clean.AI.Attachments != "unknown_to_provider" {
		t.Fatalf("unknown hash handling: %+v %v", clean.Report.AttachmentReputation, clean.AI)
	}

	// Pasted body without headers: nothing is fabricated.
	pasted := decodeAnalysis(t, a.must(201, "POST", "/analyses", map[string]any{"source_type": "paste", "text": "Please review this request.", "external_processing_consent": true}))
	if pasted.AI == nil || pasted.AI.Verdict != "inconclusive" || pasted.Report.Email.Sender != "" || len(pasted.Report.Email.Attachments) != 0 || pasted.Report.VirusTotalStatus != "skipped_no_attachments" {
		t.Fatalf("paste: %+v", pasted.Report.Email)
	}
	for _, auth := range pasted.Report.Authentication {
		if auth.Result != "unavailable" {
			t.Fatal("authentication fabricated for pasted text")
		}
	}
	// Pasted raw source with headers is parsed as an email.
	raw := decodeAnalysis(t, a.must(201, "POST", "/analyses", map[string]any{"source_type": "paste", "text": "From: Raw Sender <raw@example.test>\nSubject: Raw source\nAuthentication-Results: mx.example.test; dmarc=fail\n\nBody of the raw message.", "external_processing_consent": true}))
	if raw.Report.Email.Sender != "Raw Sender <raw@example.test>" || raw.Report.Email.Subject != "Raw source" || raw.AI.Authentication.DMARC != "reported_fail" {
		t.Fatalf("raw paste: %+v", raw.Report.Email)
	}
	// MSG upload.
	msg := decodeAnalysis(t, a.must(201, "POST", "/analyses", file("synthetic.msg", testfixtures.MSG(), bothConsents)))
	if msg.Report.Email.Source != "msg" || msg.AIExecution.Status != "completed" {
		t.Fatalf("msg: %+v", msg.AIExecution)
	}

	// No consent: no provider request at all, and that is what is reported.
	callsAI, callsVT := e.openai.Responses.Load(), e.vt.Calls.Load()
	silent := decodeAnalysis(t, a.must(201, "POST", "/analyses", file("delivery.eml", message, nil)))
	if e.openai.Responses.Load() != callsAI || e.vt.Calls.Load() != callsVT {
		t.Fatal("provider called without consent")
	}
	if silent.Status != "partial" || silent.AI != nil || silent.AIExecution.Status != "not_requested" || silent.AIExecution.Final != "" || silent.Report.VirusTotalStatus != "not_requested" || silent.Report.AttachmentReputation[0].Status != "not_requested" || len(silent.Report.Evidence) == 0 {
		t.Fatalf("no-consent analysis: %+v", silent.AIExecution)
	}

	// Invalid uploads are client errors with specific codes.
	for want, u := range map[string]*upload{"UNSUPPORTED_FORMAT": file("notes.txt", []byte("hello"), nil), "INVALID_EMAIL": file("broken.eml", []byte("no headers here"), nil), "INVALID_MSG": file("broken.msg", []byte("not an OLE file"), nil)} {
		if status, body := a.do("POST", "/analyses", u); status != 400 || errorCode(body) != want {
			t.Fatalf("%s: %d %s", want, status, body)
		}
	}
	if status, body := a.do("POST", "/analyses", map[string]any{"source_type": "demo", "demo_sample_id": "credentials"}); status != 400 {
		t.Fatal("demo submission accepted", status, string(body))
	}
	if status, body := a.do("POST", "/analyses", map[string]any{"source_type": "paste", "text": "   "}); status != 400 || errorCode(body) != "INVALID_REQUEST" {
		t.Fatal(status, string(body))
	}

	// History and dashboard reflect exactly what was stored.
	history := a.object(200, "GET", "/analyses?page_size=50", nil)
	if history["total"] != float64(6) {
		t.Fatal("history total", history["total"])
	}
	for query, want := range map[string]float64{"verdict=phishing": 1, "verdict=legitimate": 2, "verdict=inconclusive": 2, "status=partial": 1, "status=complete": 5, "status=legacy": 0, "search=Weekly": 1, "search=%25": 0} {
		if got := a.object(200, "GET", "/analyses?"+query, nil)["total"]; got != want {
			t.Errorf("history %s: got %v want %v", query, got, want)
		}
	}
	if status, _ := a.do("GET", "/analyses?status=bogus", nil); status != 400 {
		t.Fatal("invalid filter accepted")
	}
	stats := a.object(200, "GET", "/dashboard/stats?period=all", nil)
	if stats["total_analyses"] != float64(6) || stats["completed_count"] != float64(5) || stats["incomplete_count"] != float64(1) || stats["legacy_count"] != float64(0) || stats["phishing_count"] != float64(1) || stats["legitimate_count"] != float64(2) || stats["inconclusive_count"] != float64(2) {
		t.Fatalf("dashboard: %v", stats)
	}
	if severities := stats["severity_distribution"].(map[string]any); severities["high"] != float64(1) || severities["none"] != float64(2) {
		t.Fatalf("severity distribution: %v", severities)
	}
	if other := b.object(200, "GET", "/dashboard/stats?period=all", nil); other["total_analyses"] != float64(0) {
		t.Fatal("dashboard leaked across users")
	}
	a.must(204, "DELETE", "/analyses/"+done.ID, nil)
	if status, _ := a.do("GET", "/analyses/"+done.ID, nil); status != 404 {
		t.Fatal("deleted analysis still readable")
	}
}

// TestProviderFailuresNeverProduceAVerdict: for every failure mode the parsed
// evidence and VirusTotal results are kept, the real state is reported, and
// there is no assessment and no heuristic substitute.
func TestProviderFailuresNeverProduceAVerdict(t *testing.T) {
	e := newEnv(t)
	message := mimeMessage("Delivery label", "Open the attached label.", map[string][]byte{"label.pdf.exe": mockproviders.MaliciousFixture})
	cases := []struct{ key, status, failure string }{
		{mockproviders.KeyInvalid, "authentication_failed", "PROVIDER_INVALID_CREDENTIALS"},
		{mockproviders.KeyQuota, "quota_exceeded", "PROVIDER_INSUFFICIENT_QUOTA"},
		{mockproviders.KeyMalformed, "invalid_response", "PROVIDER_INVALID_OUTPUT"},
		{mockproviders.KeyInvented, "invalid_response", "PROVIDER_INVALID_OUTPUT"},
		{mockproviders.KeyOverclaiming, "invalid_response", "PROVIDER_UNSUPPORTED_CLAIM"},
	}
	for _, tc := range cases {
		a := e.user()
		a.configure(tc.key, mockproviders.KeyValid)
		got := decodeAnalysis(t, a.must(201, "POST", "/analyses", file("delivery.eml", message, bothConsents)))
		if got.AIExecution.Status != tc.status || got.AIExecution.Failure != tc.failure {
			t.Errorf("%s: got %s/%s", tc.key, got.AIExecution.Status, got.AIExecution.Failure)
		}
		if got.AI != nil || got.Status != "partial" || got.AIExecution.Final != "" || got.Report.Score != 0 || got.Report.Verdict != "inconclusive" {
			t.Errorf("%s: a verdict was produced despite the failure", tc.key)
		}
		if len(got.Report.Evidence) == 0 || len(got.Report.AttachmentReputation) != 1 || got.Report.AttachmentReputation[0].Statistics["malicious"] != 62 {
			t.Errorf("%s: evidence or reputation lost", tc.key)
		}
		// The incomplete state survives storage, export and statistics.
		again := decodeAnalysis(t, a.must(200, "GET", "/analyses/"+got.ID, nil))
		if again.AI != nil || again.AIExecution.Failure != tc.failure {
			t.Errorf("%s: failure state not persisted", tc.key)
		}
		if pdf := a.must(200, "GET", "/analyses/"+got.ID+"/export?format=pdf&lang=ru", nil); !bytes.HasPrefix(pdf, []byte("%PDF")) {
			t.Errorf("%s: PDF of incomplete analysis", tc.key)
		}
		stats := a.object(200, "GET", "/dashboard/stats?period=all", nil)
		if stats["incomplete_count"] != float64(1) || stats["inconclusive_count"] != float64(0) || stats["phishing_count"] != float64(0) {
			t.Errorf("%s: incomplete analysis counted as a verdict: %v", tc.key, stats)
		}
		if a.object(200, "GET", "/analyses?verdict=inconclusive", nil)["total"] != float64(0) {
			t.Errorf("%s: incomplete analysis matched a verdict filter", tc.key)
		}
	}

	// OpenAI not configured, or configured but disabled.
	a := e.user()
	got := decodeAnalysis(t, a.must(201, "POST", "/analyses", map[string]any{"source_type": "paste", "text": "Hello there", "external_processing_consent": true}))
	if got.AIExecution.Status != "not_configured" || got.AIExecution.Failure != "PROVIDER_NOT_CONFIGURED" || got.AI != nil {
		t.Fatalf("%+v", got.AIExecution)
	}
	a.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "mock-assessment-large", "api_key": mockproviders.KeyValid, "enabled": false})
	got = decodeAnalysis(t, a.must(201, "POST", "/analyses", map[string]any{"source_type": "paste", "text": "Hello there", "external_processing_consent": true}))
	if got.AIExecution.Status != "not_configured" || got.AIExecution.Failure != "PROVIDER_DISABLED" {
		t.Fatalf("%+v", got.AIExecution)
	}
	// Unsupported model selected in Settings.
	a.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "retired-model", "api_key": "", "enabled": true})
	got = decodeAnalysis(t, a.must(201, "POST", "/analyses", map[string]any{"source_type": "paste", "text": "Hello there", "external_processing_consent": true}))
	if got.AIExecution.Status != "unsupported_model" || got.AIExecution.Model != "retired-model" {
		t.Fatalf("%+v", got.AIExecution)
	}
	// Provider unreachable.
	e.server.ProviderSettings.OpenAIBaseURL = "http://127.0.0.1:1"
	a.must(200, "POST", "/settings/ai-provider", map[string]any{"provider": "openai", "model": "mock-assessment-large", "api_key": "", "enabled": true})
	got = decodeAnalysis(t, a.must(201, "POST", "/analyses", map[string]any{"source_type": "paste", "text": "Hello there", "external_processing_consent": true}))
	if got.AIExecution.Status != "network_error" || got.AI != nil {
		t.Fatalf("%+v", got.AIExecution)
	}
	if result := a.object(200, "POST", "/settings/ai-provider/test", nil); result["failure_code"] != "PROVIDER_NETWORK_FAILURE" {
		t.Fatal(result)
	}

	// VirusTotal failures do not block the assessment and are never "clean".
	e.server.ProviderSettings.OpenAIBaseURL = e.aiURL
	for key, want := range map[string]string{mockproviders.KeyInvalid: "authentication_failed", mockproviders.KeyRateLimited: "rate_limited", mockproviders.KeyServerError: "provider_error"} {
		u := e.user()
		u.configure(mockproviders.KeyValid, key)
		got := decodeAnalysis(t, u.must(201, "POST", "/analyses", file("report.eml", mimeMessage("Report", "See attachment.", map[string][]byte{"report.pdf": []byte("%PDF x")}), bothConsents)))
		if got.Report.VirusTotalStatus != want || got.Report.AttachmentReputation[0].Status != want || got.Report.AttachmentReputation[0].Statistics != nil {
			t.Errorf("VirusTotal %s: %s %+v", key, got.Report.VirusTotalStatus, got.Report.AttachmentReputation)
		}
		if got.AI == nil || got.AI.Attachments != "lookup_incomplete" {
			t.Errorf("VirusTotal %s: assessment should run with an explicit incomplete lookup", key)
		}
	}
	// VirusTotal consent given but provider not configured.
	u := e.user()
	u.configure(mockproviders.KeyValid, "")
	got = decodeAnalysis(t, u.must(201, "POST", "/analyses", file("report.eml", mimeMessage("Report", "See attachment.", map[string][]byte{"report.pdf": []byte("%PDF y")}), bothConsents)))
	if got.Report.VirusTotalStatus != "not_configured" || got.AI.Attachments != "not_checked" {
		t.Fatalf("%s %s", got.Report.VirusTotalStatus, got.AI.Attachments)
	}
}

// TestVirusTotalBatchesQuotaAndRecheck: duplicate hashes are requested once,
// the per-minute allowance is respected, deferred hashes are labelled as such
// and can be completed later without repeating answered lookups.
func TestVirusTotalBatchesQuotaAndRecheck(t *testing.T) {
	e := newEnv(t)
	a := e.user()
	a.configure(mockproviders.KeyValid, mockproviders.KeyValid)
	attachments := map[string][]byte{"copy-1.bin": []byte("same content"), "copy-2.bin": []byte("same content")}
	for i := 0; i < 5; i++ {
		attachments[fmt.Sprintf("file-%d.bin", i)] = []byte(fmt.Sprintf("distinct content %d", i))
	}
	got := decodeAnalysis(t, a.must(201, "POST", "/analyses", file("batch.eml", mimeMessage("Batch", "Seven attachments, six distinct.", attachments), bothConsents)))
	answered, deferred := 0, 0
	seen := map[string]string{}
	for _, v := range got.Report.AttachmentReputation {
		if previous, ok := seen[v.SHA256]; ok && previous != v.Status {
			t.Fatal("duplicate hash has inconsistent results")
		}
		seen[v.SHA256] = v.Status
	}
	for _, status := range seen {
		switch status {
		case "not_found":
			answered++
		case "deferred_local_limit":
			deferred++
		default:
			t.Fatal("unexpected status", status)
		}
	}
	if len(got.Report.AttachmentReputation) != 7 || len(seen) != 6 || answered != 4 || deferred != 2 || e.vt.Calls.Load() != 4 || got.Report.VirusTotalStatus != "partial" {
		t.Fatalf("answered=%d deferred=%d calls=%d status=%s", answered, deferred, e.vt.Calls.Load(), got.Report.VirusTotalStatus)
	}
	if got.AI == nil || got.AI.Attachments != "lookup_incomplete" {
		t.Fatal("assessment must state that the lookup is incomplete")
	}
	// Still inside the same minute: nothing more is sent.
	if status, body := a.do("POST", "/analyses/"+got.ID+"/virustotal", map[string]any{"virustotal_consent": false}); status != 400 || errorCode(body) != "VIRUSTOTAL_CONSENT_REQUIRED" {
		t.Fatal(status, string(body))
	}
	still := decodeAnalysis(t, a.must(200, "POST", "/analyses/"+got.ID+"/virustotal", map[string]any{"virustotal_consent": true}))
	if e.vt.Calls.Load() != 4 || still.Report.VirusTotalStatus != "partial" {
		t.Fatal("local allowance bypassed", e.vt.Calls.Load())
	}
	// A later minute (simulated by clearing this user's window in the test database).
	if _, err := e.db.Exec(context.Background(), `UPDATE provider_settings p SET lookup_recent='{}' FROM users u WHERE u.id=p.user_id AND u.email=$1`, a.email); err != nil {
		t.Fatal(err)
	}
	complete := decodeAnalysis(t, a.must(200, "POST", "/analyses/"+got.ID+"/virustotal", map[string]any{"virustotal_consent": true}))
	if e.vt.Calls.Load() != 6 || complete.Report.VirusTotalStatus != "completed" {
		t.Fatalf("recheck: calls=%d status=%s", e.vt.Calls.Load(), complete.Report.VirusTotalStatus)
	}
	for _, v := range complete.Report.AttachmentReputation {
		if v.Status != "not_found" {
			t.Fatal("recheck result missing", v)
		}
	}
	// The earlier verdict is kept but visibly marked as predating the update.
	if complete.AI == nil || !strings.Contains(strings.Join(complete.Report.Limitations, ","), "REPUTATION_UPDATED_AFTER_ASSESSMENT") {
		t.Fatal("verdict not marked as predating the reputation update")
	}
	stored := decodeAnalysis(t, a.must(200, "GET", "/analyses/"+got.ID, nil))
	if stored.Report.VirusTotalStatus != "completed" {
		t.Fatal("recheck not persisted")
	}
	if status, body := a.do("POST", "/analyses/"+got.ID+"/virustotal", map[string]any{"virustotal_consent": true}); status != 409 || errorCode(body) != "NOTHING_TO_RECHECK" {
		t.Fatal(status, string(body))
	}
	// Daily allowance.
	e.server.ProviderSettings.LookupsPerDay = 6
	e.db.Exec(context.Background(), `UPDATE provider_settings p SET lookup_recent='{}' FROM users u WHERE u.id=p.user_id AND u.email=$1`, a.email)
	if result := a.object(200, "POST", "/settings/virustotal/test", nil); result["success"] != false || result["failure_code"] != "deferred_local_limit" || e.vt.Calls.Load() != 6 {
		t.Fatal("daily allowance bypassed", result)
	}
}

// TestLegacyReportsStayReadable: reports written by the retired weighted-score
// detector open, export and count separately; their obsolete attack-framework
// metadata is never returned.
func TestLegacyReportsStayReadable(t *testing.T) {
	e := newEnv(t)
	a := e.user()
	id := uuid.NewString()
	legacy := `{"id":"` + id + `","mode":"live","status":"partial","created_at":"2026-01-10T10:00:00Z","ai_execution":{"status":"not_requested","final_verdict":"phishing","influence_code":"STATIC_ONLY"},"top_findings":[],"explanations":{"en":"old"},"recommendations":{"en":"old"},"report":{"verdict":"phishing","risk_score":85,"risk_level":"high","scoring_version":"2.0.0","attack_types":["credential_phishing"],"mitre_mappings":[{"technique_id":"T1566.002","name":"Spearphishing Link"}],"indicators":[{"id":"e1","rule_id":"URGENCY","type":"static","severity":"medium","evidence":"Urgent","evidence_source":"body","description_code":"URGENCY","analysis_method":"deterministic","status":"observed"}],"iocs":[{"type":"url","value":"https://192.0.2.1/login","normalized_value":"https://192.0.2.1/login","defanged_value":"hxxps://192[.]0[.]2[.]1/login","source":"body"}],"limitations":["HEURISTIC_NOT_PROBABILITY"],"manual_review_required":true,"email":{"source_type":"paste","subject":"Old report","sender":"old@example.test","attachments":[],"parser_warnings":[]},"ai_status":"not_requested"}}`
	if _, err := e.db.Exec(context.Background(), `INSERT INTO analyses(id,user_id,mode,status,verdict,risk_score,risk_level,subject,sender,scoring_version,report,created_at) SELECT $1,u.id,'live','partial','phishing',85,'high','Old report','old@example.test','2.0.0',$2::jsonb,now() FROM users u WHERE u.email=$3`, id, legacy, a.email); err != nil {
		t.Fatal(err)
	}
	detail := a.must(200, "GET", "/analyses/"+id, nil)
	old := decodeAnalysis(t, detail)
	if old.Report.Score != 85 || old.Report.Version != "2.0.0" || old.Report.Email.Subject != "Old report" {
		t.Fatal("legacy report not readable")
	}
	export := a.must(200, "GET", "/analyses/"+id+"/export?format=json", nil)
	list := a.must(200, "GET", "/analyses", nil)
	for name, body := range map[string][]byte{"detail": detail, "export": export, "history": list} {
		if bytes.Contains(bytes.ToLower(body), []byte("mitre")) || bytes.Contains(body, []byte("T1566")) {
			t.Fatalf("%s still returns attack-framework metadata", name)
		}
	}
	for _, lang := range []string{"en", "ru", "kk"} {
		if pdf := a.must(200, "GET", "/analyses/"+id+"/export?format=pdf&lang="+lang, nil); !bytes.HasPrefix(pdf, []byte("%PDF")) {
			t.Fatal("legacy PDF")
		}
	}
	// A historical score never enters the current verdict statistics.
	stats := a.object(200, "GET", "/dashboard/stats?period=all", nil)
	if stats["legacy_count"] != float64(1) || stats["phishing_count"] != float64(0) || stats["completed_count"] != float64(0) || stats["total_analyses"] != float64(1) {
		t.Fatalf("legacy report distorts statistics: %v", stats)
	}
	if a.object(200, "GET", "/analyses?status=legacy", nil)["total"] != float64(1) {
		t.Fatal("legacy filter")
	}
	if status, body := a.do("POST", "/analyses/"+id+"/virustotal", map[string]any{"virustotal_consent": true}); status != 409 || errorCode(body) != "RECHECK_NOT_SUPPORTED" {
		t.Fatal(status, string(body))
	}
	// The data itself is untouched in storage.
	var kept bool
	e.db.QueryRow(context.Background(), `SELECT report->'report' ? 'mitre_mappings' FROM analyses WHERE id=$1`, id).Scan(&kept)
	if !kept {
		t.Fatal("historical data was modified")
	}
}

// TestAuthenticationFlow covers sign-in, session persistence, password change
// and sign-out against PostgreSQL.
func TestAuthenticationFlow(t *testing.T) {
	e := newEnv(t)
	a := e.user()
	me := a.object(200, "GET", "/auth/me", nil)
	if me["csrf_token"] != a.csrf || me["user"].(map[string]any)["email"] != a.email {
		t.Fatal("session not persistent", me)
	}
	if status, body := a.do("POST", "/auth/login", map[string]string{"email": a.email, "password": "wrong password value"}); status != 401 || errorCode(body) != "INVALID_CREDENTIALS" {
		t.Fatal(status, string(body))
	}
	a.must(204, "POST", "/auth/change-password", map[string]string{"current_password": testPassword, "new_password": "another strong test passphrase", "confirm_password": "another strong test passphrase"})
	if status, _ := a.do("GET", "/auth/me", nil); status != 401 {
		t.Fatal("old session survived a password change")
	}
	var session auth.Session
	json.Unmarshal(a.must(200, "POST", "/auth/login", map[string]string{"email": a.email, "password": "another strong test passphrase"}), &session)
	a.csrf = session.CSRF
	a.must(204, "POST", "/auth/logout", nil)
	if status, _ := a.do("GET", "/analyses", nil); status != 401 {
		t.Fatal("signed-out session accepted")
	}
	// Registration can be disabled by configuration.
	e.server.PublicRegistration = false
	if status, body := a.do("POST", "/auth/register", map[string]string{"email": uuid.NewString() + "@example.test", "display_name": "x", "password": testPassword, "confirm_password": testPassword}); status != 403 || errorCode(body) != "REGISTRATION_DISABLED" {
		t.Fatal(status, string(body))
	}
}
