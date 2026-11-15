package api

import (
	"bytes"
	"context"
	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/detection"
	ai "cyberguard.local/backend/internal/openai"
	"cyberguard.local/backend/internal/providers"
	"cyberguard.local/backend/internal/testfixtures"
	"cyberguard.local/backend/internal/virustotal"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPostgresHTTPWorkflow(t *testing.T) {
	t.Setenv("PROVIDER_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not configured")
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal("invalid test DSN")
	}
	if cfg.ConnConfig.Database != "cyberguard_test" {
		t.Fatal("integration tests require cyberguard_test")
	}
	db, e := pgxpool.NewWithConfig(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Close)
	svc := auth.New(db)
	s := &Server{Auth: svc, Origin: "http://localhost:3000"}
	ts := httptest.NewServer(s.Router())
	defer ts.Close()
	request := func(c *http.Client, method, path, csrf string, body any, want int) []byte {
		t.Helper()
		var input io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			input = bytes.NewReader(b)
		}
		r, _ := http.NewRequest(method, ts.URL+"/api/v1"+path, input)
		r.Header.Set("Origin", s.Origin)
		r.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		resp, e := c.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, resp.StatusCode, want, b)
		}
		return b
	}
	makeUser := func() (*http.Client, string, string) {
		email := uuid.NewString() + "@example.test"
		pw, e := svc.Provision(context.Background(), email, "Synthetic analyst", "create")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { db.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, email) })
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		b := request(c, "POST", "/auth/login", "", map[string]string{"email": email, "password": pw}, 200)
		var setup auth.Session
		json.Unmarshal(b, &setup)
		if !setup.Setup {
			t.Fatal("missing setup restriction")
		}
		request(c, "GET", "/analyses", "", nil, 403)
		request(c, "POST", "/auth/activate-account", "wrong", map[string]string{"new_password": "correct horse battery staple", "confirm_password": "correct horse battery staple"}, 403)
		b = request(c, "POST", "/auth/activate-account", setup.CSRF, map[string]string{"new_password": "correct horse battery staple", "confirm_password": "correct horse battery staple"}, 200)
		var regular auth.Session
		json.Unmarshal(b, &regular)
		if regular.Setup || regular.CSRF == setup.CSRF {
			t.Fatal("activation did not rotate")
		}
		return c, regular.CSRF, email
	}
	a, csrf, email := makeUser()
	b, csrfB, _ := makeUser()
	settings := request(a, "POST", "/settings/ai-provider", csrf, map[string]any{"provider": "openai", "model": "test-model", "api_key": "synthetic-key-never-live", "enabled": true}, 200)
	if bytes.Contains(settings, []byte("synthetic-key-never-live")) {
		t.Fatal("credential exposed")
	}
	settings = request(b, "GET", "/settings/ai-provider", "", nil, 200)
	if bytes.Contains(settings, []byte("test-model")) {
		t.Fatal("provider isolation failed")
	}
	request(a, "DELETE", "/settings/ai-provider", csrf, nil, 204)
	for name, data := range map[string][]byte{"synthetic.eml": []byte("From: test@example.test\r\nSubject: Synthetic phishing\r\n\r\nUrgent: verify your password at https://192.0.2.1/login"), "synthetic.msg": testfixtures.MSG()} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		part, e := writer.CreateFormFile("file", name)
		if e != nil {
			t.Fatal(e)
		}
		part.Write(data)
		writer.Close()
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/analyses", &body)
		req.Header.Set("Origin", s.Origin)
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		resp, e := a.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Fatalf("upload %s: %d %s", name, resp.StatusCode, raw)
		}
		var uploaded stored
		json.Unmarshal(raw, &uploaded)
		request(a, "DELETE", "/analyses/"+uploaded.ID, csrf, nil, 204)
	}
	// Complete HTTP + PostgreSQL flow with isolated, mocked provider transports.
	vtCalls, aiCalls := 0, 0
	vtMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vtCalls++
		hash := strings.TrimPrefix(r.URL.Path, "/files/")
		if r.Method != "GET" || r.ContentLength > 0 || r.Header.Get("x-apikey") != "vt-synthetic" {
			t.Error("unexpected VT request")
		}
		JSON(w, 200, map[string]any{"data": map[string]any{"id": hash, "type": "file", "attributes": map[string]any{"sha256": hash, "last_analysis_stats": map[string]int{"malicious": 10, "undetected": 20}, "last_analysis_date": 1700000000}}})
	}))
	defer vtMock.Close()
	aiMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aiCalls++
		var input map[string]any
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Fatal("invalid model request")
		}
		data, _ := input["input"].(string)
		if !strings.Contains(data, "reputation-1") || !strings.Contains(data, "malicious") || strings.Contains(data, "vt-synthetic") {
			t.Error("missing reputation or leaked credential")
		}
		assessment := ai.Assessment{Verdict: "phishing", Severity: "high", Confidence: "medium", Observations: []detection.Observation{}, AttackTypes: []string{"suspected_malware_delivery"}, Patterns: []string{}, Supporting: []string{"reputation-1", "attachment-1"}, Contradictory: []string{}, Uncertainty: []string{"Mocked reputation"}, Explanations: map[string]string{"en": "Attachment has reported detections", "ru": "Есть обнаружения вложения", "kk": "Тіркемеде анықтаулар бар"}, Recommendations: map[string]string{"en": "Do not open attachment", "ru": "Не открывайте вложение", "kk": "Тіркемені ашпаңыз"}}
		payload, _ := json.Marshal(assessment)
		JSON(w, 200, map[string]any{"status": "completed", "output": []any{map[string]any{"content": []any{map[string]any{"type": "output_text", "text": string(payload)}}}}})
	}))
	defer aiMock.Close()
	s.ProviderSettings = providers.FromEnv(db)
	s.ProviderSettings.ClientFactory = func(key, model string) *ai.Client { return &ai.Client{Key: key, Model: model, Endpoint: aiMock.URL} }
	s.VirusTotalFactory = func(key string) *virustotal.Client { return &virustotal.Client{Key: key, Endpoint: vtMock.URL} }
	request(a, "POST", "/settings/ai-provider", csrf, map[string]any{"provider": "openai", "model": "mock", "api_key": "ai-synthetic", "enabled": true}, 200)
	request(a, "POST", "/settings/virustotal", csrf, map[string]any{"provider": "virustotal", "api_key": "vt-synthetic", "enabled": true}, 200)
	otherVT := request(b, "GET", "/settings/virustotal", "", nil, 200)
	if bytes.Contains(otherVT, []byte(`"has_credential":true`)) {
		t.Fatal("VT credential isolation failed")
	}
	mime := "From: sender@example.test\r\nSubject: attachment\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n--fixture\r\nContent-Type: text/plain\r\n\r\nPlease review this file.\r\n--fixture\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=sample.bin\r\n\r\nsynthetic harmless bytes\r\n--fixture--\r\n"
	full := request(a, "POST", "/analyses", csrf, map[string]any{"source_type": "paste", "text": mime, "external_processing_consent": true, "virustotal_consent": true}, 201)
	var completed stored
	if json.Unmarshal(full, &completed) != nil || completed.Status != "complete" || completed.Report.Verdict != "phishing" || completed.Report.Score != 0 || completed.AI == nil || len(completed.Report.AttachmentReputation) != 1 || vtCalls != 1 || aiCalls != 1 {
		t.Fatalf("mock pipeline failed: %s", full)
	}
	reopened := request(a, "GET", "/analyses/"+completed.ID, "", nil, 200)
	var persisted stored
	json.Unmarshal(reopened, &persisted)
	if len(persisted.Report.AttachmentReputation) != 1 || persisted.Report.AttachmentReputation[0].Statistics["malicious"] != 10 || persisted.AIExecution.Final != "phishing" {
		t.Fatal("provider results not persisted")
	}
	request(a, "GET", "/analyses/"+completed.ID+"/export?format=pdf", "", nil, 200)
	request(a, "DELETE", "/analyses/"+completed.ID, csrf, nil, 204)
	request(a, "DELETE", "/settings/ai-provider", csrf, nil, 204)
	request(a, "DELETE", "/settings/virustotal", csrf, nil, 204)
	raw := request(a, "POST", "/analyses", csrf, map[string]any{"source_type": "paste", "sender": "CEO <ceo@example.com>", "text": "Urgent: verify your password immediately at https://192.0.2.1/login"}, 201)
	var report stored
	if json.Unmarshal(raw, &report) != nil || report.ID == "" || report.Report.Verdict != "inconclusive" || report.Status != "partial" || report.AI != nil || report.AIExecution.Final != "" || report.Report.Score != 0 {
		t.Fatal("analysis failed")
	}
	request(a, "GET", "/analyses/"+report.ID, "", nil, 200)
	request(b, "GET", "/analyses/"+report.ID, "", nil, 404)
	request(b, "GET", "/analyses/"+report.ID+"/export?format=json", "", nil, 404)
	request(b, "DELETE", "/analyses/"+report.ID, csrfB, nil, 404)
	for _, lang := range []string{"en", "ru", "kk"} {
		pdf := request(a, "GET", "/analyses/"+report.ID+"/export?format=pdf&lang="+lang, "", nil, 200)
		if !bytes.HasPrefix(pdf, []byte("%PDF")) {
			t.Fatal("invalid PDF")
		}
	}
	request(a, "GET", "/analyses/"+report.ID+"/export?format=json", "", nil, 200)
	request(a, "GET", "/analyses?sort=risk_desc&verdict=phishing&date_from=2020-01-01", "", nil, 200)
	stats := request(a, "GET", "/dashboard/stats?period=all", "", nil, 200)
	var aggregate map[string]any
	json.Unmarshal(stats, &aggregate)
	if aggregate["total_analyses"] != float64(1) {
		t.Fatalf("unexpected total %v", aggregate["total_analyses"])
	}
	request(a, "POST", "/analyses", csrf, map[string]string{"source_type": "demo", "demo_sample_id": "credentials"}, 400)
	stats = request(a, "GET", "/dashboard/stats?period=all", "", nil, 200)
	json.Unmarshal(stats, &aggregate)
	if aggregate["total_analyses"] != float64(1) {
		t.Fatal("demo leaked into live stats")
	}
	request(a, "POST", "/auth/change-password", csrf, map[string]string{"current_password": "correct horse battery staple", "new_password": "another strong test passphrase", "confirm_password": "another strong test passphrase"}, 204)
	request(a, "GET", "/auth/me", "", nil, 401)
	login := request(a, "POST", "/auth/login", "", map[string]string{"email": email, "password": "another strong test passphrase"}, 200)
	var current auth.Session
	json.Unmarshal(login, &current)
	request(a, "DELETE", "/analyses/"+report.ID, current.CSRF, nil, 204)
	request(a, "GET", "/analyses/"+report.ID, "", nil, 404)
	request(a, "POST", "/auth/logout", current.CSRF, nil, 204)
	request(a, "GET", "/analyses", "", nil, 401)
}
