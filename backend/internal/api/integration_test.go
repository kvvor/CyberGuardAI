package api

import (
	"bytes"
	"context"
	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/testfixtures"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPostgresHTTPWorkflow(t *testing.T) {
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
	raw := request(a, "POST", "/analyses", csrf, map[string]any{"source_type": "paste", "sender": "CEO <ceo@example.com>", "text": "Urgent: verify your password immediately at https://192.0.2.1/login"}, 201)
	var report stored
	if json.Unmarshal(raw, &report) != nil || report.ID == "" || report.Report.Verdict != "phishing" {
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
	request(a, "POST", "/analyses", csrf, map[string]string{"source_type": "demo", "demo_sample_id": "credentials"}, 201)
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
