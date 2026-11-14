package api

import (
	"bytes"
	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
	"cyberguard.local/backend/internal/reports"
	"golang.org/x/image/font/sfnt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestKazakhFontCoverage(t *testing.T) {
	f, e := sfnt.Parse(reports.Font)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range "ӘәҒғҚқҢңӨөҰұҮүҺһІі" {
		idx, e := f.GlyphIndex(nil, r)
		if e != nil || idx == 0 {
			t.Fatalf("missing glyph %U", r)
		}
	}
}

func TestUnauthorized(t *testing.T) {
	s := &Server{Auth: &auth.Service{}, Origin: "http://localhost:3000"}
	for _, path := range []string{"/api/v1/analyses", "/api/v1/dashboard/stats", "/api/v1/auth/me"} {
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}
func TestOrigin(t *testing.T) {
	s := &Server{Auth: &auth.Service{}, Origin: "http://localhost:3000"}
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/auth/login", nil))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestRateLimit(t *testing.T) {
	s := &Server{}
	for i := 0; i < 10; i++ {
		if !s.allowed("127.0.0.1:123") {
			t.Fatal(i)
		}
	}
	if s.allowed("127.0.0.1:123") {
		t.Fatal("limit bypass")
	}
}
func TestPDF(t *testing.T) {
	for _, lang := range []string{"en", "ru", "kk"} {
		b, e := pdfReport(stored{ID: "test", Created: time.Now(), Report: detection.Analyze(emailparser.Email{Subject: "Тест Қауіпсіздік"})}, lang)
		if e != nil || !bytes.HasPrefix(b, []byte("%PDF")) {
			t.Fatalf("%s: %v", lang, e)
		}
	}
}
