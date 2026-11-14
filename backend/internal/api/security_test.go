package api

import (
	"cyberguard.local/backend/internal/auth"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORS(t *testing.T) {
	s := &Server{Auth: &auth.Service{}, Origin: "http://localhost:3000"}
	for _, origin := range []string{s.Origin, "https://evil.example"} {
		r := httptest.NewRequest("OPTIONS", "/api/v1/analyses", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		if origin == s.Origin {
			if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != origin {
				t.Fatal(w)
			}
		} else if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("untrusted CORS accepted")
		}
	}
}
func TestCookieSecurity(t *testing.T) {
	s := &Server{Secure: true}
	w := httptest.NewRecorder()
	s.cookie(w, "random-session-token")
	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatal("cookies")
	}
	if !cookies[0].HttpOnly || !cookies[0].Secure || strings.Contains(cookies[1].Value, "random-session-token") {
		t.Fatal("cookie isolation")
	}
	w = httptest.NewRecorder()
	s.cookie(w, "")
	for _, c := range w.Result().Cookies() {
		if c.MaxAge >= 0 {
			t.Fatal("cookie not expired")
		}
	}
}
