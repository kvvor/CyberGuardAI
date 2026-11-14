package api

import (
	"context"
	"crypto/sha256"
	"cyberguard.local/backend/internal/auth"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Auth     *auth.Service
	Origin   string
	Secure   bool
	mu       sync.Mutex
	attempts map[string]bucket
}
type bucket struct {
	count int
	until time.Time
}
type key int

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	JSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": code, "request_id": w.Header().Get("X-Request-ID")}})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing input")
	}
	return nil
}
func (s *Server) cookie(w http.ResponseWriter, token string) {
	age := 0
	if token == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: "cyberguard_session", Value: token, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: age})
	csrf := ""
	if token != "" {
		h := sha256.Sum256([]byte("cyberguard-csrf:" + token))
		csrf = base64.RawURLEncoding.EncodeToString(h[:])
	}
	http.SetCookie(w, &http.Cookie{Name: "cyberguard_csrf", Value: csrf, Path: "/", HttpOnly: false, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (s *Server) Router() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if s.Auth.DB.Ping(ctx) != nil {
			fail(w, r, 503, "DATABASE_UNAVAILABLE")
			return
		}
		JSON(w, 200, map[string]string{"status": "ok"})
	}).Methods("GET")
	r.HandleFunc("/api/v1/config/public", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, 200, map[string]any{"languages": []string{"en", "ru", "kk"}, "max_email_size": 10 << 20, "public_signup": false})
	}).Methods("GET")
	r.HandleFunc("/api/v1/auth/login", s.login).Methods("POST")
	p := r.PathPrefix("/api/v1").Subrouter()
	p.Use(s.session)
	s.analysisRoutes(p)
	p.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		v := r.Context().Value(key(0)).(auth.Session)
		if e := s.Auth.Logout(r.Context(), v.Token); e != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		s.cookie(w, "")
		w.WriteHeader(204)
	}).Methods("POST")
	p.HandleFunc("/auth/activate-account", s.password).Methods("POST")
	p.HandleFunc("/auth/change-password", s.password).Methods("POST")
	p.HandleFunc("/auth/me", func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, r.Context().Value(key(0))) }).Methods("GET")
	slots := make(chan struct{}, 8)
	bounded := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-req.Context().Done():
			return
		default:
			fail(w, req, 503, "SERVER_BUSY")
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 65*time.Second)
		defer cancel()
		r.ServeHTTP(w, req.WithContext(ctx))
	})
	return s.security(bounded)
}
func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", uuid.NewString())
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Header.Get("Origin") == s.Origin && s.Origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", s.Origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == "OPTIONS" {
			if r.Header.Get("Origin") != s.Origin {
				fail(w, r, 403, "ORIGIN_INVALID")
				return
			}
			switch r.Header.Get("Access-Control-Request-Method") {
			case "GET", "POST", "DELETE":
			default:
				fail(w, r, 403, "METHOD_NOT_ALLOWED")
				return
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			w.WriteHeader(204)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("Origin") != s.Origin {
			fail(w, r, 403, "ORIGIN_INVALID")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("cyberguard_session")
		if e != nil {
			fail(w, r, 401, "UNAUTHENTICATED")
			return
		}
		v, e := s.Auth.Resolve(r.Context(), c.Value)
		if e != nil {
			fail(w, r, 401, "UNAUTHENTICATED")
			return
		}
		if v.Setup && r.URL.Path != "/api/v1/auth/activate-account" && r.URL.Path != "/api/v1/auth/logout" {
			fail(w, r, 403, "PASSWORD_CHANGE_REQUIRED")
			return
		}
		if r.Method != "GET" && !s.Auth.CSRF(r.Context(), c.Value, r.Header.Get("X-CSRF-Token")) {
			fail(w, r, 403, "CSRF_INVALID")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), key(0), v)))
	})
}
func (s *Server) allowed(remote string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempts == nil {
		s.attempts = map[string]bucket{}
	}
	now := time.Now()
	for k, v := range s.attempts {
		if now.After(v.until) {
			delete(s.attempts, k)
		}
	}
	ip, _, _ := net.SplitHostPort(remote)
	b := s.attempts[ip]
	if b.until.IsZero() {
		if len(s.attempts) >= 10000 {
			return false
		}
		b.until = now.Add(time.Minute)
	}
	b.count++
	s.attempts[ip] = b
	return b.count <= 10
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r.RemoteAddr) {
		fail(w, r, 429, "RATE_LIMITED")
		return
	}
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if decode(w, r, &in) != nil {
		fail(w, r, 400, "INVALID_REQUEST")
		return
	}
	v, e := s.Auth.Login(r.Context(), in.Email, in.Password)
	if e != nil {
		if errors.Is(e, auth.ErrCredentials) {
			fail(w, r, 401, "INVALID_CREDENTIALS")
		} else {
			fail(w, r, 500, "INTERNAL_ERROR")
		}
		return
	}
	if old, e := r.Cookie("cyberguard_session"); e == nil {
		s.Auth.Logout(r.Context(), old.Value)
	}
	s.cookie(w, v.Token)
	JSON(w, 200, v)
}
func (s *Server) password(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r.RemoteAddr) {
		fail(w, r, 429, "RATE_LIMITED")
		return
	}
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
		Confirm string `json:"confirm_password"`
	}
	if decode(w, r, &in) != nil {
		fail(w, r, 400, "INVALID_REQUEST")
		return
	}
	if in.New != in.Confirm {
		fail(w, r, 400, "PASSWORD_MISMATCH")
		return
	}
	activate := strings.HasSuffix(r.URL.Path, "activate-account")
	v, e := s.Auth.Password(r.Context(), r.Context().Value(key(0)).(auth.Session), in.Current, in.New, activate)
	if e != nil {
		fail(w, r, 400, "PASSWORD_CHANGE_FAILED")
		return
	}
	if activate {
		s.cookie(w, v.Token)
		JSON(w, 200, v)
	} else {
		s.cookie(w, "")
		w.WriteHeader(204)
	}
}
