package api

import (
	"cyberguard.local/backend/internal/providers"
	"cyberguard.local/backend/internal/virustotal"
	"net/http"
	"strings"
)

func (s *Server) providerService() *providers.Service {
	if s.ProviderSettings != nil {
		return s.ProviderSettings
	}
	return providers.FromEnv(s.Auth.DB)
}
func (s *Server) requestProvider(r *http.Request) *providers.Service {
	if strings.Contains(r.URL.Path, "/virustotal") {
		return s.providerService().For("virustotal")
	}
	return s.providerService()
}
func (s *Server) providerSettings(w http.ResponseWriter, r *http.Request) {
	p := s.requestProvider(r)
	id := owner(r)
	switch r.Method {
	case "GET":
		c, _, e := p.Read(r.Context(), id)
		if e != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		JSON(w, 200, c)
	case "DELETE":
		if e := p.Remove(r.Context(), id); e != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		w.WriteHeader(204)
	case "POST":
		if !s.allowed(r.RemoteAddr) {
			fail(w, r, 429, "RATE_LIMITED")
			return
		}
		var in struct {
			Provider string `json:"provider"`
			Model    string `json:"model"`
			Key      string `json:"api_key"`
			Enabled  bool   `json:"enabled"`
		}
		if decode(w, r, &in) != nil {
			fail(w, r, 400, "INVALID_REQUEST")
			return
		}
		if e := p.Save(r.Context(), id, in.Provider, in.Model, in.Key, in.Enabled); e != nil {
			code := e.Error()
			switch code {
			case "PROVIDER_UNSUPPORTED", "INVALID_PROVIDER_SETTINGS", "PROVIDER_ENCRYPTION_UNAVAILABLE":
				fail(w, r, 400, code)
			default:
				fail(w, r, 500, "INTERNAL_ERROR")
			}
			return
		}
		c, _, e := p.Read(r.Context(), id)
		if e != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		JSON(w, 200, c)
	}
}
func (s *Server) providerTest(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r.RemoteAddr) {
		fail(w, r, 429, "RATE_LIMITED")
		return
	}
	p := s.requestProvider(r)
	if p.Provider == "virustotal" {
		c, b, err := p.Read(r.Context(), owner(r))
		if err != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		if !c.HasCredential {
			fail(w, r, 400, "PROVIDER_NOT_CONFIGURED")
			return
		}
		key, err := p.Open(owner(r), b)
		if err != nil {
			fail(w, r, 400, "PROVIDER_ENCRYPTION_UNAVAILABLE")
			return
		}
		allowed, err := p.ReserveLookup(r.Context(), owner(r))
		if err != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		if !allowed {
			JSON(w, 200, map[string]any{"success": false, "failure_code": "rate_limited", "test_type": "public_hash_lookup", "inference_performed": false})
			return
		}
		client := s.virusTotalClient(key)
		// Public SHA-256 of an empty file: no user email or attachment is sent.
		result := client.Lookup(r.Context(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		success := result.Status == "completed" || result.Status == "not_found"
		code := result.Status
		if success {
			code = ""
		}
		if p.Tested(r.Context(), owner(r), c, code) != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		JSON(w, 200, map[string]any{"success": success, "failure_code": code, "test_type": "public_hash_lookup", "inference_performed": false})
		return
	}
	c, client, e := p.Resolve(r.Context(), owner(r))
	if e != nil {
		fail(w, r, 400, "PROVIDER_NOT_CONFIGURED")
		return
	}
	e = client.TestConnection(r.Context())
	code := ""
	if e != nil {
		code = e.Error()
	}
	if c.Source == "user" {
		if err := p.Tested(r.Context(), owner(r), c, code); err != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
	}
	JSON(w, 200, map[string]any{"success": e == nil, "failure_code": code, "test_type": "model_metadata", "inference_performed": false, "inference_tokens": 0})
}

func (s *Server) virusTotalClient(key string) *virustotal.Client {
	if s.VirusTotalFactory != nil {
		return s.VirusTotalFactory(key)
	}
	return &virustotal.Client{Key: key}
}
