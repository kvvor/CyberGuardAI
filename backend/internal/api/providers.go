package api

import (
	"cyberguard.local/backend/internal/providers"
	"net/http"
)

func (s *Server) providerService() *providers.Service { if s.ProviderSettings!=nil{return s.ProviderSettings};return providers.FromEnv(s.Auth.DB) }
func (s *Server) providerSettings(w http.ResponseWriter, r *http.Request) {
	p := s.providerService()
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
	p := s.providerService()
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
