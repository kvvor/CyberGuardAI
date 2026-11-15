package api

import (
	"net/http"
	"strings"

	ai "cyberguard.local/backend/internal/openai"
	"cyberguard.local/backend/internal/providers"
	"cyberguard.local/backend/internal/virustotal"
)

// emptyFileSHA256 is the public hash of a zero-byte file. The VirusTotal
// connection test looks it up so that no user data is involved.
const emptyFileSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

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
	return s.providerService().For("openai")
}

// settingsView is the only provider data a browser ever receives: metadata,
// never the credential or its ciphertext.
func (s *Server) settingsView(p *providers.Service, c providers.Config) map[string]any {
	view := map[string]any{"provider": c.Provider, "model": c.Model, "enabled": c.Enabled, "has_credential": c.HasCredential, "connection_status": c.Status, "last_success_at": c.LastSuccess, "source": c.Source}
	if p.Provider == "virustotal" {
		perMinute, perDay := p.Limits()
		view["lookups_per_minute"], view["lookups_per_day"] = perMinute, perDay
	}
	return view
}

func (s *Server) providerSettings(w http.ResponseWriter, r *http.Request) {
	p := s.requestProvider(r)
	id := owner(r)
	switch r.Method {
	case "GET":
		c, _, e := p.Read(r.Context(), id)
		if e != nil {
			internal(w, r, "provider settings read", e)
			return
		}
		JSON(w, 200, s.settingsView(p, c))
	case "DELETE":
		if e := p.Remove(r.Context(), id); e != nil {
			internal(w, r, "provider settings delete", e)
			return
		}
		w.WriteHeader(204)
	case "POST":
		if !s.allowed("provider", r.RemoteAddr, 30) {
			w.Header().Set("Retry-After", "60")
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
		if in.Provider == "" {
			in.Provider = p.Provider
		}
		if e := p.Save(r.Context(), id, in.Provider, in.Model, in.Key, in.Enabled); e != nil {
			switch code := e.Error(); code {
			case "PROVIDER_UNSUPPORTED", "INVALID_PROVIDER_SETTINGS", "PROVIDER_MODEL_INVALID", "PROVIDER_KEY_MALFORMED", "PROVIDER_KEY_REQUIRED":
				fail(w, r, 400, code)
			case "PROVIDER_ENCRYPTION_UNAVAILABLE":
				// Server misconfiguration, not a user input problem.
				fail(w, r, 503, code)
			default:
				internal(w, r, "provider settings save", e)
			}
			return
		}
		c, _, e := p.Read(r.Context(), id)
		if e != nil {
			internal(w, r, "provider settings read", e)
			return
		}
		JSON(w, 200, s.settingsView(p, c))
	}
}

// providerModels lists models available to an OpenAI credential, read live
// from the provider. GET uses the saved key. POST may carry a key that has not
// been saved yet, so a model can be chosen before the first save; that key is
// used for this one metadata request and is not stored. No inference is run
// and no email content is sent.
func (s *Server) providerModels(w http.ResponseWriter, r *http.Request) {
	if !s.allowed("provider", r.RemoteAddr, 30) {
		w.Header().Set("Retry-After", "60")
		fail(w, r, 429, "RATE_LIMITED")
		return
	}
	p := s.providerService().For("openai")
	var candidate string
	if r.Method == "POST" {
		var in struct {
			Key string `json:"api_key"`
		}
		if decode(w, r, &in) != nil {
			fail(w, r, 400, "INVALID_REQUEST")
			return
		}
		key, err := providers.NormalizeKey(in.Key)
		if err != nil {
			fail(w, r, 400, err.Error())
			return
		}
		candidate = key
	}
	var client *ai.Client
	selected := ""
	if candidate != "" {
		client = p.Client(candidate, "")
	} else {
		c, b, e := p.Read(r.Context(), owner(r))
		if e != nil {
			internal(w, r, "provider settings read", e)
			return
		}
		selected = c.Model
		switch {
		case c.Source == "operator":
			client = p.Client(p.FallbackKey, c.Model)
		case !c.HasCredential:
			fail(w, r, 409, "PROVIDER_NOT_CONFIGURED")
			return
		default:
			// Listing works for a saved but disabled provider: the user is still configuring it.
			key, e := p.Open(owner(r), b)
			if e != nil {
				s.resolveFailure(w, r, c, e)
				return
			}
			client = p.Client(key, c.Model)
		}
	}
	models, e := client.ListModels(r.Context())
	if e != nil {
		JSON(w, 200, map[string]any{"success": false, "failure_code": e.Error(), "models": []any{}, "selected": selected})
		return
	}
	JSON(w, 200, map[string]any{"success": true, "failure_code": "", "models": models, "selected": selected})
}

// resolveFailure reports why a saved provider configuration cannot be used.
func (s *Server) resolveFailure(w http.ResponseWriter, r *http.Request, c providers.Config, e error) {
	switch e.Error() {
	case "PROVIDER_NOT_CONFIGURED":
		if c.HasCredential && !c.Enabled {
			fail(w, r, 409, "PROVIDER_DISABLED")
			return
		}
		fail(w, r, 409, "PROVIDER_NOT_CONFIGURED")
	case "PROVIDER_ENCRYPTION_UNAVAILABLE":
		fail(w, r, 503, "PROVIDER_ENCRYPTION_UNAVAILABLE")
	case "PROVIDER_CREDENTIAL_INVALID":
		// The stored ciphertext cannot be decrypted with the current master key.
		fail(w, r, 409, "PROVIDER_CREDENTIAL_UNREADABLE")
	default:
		internal(w, r, "provider resolve", e)
	}
}

func (s *Server) providerTest(w http.ResponseWriter, r *http.Request) {
	if !s.allowed("provider", r.RemoteAddr, 30) {
		w.Header().Set("Retry-After", "60")
		fail(w, r, 429, "RATE_LIMITED")
		return
	}
	p := s.requestProvider(r)
	if p.Provider == "virustotal" {
		c, b, err := p.Read(r.Context(), owner(r))
		if err != nil {
			internal(w, r, "provider settings read", err)
			return
		}
		if !c.HasCredential {
			fail(w, r, 409, "PROVIDER_NOT_CONFIGURED")
			return
		}
		key, err := p.Open(owner(r), b)
		if err != nil {
			s.resolveFailure(w, r, c, err)
			return
		}
		allowed, err := p.ReserveLookup(r.Context(), owner(r))
		if err != nil {
			internal(w, r, "virustotal quota", err)
			return
		}
		result := map[string]any{"success": false, "failure_code": "deferred_local_limit", "test_type": "public_hash_lookup", "inference_performed": false}
		if !allowed {
			JSON(w, 200, result)
			return
		}
		lookup := s.virusTotalClient(key).Lookup(r.Context(), emptyFileSHA256)
		// "not_found" still proves that the key was accepted.
		success := lookup.Status == "completed" || lookup.Status == "not_found"
		code := lookup.Status
		if success {
			code = ""
		}
		if err := p.Tested(r.Context(), owner(r), c, code); err != nil {
			internal(w, r, "provider test record", err)
			return
		}
		result["success"], result["failure_code"] = success, code
		JSON(w, 200, result)
		return
	}
	c, client, e := p.Resolve(r.Context(), owner(r))
	if e != nil {
		s.resolveFailure(w, r, c, e)
		return
	}
	e = client.TestConnection(r.Context())
	code := ""
	if e != nil {
		code = e.Error()
	}
	if c.Source == "user" {
		if err := p.Tested(r.Context(), owner(r), c, code); err != nil {
			internal(w, r, "provider test record", err)
			return
		}
	}
	JSON(w, 200, map[string]any{"success": e == nil, "failure_code": code, "model": c.Model, "test_type": "model_metadata", "inference_performed": false, "inference_tokens": 0})
}

func (s *Server) virusTotalClient(key string) *virustotal.Client {
	if s.VirusTotalFactory != nil {
		return s.VirusTotalFactory(key)
	}
	return &virustotal.Client{Key: key, Endpoint: s.VirusTotalBaseURL}
}
