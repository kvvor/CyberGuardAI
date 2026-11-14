package api

import (
	"cyberguard.local/backend/internal/auth"
	"errors"
	"mime"
	"net/http"
)

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.PublicRegistration {
		fail(w, r, 403, "REGISTRATION_DISABLED")
		return
	}
	if !s.allowed(r.RemoteAddr) {
		w.Header().Set("Retry-After", "60")
		fail(w, r, 429, "RATE_LIMITED")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		fail(w, r, 415, "UNSUPPORTED_MEDIA_TYPE")
		return
	}
	var input struct {
		Email        string `json:"email"`
		Name         string `json:"display_name"`
		Password     string `json:"password"`
		Confirmation string `json:"confirm_password"`
	}
	if decode(w, r, &input) != nil {
		fail(w, r, 400, "INVALID_REQUEST")
		return
	}
	if err = s.Auth.Register(r.Context(), input.Email, input.Name, input.Password, input.Confirmation); err != nil {
		if errors.Is(err, auth.ErrRegistrationInput) {
			fail(w, r, 400, "INVALID_REGISTRATION_INPUT")
		} else {
			fail(w, r, 500, "INTERNAL_ERROR")
		}
		return
	}
	JSON(w, 202, map[string]string{"code": "REGISTRATION_ACCEPTED", "message": "Registration request processed. You may now try signing in."})
}
