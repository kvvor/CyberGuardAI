package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"cyberguard.local/backend/internal/detection"
	ai "cyberguard.local/backend/internal/openai"
)

// AIExecution records what actually happened to the assessment request. A
// verdict exists only when Status is "completed".
type AIExecution struct {
	Requested  bool   `json:"requested"`
	Consent    bool   `json:"consent"`
	Configured bool   `json:"configured"`
	Provider   string `json:"provider,omitempty"`
	Model      string `json:"model,omitempty"`
	Source     string `json:"configuration_source,omitempty"`
	Status     string `json:"status"`
	Failure    string `json:"failure_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	// Legacy fields of weighted-score reports; never written by this version.
	StaticVerdict string `json:"static_verdict,omitempty"`
	StaticScore   int    `json:"deterministic_risk_score,omitempty"`
	Proposed      string `json:"ai_proposed_verdict,omitempty"`
	Final         string `json:"final_verdict"`
	Influence     string `json:"influence_code"`
}

// executionStatus maps provider failure codes to the documented execution states.
var executionStatus = map[string]string{
	"PROVIDER_NOT_CONFIGURED":         "not_configured",
	"PROVIDER_DISABLED":               "not_configured",
	"PROVIDER_INVALID_CREDENTIALS":    "authentication_failed",
	"PROVIDER_ACCESS_DENIED":          "authentication_failed",
	"PROVIDER_CREDENTIAL_UNREADABLE":  "authentication_failed",
	"PROVIDER_INSUFFICIENT_QUOTA":     "quota_exceeded",
	"PROVIDER_RATE_LIMITED":           "rate_limited",
	"PROVIDER_UNSUPPORTED_MODEL":      "unsupported_model",
	"PROVIDER_INVALID_OUTPUT":         "invalid_response",
	"PROVIDER_OUTPUT_TRUNCATED":       "invalid_response",
	"PROVIDER_REFUSED":                "invalid_response",
	"PROVIDER_UNSUPPORTED_CLAIM":      "invalid_response",
	"PROVIDER_TIMEOUT":                "timeout",
	"PROVIDER_NETWORK_FAILURE":        "network_error",
	"PROVIDER_ERROR":                  "provider_error",
	"PROVIDER_REQUEST_REJECTED":       "provider_error",
	"PROVIDER_INPUT_TOO_LARGE":        "provider_error",
	"PROVIDER_ENCRYPTION_UNAVAILABLE": "provider_error",
}

func failureCode(e error) string {
	if errors.Is(e, context.DeadlineExceeded) {
		return "PROVIDER_TIMEOUT"
	}
	code := e.Error()
	if code == "PROVIDER_CREDENTIAL_INVALID" {
		return "PROVIDER_CREDENTIAL_UNREADABLE"
	}
	if strings.HasPrefix(code, "PROVIDER_") {
		return code
	}
	return "PROVIDER_ERROR"
}

// executeAI prepares evidence and, only with a request, consent and a usable
// configuration, asks the provider for an assessment. On any failure the
// evidence is kept and no verdict is produced: there is no heuristic fallback.
func (s *Server) executeAI(ctx context.Context, id string, requested, consent bool, r *detection.Report) (AIExecution, *ai.Assessment) {
	detection.PrepareEvidence(r)
	x := AIExecution{Requested: requested, Consent: consent, Status: "not_requested", Final: "", Influence: "NO_ASSESSMENT"}
	p := s.providerService().For("openai")
	config, _, readErr := p.Read(ctx, id)
	if readErr != nil {
		slog.Error("provider configuration unavailable", "error", readErr.Error())
		x.Failure = "PROVIDER_CONFIGURATION_UNAVAILABLE"
		if requested {
			x.Status = "provider_error"
		}
		return x, nil
	}
	x.Configured = config.HasCredential && config.Enabled
	x.Provider = config.Provider
	x.Model = config.Model
	x.Source = config.Source
	if !requested {
		return x, nil
	}
	if !consent {
		// Without consent nothing is decrypted and nothing leaves the server.
		x.Failure = "AI_CONSENT_REQUIRED"
		return x, nil
	}
	_, client, e := p.Resolve(ctx, id)
	if e != nil {
		x.Failure = failureCode(e)
		if config.HasCredential && !config.Enabled {
			x.Failure = "PROVIDER_DISABLED"
		}
		x.Status = executionStatus[x.Failure]
		if x.Status == "" {
			x.Status = "provider_error"
		}
		return x, nil
	}
	started := time.Now()
	assessment, e := client.Assess(ctx, *r)
	x.DurationMS = time.Since(started).Milliseconds()
	if e != nil {
		x.Failure = failureCode(e)
		x.Status = executionStatus[x.Failure]
		if x.Status == "" {
			x.Status = "provider_error"
		}
		// Only the stable code is logged; never the key, prompt or email.
		slog.Warn("assessment not completed", "failure_code", x.Failure, "model", x.Model, "duration_ms", x.DurationMS)
		return x, nil
	}
	x.Status = "completed"
	x.Proposed = assessment.Verdict
	r.Verdict = assessment.Verdict
	// risk_level is a legacy SQL column without "none"; severity itself is
	// stored unchanged inside the assessment.
	r.Level = assessment.Severity
	if r.Level == "none" {
		r.Level = "low"
	}
	r.Manual = r.Verdict == "inconclusive" || r.Verdict == "suspicious"
	r.AttackTypes = assessment.AttackTypes
	x.Influence = "VALIDATED_MODEL_VERDICT"
	x.Final = r.Verdict
	return x, &assessment
}
