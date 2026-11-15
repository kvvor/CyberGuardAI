package api

import (
	"context"
	"cyberguard.local/backend/internal/detection"
	ai "cyberguard.local/backend/internal/openai"
	"errors"
	"strings"
)

type AIExecution struct {
	Requested     bool   `json:"requested"`
	Consent       bool   `json:"consent"`
	Configured    bool   `json:"configured"`
	Provider      string `json:"provider,omitempty"`
	Model         string `json:"model,omitempty"`
	Source        string `json:"configuration_source,omitempty"`
	Status        string `json:"status"`
	Failure       string `json:"failure_code,omitempty"`
	StaticVerdict string `json:"static_verdict,omitempty"`
	StaticScore   int    `json:"deterministic_risk_score,omitempty"`
	Proposed      string `json:"ai_proposed_verdict,omitempty"`
	Final         string `json:"final_verdict"`
	Influence     string `json:"influence_code"`
}

func failureCode(e error) string {
	if errors.Is(e, context.DeadlineExceeded) {
		return "PROVIDER_TIMEOUT"
	}
	code := e.Error()
	if strings.HasPrefix(code, "PROVIDER_") {
		return code
	}
	switch code {
	case "OPENAI_NOT_CONFIGURED":
		return "PROVIDER_NOT_CONFIGURED"
	case "OPENAI_RATE_LIMITED":
		return "PROVIDER_RATE_LIMITED"
	case "OPENAI_INVALID_OUTPUT", "OPENAI_INCOMPLETE", "OPENAI_REFUSAL", "AI_INPUT_TOO_LARGE":
		return "PROVIDER_INVALID_OUTPUT"
	default:
		return "PROVIDER_NETWORK_FAILURE"
	}
}
func (s *Server) executeAI(ctx context.Context, id string, requested, consent bool, r *detection.Report) (AIExecution, *ai.Assessment) {
	detection.PrepareEvidence(r)
	x := AIExecution{Requested: requested, Consent: consent, Status: "not_requested", Final: "", Influence: "NO_ASSESSMENT"}
	config, _, readErr := s.providerService().Read(ctx, id)
	if readErr != nil {
		x.Failure = "PROVIDER_CONFIGURATION_UNAVAILABLE"
		if requested {
			x.Status = "failed"
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
	c, client, e := s.providerService().Resolve(ctx, id)
	x.Configured = c.HasCredential && c.Enabled
	x.Provider = c.Provider
	x.Model = c.Model
	x.Source = c.Source
	if !consent {
		x.Status = "failed"
		x.Failure = "AI_CONSENT_REQUIRED"
		return x, nil
	}
	if e != nil {
		x.Status = "not_configured"
		x.Failure = failureCode(e)
		return x, nil
	}
	assessment, e := client.Assess(ctx, *r)
	if e != nil {
		x.Status = "failed"
		x.Failure = failureCode(e)
		x.Status = map[string]string{"PROVIDER_RATE_LIMITED": "rate_limited", "PROVIDER_INSUFFICIENT_QUOTA": "quota_exceeded", "PROVIDER_INVALID_CREDENTIALS": "authentication_failed", "PROVIDER_MODEL_UNAVAILABLE": "unsupported_model", "PROVIDER_INVALID_OUTPUT": "invalid_response", "PROVIDER_TIMEOUT": "timeout", "PROVIDER_NETWORK_FAILURE": "network_error"}[x.Failure]
		if x.Status == "" {
			x.Status = "provider_error"
		}
		return x, nil
	}
	x.Status = "completed"
	x.Proposed = assessment.Verdict
	r.Verdict = assessment.Verdict
	r.Level = assessment.Severity
	// Existing SQL risk_level is a legacy compatibility column, not a score.
	if r.Level == "none" {
		r.Level = "low"
	}
	r.Manual = r.Verdict == "inconclusive" || r.Verdict == "suspicious"
	r.AttackTypes = assessment.AttackTypes
	x.Influence = "VALIDATED_MODEL_VERDICT"
	x.Final = r.Verdict
	return x, &assessment
}
