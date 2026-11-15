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
	StaticVerdict string `json:"static_verdict"`
	StaticScore   int    `json:"deterministic_risk_score"`
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
	x := AIExecution{Requested: requested, Consent: consent, Status: "not_requested", StaticVerdict: r.Verdict, StaticScore: r.Score, Final: r.Verdict, Influence: "STATIC_ONLY"}
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
		if x.Failure == "PROVIDER_RATE_LIMITED" {
			x.Status = "rate_limited"
		}
		return x, nil
	}
	x.Status = "completed"
	x.Proposed = assessment.Verdict
	x.Influence = detection.Hybrid(r, assessment.Verdict, assessment.Observations)
	x.Final = r.Verdict
	return x, &assessment
}
