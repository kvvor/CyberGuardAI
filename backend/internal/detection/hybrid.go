package detection

import (
	"fmt"
	"strings"
)

type Observation struct {
	Type         string `json:"type"`
	Quote        string `json:"quote"`
	Source       string `json:"source"`
	Reason       string `json:"reason"`
	Confidence   string `json:"confidence"`
	Verification string `json:"verification_status,omitempty"`
}

func ValidateObservations(r Report, observations []Observation) error {
	if len(observations) > 8 {
		return fmt.Errorf("PROVIDER_INVALID_OUTPUT")
	}
	for _, o := range observations {
		source := ""
		switch o.Source {
		case "text_body":
			source = r.Email.Text
		case "html_body":
			source = r.Email.HTML
		case "subject":
			source = r.Email.Subject
		default:
			return fmt.Errorf("PROVIDER_INVALID_OUTPUT")
		}
		if len(o.Quote) < 8 || len(o.Quote) > 512 || !strings.Contains(source, o.Quote) || len(o.Reason) == 0 || len(o.Reason) > 1024 {
			return fmt.Errorf("PROVIDER_INVALID_OUTPUT")
		}
		switch o.Type {
		case "credential_theft", "payment_diversion", "coercion", "impersonation", "benign_context":
		default:
			return fmt.Errorf("PROVIDER_INVALID_OUTPUT")
		}
		switch o.Confidence {
		case "low", "medium", "high":
		default:
			return fmt.Errorf("PROVIDER_INVALID_OUTPUT")
		}
	}
	return nil
}
func Hybrid(r *Report, verdict string, observations []Observation) string {
	r.Version = "2.0.0"
	if ValidateObservations(*r, observations) != nil {
		return "AI_EVIDENCE_REJECTED"
	}
	delta := 0
	seen := map[string]bool{}
	benign := false
	for _, o := range observations {
		if seen[o.Type] {
			continue
		}
		seen[o.Type] = true
		if o.Type == "benign_context" {
			benign = o.Confidence == "high"
			continue
		}
		weight := 0
		if o.Confidence == "high" {
			weight = 30
		} else if o.Confidence == "medium" {
			weight = 15
		}
		delta += weight
		r.Indicators = append(r.Indicators, Finding{ID: fmt.Sprintf("ai%d", len(r.Indicators)+1), Rule: "AI_" + strings.ToUpper(o.Type), Type: "contextual_observation", Severity: "medium", Evidence: o.Quote, Source: o.Source, Code: "AI_CONTEXTUAL_OBSERVATION", Method: "model", Status: "quote_verified_interpretation_unverified"})
	}
	if delta > 60 {
		delta = 60
	}
	r.Score += delta
	if r.Score > 100 {
		r.Score = 100
	}
	r.Verdict = "inconclusive"
	r.Level = "low"
	if r.Score >= 20 {
		r.Verdict = "suspicious"
		r.Level = "medium"
	}
	if r.Score >= 45 {
		r.Level = "high"
	}
	if r.Score >= 60 {
		r.Verdict = "phishing"
	}
	if r.Score >= 70 {
		r.Level = "critical"
	}
	if verdict == "legitimate" && benign && r.Score == 0 && r.Email.Sender != "" && len(r.Email.Headers) > 0 && len(r.Email.Warnings) == 0 && len(r.Email.Attachments) == 0 {
		r.Verdict = "legitimate"
	}
	r.Manual = r.Verdict == "inconclusive" || r.Verdict == "suspicious"
	if delta > 0 {
		return "VERIFIED_QUOTES_ADDED_CONTEXTUAL_RISK"
	}
	if r.Verdict == "legitimate" {
		return "BENIGN_CONTEXT_WITH_COMPLETE_LOW_RISK_EVIDENCE"
	}
	return "STATIC_RISK_PRESERVED"
}
