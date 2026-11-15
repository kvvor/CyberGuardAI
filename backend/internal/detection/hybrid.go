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
