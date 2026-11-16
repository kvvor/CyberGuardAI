package detection

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Localized is model-written text in English, Russian and Kazakh. Reports
// stored before these fields became trilingual hold a single string; that
// string is read as the English text so that old reports stay readable.
type Localized map[string]string

func (l *Localized) UnmarshalJSON(b []byte) error {
	var single string
	if json.Unmarshal(b, &single) == nil {
		*l = Localized{"en": single}
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*l = m
	return nil
}

// Complete reports whether all three languages are present and bounded.
func (l Localized) Complete(limit int) bool {
	if len(l) != 3 {
		return false
	}
	for _, lang := range []string{"en", "ru", "kk"} {
		if strings.TrimSpace(l[lang]) == "" || len(l[lang]) > limit {
			return false
		}
	}
	return true
}

// In returns the text for lang, falling back to English.
func (l Localized) In(lang string) string {
	if v := l[lang]; v != "" {
		return v
	}
	return l["en"]
}

// Observation is a verbatim quote from the email with the model's reading of it.
type Observation struct {
	Type         string    `json:"type"`
	Quote        string    `json:"quote"`
	Source       string    `json:"source"`
	Reason       Localized `json:"reason"`
	Confidence   string    `json:"confidence"`
	Verification string    `json:"verification_status,omitempty"`
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
		// The quote must occur verbatim; the explanation must exist in all
		// three interface languages so that no report mixes languages.
		if len(o.Quote) < 8 || len(o.Quote) > 512 || !strings.Contains(source, o.Quote) || !o.Reason.Complete(2048) {
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
