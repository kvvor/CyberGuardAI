package openai

import (
	"errors"
	"strings"

	"cyberguard.local/backend/internal/detection"
)

var errInvalid = errors.New("PROVIDER_INVALID_OUTPUT")

// errUnsupportedClaim marks output that states something the backend evidence
// contradicts in a trust-increasing direction (e.g. "SPF passed" when no pass
// was reported). Such a response is discarded, never shown as a verdict.
var errUnsupportedClaim = errors.New("PROVIDER_UNSUPPORTED_CLAIM")

// AttachmentStates are the only attachment reputation summaries a model may state.
var AttachmentStates = []string{"no_attachments", "not_checked", "unknown_to_provider", "no_detections_reported", "detections_reported", "lookup_incomplete"}

// AttachmentState derives the reputation summary from stored VirusTotal results.
// It is deliberately conservative: anything short of a completed lookup for
// every attachment is not "no detections".
func AttachmentState(r detection.Report) string {
	if len(r.Email.Attachments) == 0 {
		return "no_attachments"
	}
	byHash := map[string]string{}
	detections := false
	for _, v := range r.AttachmentReputation {
		byHash[strings.ToLower(v.SHA256)] = v.Status
		if v.Status == "completed" && (v.Statistics["malicious"] > 0 || v.Statistics["suspicious"] > 0) {
			detections = true
		}
	}
	if detections {
		return "detections_reported"
	}
	completed, unknown, unchecked, failed := 0, 0, 0, 0
	for _, a := range r.Email.Attachments {
		switch byHash[strings.ToLower(a.SHA256)] {
		case "completed":
			completed++
		case "not_found":
			unknown++
		case "", "not_requested", "not_configured":
			unchecked++
		default:
			failed++
		}
	}
	switch {
	case failed > 0:
		return "lookup_incomplete"
	case unchecked == len(r.Email.Attachments):
		return "not_checked"
	case unchecked > 0:
		return "lookup_incomplete"
	case unknown > 0:
		return "unknown_to_provider"
	}
	return "no_detections_reported"
}

func reportedCategory(result string) string {
	switch strings.ToLower(result) {
	case "pass":
		return "reported_pass"
	case "fail", "hardfail", "permerror", "softfail":
		if strings.EqualFold(result, "softfail") {
			return "reported_other"
		}
		return "reported_fail"
	case "", "unavailable":
		return "not_available"
	}
	return "reported_other"
}

// AuthenticationState derives, per mechanism, every category the uploaded
// headers reported, and whether anything was independently verified.
func AuthenticationState(r detection.Report) (map[string]map[string]bool, bool) {
	states := map[string]map[string]bool{"spf": {}, "dkim": {}, "dmarc": {}}
	verified := false
	for _, a := range r.Authentication {
		m := strings.ToLower(a.Mechanism)
		if states[m] == nil {
			continue
		}
		states[m][reportedCategory(a.Result)] = true
		if a.Verification == "verified" {
			verified = true
		}
	}
	for _, set := range states {
		if len(set) == 0 {
			set["not_available"] = true
		}
	}
	return states, verified
}

func canonical(set map[string]bool) string {
	for _, k := range []string{"reported_fail", "reported_other", "reported_pass", "not_available"} {
		if set[k] {
			return k
		}
	}
	return "not_available"
}

func localized(m map[string]string, limit int) bool {
	if len(m) != 3 {
		return false
	}
	for _, l := range []string{"en", "ru", "kk"} {
		if strings.TrimSpace(m[l]) == "" || len(m[l]) > limit {
			return false
		}
	}
	return true
}

// reconcile validates model output against backend evidence and returns the
// assessment that may be stored. Checkable facts are replaced by backend truth.
func reconcile(out modelOutput, r detection.Report) (Assessment, error) {
	a := Assessment{Verdict: out.Verdict, Severity: out.Severity, Confidence: out.Confidence, AttackTypes: out.AttackTypes, Patterns: out.Patterns, Findings: out.Findings, Observations: out.Observations, Uncertainty: out.Uncertainty, Explanations: out.Explanations, Recommendations: out.Recommendations, Supporting: []string{}, Contradictory: []string{}}
	switch a.Verdict {
	case "legitimate", "suspicious", "phishing", "inconclusive":
	default:
		return a, errInvalid
	}
	switch a.Severity {
	case "none", "low", "medium", "high", "critical":
	default:
		return a, errInvalid
	}
	switch a.Confidence {
	case "low", "medium", "high":
	default:
		return a, errInvalid
	}
	if !localized(a.Explanations, 16000) || !localized(a.Recommendations, 16000) {
		return a, errInvalid
	}
	if e := detection.ValidateObservations(r, a.Observations); e != nil {
		return a, errInvalid
	}
	for i := range a.Observations {
		a.Observations[i].Verification = "quote_verified_interpretation_unverified"
	}
	if len(a.Patterns) > 32 || len(a.Uncertainty) > 16 {
		return a, errInvalid
	}
	for _, s := range a.Patterns {
		if len(s) > 2048 {
			return a, errInvalid
		}
	}
	for _, note := range a.Uncertainty {
		if !note.Complete(2048) {
			return a, errInvalid
		}
	}
	if len(a.AttackTypes) > len(attackTypes) {
		return a, errInvalid
	}
	for _, kind := range a.AttackTypes {
		known := false
		for _, allowed := range attackTypes {
			known = known || kind == allowed
		}
		if !known {
			return a, errInvalid
		}
	}

	// Evidence references must exist. Model prose can interpret evidence but
	// cannot introduce an identifier the backend did not produce.
	allowed := map[string]bool{}
	for _, e := range r.Evidence {
		allowed[e.ID] = true
	}
	if len(a.Findings) > 16 {
		return a, errInvalid
	}
	stance := map[string]string{}
	for _, f := range a.Findings {
		if (f.Stance != "supporting" && f.Stance != "contradictory") || len(f.EvidenceIDs) == 0 || len(f.EvidenceIDs) > 16 || !localized(f.Explanation, 4000) {
			return a, errInvalid
		}
		for _, id := range f.EvidenceIDs {
			if !allowed[id] {
				return a, errInvalid
			}
			if previous, seen := stance[id]; seen && previous != f.Stance {
				// The same fact cannot both support and contradict the verdict.
				return a, errInvalid
			}
			if _, seen := stance[id]; !seen {
				if f.Stance == "supporting" {
					a.Supporting = append(a.Supporting, id)
				} else {
					a.Contradictory = append(a.Contradictory, id)
				}
			}
			stance[id] = f.Stance
		}
	}
	if a.Verdict != "inconclusive" && len(a.Supporting) == 0 && len(a.Observations) == 0 {
		return a, errInvalid
	}

	// Typed authentication claims: a model may not upgrade reported results.
	states, verified := AuthenticationState(r)
	claims := map[string]string{"spf": out.Authentication.SPF, "dkim": out.Authentication.DKIM, "dmarc": out.Authentication.DMARC}
	for mechanism, claim := range claims {
		switch claim {
		case "reported_pass", "reported_fail", "reported_other", "not_available":
		default:
			return a, errInvalid
		}
		if claim == "reported_pass" && !states[mechanism]["reported_pass"] {
			return a, errUnsupportedClaim
		}
		if claim == "not_available" && states[mechanism]["reported_fail"] {
			// Ignoring a reported failure is also trust-increasing.
			return a, errUnsupportedClaim
		}
	}
	if out.Authentication.IndependentlyVerified && !verified {
		return a, errUnsupportedClaim
	}
	a.Authentication = &AuthenticationAssessment{SPF: canonical(states["spf"]), DKIM: canonical(states["dkim"]), DMARC: canonical(states["dmarc"]), IndependentlyVerified: verified}

	// Typed attachment claim: never "no detections" unless that is what the provider reported.
	truth := AttachmentState(r)
	known := false
	for _, s := range AttachmentStates {
		known = known || s == out.Attachments
	}
	if !known {
		return a, errInvalid
	}
	if out.Attachments != truth && (truth == "detections_reported" || out.Attachments == "no_detections_reported" || out.Attachments == "no_attachments") {
		return a, errUnsupportedClaim
	}
	a.Attachments = truth
	return a, nil
}
