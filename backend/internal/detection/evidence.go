package detection

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Evidence struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Value  string `json:"value"`
	Trust  string `json:"trust_status"`
}
type Authentication struct {
	ID           string   `json:"evidence_id"`
	Mechanism    string   `json:"mechanism"`
	Result       string   `json:"reported_result"`
	Server       string   `json:"reporting_server"`
	Source       string   `json:"evidence_source"`
	Trust        string   `json:"trust_status"`
	Verification string   `json:"verification_status"`
	Alignment    string   `json:"alignment_information"`
	Limitations  []string `json:"limitations"`
}

var authResult = regexp.MustCompile(`(?i)^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b`)

// PrepareEvidence upgrades the existing extraction result for the live model
// pipeline. Legacy weights never enter the model input or become a live verdict.
func PrepareEvidence(r *Report) {
	r.Score = 0
	r.Verdict = "inconclusive"
	r.Level = "low"
	r.Version = "3.0.0"
	r.Manual = true
	r.AttackTypes = []string{}
	r.Evidence = []Evidence{}
	r.Authentication = []Authentication{}
	r.Limitations = append([]string{"AUTHENTICATION_HEADERS_UNVERIFIED", "NO_INDEPENDENT_DKIM_VERIFICATION"}, r.Email.Warnings...)
	trim := func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		r.Limitations = append(r.Limitations, "MODEL_INPUT_TRUNCATED")
		for !utf8.RuneStart(s[n]) {
			n--
		}
		return s[:n]
	}
	r.Email.Text = trim(r.Email.Text, 24000)
	// Extract text without scripts/styles; no resource is ever fetched.
	if r.Email.HTML != "" {
		doc, _ := html.Parse(strings.NewReader(r.Email.HTML))
		var out strings.Builder
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if out.Len() > 24000 {
				return
			}
			if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
				return
			}
			if n.Type == html.TextNode {
				out.WriteString(n.Data)
				out.WriteByte(' ')
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		if doc != nil {
			walk(doc)
		}
		r.Email.HTML = trim(strings.Join(strings.Fields(out.String()), " "), 24000)
	}
	add := func(id, source, value, trust string) {
		if value != "" {
			r.Evidence = append(r.Evidence, Evidence{id, source, trim(value, 4096), trust})
		}
	}
	add("subject-1", "subject", r.Email.Subject, "untrusted_content")
	add("sender-1", "from", r.Email.Sender, "untrusted_header")
	add("reply-to-1", "reply_to", r.Email.ReplyTo, "untrusted_header")
	for _, key := range []string{"Return-Path", "Sender", "Received", "Received-Spf", "Dkim-Signature"} {
		for i, value := range r.Email.Headers[key] {
			if i >= 16 {
				r.Limitations = append(r.Limitations, "HEADER_EVIDENCE_TRUNCATED")
				break
			}
			add(fmt.Sprintf("%s-%d", strings.ToLower(key), i+1), key, value, "untrusted_header")
		}
	}
	for _, mechanism := range []string{"spf", "dkim", "dmarc"} {
		found := false
		for i, value := range r.Email.AuthenticationResults {
			if i >= 16 {
				break
			}
			parts := strings.Split(value, ";")
			for _, part := range parts[1:] {
				m := authResult.FindStringSubmatch(part)
				if len(m) != 3 || strings.ToLower(m[1]) != mechanism {
					continue
				}
				id := fmt.Sprintf("authentication-%s-%d", mechanism, len(r.Authentication)+1)
				add(id, "Authentication-Results", value, "untrusted_reported")
				r.Authentication = append(r.Authentication, Authentication{id, mechanism, strings.ToLower(m[2]), trim(strings.TrimSpace(parts[0]), 256), "Authentication-Results", "untrusted_reported", "unable_to_verify", "not independently established", []string{"Uploaded headers may be forged; no trusted receiver is configured."}})
				found = true
			}
		}
		if !found {
			r.Authentication = append(r.Authentication, Authentication{Mechanism: mechanism, Result: "unavailable", Source: "missing", Trust: "unavailable", Verification: "unavailable", Alignment: "unavailable", Limitations: []string{"No usable reported result; body text is not authentication evidence."}})
		}
	}
	technical := []Finding{}
	for _, f := range r.Indicators {
		switch f.Rule {
		case "CREDENTIAL_REQUEST", "URGENCY", "ACCOUNT_SUSPENSION", "PAYMENT_REQUEST", "BEC_SECRECY", "BRAND_DOMAIN_MISMATCH", "LOOKALIKE_DOMAIN":
			continue
		}
		f.Severity = "low"
		f.Status = "observed_not_a_verdict"
		technical = append(technical, f)
		add(f.ID, f.Source, f.Evidence, "deterministic_observation")
	}
	r.Indicators = technical
	for i, ioc := range r.IOCs {
		if ioc.Category == "embedded_resource" || ioc.Category == "tracking_url" {
			continue
		}
		if i >= 64 {
			r.Limitations = append(r.Limitations, "MODEL_IOCS_TRUNCATED")
			break
		}
		add(fmt.Sprintf("ioc-%d", i+1), ioc.Source, ioc.Normalized, "extracted_observable")
	}
	for i, a := range r.Email.Attachments {
		b, _ := json.Marshal(a)
		add(fmt.Sprintf("attachment-%d", i+1), "attachment_metadata", string(b), "deterministic_observation")
	}
	for i, v := range r.AttachmentReputation {
		b, _ := json.Marshal(v)
		add(fmt.Sprintf("reputation-%d", i+1), "virustotal", string(b), "provider_reported")
	}
}
