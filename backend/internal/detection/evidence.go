package detection

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"cyberguard.local/backend/internal/virustotal"
	"golang.org/x/net/html"
)

type Evidence struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Value  string `json:"value"`
	Trust  string `json:"trust_status"`
}

// Authentication describes one reported email authentication result. CyberGuard
// receives a file after delivery, so it cannot reproduce SPF (needs the SMTP
// client address) and does not perform DKIM cryptographic verification.
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
	// Raw is the complete header this result was read from, for forensic review.
	Raw string `json:"raw_value,omitempty"`
}

// stripComments removes RFC 5322 comments, including nested ones.
func stripComments(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TrustedAuthServers lists authserv-id values (RFC 8601) of the operator's own
// receiving mail servers. Only the topmost Authentication-Results header added
// by such a server is labelled trusted_reported. Empty by default: without a
// trust anchor every reported result is untrusted.
var TrustedAuthServers []string

var authResult = regexp.MustCompile(`(?i)^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b(.*)$`)
var authProperty = regexp.MustCompile(`(?i)\b(header\.from|header\.d|header\.i|smtp\.mailfrom|smtp\.helo)\s*=\s*([^\s;()]+)`)
var receivedSPF = regexp.MustCompile(`(?i)^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b`)
var dkimTag = regexp.MustCompile(`(?i)(?:^|;)\s*([ads])\s*=\s*([^;\s]+)`)

func cut(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

func note(r *Report, code string) {
	for _, l := range r.Limitations {
		if l == code {
			return
		}
	}
	r.Limitations = append(r.Limitations, code)
}

// htmlText extracts readable text; scripts, styles and markup are dropped and
// no resource is ever fetched.
func htmlText(source string, limit int) string {
	doc, _ := html.Parse(strings.NewReader(source))
	if doc == nil {
		return ""
	}
	var out strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if out.Len() > limit*2 {
			return
		}
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "head" || n.Data == "noscript" || n.Data == "template") {
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
	walk(doc)
	return strings.Join(strings.Fields(out.String()), " ")
}

// PrepareEvidence turns the extraction result into the bounded, identified
// evidence set that is stored, shown and sent to the assessment model.
func PrepareEvidence(r *Report) {
	r.Score = 0
	r.Verdict = "inconclusive"
	r.Level = "low"
	r.Version = EvidenceVersion
	r.Manual = true
	r.AttackTypes = []string{}
	r.Evidence = []Evidence{}
	r.Authentication = []Authentication{}
	limitations := append([]string{}, r.Limitations...)
	r.Limitations = []string{"AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED"}
	for _, l := range append(limitations, r.Email.Warnings...) {
		note(r, l)
	}
	trim := func(s string, n int) string {
		s, shortened := cut(s, n)
		if shortened {
			note(r, "MODEL_INPUT_TRUNCATED")
		}
		return s
	}
	r.Email.Text = trim(r.Email.Text, 24000)
	if r.Email.HTML != "" {
		r.Email.HTML = trim(htmlText(r.Email.HTML, 24000), 24000)
	}
	add := func(id, source, value, trust string) {
		if strings.TrimSpace(value) != "" && len(r.Evidence) < 400 {
			r.Evidence = append(r.Evidence, Evidence{id, source, trim(value, 2048), trust})
		}
	}
	add("subject-1", "subject", r.Email.Subject, "untrusted_content")
	add("sender-1", "from", r.Email.Sender, "untrusted_header")
	add("reply-to-1", "reply_to", r.Email.ReplyTo, "untrusted_header")
	add("message-id-1", "message_id", r.Email.MessageID, "untrusted_header")
	if r.Email.Timestamp != nil {
		add("date-1", "date", r.Email.Timestamp.Format("2006-01-02T15:04:05Z07:00"), "untrusted_header")
	}
	for _, key := range []string{"Return-Path", "Sender", "Received", "Received-Spf", "Dkim-Signature"} {
		for i, value := range r.Email.Headers[key] {
			if i >= 8 {
				note(r, "HEADER_EVIDENCE_TRUNCATED")
				break
			}
			value = strings.Join(strings.Fields(value), " ")
			if key == "Dkim-Signature" {
				// The signature blob is useless to a reader; keep the identifying tags.
				tags := []string{}
				for _, m := range dkimTag.FindAllStringSubmatch(value, 8) {
					tags = append(tags, strings.ToLower(m[1])+"="+m[2])
				}
				value = "signature present, not cryptographically verified: " + strings.Join(tags, "; ")
			}
			add(fmt.Sprintf("%s-%d", strings.ToLower(key), i+1), key, value, "untrusted_header")
		}
	}

	// Reported authentication results.
	found := map[string]bool{}
	for i, value := range r.Email.AuthenticationResults {
		if i >= 8 {
			note(r, "HEADER_EVIDENCE_TRUNCATED")
			break
		}
		value = strings.Join(strings.Fields(value), " ")
		// Comments "(...)" may contain semicolons and equals signs; they are
		// removed for parsing only. The complete header stays in the report.
		parts := strings.Split(stripComments(value), ";")
		server := ""
		results := parts
		// RFC 8601 puts the reporting server (authserv-id) first. Microsoft 365
		// and others often omit it and start directly with "spf=pass ...". The
		// old code then took "spf=pass" for the server name and lost the SPF
		// result, which produced the mixed-up authentication display.
		if first := strings.Fields(parts[0]); len(first) > 0 && !strings.Contains(first[0], "=") {
			server = strings.ToLower(first[0])
			results = parts[1:]
			// "server 1; spf=..." (version) is fine; "server spf=pass" on the
			// same segment is also seen in the wild.
			if rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[0]), first[0])); strings.Contains(rest, "=") {
				results = append([]string{rest}, results...)
			}
		}
		trust := "untrusted_reported"
		limitation := "UPLOADED_HEADERS_CAN_BE_FORGED"
		if i == 0 {
			for _, trusted := range TrustedAuthServers {
				if trusted != "" && strings.EqualFold(strings.TrimSpace(trusted), server) {
					trust = "trusted_reported"
					limitation = "REPORTED_BY_CONFIGURED_RECEIVER_NOT_REVERIFIED"
				}
			}
		}
		for _, part := range results {
			m := authResult.FindStringSubmatch(part)
			if len(m) != 4 || len(r.Authentication) >= 24 {
				continue
			}
			mechanism, result := strings.ToLower(m[1]), strings.ToLower(m[2])
			// Properties are read from this result's own segment only, so one
			// method never receives another method's details.
			properties := []string{}
			for _, p := range authProperty.FindAllStringSubmatch(m[3], 6) {
				properties = append(properties, strings.ToLower(p[1])+"="+p[2])
			}
			alignment := "not_reported"
			if len(properties) > 0 {
				alignment = "reported: " + strings.Join(properties, "; ")
			}
			limitations := []string{limitation}
			if result == "bestguesspass" {
				// Microsoft's value for a domain without a DMARC record: a guess,
				// not a pass of a published policy.
				limitations = append(limitations, "DMARC_BESTGUESS_IS_NOT_A_POLICY_PASS")
			}
			id := fmt.Sprintf("authentication-%s-%d", mechanism, len(r.Authentication)+1)
			segment := strings.TrimSpace(part)
			add(id, "Authentication-Results", segment, trust)
			reporter, _ := cut(server, 256)
			raw, _ := cut(value, 2048)
			r.Authentication = append(r.Authentication, Authentication{ID: id, Mechanism: mechanism, Result: result, Server: reporter, Source: "Authentication-Results", Trust: trust, Verification: "unable_to_verify", Alignment: alignment, Limitations: limitations, Raw: raw})
			found[mechanism] = true
		}
	}
	if !found["spf"] {
		for _, value := range r.Email.Headers["Received-Spf"] {
			if m := receivedSPF.FindStringSubmatch(value); m != nil {
				id := fmt.Sprintf("authentication-spf-%d", len(r.Authentication)+1)
				add(id, "Received-SPF", strings.Join(strings.Fields(value), " "), "untrusted_reported")
				raw, _ := cut(strings.Join(strings.Fields(value), " "), 2048)
				r.Authentication = append(r.Authentication, Authentication{ID: id, Mechanism: "spf", Result: strings.ToLower(m[1]), Source: "Received-SPF", Trust: "untrusted_reported", Verification: "unable_to_verify", Alignment: "not_reported", Limitations: []string{"UPLOADED_HEADERS_CAN_BE_FORGED"}, Raw: raw})
				found["spf"] = true
			}
			break
		}
	}
	for _, mechanism := range []string{"spf", "dkim", "dmarc"} {
		if found[mechanism] {
			continue
		}
		limitation := "NO_REPORTED_RESULT"
		source := "missing"
		if mechanism == "dkim" && len(r.Email.Headers["Dkim-Signature"]) > 0 {
			limitation, source = "DKIM_SIGNATURE_PRESENT_NOT_VERIFIED", "DKIM-Signature"
		}
		r.Authentication = append(r.Authentication, Authentication{Mechanism: mechanism, Result: "unavailable", Source: source, Trust: "unavailable", Verification: "unavailable", Alignment: "unavailable", Limitations: []string{limitation}})
	}

	for _, f := range r.Indicators {
		add(f.ID, "observation:"+f.Rule, f.Evidence, "deterministic_observation")
	}
	for i, l := range r.Links {
		if i >= 40 {
			note(r, "MODEL_LINKS_TRUNCATED")
			break
		}
		b, _ := json.Marshal(l)
		add(fmt.Sprintf("link-%d", i+1), "hyperlink", string(b), "extracted_observable")
	}
	sent, resources := 0, map[string]int{}
	for _, ioc := range r.IOCs {
		if !Actionable(ioc.Category) {
			resources[ioc.Category]++
			continue
		}
		if ioc.Type == "url" && ioc.Category != "script_resource" {
			continue // already present as link-N with its visible text
		}
		if sent >= 64 {
			note(r, "MODEL_IOCS_TRUNCATED")
			break
		}
		sent++
		add(fmt.Sprintf("ioc-%d", sent), ioc.Type+":"+ioc.Category, ioc.Normalized, "extracted_observable")
	}
	if len(resources) > 0 {
		// Page furniture is summarised, not listed: it is rarely decisive and
		// previously drowned the actionable indicators.
		b, _ := json.Marshal(resources)
		add("resources-1", "embedded_resource_counts", string(b), "deterministic_observation")
	}
	for i, a := range r.Email.Attachments {
		b, _ := json.Marshal(a)
		add(fmt.Sprintf("attachment-%d", i+1), "attachment_metadata", string(b), "deterministic_observation")
	}
	for i, v := range r.AttachmentReputation {
		add(fmt.Sprintf("reputation-%d", i+1), "virustotal", ReputationValue(v), "provider_reported")
	}
}

// ReputationValue is the evidence text for one VirusTotal result. Engine names
// stay in the stored report; counts and a few labels are enough as evidence.
func ReputationValue(v virustotal.Result) string {
	summary := map[string]any{"sha256": v.SHA256, "status": v.Status, "source": v.Source}
	if v.Statistics != nil {
		summary["statistics"] = v.Statistics
	}
	if v.LastAnalysis != nil {
		summary["last_analysis_at"] = v.LastAnalysis
	}
	if len(v.Engines) > 0 {
		n := len(v.Engines)
		if n > 5 {
			n = 5
		}
		summary["sample_detections"] = v.Engines[:n]
	}
	b, _ := json.Marshal(summary)
	return string(b)
}
