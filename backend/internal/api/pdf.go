package api

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode"

	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/reports"
	"github.com/go-pdf/fpdf"
)

// stripNUL removes JSON-escaped NUL characters, which PostgreSQL jsonb rejects,
// without touching an escaped backslash that merely precedes the text "u0000".
func stripNUL(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' && i+1 < len(b) {
			if b[i+1] == 'u' && i+5 < len(b) && string(b[i+2:i+6]) == "0000" {
				i += 5
				continue
			}
			out = append(out, b[i], b[i+1])
			i++
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// printable makes untrusted text safe for the embedded font: control
// characters are dropped and characters outside the Basic Multilingual Plane,
// which the PDF library cannot map, are replaced.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r) || r == unicode.ReplacementChar || (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0xFEFF:
			// includes bidirectional overrides that could visually reorder evidence
		case r > 0xFFFF:
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pdfReport renders only stored findings. Nothing here is computed from the
// email again and no provider result is invented for missing data.
func pdfReport(row stored, lang string) (data []byte, err error) {
	defer func() {
		if recover() != nil {
			data, err = nil, fmt.Errorf("pdf rendering failed")
		}
	}()
	L := func(key string) string { return reports.Label(lang, key) }
	p := fpdf.New("P", "mm", "A4", "")
	p.AddUTF8FontFromBytes("Noto", "", reports.Font)
	p.SetAutoPageBreak(true, 15)
	p.SetMargins(15, 15, 15)
	p.AddPage()
	text := func(size float64, s string) {
		p.SetFont("Noto", "", size)
		p.MultiCell(180, size*0.52, printable(s), "", "", false)
	}
	heading := func(s string) {
		p.Ln(3)
		p.SetTextColor(20, 80, 130)
		text(13, s)
		p.SetTextColor(0, 0, 0)
		p.Ln(1)
	}
	line := func(s string) { text(10, s) }
	field := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			value = L("not_provided")
		}
		line(L(key) + ": " + value)
	}
	bullet := func(s string) { line("• " + s) }
	local := func(m map[string]string) string {
		if v := m[lang]; v != "" {
			return v
		}
		return m["en"]
	}
	r, a := row.Report, row.AI
	legacy := r.Version != detection.EvidenceVersion

	text(16, "CyberGuard AI — "+L("title"))
	line("Security, made clear.")
	heading(L("section_identity"))
	field("id", row.ID)
	field("date", row.Created.UTC().Format(time.RFC3339))
	field("source_type", r.Email.Source)
	field("filename", r.Email.Filename)
	field("file_sha256", r.Email.SHA256)

	heading(L("section_email"))
	field("subject", r.Email.Subject)
	field("sender", r.Email.Sender)
	field("reply_to", r.Email.ReplyTo)
	field("recipients", strings.Join(r.Email.Recipients, ", "))
	if r.Email.Timestamp != nil {
		field("email_date", r.Email.Timestamp.UTC().Format(time.RFC3339))
	} else {
		field("email_date", "")
	}
	field("message_id", r.Email.MessageID)

	heading(L("section_assessment"))
	switch {
	case legacy:
		line(L("legacy_notice"))
		field("verdict", L(r.Verdict))
		line(L("risk") + ": " + fmt.Sprintf("%d / %s", r.Score, L(r.Level)))
	case a == nil:
		line(L("incomplete_notice"))
	default:
		field("verdict", L(a.Verdict))
		field("severity", L(a.Severity))
		field("confidence", L(a.Confidence))
		line(L("confidence_notice"))
	}

	heading(L("section_providers"))
	if !legacy {
		model := row.AIExecution.Model
		if model == "" {
			model = L("not_provided")
		}
		line("OpenAI: " + L("status_"+row.AIExecution.Status) + " (" + L("model") + ": " + model + ")")
		if row.AIExecution.Failure != "" {
			field("failure", L(row.AIExecution.Failure))
		}
		vt := r.VirusTotalStatus
		if vt == "" {
			vt = "not_requested"
		}
		line("VirusTotal: " + L("status_"+vt))
	} else {
		line("AI: " + row.AIExecution.Status)
	}

	if a != nil && !legacy {
		heading(L("summary"))
		line(local(a.Explanations))
		heading(L("recommendations"))
		line(local(a.Recommendations))
		evidence := map[string]string{}
		for _, e := range r.Evidence {
			evidence[e.ID] = e.Value
		}
		for _, stance := range []string{"supporting", "contradictory"} {
			heading(L("section_" + stance))
			count := 0
			for _, f := range a.Findings {
				if f.Stance != stance {
					continue
				}
				count++
				bullet(local(f.Explanation))
				for _, id := range f.EvidenceIDs {
					value, _ := cutString(evidence[id], 400)
					line("    [" + id + "] " + value)
				}
			}
			if len(a.Findings) == 0 {
				// Reports created before evidence_findings existed list IDs only.
				ids := a.Supporting
				if stance == "contradictory" {
					ids = a.Contradictory
				}
				for _, id := range ids {
					count++
					value, _ := cutString(evidence[id], 400)
					bullet("[" + id + "] " + value)
				}
			}
			if stance == "supporting" {
				for _, o := range a.Observations {
					count++
					bullet("“" + o.Quote + "” — " + o.Reason + " (" + L("quote_notice") + ")")
				}
			}
			if count == 0 {
				line(L("none"))
			}
		}
		if len(a.Uncertainty) > 0 {
			heading(L("uncertainty"))
			for _, u := range a.Uncertainty {
				bullet(u)
			}
		}
	} else if legacy {
		explanation, recommendation := detection.Narrative(lang)
		heading(L("summary"))
		line(explanation)
		heading(L("recommendations"))
		line(recommendation)
	} else {
		heading(L("summary"))
		line(local(row.Explanations))
	}

	if !legacy {
		heading(L("section_authentication"))
		line(L("authentication_notice"))
		for _, v := range r.Authentication {
			s := strings.ToUpper(v.Mechanism) + ": " + v.Result + " — " + L(v.Trust) + ", " + L(v.Verification)
			if v.Server != "" {
				s += " (" + v.Server + ")"
			}
			bullet(s)
		}
	} else if len(r.Email.AuthenticationResults) > 0 {
		heading(L("section_authentication"))
		for _, v := range r.Email.AuthenticationResults {
			bullet(v)
		}
	}

	heading(L("attachments"))
	if len(r.Email.Attachments) == 0 {
		line(L("none"))
	}
	for _, at := range r.Email.Attachments {
		bullet(fmt.Sprintf("%s (%d %s; %s / %s)", at.Filename, at.Size, L("bytes"), at.Declared, at.Detected))
		line("    SHA-256: " + at.SHA256)
		for _, rep := range r.AttachmentReputation {
			if rep.SHA256 != at.SHA256 {
				continue
			}
			s := "    VirusTotal: " + L("status_"+rep.Status)
			if rep.Statistics != nil {
				s += fmt.Sprintf(" — %s: %d, %s: %d, %s: %d, %s: %d", L("malicious"), rep.Statistics["malicious"], L("suspicious_count"), rep.Statistics["suspicious"], L("harmless"), rep.Statistics["harmless"], L("undetected"), rep.Statistics["undetected"])
			}
			if rep.LastAnalysis != nil {
				s += "; " + L("last_analysis") + ": " + rep.LastAnalysis.UTC().Format(time.RFC3339)
			}
			line(s)
			break
		}
	}
	if len(r.Email.Attachments) > 0 {
		line(L("reputation_notice"))
	}

	heading(L("iocs"))
	shown, omitted := 0, 0
	for _, x := range r.IOCs {
		if !legacy && !detection.Actionable(x.Category) {
			omitted++
			continue
		}
		if shown >= 150 {
			omitted++
			continue
		}
		shown++
		bullet(x.Type + ": " + x.Defanged)
	}
	if shown == 0 {
		line(L("none"))
	}
	if omitted > 0 {
		line(fmt.Sprintf(L("omitted_resources"), omitted))
	}

	heading(L("indicators"))
	if len(r.Indicators) == 0 {
		line(L("none"))
	}
	for _, f := range r.Indicators {
		value, _ := cutString(f.Evidence, 500)
		bullet(L(f.Code) + ": " + value)
	}

	heading(L("limitations"))
	if len(r.Limitations) == 0 {
		line(L("none"))
	}
	for _, l := range r.Limitations {
		bullet(L(l))
	}
	p.Ln(4)
	text(8, L("footer"))
	var b bytes.Buffer
	if err = p.Output(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
