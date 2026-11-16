package api

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode"

	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
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

// / shorten keeps long technical values readable in summary sections; the
// complete value is always present in the technical part or the JSON export.
func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut, _ := cutString(s, n)
	return cut + "…"
}

// keyLinks selects the destinations a reader most needs to see: links whose
// visible text names another site, links to bare IP addresses and form
// targets first, then ordinary links, three at most.
func keyLinks(links []detection.Link) []detection.Link {
	out := []detection.Link{}
	for _, l := range links {
		if l.Mismatch || l.Kind == "form_action" {
			out = append(out, l)
		}
	}
	for _, l := range links {
		if len(out) >= 3 {
			break
		}
		if !l.Mismatch && l.Kind != "form_action" {
			out = append(out, l)
		}
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// pdfReport renders only stored findings. Nothing here is computed from the
// email again and no provider result is invented for missing data. The first
// page answers "what is it and what should I do"; technical details follow.
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
	small := func(s string) {
		p.SetTextColor(90, 90, 90)
		text(8.5, s)
		p.SetTextColor(0, 0, 0)
	}
	// field prints a labelled value and nothing at all when the value is empty.
	field := func(key, value string) {
		if strings.TrimSpace(value) != "" && value != "." {
			line(L(key) + ": " + value)
		}
	}
	bullet := func(s string) { line("• " + s) }
	r, a := row.Report, row.AI
	legacy := r.Version != detection.EvidenceVersion
	evidence := map[string]string{}
	for _, e := range r.Evidence {
		evidence[e.ID] = e.Value
	}
	reputation := map[string]int{}
	for i, rep := range r.AttachmentReputation {
		reputation[rep.SHA256] = i + 1
	}

	text(16, "CyberGuard AI — "+L("title"))
	small(L("id") + ": " + row.ID + " · " + L("date") + ": " + row.Created.UTC().Format(time.RFC3339))

	// ---- Result ----------------------------------------------------------
	heading(L("section_assessment"))
	switch {
	case legacy:
		line(L("legacy_notice"))
		field("verdict", L(r.Verdict))
		line(L("risk") + ": " + fmt.Sprintf("%d / %s", r.Score, L(r.Level)))
	case a == nil:
		line(L("incomplete_notice"))
		line("OpenAI: " + L("status_"+row.AIExecution.Status))
		if row.AIExecution.Failure != "" {
			field("failure", L(row.AIExecution.Failure))
		}
	default:
		text(14, L(a.Verdict))
		line(L("severity") + ": " + L(a.Severity) + " · " + L("confidence") + ": " + L(a.Confidence))
		if a.Verdict == "legitimate" {
			line(L("legitimate_notice"))
		}
		small(L("confidence_notice"))
	}

	heading(L("section_email"))
	field("subject", r.Email.Subject)
	name, address := r.Email.SenderName, r.Email.SenderAddress
	if name == "" && address == "" {
		// Reports stored before the fields were split.
		name, address = emailparser.SplitAddress(r.Email.Sender)
	}
	field("display_name", name)
	field("from_address", address)
	if name != "" && address != "" {
		small(L("display_name_notice"))
	}
	field("reply_to", r.Email.ReplyTo)
	field("recipients", strings.Join(r.Email.Recipients, ", "))
	if r.Email.Timestamp != nil {
		field("email_date", r.Email.Timestamp.UTC().Format(time.RFC3339))
	}

	if a != nil && !legacy {
		heading(L("summary"))
		line(a.Explanations[lang])

		heading(L("main_reasons"))
		reasons := 0
		for _, f := range a.Findings {
			if f.Stance == "supporting" && reasons < 4 {
				reasons++
				bullet(f.Explanation[lang])
			}
		}
		for i, o := range a.Observations {
			if !supportsVerdict(a.Verdict, o.Type) || i >= 2 || reasons >= 5 {
				continue
			}
			reasons++
			bullet("“" + shorten(o.Quote, 220) + "” — " + o.Reason.In(lang))
		}
		if reasons == 0 {
			line(L("none"))
		}
	} else if legacy {
		explanation, recommendation := detection.Narrative(lang)
		heading(L("summary"))
		line(explanation)
		heading(L("recommendations"))
		line(recommendation)
	}

	if !legacy && (len(r.Links) > 0 || len(r.Email.Attachments) > 0) {
		heading(L("key_items"))
		for _, l := range keyLinks(r.Links) {
			s := L("link_leads") + " " + shorten(detection.Defang(l.Destination), 110)
			if l.Mismatch && l.Text != "" {
				s = L("link_shown") + " “" + shorten(l.Text, 60) + "”, " + s
			}
			bullet(s)
		}
		for _, at := range r.Email.Attachments {
			s := at.Filename
			if i, ok := reputation[at.SHA256]; ok {
				rep := r.AttachmentReputation[i-1]
				s += " — VirusTotal: " + L("status_"+rep.Status)
				if rep.Statistics != nil {
					s += fmt.Sprintf(" (%s: %d)", L("malicious"), rep.Statistics["malicious"])
				}
			}
			bullet(s)
		}
	}

	if a != nil && !legacy {
		heading(L("recommendations"))
		line(a.Recommendations[lang])
	}

	// ---- Technical details -----------------------------------------------
	p.Ln(4)
	p.SetTextColor(20, 80, 130)
	text(15, L("technical_details"))
	p.SetTextColor(0, 0, 0)

	heading(L("section_providers"))
	if !legacy {
		model := row.AIExecution.Model
		if model == "" {
			model = L("not_provided")
		}
		line("OpenAI: " + L("status_"+row.AIExecution.Status) + " (" + L("model") + ": " + model + ")")
		if row.AIExecution.DurationMS > 0 {
			line(L("duration") + ": " + fmt.Sprintf("%.1f s", float64(row.AIExecution.DurationMS)/1000))
		}
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
	field("source_type", L("source_"+r.Email.Source))
	field("filename", r.Email.Filename)
	field("file_sha256", r.Email.SHA256)
	field("message_id", r.Email.MessageID)

	if a != nil && !legacy {
		heading(L("section_supporting"))
		small(L("evidence_notice"))
		count := 0
		for _, f := range a.Findings {
			if f.Stance != "supporting" {
				continue
			}
			count++
			bullet(f.Explanation[lang])
			for _, id := range f.EvidenceIDs {
				value, _ := cutString(evidence[id], 400)
				small("    [" + id + "] " + value)
			}
		}
		if len(a.Findings) == 0 {
			// Reports created before per-finding explanations list IDs only.
			for _, id := range a.Supporting {
				count++
				value, _ := cutString(evidence[id], 400)
				bullet("[" + id + "] " + value)
			}
		}
		for _, o := range a.Observations {
			if !supportsVerdict(a.Verdict, o.Type) {
				continue
			}
			count++
			bullet("“" + o.Quote + "” — " + o.Reason.In(lang))
		}
		if count == 0 {
			line(L("none"))
		}
	}

	if !legacy {
		heading(L("section_authentication"))
		small(L("authentication_notice"))
		for _, v := range r.Authentication {
			s := strings.ToUpper(v.Mechanism) + ": "
			if v.Result == "unavailable" || v.Result == "" {
				s += L("unavailable")
			} else {
				s += v.Result + " — " + L(v.Trust) + "; " + L(v.Verification)
				if v.Server != "" {
					s += "; " + L("reported_by") + " " + v.Server
				}
			}
			bullet(s)
			for _, l := range v.Limitations {
				if l != "UPLOADED_HEADERS_CAN_BE_FORGED" && l != "NO_REPORTED_RESULT" {
					small("    " + L(l))
				}
			}
		}
		raw := map[string]bool{}
		for _, v := range r.Authentication {
			if v.Raw != "" && !raw[v.Raw] {
				raw[v.Raw] = true
				small(v.Source + ": " + v.Raw)
			}
		}
	} else if len(r.Email.AuthenticationResults) > 0 {
		heading(L("section_authentication"))
		for _, v := range r.Email.AuthenticationResults {
			bullet(v)
		}
	}

	if len(r.Email.Attachments) > 0 {
		heading(L("attachments"))
		for _, at := range r.Email.Attachments {
			bullet(fmt.Sprintf("%s (%d %s; %s / %s)", at.Filename, at.Size, L("bytes"), at.Declared, at.Detected))
			small("    SHA-256: " + at.SHA256)
			if i, ok := reputation[at.SHA256]; ok {
				rep := r.AttachmentReputation[i-1]
				s := "    VirusTotal: " + L("status_"+rep.Status)
				if rep.Statistics != nil {
					s += fmt.Sprintf(" — %s: %d, %s: %d, %s: %d, %s: %d", L("malicious"), rep.Statistics["malicious"], L("suspicious_count"), rep.Statistics["suspicious"], L("harmless"), rep.Statistics["harmless"], L("undetected"), rep.Statistics["undetected"])
				}
				if rep.LastAnalysis != nil {
					s += "; " + L("last_analysis") + ": " + rep.LastAnalysis.UTC().Format(time.RFC3339)
				}
				small(s)
			}
		}
		small(L("reputation_notice"))
	}

	shown, omitted := 0, 0
	lines := []string{}
	for _, x := range r.IOCs {
		if (!legacy && !detection.Actionable(x.Category)) || shown >= 150 {
			omitted++
			continue
		}
		// Attachment hashes are already listed with their attachments.
		if x.Type == "sha256" && !legacy {
			continue
		}
		shown++
		lines = append(lines, x.Type+": "+x.Defanged)
	}
	if shown > 0 || omitted > 0 {
		heading(L("iocs"))
		for _, s := range lines {
			bullet(s)
		}
		if omitted > 0 {
			small(fmt.Sprintf(L("omitted_resources"), omitted))
		}
	}

	if len(r.Indicators) > 0 {
		heading(L("indicators"))
		for _, f := range r.Indicators {
			value, _ := cutString(f.Evidence, 500)
			bullet(L(f.Code) + ": " + value)
		}
	}

	heading(L("limitations"))
	for _, l := range r.Limitations {
		bullet(L(l))
	}
	// Standing qualifications that apply to every report.
	bullet(L("caveat_not_guarantee"))
	if len(r.Email.Attachments) > 0 {
		bullet(L("caveat_reputation"))
	}
	p.Ln(4)
	small(L("footer"))
	var b bytes.Buffer
	if err = p.Output(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// supportsVerdict reports whether a quoted passage argues for the verdict:
// benign context supports "legitimate", everything else supports "phishing"
// and "suspicious". Quotes that argue the other way are part of the model's
// internal weighing and are not listed as reasons.
func supportsVerdict(verdict, kind string) bool {
	switch verdict {
	case "legitimate":
		return kind == "benign_context"
	case "phishing", "suspicious":
		return kind != "benign_context"
	}
	return true
}
