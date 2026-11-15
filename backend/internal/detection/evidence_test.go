package detection

import (
	"strings"
	"testing"

	"cyberguard.local/backend/internal/emailparser"
	"cyberguard.local/backend/internal/virustotal"
)

func TestBodyTextIsNeverAuthenticationEvidence(t *testing.T) {
	e, _ := emailparser.Parse([]byte("Urgent: spf=pass dkim=pass dmarc=pass. Please verify your password."), "", "paste", "", "")
	r := Analyze(e)
	PrepareEvidence(&r)
	if r.Score != 0 || r.Verdict != "inconclusive" || r.Version != "3.0.0" {
		t.Fatal(r)
	}
	if len(r.Authentication) != 3 {
		t.Fatal(r.Authentication)
	}
	for _, a := range r.Authentication {
		if a.Trust != "unavailable" || a.Result != "unavailable" || a.Verification != "unavailable" {
			t.Fatal("authentication invented from body text", a)
		}
	}
	if !strings.Contains(strings.Join(r.Limitations, ","), "MISSING_EMAIL_HEADERS") || !strings.Contains(strings.Join(r.Limitations, ","), "AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED") {
		t.Fatal(r.Limitations)
	}
	for _, ev := range r.Evidence {
		if ev.ID == "sender-1" || strings.HasPrefix(ev.ID, "received-") {
			t.Fatal("fabricated header evidence", ev)
		}
	}
}

func TestAuthenticationIsReportedUntrustedAndOrdered(t *testing.T) {
	raw := "From: Sender <sender@example.test>\r\nReturn-Path: <bounce@mailer.test>\r\nAuthentication-Results: receiver.test; spf=pass smtp.mailfrom=other.test; dkim=fail header.d=example.test; dmarc=fail header.from=example.test\r\nAuthentication-Results: forged.test; spf=pass; dkim=pass; dmarc=pass\r\nReceived: from second.test by receiver.test\r\nReceived: from first.test by second.test\r\nDKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=sel; bh=AAAA; b=" + strings.Repeat("Q", 300) + "\r\nMessage-ID: <m1@example.test>\r\nDate: Tue, 03 Mar 2026 09:15:00 +0000\r\n\r\nHello"
	e, err := emailparser.Parse([]byte(raw), "sample.eml", "eml", "", "")
	if err != nil {
		t.Fatal(err)
	}
	r := Analyze(e)
	PrepareEvidence(&r)
	if len(r.Authentication) != 6 {
		t.Fatal(r.Authentication)
	}
	for _, a := range r.Authentication {
		if a.Trust != "untrusted_reported" || a.Verification != "unable_to_verify" || a.ID == "" || len(a.Limitations) != 1 {
			t.Fatal(a)
		}
	}
	first := r.Authentication[0]
	if first.Mechanism != "spf" || first.Result != "pass" || first.Server != "receiver.test" || !strings.Contains(first.Alignment, "smtp.mailfrom=other.test") {
		t.Fatal(first)
	}
	values := map[string]string{}
	var route []string
	for _, ev := range r.Evidence {
		values[ev.ID] = ev.Value
		if ev.Source == "Received" {
			route = append(route, ev.Value)
		}
	}
	if len(route) != 2 || !strings.Contains(route[0], "second.test by receiver") {
		t.Fatal(route)
	}
	if values["return-path-1"] == "" || values["message-id-1"] != "<m1@example.test>" || !strings.HasPrefix(values["date-1"], "2026-03-03T09:15:00") {
		t.Fatal(values)
	}
	if sig := values["dkim-signature-1"]; !strings.Contains(sig, "d=example.test") || !strings.Contains(sig, "not cryptographically verified") || strings.Contains(sig, "QQQQ") {
		t.Fatal(sig)
	}
	if !observed(r)["RETURN_PATH_DOMAIN_DIFFERS"] || !observed(r)["REPORTED_AUTHENTICATION_FAILURE"] {
		t.Fatal(r.Indicators)
	}
}

func TestTrustedReceiverAndReceivedSPF(t *testing.T) {
	TrustedAuthServers = []string{"MX.Own.Example"}
	defer func() { TrustedAuthServers = nil }()
	e, _ := emailparser.Parse([]byte("From: a@example.test\r\nAuthentication-Results: mx.own.example; dkim=pass header.d=example.test\r\nAuthentication-Results: mx.own.example; dmarc=pass\r\nReceived-SPF: softfail (domain of transitioning a@example.test) client-ip=192.0.2.1;\r\n\r\nbody"), "x.eml", "eml", "", "")
	r := Analyze(e)
	PrepareEvidence(&r)
	byMechanism := map[string]Authentication{}
	for _, a := range r.Authentication {
		byMechanism[a.Mechanism] = a
	}
	// Only the topmost header of the configured receiver is trusted; a lower
	// header naming the same server could have been inserted by the sender.
	if a := byMechanism["dkim"]; a.Trust != "trusted_reported" || a.Verification != "unable_to_verify" {
		t.Fatal(a)
	}
	if a := byMechanism["dmarc"]; a.Trust != "untrusted_reported" {
		t.Fatal(a)
	}
	if a := byMechanism["spf"]; a.Source != "Received-SPF" || a.Result != "softfail" || a.Trust != "untrusted_reported" {
		t.Fatal(a)
	}
}

func TestDKIMSignatureWithoutResultIsNotAPass(t *testing.T) {
	e, _ := emailparser.Parse([]byte("From: a@example.test\r\nDKIM-Signature: v=1; d=example.test; s=s1; b=abc\r\n\r\nbody"), "x.eml", "eml", "", "")
	r := Analyze(e)
	PrepareEvidence(&r)
	for _, a := range r.Authentication {
		if a.Result != "unavailable" {
			t.Fatal("result invented", a)
		}
		if a.Mechanism == "dkim" && (a.Source != "DKIM-Signature" || a.Limitations[0] != "DKIM_SIGNATURE_PRESENT_NOT_VERIFIED") {
			t.Fatal(a)
		}
	}
}

func TestEvidenceIsBoundedSanitizedAndSummarized(t *testing.T) {
	html := `<head><title>hidden-title</title></head><style>secret-style</style><script>secret-script</script><p>Actual message</p><a href="https://portal.example.test/login">Sign in</a>`
	for i := 0; i < 30; i++ {
		html += `<img src="https://cdn.example.test/i` + string(rune('a'+i%26)) + strings.Repeat("z", i) + `.png">`
	}
	r := Analyze(emailparser.Email{Subject: "S", Text: strings.Repeat("Қ", 20000), HTML: html, Attachments: []emailparser.Attachment{{Filename: "a.pdf", SHA256: strings.Repeat("a", 64)}}})
	r.AttachmentReputation = []virustotal.Result{{SHA256: strings.Repeat("a", 64), Status: "completed", Source: "VirusTotal API v3", Statistics: map[string]int{"malicious": 3}, Engines: make([]virustotal.Engine, 20)}}
	PrepareEvidence(&r)
	if strings.Contains(r.Email.HTML, "secret") || strings.Contains(r.Email.HTML, "hidden-title") || strings.Contains(r.Email.HTML, "<") || !strings.Contains(r.Email.HTML, "Actual message") || len(r.Email.Text) > 24000 {
		t.Fatal("unsafe or unbounded text")
	}
	if !strings.Contains(strings.Join(r.Limitations, ","), "MODEL_INPUT_TRUNCATED") {
		t.Fatal("missing truncation notice")
	}
	ids := map[string]string{}
	for _, ev := range r.Evidence {
		if ids[ev.ID] != "" {
			t.Fatal("duplicate evidence id", ev.ID)
		}
		ids[ev.ID] = ev.Value
		if strings.Contains(ev.Value, "cdn.example.test") {
			t.Fatal("embedded image listed as evidence")
		}
		if len(ev.Value) > 2048 {
			t.Fatal("unbounded evidence value")
		}
	}
	if !strings.Contains(ids["resources-1"], `"embedded_image":30`) || !strings.Contains(ids["link-1"], "portal.example.test") || !strings.Contains(ids["link-1"], "Sign in") {
		t.Fatal(ids)
	}
	if !strings.Contains(ids["reputation-1"], `"malicious":3`) || strings.Count(ids["reputation-1"], `"name"`) != 5 || ids["attachment-1"] == "" {
		t.Fatal(ids["reputation-1"])
	}
}
