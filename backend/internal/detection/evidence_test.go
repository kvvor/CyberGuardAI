package detection

import (
	"cyberguard.local/backend/internal/emailparser"
	"strings"
	"testing"
)

func TestEvidenceNeverUsesBodyAuthenticationOrWeights(t *testing.T) {
	e, _ := emailparser.Parse([]byte("Urgent: spf=pass dkim=pass dmarc=pass. Please verify your password."), "", "paste", "", "")
	r := Analyze(e)
	PrepareEvidence(&r)
	if r.Score != 0 || r.Verdict != "inconclusive" || r.Version != "3.0.0" {
		t.Fatal(r)
	}
	for _, a := range r.Authentication {
		if a.Trust != "unavailable" {
			t.Fatal(a)
		}
	}
	for _, f := range r.Indicators {
		if f.Rule == "URGENCY" || f.Rule == "CREDENTIAL_REQUEST" {
			t.Fatal("keyword judgment retained")
		}
	}
}

func TestAuthenticationIsUntrustedAndRoutingOrderPreserved(t *testing.T) {
	e, err := emailparser.Parse([]byte("From: Sender <sender@example.test>\r\nAuthentication-Results: receiver.test; spf=pass smtp.mailfrom=other.test; dkim=fail; dmarc=fail\r\nReceived: from second.test by receiver.test\r\nReceived: from first.test by second.test\r\n\r\nHello"), "sample.eml", "eml", "", "")
	if err != nil {
		t.Fatal(err)
	}
	r := Analyze(e)
	PrepareEvidence(&r)
	if len(r.Authentication) != 3 {
		t.Fatal(r.Authentication)
	}
	for _, a := range r.Authentication {
		if a.Trust != "untrusted_reported" || a.Verification != "unable_to_verify" || a.Server != "receiver.test" {
			t.Fatal(a)
		}
	}
	var route []string
	for _, e := range r.Evidence {
		if e.Source == "Received" {
			route = append(route, e.Value)
		}
	}
	if len(route) != 2 || !strings.Contains(route[0], "second.test by receiver") {
		t.Fatal(route)
	}
}

func TestEvidenceHTMLAndTruncation(t *testing.T) {
	r := Analyze(emailparser.Email{Text: strings.Repeat("Қ", 20000), HTML: `<style>secret-style</style><script>secret-script</script><p>Actual message</p><img src="https://example.test/pixel">`})
	PrepareEvidence(&r)
	if strings.Contains(r.Email.HTML, "secret") || !strings.Contains(r.Email.HTML, "Actual message") || len(r.Email.Text) > 24000 {
		t.Fatal("unsafe text")
	}
	if !strings.Contains(strings.Join(r.Limitations, ","), "TRUNCATED") {
		t.Fatal("missing truncation notice")
	}
}
