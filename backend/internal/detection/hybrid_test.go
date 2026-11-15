package detection

import (
	"cyberguard.local/backend/internal/emailparser"
	"net/url"
	"strings"
	"testing"
)

func TestSafeLinksRegression(t *testing.T) {
	for _, host := range []string{"www.cisco.com", "www.netacad.com", "www.credly.com"} {
		destination := "https://" + host + "/certification?token=" + strings.Repeat("a", 600)
		wrapper := "https://nam01.safelinks.protection.outlook.com/?url=" + url.QueryEscape(destination) + "&amp;data=synthetic"
		r := Analyze(emailparser.Email{HTML: `<a href="` + wrapper + `">https://` + host + `</a><img src="https://cdn.example.test/logo.png">`})
		if r.Score != 0 {
			t.Fatalf("false positive: %+v", r.Indicators)
		}
		found := false
		for _, i := range r.IOCs {
			if i.Category == "security_wrapped" && i.Normalized == destination {
				found = true
			}
		}
		if !found {
			t.Fatal("wrapper evidence missing")
		}
	}
	r := Analyze(emailparser.Email{Text: "verify your password immediately https://192.0.2.1/login"})
	if r.Score < 60 {
		t.Fatal("phishing regression", r.Score)
	}
}
func TestHybridEvidence(t *testing.T) {
	email := emailparser.Email{Sender: "analyst@example.test", Headers: map[string][]string{"From": {"analyst@example.test"}}, Text: "Please send your account secret. Transfer money to my new account."}
	r := Analyze(email)
	obs := []Observation{{Type: "credential_theft", Quote: "Please send your account secret.", Source: "text_body", Reason: "Requests a secret", Confidence: "high"}, {Type: "payment_diversion", Quote: "Transfer money to my new account.", Source: "text_body", Reason: "Redirects payment", Confidence: "high"}}
	Hybrid(&r, "phishing", obs)
	if r.Verdict != "phishing" || r.Score != 60 {
		t.Fatal(r)
	}
	obs[0].Quote = "invented quotation"
	if ValidateObservations(r, obs) == nil {
		t.Fatal("fabrication accepted")
	}
	r = Analyze(emailparser.Email{Sender: "analyst@example.test", Headers: map[string][]string{"From": {"analyst@example.test"}}, Text: "Your certification has been issued."})
	Hybrid(&r, "legitimate", []Observation{{Type: "benign_context", Source: "text_body", Quote: "Your certification has been issued.", Reason: "Informational message", Confidence: "high"}})
	if r.Verdict != "legitimate" {
		t.Fatal(r)
	}
	r = Analyze(emailparser.Email{Text: "Your certification has been issued."})
	Hybrid(&r, "legitimate", nil)
	if r.Verdict != "inconclusive" {
		t.Fatal("missing evidence ignored")
	}
}
