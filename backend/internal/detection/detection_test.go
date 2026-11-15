package detection

import (
	"cyberguard.local/backend/internal/emailparser"
	"testing"
)

func TestPhishing(t *testing.T) {
	r := Analyze(emailparser.Email{Sender: "CEO <ceo@example.com>", ReplyTo: "criminal@evil.example", Text: "Urgent: verify your password immediately at https://192.0.2.1/login"})
	if r.Verdict != "inconclusive" || r.Score != 0 || len(r.IOCs) < 2 {
		t.Fatalf("unexpected: %+v", r)
	}
}
func TestInsufficient(t *testing.T) {
	r := Analyze(emailparser.Email{Text: "Hello"})
	if r.Verdict != "inconclusive" {
		t.Fatal("invented certainty")
	}
	if Defang("https://example.com") != "hxxps://example[.]com" {
		t.Fatal("defang")
	}
}
