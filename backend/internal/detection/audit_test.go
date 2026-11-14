package detection

import (
	"cyberguard.local/backend/internal/emailparser"
	"testing"
)

func TestObservableSpoofingAndIOCs(t *testing.T) {
	r := Analyze(emailparser.Email{Sender: `"billing@paypal.com" <billing@paypa1.com>`, Text: "Connect to 2001:db8::1 or 192.0.2.3. Contact analyst@example.test."})
	rules := map[string]bool{}
	for _, f := range r.Indicators {
		rules[f.Rule] = true
	}
	if !rules["DISPLAY_NAME_SPOOFING"] || !rules["LOOKALIKE_DOMAIN"] {
		t.Fatal(r.Indicators)
	}
	values := map[string]bool{}
	for _, i := range r.IOCs {
		values[i.Normalized] = true
	}
	for _, v := range []string{"2001:db8::1", "192.0.2.3", "example.test"} {
		if !values[v] {
			t.Fatal("missing IOC", v)
		}
	}
}
func TestUntrustedAuthentication(t *testing.T) {
	r := Analyze(emailparser.Email{AuthenticationResults: []string{"attacker.example; spf=fail"}})
	if len(r.Indicators) != 1 || r.Indicators[0].Source != "untrusted_header" || r.Score > 5 || r.Verdict != "inconclusive" {
		t.Fatal(r)
	}
}
