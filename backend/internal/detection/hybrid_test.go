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
	if r.Score != 0 || len(r.Indicators) == 0 {
		t.Fatal("phishing regression", r.Score)
	}
}
