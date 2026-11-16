package detection

import (
	"encoding/json"
	"strings"
	"testing"

	"cyberguard.local/backend/internal/emailparser"
)

func prepared(t *testing.T, raw string) Report {
	t.Helper()
	e, err := emailparser.Parse([]byte(raw), "sample.eml", "eml", "", "")
	if err != nil {
		t.Fatal(err)
	}
	r := Analyze(e)
	PrepareEvidence(&r)
	return r
}

func byMechanism(r Report) map[string][]Authentication {
	out := map[string][]Authentication{}
	for _, a := range r.Authentication {
		out[a.Mechanism] = append(out[a.Mechanism], a)
	}
	return out
}

// Microsoft 365 writes Authentication-Results without a reporting server and
// with comments. The old parser took "spf=pass" for the server name, dropped
// the SPF result and showed "...reported by spf=pass" under the other methods.
func TestCompoundAuthenticationResultsAreMappedPerMethod(t *testing.T) {
	r := prepared(t, "From: Sender <a@contoso.example>\r\nAuthentication-Results: spf=pass (sender IP is 203.0.113.5; a=b) smtp.mailfrom=bounce.mailer.example; dkim=none (message not signed) header.d=none;dmarc=bestguesspass action=none header.from=contoso.example;compauth=pass reason=109\r\n\r\nbody")
	auth := byMechanism(r)
	if len(r.Authentication) != 3 || len(auth["spf"]) != 1 || len(auth["dkim"]) != 1 || len(auth["dmarc"]) != 1 {
		t.Fatalf("%+v", r.Authentication)
	}
	spf, dkim, dmarc := auth["spf"][0], auth["dkim"][0], auth["dmarc"][0]
	if spf.Result != "pass" || dkim.Result != "none" || dmarc.Result != "bestguesspass" {
		t.Fatalf("results mixed: spf=%s dkim=%s dmarc=%s", spf.Result, dkim.Result, dmarc.Result)
	}
	for _, a := range r.Authentication {
		// No method name or result may ever appear as the reporting server.
		if a.Server != "" || strings.Contains(a.Server, "=") {
			t.Fatalf("server %q for %s", a.Server, a.Mechanism)
		}
		if a.Trust != "untrusted_reported" || a.Verification != "unable_to_verify" || !strings.Contains(a.Raw, "compauth=pass") {
			t.Fatalf("%+v", a)
		}
	}
	// Each method keeps only its own properties.
	if !strings.Contains(spf.Alignment, "smtp.mailfrom=bounce.mailer.example") || strings.Contains(spf.Alignment, "header.from") {
		t.Fatal(spf.Alignment)
	}
	if !strings.Contains(dmarc.Alignment, "header.from=contoso.example") || strings.Contains(dmarc.Alignment, "mailfrom") {
		t.Fatal(dmarc.Alignment)
	}
	if strings.Join(dmarc.Limitations, ",") != "UPLOADED_HEADERS_CAN_BE_FORGED,DMARC_BESTGUESS_IS_NOT_A_POLICY_PASS" {
		t.Fatal(dmarc.Limitations)
	}
}

func TestAuthenticationResultVariants(t *testing.T) {
	cases := []struct {
		header              string
		server              string
		spf, dkim, dmarc    string
		methodsWithEvidence int
	}{
		{"mx.google.example; dkim=pass header.i=@a.example header.s=s1; spf=softfail (domain transitioning) smtp.mailfrom=a.example; dmarc=fail (p=REJECT) header.from=a.example", "mx.google.example", "softfail", "pass", "fail", 3},
		{"mx.example 1; spf=neutral; dkim=temperror; dmarc=permerror", "mx.example", "neutral", "temperror", "permerror", 3},
		{"mx.example; none", "mx.example", "unavailable", "unavailable", "unavailable", 0},
		{"mx.example; spf=none smtp.mailfrom=a.example", "mx.example", "none", "unavailable", "unavailable", 1},
		{"mx.example spf=pass smtp.mailfrom=a.example; dkim=fail", "mx.example", "pass", "fail", "unavailable", 2},
		{"; ;", "", "unavailable", "unavailable", "unavailable", 0},
	}
	for _, c := range cases {
		r := prepared(t, "From: a@a.example\r\nAuthentication-Results: "+c.header+"\r\n\r\nx")
		auth := byMechanism(r)
		got := map[string]string{}
		reported := 0
		for m, list := range auth {
			got[m] = list[0].Result
			for _, a := range list {
				if a.Result != "unavailable" {
					reported++
					if a.Server != c.server {
						t.Errorf("%q: server %q, want %q", c.header, a.Server, c.server)
					}
				}
			}
		}
		if got["spf"] != c.spf || got["dkim"] != c.dkim || got["dmarc"] != c.dmarc || reported != c.methodsWithEvidence || len(auth) != 3 {
			t.Errorf("%q: got %v (%d reported)", c.header, got, reported)
		}
	}
}

// Sanitised versions of the reports that motivated the display fixes.
func TestRealWorldSenderPresentations(t *testing.T) {
	// Ledger-themed phishing: brand and domain in the display name, unrelated sending address, German subject.
	ledger := prepared(t, "From: Noreply@ledger.example | (ledger.example) #BIOH <emailfromweb3-mexk8@ledgermail.onmicrosoft.example>\r\nSubject: =?utf-8?Q?Verd=C3=A4chtige_DEX-Aktivit=C3=A4t_erkannt_(#DE62U8Q2Q7?=\r\n\r\nBitte bestätigen Sie Ihre Wallet.")
	if ledger.Email.SenderName != "Noreply@ledger.example | (ledger.example) #BIOH" || ledger.Email.SenderAddress != "emailfromweb3-mexk8@ledgermail.onmicrosoft.example" {
		t.Fatalf("%q / %q", ledger.Email.SenderName, ledger.Email.SenderAddress)
	}
	// The subject is decoded for reading and left in its original language.
	if ledger.Email.Subject != "Verdächtige DEX-Aktivität erkannt (#DE62U8Q2Q7" {
		t.Fatal(ledger.Email.Subject)
	}
	if !observed(ledger)["DISPLAY_NAME_CONTAINS_OTHER_ADDRESS"] {
		t.Fatal(ledger.Indicators)
	}

	// Microsoft impersonation: lookalike letters in the display name, unrelated links, .mobileconfig attachments.
	microsoft := Analyze(emailparser.Email{
		Sender: "Micrоsоft Account Team <security@account-notice.example>",
		HTML:   `<a href="https://login.account-notice.example/verify">https://account.microsoft.com</a><a href="mailto:help@account-notice.example?subject=x">Contact us</a>`,
		Attachments: []emailparser.Attachment{
			{Filename: "Security-Update.mobileconfig", Declared: "application/x-apple-aspen-config", Detected: "text/xml; charset=utf-8", SHA256: strings.Repeat("a", 64)},
			{Filename: "Profile.mobileconfig", SHA256: strings.Repeat("b", 64)},
		},
	})
	seen := observed(microsoft)
	for _, rule := range []string{"DISPLAY_NAME_MIXES_ALPHABETS", "LINK_TEXT_SHOWS_DIFFERENT_HOST", "CONFIGURATION_PROFILE_ATTACHMENT"} {
		if !seen[rule] {
			t.Errorf("missing %s: %v", rule, seen)
		}
	}
	// A risky type is noted; it is not called executable or malicious.
	if seen["EXECUTABLE_ATTACHMENT_TYPE"] {
		t.Fatal("configuration profile labelled executable")
	}
	for _, f := range microsoft.Indicators {
		if f.Severity != "info" || f.Status != "observed_not_a_verdict" {
			t.Fatal("observation presented as a finding", f)
		}
	}
	// The mailto link is an address, not a web link.
	kinds := map[string]string{}
	for _, i := range microsoft.IOCs {
		kinds[i.Type+":"+i.Normalized] = i.Category
	}
	if kinds["email:help@account-notice.example"] != "email_address" || len(microsoft.Links) != 1 {
		t.Fatalf("%v %+v", kinds, microsoft.Links)
	}

	// Plausibly legitimate competition announcement pasted without headers:
	// nothing is observed and nothing about the sender is invented.
	pasted, _ := emailparser.Parse([]byte("Dear students,\n\nRegistration for the ICT Competition regional stage is open until 30 March. Details: https://e.huawei.example/en/talent/ict-academy\n\nGood luck!"), "", "paste", "", "")
	huawei := Analyze(pasted)
	PrepareEvidence(&huawei)
	if len(huawei.Indicators) != 0 || huawei.Email.SenderAddress != "" || huawei.Email.Filename != "" || len(huawei.Links) != 1 {
		t.Fatalf("%+v %+v", huawei.Indicators, huawei.Email)
	}
	for _, a := range huawei.Authentication {
		if a.Result != "unavailable" {
			t.Fatal("authentication invented for pasted text")
		}
	}
}

func TestDisplayNameObservationsAvoidOrdinaryNames(t *testing.T) {
	for _, sender := range []string{
		"Иван Петров <ivan@company.example>",
		"Анна (Northwind Support) <anna@northwind.example>",
		"Northwind via ticket.northwind.example <support@northwind.example>",
		"news@fabrikam.example <news@fabrikam.example>",
		"Jürgen Müller <j@firma.example>",
	} {
		seen := observed(Analyze(emailparser.Email{Sender: sender}))
		for _, rule := range []string{"DISPLAY_NAME_MIXES_ALPHABETS", "DISPLAY_NAME_SHOWS_OTHER_DOMAIN", "DISPLAY_NAME_CONTAINS_OTHER_ADDRESS"} {
			if seen[rule] {
				t.Errorf("%q flagged as %s", sender, rule)
			}
		}
	}
	if !observed(Analyze(emailparser.Email{Sender: "PayPal (paypal.com) <service@billing-desk.example>"}))["DISPLAY_NAME_SHOWS_OTHER_DOMAIN"] {
		t.Fatal("other domain in display name not recorded")
	}
}

func TestLinkAndResourceClassificationStaysSeparate(t *testing.T) {
	r := Analyze(emailparser.Email{
		Text: "See https://portal.example.org/a and https://portal.example.org/a again.",
		HTML: `<a href="https://portal.example.org/a">Portal</a>
<a href="mailto:Sales%40example.org?subject=Hi">sales</a><a href="MAILTO:sales@example.org">again</a>
<a href="tel:+100000000">call</a><a href="#top">top</a><a href="javascript:void(0)">x</a><a href="">empty</a>
<img src="https://cdn.example.org/logo.png"><img src="https://t.example.org/o.gif" width="1" height="1">
<link rel="stylesheet" href="https://cdn.example.org/s.css">
<p>-- <br>Jane Doe<br><a href="https://www.example.org">www.example.org</a></p>`,
	})
	counts := map[string]int{}
	for _, i := range r.IOCs {
		counts[i.Type+"/"+i.Category]++
	}
	want := map[string]int{"url/actionable_hyperlink": 2, "url/embedded_image": 1, "url/tracking_url": 1, "url/stylesheet": 1, "email/email_address": 1, "domain/email_domain": 1, "domain/link_host": 2}
	for k, n := range want {
		if counts[k] != n {
			t.Errorf("%s: %d, want %d (%v)", k, counts[k], n, counts)
		}
	}
	// Two clickable destinations (duplicates merged), no observation: a
	// signature link and embedded resources are not treated as deception.
	if len(r.Links) != 2 || len(r.Indicators) != 0 {
		t.Fatalf("links %+v observations %+v", r.Links, r.Indicators)
	}
}

func TestStoredSingleLanguageTextStaysReadable(t *testing.T) {
	var o Observation
	if err := json.Unmarshal([]byte(`{"type":"coercion","quote":"old quote","source":"text_body","reason":"English only reason","confidence":"low"}`), &o); err != nil {
		t.Fatal(err)
	}
	if o.Reason.In("ru") != "English only reason" || o.Reason.Complete(100) {
		t.Fatalf("%v", o.Reason)
	}
	if err := json.Unmarshal([]byte(`{"reason":{"en":"a","ru":"б","kk":"в"}}`), &o); err != nil || o.Reason.In("kk") != "в" || !o.Reason.Complete(10) {
		t.Fatal(o.Reason, err)
	}
}
