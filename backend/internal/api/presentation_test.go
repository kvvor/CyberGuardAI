package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"cyberguard.local/backend/internal/mockproviders"
)

// TestManualHashLookup: one explicit request makes one VirusTotal hash lookup
// under the user's key and allowance; nothing is uploaded or stored.
func TestManualHashLookup(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(), e.user()
	known := strings.Repeat("ab", 32)
	e.vt.Known[known] = map[string]int{"malicious": 0, "suspicious": 0, "harmless": 5, "undetected": 60}
	lookup := func(c *client, hash string) (int, map[string]any, string) {
		status, body := c.do("POST", "/reputation/virustotal", map[string]any{"sha256": hash})
		var out struct {
			Result map[string]any `json:"result"`
		}
		json.Unmarshal(body, &out)
		return status, out.Result, errorCode(body)
	}
	// Not configured, then disabled.
	if status, _, code := lookup(a, known); status != 409 || code != "PROVIDER_NOT_CONFIGURED" {
		t.Fatal(status, code)
	}
	a.must(200, "POST", "/settings/virustotal", map[string]any{"provider": "virustotal", "api_key": mockproviders.KeyValid, "enabled": false})
	if status, _, code := lookup(a, known); status != 409 || code != "PROVIDER_DISABLED" {
		t.Fatal(status, code)
	}
	a.must(200, "POST", "/settings/virustotal", map[string]any{"provider": "virustotal", "api_key": "", "enabled": true})
	// Input validation happens before any provider call.
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("a", 32), "../" + strings.Repeat("a", 61)} {
		if status, _, code := lookup(a, bad); status != 400 || code != "INVALID_SHA256" {
			t.Fatalf("%q: %d %s", bad, status, code)
		}
	}
	if e.vt.Calls.Load() != 0 {
		t.Fatal("provider called for invalid input")
	}
	// Known hash with no detections; upper-case and padded input is accepted.
	status, result, _ := lookup(a, "  "+strings.ToUpper(known)+" ")
	stats, _ := result["statistics"].(map[string]any)
	if status != 200 || result["status"] != "completed" || result["sha256"] != known || stats["harmless"] != float64(5) || stats["malicious"] != float64(0) || result["last_analysis_at"] == nil {
		t.Fatalf("%d %v", status, result)
	}
	// Detected and unknown hashes.
	if _, result, _ = lookup(a, mockproviders.MaliciousSHA256); result["status"] != "completed" || result["statistics"].(map[string]any)["malicious"] != float64(62) {
		t.Fatal(result)
	}
	if _, result, _ = lookup(a, strings.Repeat("c", 64)); result["status"] != "not_found" || result["statistics"] != nil {
		t.Fatal(result)
	}
	if e.vt.Calls.Load() != 3 || e.vt.Uploads.Load() != 0 {
		t.Fatal("unexpected provider traffic", e.vt.Calls.Load(), e.vt.Uploads.Load())
	}
	// The per-minute allowance is shared with attachment lookups: the fifth is not sent.
	lookup(a, strings.Repeat("d", 64))
	if status, result, _ = lookup(a, strings.Repeat("e", 64)); status != 200 || result["status"] != "deferred_local_limit" || e.vt.Calls.Load() != 4 {
		t.Fatalf("allowance bypassed: %v calls=%d", result, e.vt.Calls.Load())
	}
	// Nothing was written to the analysis history.
	if a.object(200, "GET", "/analyses", nil)["total"] != float64(0) {
		t.Fatal("lookup stored an analysis")
	}
	// Provider failures are reported as states, never as "clean".
	b.configure("", mockproviders.KeyInvalid)
	if _, result, _ = lookup(b, known); result["status"] != "authentication_failed" || result["statistics"] != nil {
		t.Fatal(result)
	}
	// Authentication and CSRF are required.
	valid := a.csrf
	a.csrf = "forged"
	if status, _, code := lookup(a, known); status != 403 || code != "CSRF_INVALID" {
		t.Fatal(status, code)
	}
	a.csrf = valid
	a.must(204, "POST", "/auth/logout", nil)
	if status, _, code := lookup(a, known); status != 401 || code != "UNAUTHENTICATED" {
		t.Fatal(status, code)
	}
}

// TestReportPresentationContract covers what the simplified report and the
// exports rely on: separated sender fields, per-method authentication,
// trilingual model text and no contradictory-evidence section in the export.
func TestReportPresentationContract(t *testing.T) {
	e := newEnv(t)
	a := e.user()
	a.configure(mockproviders.KeyValid, "")
	e.openai.Assess = func(doc map[string]any) map[string]any {
		out := mockproviders.Assess(doc)
		text := func(en string) map[string]string {
			return map[string]string{"en": en, "ru": "ru: " + en, "kk": "kk: " + en}
		}
		out["evidence_findings"] = []any{
			map[string]any{"evidence_ids": []string{"sender-1"}, "stance": "supporting", "explanation": text("sender finding")},
			map[string]any{"evidence_ids": []string{"subject-1"}, "stance": "contradictory", "explanation": text("weighed against")},
		}
		out["contextual_findings"] = []any{map[string]any{"type": "coercion", "quote": "Bitte bestätigen Sie Ihre Wallet", "source": "text_body", "reason": text("pressure to act"), "confidence": "medium"}}
		out["proposed_verdict"], out["severity"] = "suspicious", "medium"
		return out
	}
	raw := "From: Noreply@ledger.example | (ledger.example) #BIOH <emailfromweb3@ledgermail.onmicrosoft.example>\r\nSubject: =?utf-8?Q?Verd=C3=A4chtige_DEX-Aktivit=C3=A4t_erkannt?=\r\nAuthentication-Results: spf=pass (sender IP is 203.0.113.5) smtp.mailfrom=ledgermail.onmicrosoft.example; dkim=none; dmarc=bestguesspass action=none header.from=ledgermail.onmicrosoft.example\r\n\r\nBitte bestätigen Sie Ihre Wallet sofort."
	got := decodeAnalysis(t, a.must(201, "POST", "/analyses", file("ledger.eml", []byte(raw), map[string]string{"external_processing_consent": "true"})))
	if got.AI == nil {
		t.Fatalf("no assessment: %+v", got.AIExecution)
	}
	mail := got.Report.Email
	if mail.Subject != "Verdächtige DEX-Aktivität erkannt" || mail.RawSubject == "" || mail.SenderName != "Noreply@ledger.example | (ledger.example) #BIOH" || mail.SenderAddress != "emailfromweb3@ledgermail.onmicrosoft.example" {
		t.Fatalf("metadata: %+v", mail)
	}
	results := map[string]string{}
	for _, v := range got.Report.Authentication {
		results[v.Mechanism] = v.Result
		if v.Server != "" {
			t.Fatalf("reporting server %q invented for %s", v.Server, v.Mechanism)
		}
	}
	if results["spf"] != "pass" || results["dkim"] != "none" || results["dmarc"] != "bestguesspass" {
		t.Fatal(results)
	}
	// bestguesspass is never recorded as a DMARC pass.
	if got.AI.Authentication.DMARC != "reported_other" || got.AI.Authentication.SPF != "reported_pass" {
		t.Fatalf("%+v", got.AI.Authentication)
	}
	// The quote stays in its original language; its explanation exists in all three.
	o := got.AI.Observations[0]
	if o.Quote != "Bitte bestätigen Sie Ihre Wallet" || o.Reason["ru"] != "ru: pressure to act" || o.Reason["kk"] != "kk: pressure to act" || got.AI.Uncertainty[0]["ru"] == "" {
		t.Fatalf("%+v", o)
	}
	// Internally the contradictory finding is kept and validated.
	if len(got.AI.Contradictory) != 1 || len(got.AI.Findings) != 2 {
		t.Fatalf("%v %v", got.AI.Contradictory, got.AI.Findings)
	}
	// The user-facing export has no contradictory section but keeps all evidence.
	export := a.must(200, "GET", "/analyses/"+got.ID+"/export?format=json", nil)
	if bytes.Contains(export, []byte("contradictory")) || bytes.Contains(export, []byte("weighed against")) {
		t.Fatal("contradictory section exported")
	}
	if !bytes.Contains(export, []byte("sender finding")) || !bytes.Contains(export, []byte(`"id":"subject-1"`)) || !bytes.Contains(export, []byte("bestguesspass")) {
		t.Fatal("export lost evidence")
	}
	for _, lang := range []string{"en", "ru", "kk"} {
		if pdf := a.must(200, "GET", "/analyses/"+got.ID+"/export?format=pdf&lang="+lang, nil); !bytes.HasPrefix(pdf, []byte("%PDF")) {
			t.Fatal("pdf", lang)
		}
	}
	// A pasted message has no file name in the stored report.
	pasted := decodeAnalysis(t, a.must(201, "POST", "/analyses", map[string]any{"source_type": "paste", "text": "Registration for the competition is open until 30 March."}))
	if pasted.Report.Email.Filename != "" {
		t.Fatalf("file name %q for pasted text", pasted.Report.Email.Filename)
	}
}
