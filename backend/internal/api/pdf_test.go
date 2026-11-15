package api

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
	ai "cyberguard.local/backend/internal/openai"
	"cyberguard.local/backend/internal/reports"
	"cyberguard.local/backend/internal/virustotal"
)

func TestPDFHandlesHostileAndEmptyContent(t *testing.T) {
	long := "https://very-long.example/" + strings.Repeat("segment-without-spaces-", 120)
	analysed := time.Date(2026, 3, 3, 9, 0, 0, 0, time.UTC)
	full := stored{ID: "11111111-1111-1111-1111-111111111111", Created: analysed, Status: "complete",
		AIExecution: AIExecution{Status: "completed", Model: "model-x", Provider: "openai"},
		AI: &ai.Assessment{Verdict: "phishing", Severity: "high", Confidence: "medium",
			Findings:        []ai.EvidenceFinding{{EvidenceIDs: []string{"link-1", "missing-id"}, Stance: "supporting", Explanation: map[string]string{"en": "Deceptive link", "ru": "Обманная ссылка", "kk": "Алдамшы сілтеме"}}, {EvidenceIDs: []string{"sender-1"}, Stance: "contradictory", Explanation: map[string]string{"en": "Known sender"}}},
			Observations:    []detection.Observation{{Quote: "confirm ‮your password 😀", Reason: "asks for a secret"}},
			Uncertainty:     []string{"headers unverified"},
			Explanations:    map[string]string{"en": "Summary", "ru": "Кратко: фишинг", "kk": "Қысқаша: фишинг ӘәҒғҚқҢңӨөҰұҮүҺһІі"},
			Recommendations: map[string]string{"en": "Do not click", "ru": "Не переходите", "kk": "Баспаңыз"}},
		Report: detection.Report{Version: detection.EvidenceVersion, Verdict: "phishing", VirusTotalStatus: "partial",
			Email:                emailparser.Email{Subject: "Тема \x00\x07 with control characters", Sender: "Жіберуші <a@example.test>", Recipients: []string{"b@example.test"}, Timestamp: &analysed, Attachments: []emailparser.Attachment{{Filename: "файл.pdf", Size: 10, SHA256: strings.Repeat("a", 64)}, {Filename: "b.bin", SHA256: strings.Repeat("b", 64)}}},
			Evidence:             []detection.Evidence{{ID: "link-1", Value: long}, {ID: "sender-1", Value: "a@example.test"}},
			Authentication:       []detection.Authentication{{Mechanism: "spf", Result: "pass", Server: "mx.example.test", Trust: "untrusted_reported", Verification: "unable_to_verify"}, {Mechanism: "dkim", Result: "unavailable", Trust: "unavailable", Verification: "unavailable"}},
			AttachmentReputation: []virustotal.Result{{SHA256: strings.Repeat("a", 64), Status: "completed", Statistics: map[string]int{"malicious": 3, "harmless": 1}, LastAnalysis: &analysed}, {SHA256: strings.Repeat("b", 64), Status: "deferred_local_limit"}},
			IOCs:                 []detection.IOC{{Type: "url", Defanged: detection.Defang(long), Category: "actionable_hyperlink"}, {Type: "url", Defanged: "hxxps://cdn[.]example/x.png", Category: "embedded_image"}},
			Indicators:           []detection.Finding{{Code: "LINK_TEXT_SHOWS_DIFFERENT_HOST", Evidence: long}, {Code: "RETIRED_UNKNOWN_CODE", Evidence: "x"}},
			Limitations:          []string{"AUTHENTICATION_NOT_INDEPENDENTLY_VERIFIED", "SOME_FUTURE_CODE"}}}
	incomplete := stored{ID: "22222222-2222-2222-2222-222222222222", Created: analysed, Status: "partial", AIExecution: AIExecution{Status: "quota_exceeded", Failure: "PROVIDER_INSUFFICIENT_QUOTA"}, Explanations: incompleteExplanation, Report: detection.Report{Version: detection.EvidenceVersion, Verdict: "inconclusive"}}
	legacy := stored{ID: "33333333-3333-3333-3333-333333333333", Created: analysed, Report: detection.Report{Version: "2.0.0", Verdict: "phishing", Score: 85, Level: "high", Email: emailparser.Email{AuthenticationResults: []string{"mx; spf=fail"}}, IOCs: []detection.IOC{{Type: "url", Defanged: "hxxps://192[.]0[.]2[.]1"}}}}
	empty := stored{}
	for name, row := range map[string]stored{"full": full, "incomplete": incomplete, "legacy": legacy, "empty": empty} {
		for _, lang := range []string{"en", "ru", "kk"} {
			b, err := pdfReport(row, lang)
			if err != nil || !bytes.HasPrefix(b, []byte("%PDF")) || !bytes.Contains(b[len(b)-32:], []byte("%%EOF")) {
				t.Fatalf("%s/%s: %v", name, lang, err)
			}
		}
	}
	if printable("a\x00b‮c\n😀") != "abc ?" {
		t.Fatalf("%q", printable("a\x00b‮c\n😀"))
	}
}

func TestStripNUL(t *testing.T) {
	cases := map[string]string{
		`{"a":"x\u0000y"}`:         `{"a":"xy"}`,
		`{"a":"back\\u0000slash"}`: `{"a":"back\\u0000slash"}`,
		`{"a":"q\"\u0000"}`:        `{"a":"q\""}`,
		`{"a":"\u0001"}`:           `{"a":"\u0001"}`,
	}
	for in, want := range cases {
		if got := string(stripNUL([]byte(in))); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

// Every label must exist in all three languages.
func TestReportLabelsAreTranslated(t *testing.T) {
	for _, key := range reports.Keys() {
		for _, lang := range []string{"en", "ru", "kk"} {
			if strings.TrimSpace(reports.Label(lang, key)) == "" {
				t.Errorf("%s has no %s label", key, lang)
			}
		}
	}
	if reports.Label("ru", "RETIRED_CODE") != "RETIRED_CODE" || reports.Label("en", "status_future_state") != "future_state" {
		t.Fatal("unknown codes must stay readable")
	}
	for status := range executionStatus {
		if reports.Label("en", status) == status {
			t.Errorf("failure code %s has no label", status)
		}
	}
	for _, status := range executionStatus {
		if reports.Label("en", "status_"+status) == status && status != "timeout" {
			t.Errorf("execution state %s has no label", status)
		}
	}
}
