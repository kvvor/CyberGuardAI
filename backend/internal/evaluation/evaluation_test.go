package evaluation

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/mockproviders"
	ai "cyberguard.local/backend/internal/openai"
)

func rules(r detection.Report) map[string]bool {
	seen := map[string]bool{}
	for _, f := range r.Indicators {
		seen[f.Rule] = true
	}
	return seen
}

// TestCorpusEvidence checks the deterministic layer only: which facts are
// recorded, that ordinary mail does not collect deception observations, and
// that nothing is scored.
func TestCorpusEvidence(t *testing.T) {
	ids := map[string]bool{}
	counts := map[string]int{}
	for _, c := range Corpus() {
		if ids[c.ID] {
			t.Fatalf("duplicate case %s", c.ID)
		}
		ids[c.ID] = true
		counts[c.Label]++
		r, err := Evidence(c)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		seen := rules(r)
		for _, rule := range c.MustObserve {
			if !seen[rule] {
				t.Errorf("%s: expected observation %s, got %v", c.ID, rule, seen)
			}
		}
		for _, rule := range c.MustNotObserve {
			if seen[rule] {
				t.Errorf("%s: false technical observation %s", c.ID, rule)
			}
		}
		if got := ai.AttachmentState(r); got != c.AttachmentState {
			t.Errorf("%s: attachment state %s, want %s", c.ID, got, c.AttachmentState)
		}
		if r.Score != 0 || r.Verdict != "inconclusive" || r.Version != detection.EvidenceVersion {
			t.Errorf("%s: evidence layer produced a score or verdict: %d %s", c.ID, r.Score, r.Verdict)
		}
		for _, f := range r.Indicators {
			if f.Severity != "info" || f.Status != "observed_not_a_verdict" {
				t.Errorf("%s: observation %s carries a severity or verdict", c.ID, f.Rule)
			}
		}
		input, err := ai.Input(r)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		// Attachment bytes and raw markup never reach the provider.
		if bytes.Contains(input, mockproviders.MaliciousFixture) || bytes.Contains(input, []byte("<form")) || bytes.Contains(input, []byte("<a href")) || bytes.Contains(input, []byte("JVBERi0")) {
			t.Errorf("%s: provider input contains attachment bytes or raw HTML", c.ID)
		}
		if c.Source == "paste" && !strings.Contains(strings.Join(r.Limitations, ","), "MISSING_EMAIL_HEADERS") {
			t.Errorf("%s: missing headers not reported", c.ID)
		}
	}
	if counts["legitimate"] < 8 || counts["phishing"] < 10 || counts["ambiguous"] < 4 {
		t.Fatalf("corpus too small: %v", counts)
	}
}

// TestSafeLinksCertificateRegression pins the historical false positive: a
// certificate notice with long Microsoft Safe Links must yield unwrapped
// destinations and no deception observation.
func TestSafeLinksCertificateRegression(t *testing.T) {
	for _, c := range Corpus() {
		if c.ID != "legit-certificate-safelinks" {
			continue
		}
		r, err := Evidence(c)
		if err != nil {
			t.Fatal(err)
		}
		wrapped, tracking, images := 0, 0, 0
		for _, l := range r.Links {
			if l.Wrapper == "microsoft_safelinks" && strings.HasPrefix(l.Destination, "https://www.netlearn.example/") {
				wrapped++
			}
			if l.Mismatch {
				t.Fatalf("mismatch reported for %+v", l)
			}
		}
		for _, i := range r.IOCs {
			switch i.Category {
			case "tracking_url":
				tracking++
			case "embedded_image":
				images++
			}
			if strings.Contains(i.Normalized, "safelinks.protection.outlook.com") {
				t.Fatalf("wrapper host kept as indicator: %s", i.Normalized)
			}
		}
		if wrapped != 2 || tracking != 1 || images != 1 {
			t.Fatalf("wrapped=%d tracking=%d images=%d", wrapped, tracking, images)
		}
		for _, e := range r.Evidence {
			if strings.Contains(e.Value, "track.netlearn.example") || strings.Contains(e.Value, "logo.png") {
				t.Fatalf("page furniture sent as evidence: %s", e.Value)
			}
		}
		return
	}
	t.Fatal("case missing")
}

// TestCorpusPipelineWithMockProvider proves that every case travels through
// request construction, the Responses envelope and backend validation. The
// mock is a fixed rule set, so its numbers say nothing about model accuracy.
func TestCorpusPipelineWithMockProvider(t *testing.T) {
	mock := &mockproviders.OpenAI{}
	server := httptest.NewServer(mock)
	defer server.Close()
	client := &ai.Client{Key: mockproviders.KeyValid, Model: "mock-assessment-large", BaseURL: server.URL}
	outcomes, failures := Run(context.Background(), client, Corpus())
	if len(failures) != 0 {
		t.Fatalf("validated pipeline rejected mock output: %v", failures)
	}
	if int(mock.Responses.Load()) != len(Corpus()) {
		t.Fatalf("expected one request per case, got %d", mock.Responses.Load())
	}
	t.Log("MOCK PROVIDER (not a model, not an accuracy measurement):\n" + Score(outcomes).String())
}

func TestMetrics(t *testing.T) {
	m := Score([]Outcome{
		{Label: "phishing", Verdict: "phishing"}, {Label: "phishing", Verdict: "suspicious"}, {Label: "phishing", Verdict: "legitimate"},
		{Label: "legitimate", Verdict: "legitimate"}, {Label: "legitimate", Verdict: "suspicious"},
		{Label: "legitimate", Verdict: "inconclusive"}, {Label: "phishing", Verdict: ""},
		{Label: "ambiguous", Verdict: "inconclusive"}, {Label: "ambiguous", Verdict: ""},
	})
	if m.TP != 2 || m.FN != 1 || m.TN != 1 || m.FP != 1 || m.Abstained != 2 || m.Evaluated != 7 {
		t.Fatalf("%+v", m)
	}
	if m.Precision() < 0.66 || m.Precision() > 0.67 || m.Recall() < 0.66 || m.Recall() > 0.67 || m.FalsePositiveRate() != 0.5 || m.Ambiguous["inconclusive"] != 1 || m.Ambiguous["no_assessment"] != 1 {
		t.Fatalf("%s", m)
	}
	if (Metrics{}).F1() != 0 || (Metrics{}).Precision() != 0 {
		t.Fatal("division by zero")
	}
}

// TestLiveEvaluation calls the real OpenAI API and therefore costs money. It
// runs only when explicitly enabled:
//
//	CYBERGUARD_LIVE_EVAL=1 OPENAI_API_KEY=... OPENAI_MODEL=... go test ./internal/evaluation -run TestLiveEvaluation -v
func TestLiveEvaluation(t *testing.T) {
	key, model := os.Getenv("OPENAI_API_KEY"), os.Getenv("OPENAI_MODEL")
	if os.Getenv("CYBERGUARD_LIVE_EVAL") != "1" || key == "" || model == "" {
		t.Skip("live evaluation not enabled (requires explicit authorization and incurs provider charges)")
	}
	client := &ai.Client{Key: key, Model: model, BaseURL: strings.TrimRight(os.Getenv("OPENAI_BASE_URL"), "/"), Timeout: 120 * time.Second}
	outcomes, failures := Run(context.Background(), client, Corpus())
	for _, o := range outcomes {
		t.Logf("%-32s label=%-10s verdict=%s %s", o.ID, o.Label, o.Verdict, failures[o.ID])
	}
	t.Logf("model %s on %d synthetic cases:\n%s", model, len(outcomes), Score(outcomes))
}
