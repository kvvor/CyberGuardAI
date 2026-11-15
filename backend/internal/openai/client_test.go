package openai

import (
	"context"
	"cyberguard.local/backend/internal/detection"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidAndRetry(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(429)
			return
		}
		var request map[string]any
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid request")
		}
		if request["store"] != false || request["tools"] != nil || !strings.Contains(request["instructions"].(string), "untrusted") {
			t.Error("unsafe request")
		}
		a := Assessment{Observations: []detection.Observation{}, Verdict: "inconclusive", AttackTypes: []string{}, Patterns: []string{}, Supporting: []string{}, Contradictory: []string{}, Uncertainty: []string{"limited"}, Explanations: map[string]string{"en": "uncertain", "ru": "неясно", "kk": "белгісіз"}, Recommendations: map[string]string{"en": "review", "ru": "проверить", "kk": "тексеру"}}
		b, _ := json.Marshal(a)
		json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"content": []any{map[string]any{"type": "output_text", "text": string(b)}}}}})
	}))
	defer ts.Close()
	c := Client{Key: "test", Model: "test", Endpoint: ts.URL}
	a, e := c.Assess(context.Background(), detection.Report{})
	if e != nil || a.Verdict != "inconclusive" || calls != 2 {
		t.Fatal(a, e, calls)
	}
}

func TestFailures(t *testing.T) {
	for _, body := range []string{`{"status":"completed","output":[{"content":[{"type":"refusal","refusal":"no"}]}]}`, `{"status":"completed","output":[{"content":[{"type":"output_text","text":"{}"}]}]}`, `{"status":"incomplete"}`} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c := Client{Key: "test", Model: "test", Endpoint: ts.URL}
		if _, e := c.Assess(context.Background(), detection.Report{}); e == nil {
			t.Fatal("invalid response accepted")
		}
		ts.Close()
	}
}
