// Package mockproviders emulates the OpenAI Responses/Models API and the
// VirusTotal v3 file endpoint for automated tests and local end-to-end runs.
// It is a test double: its "assessment" is a fixed rule set, not a model, and
// it must never be presented as real provider output.
package mockproviders

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
)

// Special credentials that make the mocks reproduce provider failures.
const (
	KeyValid        = "mock-valid-key"
	KeyInvalid      = "mock-invalid-key"
	KeyQuota        = "mock-quota-key"
	KeyRateLimited  = "mock-rate-key"
	KeyMalformed    = "mock-malformed-key"
	KeyInvented     = "mock-invented-evidence-key"
	KeyOverclaiming = "mock-overclaim-key"
	KeyServerError  = "mock-server-error-key"
)

// MaliciousFixture is harmless text. The VirusTotal mock reports detections for
// its SHA-256 so that the detection path can be exercised without malware (and
// without an antivirus test string that scanners would quarantine).
var MaliciousFixture = []byte("CYBERGUARD MOCK FIXTURE: this harmless text stands in for a malicious attachment.")

// MaliciousSHA256 is the lower-case SHA-256 of MaliciousFixture.
var MaliciousSHA256 = func() string { h := sha256.Sum256(MaliciousFixture); return hex.EncodeToString(h[:]) }()

type OpenAI struct {
	Models []string
	// Assess builds the model output for an input document; defaults to Assess.
	Assess func(doc map[string]any) map[string]any
	// Inspect, when set, sees every request body sent to /responses.
	Inspect       func(request map[string]any)
	Responses     atomic.Int64
	MetadataCalls atomic.Int64
}

func openAIError(w http.ResponseWriter, status int, code, kind string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "mock " + code, "type": kind, "code": code}})
}

func localized(en, ru, kk string) map[string]string {
	return map[string]string{"en": en, "ru": ru, "kk": kk}
}

// Output returns a schema-complete model output that tests can adjust.
func Output(verdict, severity, confidence string) map[string]any {
	return map[string]any{
		"proposed_verdict":            verdict,
		"severity":                    severity,
		"confidence":                  confidence,
		"suspected_attack_types":      []string{},
		"social_engineering_patterns": []string{},
		"evidence_findings":           []any{},
		"contextual_findings":         []any{},
		"authentication_assessment":   map[string]any{"spf": "not_available", "dkim": "not_available", "dmarc": "not_available", "independently_verified": false},
		"attachment_assessment":       "no_attachments",
		"uncertainty_notes":           []string{"Mock provider: fixed rules, not a language model."},
		"explanations":                localized("Mock assessment.", "Тестовая оценка.", "Сынақ бағасы."),
		"recommendations":             localized("Review the evidence.", "Проверьте данные.", "Деректерді тексеріңіз."),
	}
}

func finding(stance string, ids []string, en, ru, kk string) map[string]any {
	return map[string]any{"evidence_ids": ids, "stance": stance, "explanation": localized(en, ru, kk)}
}

// Assess is the default deterministic stand-in for a model. It only cites
// evidence identifiers present in the input and mirrors the reported
// authentication and attachment state, so its output passes backend validation.
func Assess(doc map[string]any) map[string]any {
	ids := map[string]string{}
	sources := map[string]string{}
	if list, ok := doc["evidence"].([]any); ok {
		for _, item := range list {
			if e, ok := item.(map[string]any); ok {
				id, _ := e["id"].(string)
				ids[id], _ = e["value"].(string)
				sources[id], _ = e["source"].(string)
			}
		}
	}
	state, _ := doc["attachment_reputation_state"].(string)
	out := Output("legitimate", "none", "medium")
	out["attachment_assessment"] = state
	auth := map[string]any{"spf": "not_available", "dkim": "not_available", "dmarc": "not_available", "independently_verified": false}
	if list, ok := doc["authentication"].([]any); ok {
		for _, item := range list {
			a, _ := item.(map[string]any)
			mechanism, _ := a["mechanism"].(string)
			switch result, _ := a["reported_result"].(string); result {
			case "pass":
				if auth[mechanism] == "not_available" {
					auth[mechanism] = "reported_pass"
				}
			case "fail", "hardfail", "permerror":
				auth[mechanism] = "reported_fail"
			case "unavailable", "":
			default:
				if auth[mechanism] != "reported_fail" {
					auth[mechanism] = "reported_other"
				}
			}
		}
	}
	out["authentication_assessment"] = auth
	findings := []any{}
	phishing := false
	for id, source := range sources {
		switch {
		case strings.HasPrefix(id, "reputation-") && state == "detections_reported" && strings.Contains(ids[id], `"malicious":`) && !strings.Contains(ids[id], `"malicious":0`):
			phishing = true
			out["suspected_attack_types"] = []string{"suspected_malware_delivery"}
			findings = append(findings, finding("supporting", []string{id}, "The provider reports detections for this attachment hash.", "Провайдер сообщает об обнаружениях для хеша вложения.", "Провайдер тіркеме хеші бойынша анықтауларды хабарлайды."))
		case strings.HasSuffix(source, "LINK_TEXT_SHOWS_DIFFERENT_HOST") || strings.HasSuffix(source, "LINK_TO_IP_ADDRESS") || strings.HasSuffix(source, "HTML_FORM_SUBMITS_TO_URL"):
			phishing = true
			out["suspected_attack_types"] = []string{"credential_phishing"}
			findings = append(findings, finding("supporting", []string{id}, "The link destination does not match what the reader is shown.", "Адрес ссылки не совпадает с тем, что видит читатель.", "Сілтеме мекенжайы оқырманға көрсетілгенге сәйкес келмейді."))
		case strings.HasSuffix(source, "TEXT_ADDRESSED_TO_AUTOMATED_ANALYSIS"):
			phishing = true
			findings = append(findings, finding("supporting", []string{id}, "The message tries to instruct the analysis system.", "Письмо пытается управлять системой анализа.", "Хат талдау жүйесін басқаруға тырысады."))
		}
	}
	switch {
	case phishing:
		out["proposed_verdict"], out["severity"], out["confidence"] = "phishing", "high", "medium"
		out["explanations"] = localized("Mock: deceptive technical evidence was found.", "Тест: найдены обманные технические признаки.", "Сынақ: алдамшы техникалық белгілер табылды.")
		out["recommendations"] = localized("Do not open links or attachments; report the message.", "Не открывайте ссылки и вложения; сообщите о письме.", "Сілтемелер мен тіркемелерді ашпаңыз; хат туралы хабарлаңыз.")
	case ids["sender-1"] == "":
		out["proposed_verdict"], out["severity"], out["confidence"] = "inconclusive", "low", "low"
		out["explanations"] = localized("Mock: no sender or headers, evidence is insufficient.", "Тест: нет отправителя и заголовков, данных недостаточно.", "Сынақ: жіберуші мен тақырыптар жоқ, деректер жеткіліксіз.")
	default:
		findings = append(findings, finding("supporting", []string{"sender-1"}, "The sender information is consistent with an ordinary message.", "Данные отправителя соответствуют обычному письму.", "Жіберуші деректері кәдімгі хатқа сәйкес келеді."))
	}
	out["evidence_findings"] = findings
	return out
}

// Envelope wraps model output in a Responses API result.
func Envelope(output map[string]any) map[string]any {
	text, _ := json.Marshal(output)
	return map[string]any{"id": "resp_mock", "object": "response", "status": "completed", "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": string(text)}}}}, "usage": map[string]any{"input_tokens": 100, "output_tokens": 50, "total_tokens": 150}}
}

func (m *OpenAI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch key {
	case KeyInvalid, "":
		openAIError(w, 401, "invalid_api_key", "invalid_request_error")
		return
	case KeyQuota:
		if strings.HasSuffix(r.URL.Path, "/responses") {
			openAIError(w, 429, "insufficient_quota", "insufficient_quota")
			return
		}
	case KeyRateLimited:
		if strings.HasSuffix(r.URL.Path, "/responses") {
			openAIError(w, 429, "rate_limit_exceeded", "rate_limit_error")
			return
		}
	case KeyServerError:
		if strings.HasSuffix(r.URL.Path, "/responses") {
			openAIError(w, 500, "server_error", "server_error")
			return
		}
	}
	models := m.Models
	if len(models) == 0 {
		models = []string{"mock-assessment-large", "mock-assessment-small", "mock-text-embedding"}
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/models"):
		m.MetadataCalls.Add(1)
		data := []any{}
		for i, id := range models {
			data = append(data, map[string]any{"id": id, "object": "model", "created": 1700000000 - i, "owned_by": "mock"})
		}
		json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/models/"):
		m.MetadataCalls.Add(1)
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		for _, known := range models {
			if known == id {
				json.NewEncoder(w).Encode(map[string]any{"id": id, "object": "model"})
				return
			}
		}
		openAIError(w, 404, "model_not_found", "invalid_request_error")
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/responses"):
		m.Responses.Add(1)
		var request map[string]any
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if json.Unmarshal(body, &request) != nil {
			openAIError(w, 400, "invalid_json", "invalid_request_error")
			return
		}
		if m.Inspect != nil {
			m.Inspect(request)
		}
		model, _ := request["model"].(string)
		known := false
		for _, id := range models {
			known = known || id == model
		}
		if !known {
			openAIError(w, 404, "model_not_found", "invalid_request_error")
			return
		}
		var doc map[string]any
		input, _ := request["input"].(string)
		json.Unmarshal([]byte(input), &doc)
		assess := m.Assess
		if assess == nil {
			assess = Assess
		}
		out := assess(doc)
		switch key {
		case KeyMalformed:
			json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"content": []any{map[string]any{"type": "output_text", "text": "{\"proposed_verdict\":\"legitimate\""}}}}})
			return
		case KeyInvented:
			out["proposed_verdict"] = "legitimate"
			out["evidence_findings"] = []any{finding("supporting", []string{"dkim-verified-99"}, "invented", "выдумано", "ойдан шығарылған")}
		case KeyOverclaiming:
			out["authentication_assessment"] = map[string]any{"spf": "reported_pass", "dkim": "reported_pass", "dmarc": "reported_pass", "independently_verified": true}
		}
		json.NewEncoder(w).Encode(Envelope(out))
	default:
		openAIError(w, 404, "not_found", "invalid_request_error")
	}
}

type VirusTotal struct {
	// Known maps lower-case SHA-256 to last_analysis_stats. MaliciousSHA256 is built in.
	Known map[string]map[string]int
	Calls atomic.Int64
	// Uploads counts any request that is not a hash lookup; it must stay zero.
	Uploads atomic.Int64
}

func (m *VirusTotal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet || r.ContentLength > 0 || !strings.Contains(r.URL.Path, "/files/") {
		m.Uploads.Add(1)
		w.WriteHeader(405)
		return
	}
	m.Calls.Add(1)
	switch r.Header.Get("x-apikey") {
	case KeyValid:
	case KeyRateLimited, KeyQuota:
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "QuotaExceededError"}})
		return
	case KeyServerError:
		w.WriteHeader(503)
		return
	default:
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "WrongCredentialsError"}})
		return
	}
	hash := strings.ToLower(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
	stats, ok := m.Known[hash]
	if !ok && hash == MaliciousSHA256 {
		stats, ok = map[string]int{"malicious": 62, "suspicious": 0, "harmless": 0, "undetected": 8}, true
	}
	if !ok {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "NotFoundError"}})
		return
	}
	results := map[string]any{}
	if stats["malicious"] > 0 {
		results["MockEngine"] = map[string]any{"category": "malicious", "result": "Mock.Test.Detection"}
	}
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": hash, "type": "file", "attributes": map[string]any{"sha256": hash, "last_analysis_stats": stats, "last_analysis_date": 1700000000, "last_analysis_results": results}}})
}
