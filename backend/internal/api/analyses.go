package api

import (
	"bytes"
	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/demo"
	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
	ai "cyberguard.local/backend/internal/openai"
	"cyberguard.local/backend/internal/reports"
	"cyberguard.local/backend/internal/repository"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-pdf/fpdf"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type stored struct {
	AIExecution     AIExecution         `json:"ai_execution"`
	TopFindings     []detection.Finding `json:"top_findings"`
	ID              string              `json:"id"`
	Mode            string              `json:"mode"`
	Created         time.Time           `json:"created_at"`
	Report          detection.Report    `json:"report"`
	AI              *ai.Assessment      `json:"ai_assessment,omitempty"`
	Status          string              `json:"status"`
	Explanations    map[string]string   `json:"explanations"`
	Recommendations map[string]string   `json:"recommendations"`
}

func (s *Server) analysisRoutes(p *mux.Router) {
	p.HandleFunc("/demo/samples", func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, demo.Samples()) }).Methods("GET")
	p.HandleFunc("/analyses", s.create).Methods("POST")
	p.HandleFunc("/analyses", s.history).Methods("GET")
	p.HandleFunc("/analyses/{id}", s.detail).Methods("GET", "DELETE")
	p.HandleFunc("/analyses/{id}/export", s.detail).Methods("GET")
	p.HandleFunc("/dashboard/stats", s.stats).Methods("GET")
}
func owner(r *http.Request) string { return r.Context().Value(key(0)).(auth.Session).User.ID }
func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, (10<<20)+65536)
	var e emailparser.Email
	var err error
	consent := false
	vtConsent := false
	requested := false
	demoID := ""
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err = r.ParseMultipartForm(1 << 20); err != nil {
			fail(w, r, 400, "INVALID_UPLOAD")
			return
		}
		defer r.MultipartForm.RemoveAll()
		consent = r.FormValue("external_processing_consent") == "true"
		vtConsent = r.FormValue("virustotal_consent") == "true"
		requested = r.FormValue("ai_requested") == "true" || consent
		f, h, x := r.FormFile("file")
		if x != nil {
			fail(w, r, 400, "INVALID_UPLOAD")
			return
		}
		defer f.Close()
		b, x := io.ReadAll(io.LimitReader(f, (10<<20)+1))
		if x != nil {
			fail(w, r, 400, "INVALID_UPLOAD")
			return
		}
		if strings.HasSuffix(strings.ToLower(h.Filename), ".msg") {
			e, err = emailparser.ParseMSG(b, h.Filename)
		} else {
			e, err = emailparser.Parse(b, h.Filename, "eml", "", "")
		}
	} else {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(w, r, 415, "UNSUPPORTED_MEDIA_TYPE")
			return
		}
		var in struct {
			Source      string `json:"source_type"`
			Text        string `json:"text"`
			Sender      string `json:"sender"`
			Subject     string `json:"subject"`
			Consent     bool   `json:"external_processing_consent"`
			VTConsent   bool   `json:"virustotal_consent"`
			AIRequested *bool  `json:"ai_requested"`
			DemoID      string `json:"demo_sample_id"`
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || (in.Source != "paste" && in.Source != "demo") {
			fail(w, r, 400, "INVALID_REQUEST")
			return
		}
		if len(in.Sender) > 1024 || len(in.Subject) > 4096 || (in.Source == "paste" && strings.TrimSpace(in.Text) == "") {
			fail(w, r, 400, "INVALID_REQUEST")
			return
		}
		e, err = emailparser.Parse([]byte(in.Text), "", "paste", in.Sender, in.Subject)
		consent = in.Consent
		vtConsent = in.VTConsent
		requested = consent
		if in.AIRequested != nil {
			requested = *in.AIRequested
		}
		if in.Source == "demo" {
			demoID = in.DemoID
			if demoID == "" {
				fail(w, r, 400, "UNKNOWN_DEMO_SAMPLE")
				return
			}
		}
	}
	if err != nil {
		fail(w, r, 400, err.Error())
		return
	}
	report := detection.Analyze(e)
	mode := "live"
	var assessment *ai.Assessment
	if demoID != "" {
		report, err = demo.Analyze(demoID)
		if err != nil {
			fail(w, r, 400, "UNKNOWN_DEMO_SAMPLE")
			return
		}
		mode = "demo"
		e = report.Email
	}
	execution := AIExecution{Status: "not_requested", StaticVerdict: report.Verdict, StaticScore: report.Score, Final: report.Verdict, Influence: "STATIC_ONLY"}
	if mode != "demo" {
		report.AttachmentReputation, report.VirusTotalStatus = s.executeVirusTotal(r.Context(), owner(r), vtConsent, report.Email.Attachments)
		execution, assessment = s.executeAI(r.Context(), owner(r), requested, consent, &report)
		report.AIStatus = execution.Status
		if execution.Failure != "" {
			report.Limitations = append(report.Limitations, execution.Failure)
		}
	}
	report.Email.Text = ""
	report.Email.HTML = ""
	report.Email.Headers = nil
	row := stored{ID: uuid.NewString(), Mode: mode, Created: time.Now().UTC(), Report: report, AI: assessment}
	row.AIExecution = execution
	row.TopFindings = report.Indicators
	if len(row.TopFindings) > 5 {
		row.TopFindings = row.TopFindings[:5]
	}
	row.Status = "partial"
	if mode == "demo" || assessment != nil {
		row.Status = "complete"
	}
	row.Explanations = map[string]string{}
	row.Recommendations = map[string]string{}
	for _, lang := range []string{"en", "ru", "kk"} {
		row.Explanations[lang], row.Recommendations[lang] = detection.Narrative(lang)
	}
	if mode == "live" && assessment == nil {
		row.Explanations = map[string]string{"en": "AI assessment was not completed. Review the provider execution status and extracted evidence.", "ru": "Анализ ИИ не завершён. Проверьте состояние провайдера и извлечённые данные.", "kk": "ЖИ талдауы аяқталмады. Провайдер күйін және алынған деректерді тексеріңіз."}
		row.Recommendations = map[string]string{}
	}
	if assessment != nil {
		row.Explanations = assessment.Explanations
		row.Recommendations = assessment.Recommendations
	}
	b, err := json.Marshal(row)
	if err != nil {
		fail(w, r, 500, "INTERNAL_ERROR")
		return
	}
	_, err = s.Auth.DB.Exec(r.Context(), `INSERT INTO analyses(id,user_id,mode,status,verdict,risk_score,risk_level,subject,sender,scoring_version,report,created_at) VALUES($1,$2,$3,$12,$4,$5,$6,$7,$8,$9,$10,$11)`, row.ID, owner(r), row.Mode, report.Verdict, report.Score, report.Level, e.Subject, e.Sender, report.Version, b, row.Created, row.Status)
	if err != nil {
		fail(w, r, 500, "INTERNAL_ERROR")
		return
	}
	JSON(w, 201, row)
}
func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, e := uuid.Parse(id); e != nil {
		fail(w, r, 404, "NOT_FOUND")
		return
	}
	if r.Method == "DELETE" {
		tag, e := s.Auth.DB.Exec(r.Context(), `DELETE FROM analyses WHERE id=$1 AND user_id=$2`, id, owner(r))
		if e != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		if tag.RowsAffected() == 0 {
			fail(w, r, 404, "NOT_FOUND")
			return
		}
		w.WriteHeader(204)
		return
	}
	var row stored
	var b []byte
	err := s.Auth.DB.QueryRow(r.Context(), `SELECT id,mode,created_at,report FROM analyses WHERE id=$1 AND user_id=$2`, id, owner(r)).Scan(&row.ID, &row.Mode, &row.Created, &b)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, r, 404, "NOT_FOUND")
		} else {
			fail(w, r, 500, "INTERNAL_ERROR")
		}
		return
	}
	if json.Unmarshal(b, &row) != nil {
		fail(w, r, 500, "INTERNAL_ERROR")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/export") {
		format := r.URL.Query().Get("format")
		lang := r.URL.Query().Get("lang")
		if lang == "" {
			lang = "en"
		}
		if lang != "en" && lang != "ru" && lang != "kk" {
			fail(w, r, 400, "INVALID_LANGUAGE")
			return
		}
		if format == "pdf" {
			data, e := pdfReport(row, lang)
			if e != nil {
				fail(w, r, 500, "EXPORT_FAILED")
				return
			}
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", `attachment; filename="cyberguard-report.pdf"`)
			w.Write(data)
			return
		}
		if format != "json" {
			fail(w, r, 400, "INVALID_FORMAT")
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="cyberguard-report.json"`)
	}
	JSON(w, 200, row)
}
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	f, e := repository.ParseHistory(r.URL.Query())
	if e != nil {
		fail(w, r, 400, "INVALID_FILTER")
		return
	}
	items, total, e := repository.History(r.Context(), s.Auth.DB, owner(r), f)
	if e != nil {
		fail(w, r, 500, "INTERNAL_ERROR")
		return
	}
	JSON(w, 200, map[string]any{"items": items, "total": total, "page": f.Page, "page_size": f.Size})
}
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	days := 30
	switch r.URL.Query().Get("period") {
	case "7":
		days = 7
	case "90":
		days = 90
	case "all":
		days = 36500
	case "", "30":
	default:
		fail(w, r, 400, "INVALID_PERIOD")
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "live"
	}
	if mode != "live" && mode != "demo" {
		fail(w, r, 400, "INVALID_FILTER")
		return
	}
	rows, e := s.Auth.DB.Query(r.Context(), `SELECT verdict,risk_level,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD'),count(*) FROM analyses WHERE user_id=$1 AND mode=$2 AND created_at>=$3 GROUP BY 1,2,3 ORDER BY 3`, owner(r), mode, time.Now().AddDate(0, 0, -days))
	if e != nil {
		fail(w, r, 500, "INTERNAL_ERROR")
		return
	}
	defer rows.Close()
	verdicts := map[string]int{"legitimate": 0, "suspicious": 0, "phishing": 0, "inconclusive": 0}
	risks := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	dates := map[string]int{}
	total := 0
	for rows.Next() {
		var v, l, d string
		var n int
		if rows.Scan(&v, &l, &d, &n) != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		verdicts[v] += n
		risks[l] += n
		dates[d] += n
		total += n
	}
	if rows.Err() != nil {
		fail(w, r, 500, "INTERNAL_ERROR")
		return
	}
	rows.Close()
	result := map[string]any{"total_analyses": total, "verdict_distribution": verdicts, "risk_distribution": risks, "activity": dates, "mode": mode}
	series := []map[string]any{}
	keys := []string{}
	for d := range dates {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	for _, d := range keys {
		series = append(series, map[string]any{"date": d, "count": dates[d]})
	}
	result["activity_series"] = series
	recent, _, err := repository.History(r.Context(), s.Auth.DB, owner(r), repository.HistoryFilter{Page: 1, Size: 5, Mode: mode, Sort: "newest"})
	if err != nil {
		fail(w, r, 500, "INTERNAL_ERROR")
		return
	}
	result["recent_analyses"] = recent
	for verdict, count := range verdicts {
		result[verdict+"_count"] = count
	}
	for _, group := range []struct{ name, path, field string }{{"common_indicators", "indicators", "rule_id"}, {"common_attack_types", "attack_types", ""}, {"mitre_frequency", "mitre_mappings", "technique_id"}} {
		expr := "item #>> '{}'"
		if group.field != "" {
			expr = "item ->> '" + group.field + "'"
		}
		query := `SELECT ` + expr + `,count(*) FROM analyses a CROSS JOIN LATERAL jsonb_array_elements(a.report->'report'->'` + group.path + `') item WHERE user_id=$1 AND mode=$2 AND created_at>=$3 GROUP BY 1 ORDER BY 2 DESC,1 LIMIT 10`
		rs, x := s.Auth.DB.Query(r.Context(), query, owner(r), mode, time.Now().AddDate(0, 0, -days))
		if x != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		values := []map[string]any{}
		for rs.Next() {
			var name string
			var count int
			if rs.Scan(&name, &count) != nil {
				rs.Close()
				fail(w, r, 500, "INTERNAL_ERROR")
				return
			}
			values = append(values, map[string]any{"name": name, "count": count})
		}
		x = rs.Err()
		rs.Close()
		if x != nil {
			fail(w, r, 500, "INTERNAL_ERROR")
			return
		}
		result[group.name] = values
	}
	JSON(w, 200, result)
}
func pdfReport(row stored, lang string) ([]byte, error) {
	p := fpdf.New("P", "mm", "A4", "")
	p.AddUTF8FontFromBytes("Go", "", reports.Font)
	p.SetFont("Go", "", 11)
	p.SetAutoPageBreak(true, 15)
	p.AddPage()
	title := map[string]string{"en": "Security report", "ru": "Отчёт безопасности", "kk": "Қауіпсіздік есебі"}[lang]
	line := func(s string) { p.MultiCell(180, 6, s, "", "", false) }
	line("CyberGuard AI — Security, made clear.")
	line(title)
	line("AI: " + row.AIExecution.Status + " / " + row.AIExecution.Provider + " / " + row.AIExecution.Model)
	if row.AIExecution.Failure != "" {
		line(row.AIExecution.Failure)
	}
	line(row.AIExecution.Influence)
	label := func(key string) string { return reports.Label(lang, key) }
	if row.Mode == "demo" {
		line(label("synthetic"))
	}
	line(label("id") + ": " + row.ID)
	line(label("date") + ": " + row.Created.Format(time.RFC3339))
	line(label("subject") + ": " + row.Report.Email.Subject)
	line(label("sender") + ": " + row.Report.Email.Sender)
	line(label("verdict") + ": " + label(row.Report.Verdict))
	if row.Report.Version != "3.0.0" {
		line(label("risk") + ": " + fmt.Sprintf("%d / %s", row.Report.Score, label(row.Report.Level)))
	} else if row.AI != nil {
		line(label(row.AI.Severity) + " / " + label(row.AI.Confidence))
	}
	explanation, recommendation := detection.Narrative(lang)
	if row.Report.Version == "3.0.0" {
		explanation = row.Explanations[lang]
		recommendation = row.Recommendations[lang]
	}
	if row.AI != nil {
		explanation = row.AI.Explanations[lang]
		recommendation = row.AI.Recommendations[lang]
	}
	line(label("explanation") + ": " + explanation)
	line(label("recommendations") + ": " + recommendation)
	for _, a := range row.Report.Authentication {
		line(a.Mechanism + ": " + a.Result + " / " + a.Trust + " / " + a.Verification)
	}
	if row.AI != nil {
		for _, id := range row.AI.Supporting {
			for _, e := range row.Report.Evidence {
				if e.ID == id {
					line(id + ": " + e.Value)
				}
			}
		}
		for _, o := range row.AI.Observations {
			line(o.Quote + " — " + o.Reason)
		}
	}
	line(label("indicators"))
	for _, f := range row.Report.Indicators {
		line(f.Code + ": " + f.Evidence)
	}
	line(label("iocs"))
	for _, x := range row.Report.IOCs {
		line(x.Type + ": " + x.Defanged)
	}
	line(label("attachments"))
	for _, a := range row.Report.Email.Attachments {
		line(fmt.Sprintf("%s (%d bytes) %s / %s SHA-256: %s", a.Filename, a.Size, a.Declared, a.Detected, a.SHA256))
		for _, reputation := range row.Report.AttachmentReputation {
			if reputation.SHA256 != a.SHA256 {
				continue
			}
			line("VirusTotal: " + reputation.Status)
			if reputation.Statistics != nil {
				line(fmt.Sprintf("malicious: %d; suspicious: %d; undetected: %d", reputation.Statistics["malicious"], reputation.Statistics["suspicious"], reputation.Statistics["undetected"]))
			}
			if reputation.LastAnalysis != nil {
				line(reputation.LastAnalysis.Format(time.RFC3339))
			}
			break
		}
	}
	line(label("mitre"))
	for _, m := range row.Report.MITRE {
		line(m.ID + " " + m.Name + " (" + m.Status + ")")
	}
	line(label("limitations"))
	for _, l := range row.Report.Limitations {
		line(l)
	}
	var b bytes.Buffer
	e := p.Output(&b)
	return b.Bytes(), e
}
