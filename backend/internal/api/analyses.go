package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
	ai "cyberguard.local/backend/internal/openai"
	"cyberguard.local/backend/internal/repository"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
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
	p.HandleFunc("/analyses", s.create).Methods("POST")
	p.HandleFunc("/analyses", s.history).Methods("GET")
	p.HandleFunc("/analyses/{id}", s.detail).Methods("GET", "DELETE")
	p.HandleFunc("/analyses/{id}/export", s.detail).Methods("GET")
	p.HandleFunc("/analyses/{id}/virustotal", s.recheckVirusTotal).Methods("POST")
	p.HandleFunc("/dashboard/stats", s.stats).Methods("GET")
}
func owner(r *http.Request) string { return r.Context().Value(key(0)).(auth.Session).User.ID }

var incompleteExplanation = map[string]string{
	"en": "No AI assessment was produced, so there is no verdict. The extracted technical evidence below is complete; review the provider status to see why the assessment did not run.",
	"ru": "Оценка ИИ не получена, поэтому вердикта нет. Извлечённые технические данные ниже сохранены полностью; причина указана в состоянии провайдера.",
	"kk": "ЖИ бағасы алынбады, сондықтан қорытынды жоқ. Төмендегі техникалық деректер толық сақталды; себебі провайдер күйінде көрсетілген.",
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, (10<<20)+65536)
	var e emailparser.Email
	var err error
	consent := false
	vtConsent := false
	requested := false
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err = r.ParseMultipartForm(1 << 20); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				fail(w, r, 413, "EMAIL_TOO_LARGE")
				return
			}
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
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if x := d.Decode(&in); x != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(x, &tooLarge) {
				fail(w, r, 413, "EMAIL_TOO_LARGE")
				return
			}
			fail(w, r, 400, "INVALID_REQUEST")
			return
		}
		if d.Decode(new(any)) != io.EOF || in.Source != "paste" {
			fail(w, r, 400, "INVALID_REQUEST")
			return
		}
		if len(in.Sender) > 1024 || len(in.Subject) > 4096 || strings.TrimSpace(in.Text) == "" {
			fail(w, r, 400, "INVALID_REQUEST")
			return
		}
		e, err = emailparser.Parse([]byte(in.Text), "", "paste", strings.TrimSpace(in.Sender), strings.TrimSpace(in.Subject))
		consent = in.Consent
		vtConsent = in.VTConsent
		requested = consent
		if in.AIRequested != nil {
			requested = *in.AIRequested
		}
	}
	if err != nil {
		// Parser errors are fixed codes such as INVALID_EMAIL, never raw text.
		fail(w, r, 400, err.Error())
		return
	}
	report := detection.Analyze(e)
	report.AttachmentReputation, report.VirusTotalStatus = s.executeVirusTotal(r.Context(), owner(r), vtConsent, report.Email.Attachments)
	execution, assessment := s.executeAI(r.Context(), owner(r), requested, consent, &report)
	report.AIStatus = execution.Status
	// Bodies and the raw header map are not persisted; the bounded evidence
	// list and validated quotes are.
	report.Email.Text = ""
	report.Email.HTML = ""
	report.Email.Headers = nil
	row := stored{ID: uuid.NewString(), Mode: "live", Created: time.Now().UTC(), Report: report, AI: assessment, AIExecution: execution}
	row.TopFindings = report.Indicators
	if len(row.TopFindings) > 5 {
		row.TopFindings = row.TopFindings[:5]
	}
	row.Status = "partial"
	row.Explanations = incompleteExplanation
	row.Recommendations = map[string]string{}
	if assessment != nil {
		row.Status = "complete"
		row.Explanations = assessment.Explanations
		row.Recommendations = assessment.Recommendations
	}
	b, err := json.Marshal(row)
	if err != nil {
		internal(w, r, "analysis encode", err)
		return
	}
	// PostgreSQL jsonb cannot store NUL; malformed mail can contain it.
	b = stripNUL(b)
	subject, _ := cutString(strings.ReplaceAll(e.Subject, "\x00", ""), 2000)
	sender, _ := cutString(strings.ReplaceAll(e.Sender, "\x00", ""), 1000)
	_, err = s.Auth.DB.Exec(r.Context(), `INSERT INTO analyses(id,user_id,mode,status,verdict,risk_score,risk_level,subject,sender,scoring_version,report,created_at) VALUES($1,$2,$3,$12,$4,$5,$6,$7,$8,$9,$10,$11)`, row.ID, owner(r), row.Mode, report.Verdict, report.Score, report.Level, subject, sender, report.Version, b, row.Created, row.Status)
	if err != nil {
		internal(w, r, "analysis insert", err)
		return
	}
	JSON(w, 201, row)
}

func cutString(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	return strings.ToValidUTF8(s[:n], ""), true
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
			internal(w, r, "analysis delete", e)
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
			internal(w, r, "analysis read", err)
		}
		return
	}
	// Decoding into the typed structure drops obsolete fields of historical
	// reports (attack-framework mappings) from every response and export.
	if err = json.Unmarshal(b, &row); err != nil {
		internal(w, r, "analysis decode", err)
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
				internal(w, r, "pdf export", e)
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
		row = exportView(row)
		JSON(w, 200, map[string]any{"export": map[string]any{"format": "cyberguard-analysis", "format_version": 2, "exported_at": time.Now().UTC(), "generator": "CyberGuard AI", "notice": "Verdict, severity and confidence are a model assessment of the listed evidence, not a probability. Authentication results are reported by uploaded headers unless marked verified."}, "analysis": row})
		return
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
		internal(w, r, "history", e)
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
	if mode != "live" {
		fail(w, r, 400, "INVALID_FILTER")
		return
	}
	since := time.Now().AddDate(0, 0, -days)
	rows, e := s.Auth.DB.Query(r.Context(), `SELECT verdict,COALESCE(report->'ai_assessment'->>'severity',risk_level),to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD'),status,scoring_version,count(*) FROM analyses WHERE user_id=$1 AND mode=$2 AND created_at>=$3 GROUP BY 1,2,3,4,5 ORDER BY 3`, owner(r), mode, since)
	if e != nil {
		internal(w, r, "dashboard", e)
		return
	}
	defer rows.Close()
	verdicts := map[string]int{"legitimate": 0, "suspicious": 0, "phishing": 0, "inconclusive": 0}
	severities := map[string]int{"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
	dates := map[string]int{}
	total := 0
	completed, incomplete, legacy := 0, 0, 0
	for rows.Next() {
		var v, l, d, status, version string
		var n int
		if e = rows.Scan(&v, &l, &d, &status, &version, &n); e != nil {
			internal(w, r, "dashboard", e)
			return
		}
		// Only validated assessments of the current pipeline count as verdicts.
		// Historical weighted-score reports and incomplete analyses are counted
		// separately so they cannot distort the verdict statistics.
		if version != detection.EvidenceVersion {
			legacy += n
		} else if status == "complete" {
			completed += n
			verdicts[v] += n
			severities[l] += n
		} else {
			incomplete += n
		}
		dates[d] += n
		total += n
	}
	if e = rows.Err(); e != nil {
		internal(w, r, "dashboard", e)
		return
	}
	rows.Close()
	result := map[string]any{"total_analyses": total, "verdict_distribution": verdicts, "severity_distribution": severities, "risk_distribution": severities, "activity": dates, "mode": mode}
	result["completed_count"] = completed
	result["incomplete_count"] = incomplete
	result["legacy_count"] = legacy
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
		internal(w, r, "dashboard recent", err)
		return
	}
	result["recent_analyses"] = recent
	for verdict, count := range verdicts {
		result[verdict+"_count"] = count
	}
	// Categories suspected by validated assessments of the current pipeline only.
	rs, x := s.Auth.DB.Query(r.Context(), `SELECT item #>> '{}',count(*) FROM analyses a CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(a.report->'ai_assessment'->'suspected_attack_types')='array' THEN a.report->'ai_assessment'->'suspected_attack_types' ELSE '[]'::jsonb END) item WHERE user_id=$1 AND mode=$2 AND created_at>=$3 AND status='complete' AND scoring_version=$4 GROUP BY 1 ORDER BY 2 DESC,1 LIMIT 10`, owner(r), mode, since, detection.EvidenceVersion)
	if x != nil {
		internal(w, r, "dashboard categories", x)
		return
	}
	categories := []map[string]any{}
	for rs.Next() {
		var name string
		var count int
		if x = rs.Scan(&name, &count); x != nil {
			rs.Close()
			internal(w, r, "dashboard categories", x)
			return
		}
		categories = append(categories, map[string]any{"name": name, "count": count})
	}
	x = rs.Err()
	rs.Close()
	if x != nil {
		internal(w, r, "dashboard categories", x)
		return
	}
	result["common_attack_types"] = categories
	JSON(w, 200, result)
}

// exportView prepares an analysis for the user-facing JSON export. The report
// has no "contradictory evidence" section: findings the model weighed against
// its verdict are not exported as a list of their own, and the summary and
// limitations carry any remaining doubt. All backend evidence, verified quotes
// and every supporting reference stay intact, so each exported statement can
// still be traced to its evidence item.
func exportView(row stored) stored {
	if row.AI == nil {
		return row
	}
	a := *row.AI
	a.Contradictory = nil
	supporting := make([]ai.EvidenceFinding, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Stance == "supporting" {
			supporting = append(supporting, f)
		}
	}
	a.Findings = supporting
	row.AI = &a
	return row
}
