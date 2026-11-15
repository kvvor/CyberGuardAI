package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
	"cyberguard.local/backend/internal/virustotal"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// reputationKnown reports whether a lookup produced a provider answer.
func reputationKnown(status string) bool { return status == "completed" || status == "not_found" }

// executeVirusTotal looks up attachment SHA-256 hashes only. Attachment bytes
// never reach this function; without explicit per-analysis consent no request
// is made and no credential is even read.
func (s *Server) executeVirusTotal(ctx context.Context, owner string, consent bool, attachments []emailparser.Attachment) ([]virustotal.Result, string) {
	if len(attachments) == 0 {
		return []virustotal.Result{}, "skipped_no_attachments"
	}
	status := "not_requested"
	var client *virustotal.Client
	if consent {
		p := s.providerService().For("virustotal")
		c, secret, err := p.Read(ctx, owner)
		switch {
		case err != nil:
			status = "provider_error"
		case !c.Enabled || !c.HasCredential:
			status = "not_configured"
		default:
			key, err := p.Open(owner, secret)
			if err != nil {
				status = "provider_error"
			} else {
				client = s.virusTotalClient(key)
			}
		}
	}
	hashes := make([]string, len(attachments))
	for i, a := range attachments {
		hashes[i] = a.SHA256
	}
	if client == nil {
		results := make([]virustotal.Result, len(hashes))
		for i, h := range hashes {
			results[i] = virustotal.Result{SHA256: h, Status: status, Source: "VirusTotal API v3"}
		}
		return results, status
	}
	// The batch has its own budget so that slow lookups cannot starve the
	// assessment that follows in the same request.
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	p := s.providerService().For("virustotal")
	results := client.LookupMany(ctx, hashes, func() bool { ok, err := p.ReserveLookup(ctx, owner); return err == nil && ok })
	known, firstFailure := 0, ""
	for _, r := range results {
		if reputationKnown(r.Status) {
			known++
		} else if firstFailure == "" {
			firstFailure = r.Status
		}
	}
	switch {
	case known == len(results):
		return results, "completed"
	case known > 0:
		// Some hashes were answered; the remaining ones keep their own status
		// and can be re-checked later without repeating the answered lookups.
		return results, "partial"
	}
	return results, firstFailure
}

// recheckVirusTotal completes attachment lookups that did not get a provider
// answer (local quota, rate limit, timeout). It is the user-triggered
// continuation for batches larger than the per-minute allowance. Hashes that
// already have an answer are never requested again.
func (s *Server) recheckVirusTotal(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, e := uuid.Parse(id); e != nil {
		fail(w, r, 404, "NOT_FOUND")
		return
	}
	var in struct {
		Consent bool `json:"virustotal_consent"`
	}
	if decode(w, r, &in) != nil {
		fail(w, r, 400, "INVALID_REQUEST")
		return
	}
	if !in.Consent {
		fail(w, r, 400, "VIRUSTOTAL_CONSENT_REQUIRED")
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
	if json.Unmarshal(b, &row) != nil || row.Report.Version != detection.EvidenceVersion {
		fail(w, r, 409, "RECHECK_NOT_SUPPORTED")
		return
	}
	previous := map[string]virustotal.Result{}
	for _, v := range row.Report.AttachmentReputation {
		previous[v.SHA256] = v
	}
	pending := []emailparser.Attachment{}
	for _, a := range row.Report.Email.Attachments {
		if v, ok := previous[a.SHA256]; !ok || !reputationKnown(v.Status) {
			pending = append(pending, a)
		}
	}
	if len(pending) == 0 {
		fail(w, r, 409, "NOTHING_TO_RECHECK")
		return
	}
	fresh, _ := s.executeVirusTotal(r.Context(), owner(r), true, pending)
	for _, v := range fresh {
		previous[v.SHA256] = v
	}
	results := make([]virustotal.Result, 0, len(row.Report.Email.Attachments))
	known := 0
	for i, a := range row.Report.Email.Attachments {
		v := previous[a.SHA256]
		results = append(results, v)
		if reputationKnown(v.Status) {
			known++
		}
		evidenceID := fmt.Sprintf("reputation-%d", i+1)
		replaced := false
		for j := range row.Report.Evidence {
			if row.Report.Evidence[j].ID == evidenceID {
				row.Report.Evidence[j].Value = detection.ReputationValue(v)
				replaced = true
			}
		}
		if !replaced {
			row.Report.Evidence = append(row.Report.Evidence, detection.Evidence{ID: evidenceID, Source: "virustotal", Value: detection.ReputationValue(v), Trust: "provider_reported"})
		}
	}
	row.Report.AttachmentReputation = results
	switch {
	case known == len(results):
		row.Report.VirusTotalStatus = "completed"
	case known > 0:
		row.Report.VirusTotalStatus = "partial"
	default:
		row.Report.VirusTotalStatus = results[0].Status
	}
	if row.AI != nil {
		// The stored verdict was produced before these results existed. It is
		// kept as it was and visibly marked instead of being silently reused.
		note := "REPUTATION_UPDATED_AFTER_ASSESSMENT"
		present := false
		for _, l := range row.Report.Limitations {
			present = present || l == note
		}
		if !present {
			row.Report.Limitations = append(row.Report.Limitations, note)
		}
	}
	updated, err := json.Marshal(row)
	if err != nil {
		internal(w, r, "analysis encode", err)
		return
	}
	if _, err = s.Auth.DB.Exec(r.Context(), `UPDATE analyses SET report=$1 WHERE id=$2 AND user_id=$3`, updated, id, owner(r)); err != nil {
		internal(w, r, "analysis update", err)
		return
	}
	JSON(w, 200, row)
}
