package api

import (
	"context"
	"cyberguard.local/backend/internal/emailparser"
	"cyberguard.local/backend/internal/virustotal"
)

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
	if client != nil {
		p := s.providerService().For("virustotal")
		results := client.LookupMany(ctx, hashes, func() bool { ok, err := p.ReserveLookup(ctx, owner); return err == nil && ok })
		status = "completed"
		for _, r := range results {
			if r.Status != "completed" && r.Status != "not_found" {
				status = r.Status
				break
			}
		}
		return results, status
	}
	results := make([]virustotal.Result, len(hashes))
	for i, h := range hashes {
		results[i] = virustotal.Result{SHA256: h, Status: status, Source: "VirusTotal API v3"}
	}
	return results, status
}
