package api

import (
	"context"
	"cyberguard.local/backend/internal/emailparser"
	"testing"
)

func TestVirusTotalNoAttachmentsAndNoConsent(t *testing.T) {
	s := &Server{}
	// Neither branch is allowed even to read provider credentials.
	for _, consent := range []bool{false, true} {
		r, status := s.executeVirusTotal(context.Background(), "unused", consent, nil)
		if len(r) != 0 || status != "skipped_no_attachments" {
			t.Fatal(status, r)
		}
	}
	r, status := s.executeVirusTotal(context.Background(), "unused", false, []emailparser.Attachment{{SHA256: "hash"}})
	if len(r) != 1 || status != "not_requested" {
		t.Fatal(status, r)
	}
}
