package evaluation

import (
	"context"
	"strings"

	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
	"cyberguard.local/backend/internal/mockproviders"
	ai "cyberguard.local/backend/internal/openai"
	"cyberguard.local/backend/internal/virustotal"
)

// Evidence runs the production parsing and evidence pipeline for a case. The
// reputation result is synthesised from the case label (no network access).
func Evidence(c Case) (detection.Report, error) {
	var e emailparser.Email
	var err error
	if c.Source == "paste" {
		e, err = emailparser.Parse([]byte(c.Raw), "", "paste", "", "")
	} else {
		e, err = emailparser.Parse([]byte(c.Raw), c.ID+".eml", "eml", "", "")
	}
	if err != nil {
		return detection.Report{}, err
	}
	r := detection.Analyze(e)
	for _, a := range r.Email.Attachments {
		v := virustotal.Result{SHA256: a.SHA256, Source: "VirusTotal API v3", Status: "not_requested"}
		switch c.Reputation {
		case "unknown":
			v.Status = "not_found"
		case "clean":
			v.Status, v.Statistics = "completed", map[string]int{"malicious": 0, "suspicious": 0, "harmless": 3, "undetected": 60}
		case "malicious":
			if strings.EqualFold(a.SHA256, mockproviders.MaliciousSHA256) {
				v.Status, v.Statistics = "completed", map[string]int{"malicious": 62, "suspicious": 0, "harmless": 0, "undetected": 8}
				v.Engines = []virustotal.Engine{{Name: "MockEngine", Category: "malicious", Result: "Mock.Test.Detection"}}
			}
		}
		r.AttachmentReputation = append(r.AttachmentReputation, v)
	}
	if len(r.Email.Attachments) > 0 {
		r.VirusTotalStatus = "not_requested"
		if c.Reputation != "" {
			r.VirusTotalStatus = "completed"
		}
	}
	detection.PrepareEvidence(&r)
	return r, nil
}

// Run assesses every case with the given client and returns the outcomes. A
// case whose assessment fails keeps an empty verdict (counted as abstention).
func Run(ctx context.Context, client *ai.Client, cases []Case) ([]Outcome, map[string]string) {
	outcomes := make([]Outcome, 0, len(cases))
	failures := map[string]string{}
	for _, c := range cases {
		o := Outcome{ID: c.ID, Label: c.Label}
		r, err := Evidence(c)
		if err == nil {
			var a ai.Assessment
			if a, err = client.Assess(ctx, r); err == nil {
				o.Verdict = a.Verdict
			}
		}
		if err != nil {
			failures[c.ID] = err.Error()
		}
		outcomes = append(outcomes, o)
	}
	return outcomes, failures
}
