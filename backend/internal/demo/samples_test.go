package demo

import (
	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/emailparser"
	"fmt"
)

type Sample struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Synthetic bool   `json:"synthetic"`
}

func Samples() []Sample {
	return []Sample{{"legitimate", "Business meeting", true}, {"credentials", "Credential phishing", true}, {"link", "Spearphishing link", true}, {"attachment", "Suspicious attachment", true}, {"bec", "Payment diversion", true}, {"ambiguous", "Insufficient evidence", true}}
}
func Analyze(id string) (detection.Report, error) {
	e := emailparser.Email{Source: "demo", Sender: "Analyst <analyst@example.com>", Subject: "Synthetic demonstration"}
	switch id {
	case "legitimate":
		e.Text = "The project meeting is tomorrow. Please review our agenda."
	case "credentials":
		e.Text = "Urgent: verify your password immediately. Your account will be closed. https://192.0.2.1/login"
	case "link":
		e.HTML = `<a href="https://192.0.2.1/login">https://example.com</a>`
		e.Text = "Urgent: account suspended"
	case "attachment":
		e.Text = "Urgent: open the attachment"
		e.Attachments = []emailparser.Attachment{{Filename: "invoice.pdf.exe", Declared: "application/octet-stream", Detected: "application/octet-stream", Size: 3, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}
	case "bec":
		e.ReplyTo = "finance@other.example"
		e.Text = "Urgent wire transfer to our new bank account. Keep this confidential. Do not call."
	case "ambiguous":
		e.Text = "Please review this request."
	default:
		return detection.Report{}, fmt.Errorf("UNKNOWN_DEMO_SAMPLE")
	}
	r := detection.Analyze(e)
	r.AIStatus = "predefined_demo"
	r.Limitations = append(r.Limitations, "SYNTHETIC_DEMO_NO_MODEL_EXECUTED")
	if id == "legitimate" {
		r.Verdict = "legitimate"
	}
	return r, nil
}
