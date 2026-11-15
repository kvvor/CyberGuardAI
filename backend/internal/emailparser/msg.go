package emailparser

import (
	"bytes"
	"fmt"
	"github.com/AkmalOt/gomsg"
	"io"
	"net/http"
	"net/mail"
	"path/filepath"
	"strings"
	"time"
)

type boundedAt struct {
	r         *bytes.Reader
	remaining int
	deadline  time.Time
	failed    bool
}

func (b *boundedAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > b.remaining || time.Now().After(b.deadline) {
		b.failed = true
		return 0, fmt.Errorf("MSG_RESOURCE_LIMIT")
	}
	b.remaining -= len(p)
	return b.r.ReadAt(p, off)
}
func ParseMSG(data []byte, name string) (out Email, err error) {
	defer func() {
		if recover() != nil {
			out = Email{}
			err = fmt.Errorf("INVALID_MSG")
		}
	}()
	if len(data) > 10<<20 {
		return out, fmt.Errorf("EMAIL_TOO_LARGE")
	}
	if strings.ToLower(filepath.Ext(name)) != ".msg" || len(data) < 512 || !bytes.Equal(data[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		return out, fmt.Errorf("INVALID_MSG")
	}
	reader := &boundedAt{bytes.NewReader(data), 64 << 20, time.Now().Add(5 * time.Second), false}
	m, e := gomsg.OpenReader(reader, int64(len(data)))
	if e != nil || reader.failed {
		return out, fmt.Errorf("INVALID_OR_LIMITED_MSG")
	}
	sender := strings.TrimSpace(m.SenderSMTP)
	warnings := []string{"MSG_PARTIAL_EVIDENCE"}
	if sender == "" && strings.Contains(m.SenderEmail, "@") {
		sender = strings.TrimSpace(m.SenderEmail)
	}
	if sender == "" && m.SenderEmail != "" {
		// Exchange (EX) addresses are internal directory names, not SMTP addresses.
		warnings = append(warnings, "MSG_SENDER_NOT_SMTP_ADDRESS")
	}
	if name := strings.TrimSpace(m.SenderName); name != "" && sender != "" && !strings.EqualFold(name, sender) {
		sender = (&mail.Address{Name: name, Address: sender}).String()
	} else if sender == "" {
		sender = strings.TrimSpace(m.SenderName)
	}
	recipients := []string{}
	for _, value := range []string{m.DisplayTo, m.DisplayCC} {
		if strings.TrimSpace(value) != "" {
			recipients = append(recipients, strings.TrimSpace(value))
		}
	}
	out = Email{Source: "msg", Filename: filepath.Base(name), SHA256: hash(data), MessageID: m.MessageID, Subject: m.Subject, Sender: sender, Text: m.Body, HTML: string(m.BodyHTML), Recipients: recipients, Attachments: []Attachment{}, Headers: map[string][]string{}, Warnings: warnings}
	for _, candidate := range []time.Time{m.Date, m.DeliveryTime} {
		if !candidate.IsZero() && candidate.Year() > 1990 {
			stamp := candidate.UTC()
			out.Timestamp = &stamp
			break
		}
	}
	if m.Headers != "" {
		// PidTagTransportMessageHeaders holds the original Internet headers.
		raw := strings.TrimRight(m.Headers, "\x00\r\n ") + "\r\n\r\n"
		if h, x := Parse([]byte(raw), "headers.eml", "eml", "", ""); x == nil {
			out.Headers = h.Headers
			out.ReplyTo = h.ReplyTo
			out.AuthenticationResults = h.AuthenticationResults
			if h.Timestamp != nil {
				out.Timestamp = h.Timestamp
			}
			if h.Sender != "" {
				out.Sender = h.Sender
			}
			if h.MessageID != "" {
				out.MessageID = h.MessageID
			}
			if out.Subject == "" {
				out.Subject = h.Subject
			}
			if len(out.Recipients) == 0 {
				out.Recipients = h.Recipients
			}
			out.AvailableEvidence = []string{"headers", "body"}
		} else {
			out.Warnings = append(out.Warnings, "MSG_TRANSPORT_HEADERS_UNREADABLE")
		}
	}
	if len(out.Headers) == 0 {
		out.Warnings = append(out.Warnings, "MISSING_EMAIL_HEADERS")
		out.AvailableEvidence = []string{"body"}
	}
	if out.Sender == "" {
		out.Warnings = append(out.Warnings, "MISSING_SENDER")
	}
	total := len(out.Text) + len(out.HTML)
	if len(m.Attachments) > 32 {
		return Email{}, fmt.Errorf("ATTACHMENT_LIMIT")
	}
	for _, a := range m.Attachments {
		if a.IsEmbeddedMessage() {
			out.Warnings = append(out.Warnings, "EMBEDDED_MSG_NOT_ANALYZED")
			continue
		}
		b := a.Data()
		total += len(b)
		if total > 20<<20 {
			return Email{}, fmt.Errorf("DECODED_SIZE_LIMIT")
		}
		out.Attachments = append(out.Attachments, Attachment{Filename: filepath.Base(strings.ReplaceAll(a.DisplayName(), "\\", "/")), Declared: a.MIMEType, Detected: http.DetectContentType(b), Size: len(b), SHA256: hash(b)})
	}
	return out, nil
}

var _ io.ReaderAt = (*boundedAt)(nil)
