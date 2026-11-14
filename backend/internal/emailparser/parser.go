package emailparser

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"golang.org/x/net/html/charset"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"strings"
)

type Attachment struct {
	Filename string `json:"filename"`
	Declared string `json:"declared_mime"`
	Detected string `json:"detected_mime"`
	Size     int    `json:"size"`
	SHA256   string `json:"sha256"`
}
type Email struct {
	Source      string              `json:"source_type"`
	Filename    string              `json:"filename"`
	SHA256      string              `json:"file_sha256"`
	MessageID   string              `json:"message_id"`
	Subject     string              `json:"subject"`
	Sender      string              `json:"sender"`
	ReplyTo     string              `json:"reply_to"`
	Recipients  []string            `json:"recipients"`
	Headers     map[string][]string `json:"headers"`
	Text        string              `json:"text_body"`
	HTML        string              `json:"html_body"`
	Attachments []Attachment        `json:"attachments"`
	Warnings    []string            `json:"parser_warnings"`
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Parse(data []byte, filename, source, sender, subject string) (Email, error) {
	v := Email{Source: source, Filename: filepath.Base(filename), SHA256: hash(data), Sender: sender, Subject: subject, Attachments: []Attachment{}, Warnings: []string{}, Headers: map[string][]string{}}
	if len(data) > 10<<20 {
		return v, fmt.Errorf("EMAIL_TOO_LARGE")
	}
	if source == "paste" && !bytes.HasPrefix(data, []byte("From:")) && !bytes.HasPrefix(data, []byte("Received:")) {
		v.Text = string(data)
		v.Warnings = append(v.Warnings, "MISSING_EMAIL_HEADERS")
		return v, nil
	}
	if source != "eml" && source != "paste" {
		return v, fmt.Errorf("UNSUPPORTED_FORMAT")
	}
	if source == "eml" && strings.ToLower(filepath.Ext(filename)) != ".eml" {
		return v, fmt.Errorf("UNSUPPORTED_FORMAT")
	}
	m, e := mail.ReadMessage(bytes.NewReader(data))
	if e != nil {
		return v, fmt.Errorf("INVALID_EMAIL")
	}
	dec := mime.WordDecoder{CharsetReader: func(c string, r io.Reader) (io.Reader, error) { return charset.NewReaderLabel(c, r) }}
	decode := func(s string) string {
		x, e := dec.DecodeHeader(s)
		if e != nil {
			return s
		}
		return x
	}
	v.Subject = decode(m.Header.Get("Subject"))
	v.Sender = decode(m.Header.Get("From"))
	v.ReplyTo = decode(m.Header.Get("Reply-To"))
	v.MessageID = m.Header.Get("Message-ID")
	v.Recipients = append(m.Header["To"], m.Header["Cc"]...)
	v.Headers = map[string][]string(m.Header)
	budget := 20 << 20
	e = part(&v, textproto.MIMEHeader(m.Header), m.Body, 0, &budget)
	return v, e
}
func part(v *Email, h textproto.MIMEHeader, r io.Reader, depth int, budget *int) error {
	if depth > 12 {
		return fmt.Errorf("MIME_DEPTH_EXCEEDED")
	}
	ct, params, e := mime.ParseMediaType(h.Get("Content-Type"))
	if e != nil {
		ct = "text/plain"
		params = map[string]string{}
	}
	switch strings.ToLower(h.Get("Content-Transfer-Encoding")) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	}
	if strings.HasPrefix(ct, "multipart/") {
		if params["boundary"] == "" {
			return fmt.Errorf("INVALID_MIME")
		}
		mr := multipart.NewReader(r, params["boundary"])
		for count := 0; ; count++ {
			if count >= 128 {
				return fmt.Errorf("MIME_PART_LIMIT")
			}
			p, e := mr.NextPart()
			if e == io.EOF {
				return nil
			}
			if e != nil {
				return fmt.Errorf("INVALID_MIME")
			}
			if e = part(v, p.Header, p, depth+1, budget); e != nil {
				return e
			}
		}
	}
	b, e := io.ReadAll(io.LimitReader(r, int64(*budget)+1))
	if e != nil {
		return fmt.Errorf("INVALID_ENCODING")
	}
	*budget -= len(b)
	if *budget < 0 {
		return fmt.Errorf("DECODED_SIZE_LIMIT")
	}
	disp, dp, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	name := dp["filename"]
	if name == "" {
		name = params["name"]
	}
	if name != "" || disp == "attachment" {
		if len(v.Attachments) >= 32 {
			return fmt.Errorf("ATTACHMENT_LIMIT")
		}
		name = strings.ReplaceAll(name, "\\", "/")
		v.Attachments = append(v.Attachments, Attachment{Filename: filepath.Base(name), Declared: ct, Detected: http.DetectContentType(b), Size: len(b), SHA256: hash(b)})
		return nil
	}
	if cs := params["charset"]; cs != "" {
		rd, e := charset.NewReaderLabel(cs, bytes.NewReader(b))
		if e != nil {
			v.Warnings = append(v.Warnings, "UNSUPPORTED_CHARSET")
		} else {
			b, e = io.ReadAll(io.LimitReader(rd, int64(*budget)+1))
			if e != nil || len(b) > *budget {
				return fmt.Errorf("CHARSET_SIZE_LIMIT")
			}
			*budget -= len(b)
		}
	}
	switch ct {
	case "text/plain":
		v.Text += string(b) + "\n"
	case "text/html":
		v.HTML += string(b) + "\n"
	default:
		v.Warnings = append(v.Warnings, "UNSUPPORTED_MIME_PART")
	}
	return nil
}
