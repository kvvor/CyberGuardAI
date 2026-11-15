package emailparser

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestHeadersBodiesAndAttachments(t *testing.T) {
	raw := "From: =?UTF-8?B?0JDQvdC90LA=?= <anna@example.test>\r\n" +
		"Sender: relay@example.test\r\nReply-To: reply@other.test\r\nReturn-Path: <bounce@mailer.test>\r\n" +
		"To: =?UTF-8?Q?J=C3=BCrgen?= <j@example.test>\r\nCc: team@example.test\r\n" +
		"Subject: =?UTF-8?B?0J7RgtGH0ZHRgg==?=\r\n =?UTF-8?B?INC30LAg0LzQsNGA0YI=?=\r\n" +
		"Date: Tue, 03 Mar 2026 12:15:00 +0300\r\nMessage-ID: <id-1@example.test>\r\n" +
		"Received: from a.test by b.test; Tue, 03 Mar 2026 09:15:01 +0000\r\nReceived: from c.test by a.test\r\n" +
		"Authentication-Results: mx.b.test; spf=pass\r\nReceived-SPF: pass (b.test: domain of example.test)\r\nDKIM-Signature: v=1; d=example.test; s=k1; b=abc\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n" +
		"--inner\r\nContent-Type: text/plain; charset=windows-1251\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2}) + "\r\n" +
		"--inner\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82 <a href=3D\"https://example.test/a\">link</a></p>\r\n--inner--\r\n" +
		"--outer\r\nContent-Type: application/pdf; name=\"=?UTF-8?B?0L7RgtGH0ZHRgi5wZGY=?=\"\r\nContent-Disposition: attachment; filename=\"=?UTF-8?B?0L7RgtGH0ZHRgi5wZGY=?=\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 synthetic")) + "\r\n" +
		"--outer\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"..\\..\\evil.exe\"\r\n\r\nMZ\r\n--outer--\r\n"
	e, err := Parse([]byte(raw), "sample.eml", "eml", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if e.Sender != "Анна <anna@example.test>" || e.Subject != "Отчёт за март" || e.ReplyTo != "reply@other.test" || e.MessageID != "<id-1@example.test>" {
		t.Fatalf("headers: %+v", e)
	}
	if len(e.Recipients) != 2 || !strings.Contains(e.Recipients[0], "Jürgen") {
		t.Fatal(e.Recipients)
	}
	if e.Timestamp == nil || e.Timestamp.Format("2006-01-02T15:04:05Z") != "2026-03-03T09:15:00Z" {
		t.Fatal("date not normalised to UTC", e.Timestamp)
	}
	if len(e.Headers["Received"]) != 2 || len(e.AuthenticationResults) != 1 || len(e.Headers["Received-Spf"]) != 1 || len(e.Headers["Dkim-Signature"]) != 1 || len(e.Headers["Return-Path"]) != 1 || len(e.Headers["Sender"]) != 1 {
		t.Fatalf("routing/authentication headers lost: %v", e.Headers)
	}
	if !strings.Contains(e.Text, "Привет") || !strings.Contains(e.HTML, "Привет") || !strings.Contains(e.HTML, `href="https://example.test/a"`) {
		t.Fatalf("bodies: %q %q", e.Text, e.HTML)
	}
	if len(e.Attachments) != 2 || e.Attachments[0].Filename != "отчёт.pdf" || e.Attachments[0].Detected != "application/pdf" || e.Attachments[1].Filename != "evil.exe" {
		t.Fatalf("attachments: %+v", e.Attachments)
	}
	// SHA-256 of the decoded attachment bytes, lower-case hex.
	if e.Attachments[0].SHA256 != hash([]byte("%PDF-1.4 synthetic")) || len(e.Attachments[0].SHA256) != 64 || e.Attachments[0].Size != 18 {
		t.Fatal("attachment hash", e.Attachments[0])
	}
}

func TestPastedContentKinds(t *testing.T) {
	body, err := Parse([]byte("Dear user,\n\nFrom: this line is inside the body, not a header block."), "", "paste", "typed@example.test", "Typed subject")
	if err != nil || body.Sender != "typed@example.test" || body.Subject != "Typed subject" || len(body.Headers) != 0 || body.Timestamp != nil || len(body.AuthenticationResults) != 0 {
		t.Fatalf("body-only paste: %+v %v", body, err)
	}
	if strings.Join(body.Warnings, ",") != "MISSING_EMAIL_HEADERS" {
		t.Fatal(body.Warnings)
	}
	source, err := Parse([]byte("Received: from a by b\nFrom: Real <real@example.test>\nSubject: Real subject\n\nBody"), "", "paste", "ignored@example.test", "ignored")
	if err != nil || source.Sender != "Real <real@example.test>" || source.Subject != "Real subject" || len(source.Headers["Received"]) != 1 {
		t.Fatalf("raw source paste: %+v %v", source, err)
	}
	for _, w := range source.Warnings {
		if w == "MISSING_EMAIL_HEADERS" {
			t.Fatal("headers reported missing for raw source")
		}
	}
}

func TestMalformedAndHostileInput(t *testing.T) {
	deep := "From: a@example.test\r\n"
	body := "x"
	for i := 13; i >= 0; i-- {
		boundary := fmt.Sprintf("b%d", i)
		body = "--" + boundary + "\r\nContent-Type: multipart/mixed; boundary=b" + fmt.Sprint(i+1) + "\r\n\r\n" + body + "\r\n--" + boundary + "--\r\n"
	}
	cases := map[string]string{
		"MIME_DEPTH_EXCEEDED": deep + "Content-Type: multipart/mixed; boundary=b0\r\n\r\n" + body,
		"INVALID_MIME":        "From: a@example.test\r\nContent-Type: multipart/mixed\r\n\r\nno boundary",
		"INVALID_EMAIL":       "\x00\x01\x02 not an email",
		"ATTACHMENT_LIMIT":    "From: a@example.test\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n" + strings.Repeat("--x\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\na\r\n", 33) + "--x--\r\n",
		"MIME_PART_LIMIT":     "From: a@example.test\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n" + strings.Repeat("--x\r\nContent-Type: text/plain\r\n\r\na\r\n", 130) + "--x--\r\n",
	}
	for want, raw := range cases {
		if _, err := Parse([]byte(raw), "x.eml", "eml", "", ""); err == nil || err.Error() != want {
			t.Errorf("%s: got %v", want, err)
		}
	}
	for name, want := range map[string]string{"notes.txt": "UNSUPPORTED_FORMAT", "x.eml.exe": "UNSUPPORTED_FORMAT"} {
		if _, err := Parse([]byte("From: a@example.test\r\n\r\nx"), name, "eml", "", ""); err == nil || err.Error() != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Tolerated irregularities produce warnings, not failures or invented data.
	e, err := Parse([]byte("Subject: no sender\r\nContent-Type: text/plain; charset=x-unknown-charset\r\nDate: not a date\r\n\r\nbody"), "x.eml", "eml", "", "")
	if err != nil || e.Sender != "" || e.Timestamp != nil || !strings.Contains(strings.Join(e.Warnings, ","), "MISSING_SENDER") || !strings.Contains(strings.Join(e.Warnings, ","), "UNSUPPORTED_CHARSET") {
		t.Fatalf("%+v %v", e, err)
	}
	e, err = Parse([]byte("From: a@example.test\r\nContent-Type: application/x-custom\r\n\r\nbinary"), "x.eml", "eml", "", "")
	if err != nil || e.Text != "" || !strings.Contains(strings.Join(e.Warnings, ","), "UNSUPPORTED_MIME_PART") {
		t.Fatalf("%+v %v", e, err)
	}
	// Decoded size is bounded even when the encoded upload is within limits.
	huge := "From: a@example.test\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
	chunk := strings.Repeat("A", 6<<20)
	for i := 0; i < 4; i++ {
		huge += "--x\r\nContent-Type: text/plain\r\n\r\n" + chunk + "\r\n"
	}
	if _, err := Parse([]byte(huge+"--x--\r\n"), "x.eml", "eml", "", ""); err == nil {
		t.Fatal("oversized message accepted")
	}
}

func TestMSGLimitsAndFallbacks(t *testing.T) {
	for name, data := range map[string][]byte{"short.msg": []byte("x"), "wrong.eml": syntheticMSG(), "garbage.msg": append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, make([]byte, 2048)...)} {
		if _, err := ParseMSG(data, name); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseMSG(make([]byte, (10<<20)+1), "big.msg"); err == nil || err.Error() != "EMAIL_TOO_LARGE" {
		t.Fatal(err)
	}
	// Without transport headers nothing is invented.
	e, err := ParseMSG(syntheticMSG(), "plain.msg")
	if err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(e.Warnings, ",")
	if len(e.Headers) != 0 || len(e.AuthenticationResults) != 0 || e.Timestamp != nil || e.Sender != "" || !strings.Contains(warnings, "MISSING_EMAIL_HEADERS") || !strings.Contains(warnings, "MISSING_SENDER") || !strings.Contains(warnings, "MSG_PARTIAL_EVIDENCE") {
		t.Fatalf("%+v", e)
	}
	if len(e.AvailableEvidence) != 1 || e.AvailableEvidence[0] != "body" {
		t.Fatal(e.AvailableEvidence)
	}
}
