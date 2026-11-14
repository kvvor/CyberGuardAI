package emailparser

import (
	"strings"
	"testing"
)

func TestEML(t *testing.T) {
	raw := "From: Analyst <analyst@example.com>\r\nSubject: =?UTF-8?B?0KLQtdGB0YI=?=\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\nHello\r\n--abc\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"../../test.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVog\r\n--abc--\r\n"
	e, err := Parse([]byte(raw), "sample.eml", "eml", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if e.Subject != "Тест" || !strings.Contains(e.Text, "Hello") || len(e.Attachments) != 1 || e.Attachments[0].Filename != "test.exe" {
		t.Fatalf("unexpected parse: %+v", e)
	}
}
func TestLimits(t *testing.T) {
	if _, e := Parse(make([]byte, (10<<20)+1), "x.eml", "eml", "", ""); e == nil {
		t.Fatal("size accepted")
	}
	if _, e := Parse([]byte("broken"), "x.eml", "eml", "", ""); e == nil {
		t.Fatal("corrupt accepted")
	}
	e, err := Parse([]byte("copied body"), "", "paste", "", "")
	if err != nil || len(e.Warnings) == 0 {
		t.Fatal("missing headers not reported")
	}
}
