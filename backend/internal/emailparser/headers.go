package emailparser

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html/charset"
)

var encodedWord = regexp.MustCompile(`=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=`)

// Whitespace between two adjacent encoded words is not part of the text (RFC 2047 §6.2).
var betweenWords = regexp.MustCompile(`(\?=)[ \t\r\n]+(=\?)`)

func toUTF8(label string, raw []byte) (string, bool) {
	if strings.EqualFold(label, "utf-8") || strings.EqualFold(label, "utf8") || strings.EqualFold(label, "us-ascii") {
		if !utf8.Valid(raw) {
			return "", false
		}
		return string(raw), true
	}
	r, err := charset.NewReaderLabel(label, bytes.NewReader(raw))
	if err != nil {
		return "", false
	}
	out, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return "", false
	}
	return string(out), true
}

// decodeWord decodes one encoded word tolerantly. Real mail often carries
// base64 with wrong padding ("...MjAyNg==" where none is due), which the
// standard decoder rejects, leaving the reader with the raw "=?UTF-8?B?...?=".
func decodeWord(label, encoding, payload string) (string, bool) {
	var raw []byte
	if strings.EqualFold(encoding, "b") {
		clean := strings.TrimRight(payload, "=")
		clean = strings.NewReplacer("-", "+", "_", "/").Replace(clean)
		decoded, err := base64.RawStdEncoding.DecodeString(clean)
		if err != nil {
			return "", false
		}
		raw = decoded
	} else {
		var b bytes.Buffer
		for i := 0; i < len(payload); i++ {
			switch c := payload[i]; {
			case c == '_':
				b.WriteByte(' ')
			case c == '=' && i+2 < len(payload)+0 && isHex(payload[i+1]) && isHex(payload[i+2]):
				b.WriteByte(unhex(payload[i+1])<<4 | unhex(payload[i+2]))
				i += 2
			default:
				b.WriteByte(c)
			}
		}
		raw = b.Bytes()
	}
	return toUTF8(label, raw)
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// DecodeHeader returns the readable form of a header value containing RFC 2047
// encoded words. It only decodes: characters are never normalised, folded or
// replaced, so visually deceptive Unicode stays exactly as sent. A word that
// cannot be decoded (unknown charset, damaged data) is left as it was.
func DecodeHeader(value string) string {
	if !strings.Contains(value, "=?") {
		return value
	}
	strict := mime.WordDecoder{CharsetReader: func(c string, r io.Reader) (io.Reader, error) { return charset.NewReaderLabel(c, r) }}
	if decoded, err := strict.DecodeHeader(value); err == nil && !encodedWord.MatchString(decoded) && utf8.ValidString(decoded) {
		return decoded
	}
	joined := betweenWords.ReplaceAllString(value, "$1$2")
	return encodedWord.ReplaceAllStringFunc(joined, func(word string) string {
		m := encodedWord.FindStringSubmatch(word)
		if decoded, ok := decodeWord(m[1], m[2], m[3]); ok {
			return decoded
		}
		return word
	})
}

// SplitAddress separates a From-style value into the display name a mail
// client shows and the actual address. The display name is whatever the sender
// chose to write, including another address or brand; it is not evidence of
// identity. The value is split at the last angle-bracket pair and the name is
// kept literally: a strict parser rejects unquoted special characters and
// silently drops "(brand.com)" as a comment, hiding exactly the text a reader
// sees in the mail client.
func SplitAddress(value string) (name, address string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	open, end := strings.LastIndex(value, "<"), strings.LastIndex(value, ">")
	if open >= 0 && end > open {
		address = strings.TrimSpace(value[open+1 : end])
		name = strings.TrimSpace(value[:open])
		if len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"' {
			name = strings.ReplaceAll(name[1:len(name)-1], `\"`, `"`)
		}
		return name, address
	}
	if a, err := mail.ParseAddress(value); err == nil {
		return strings.TrimSpace(a.Name), a.Address
	}
	if strings.Contains(value, "@") && !strings.ContainsAny(value, " \t") {
		return "", value
	}
	return value, ""
}
