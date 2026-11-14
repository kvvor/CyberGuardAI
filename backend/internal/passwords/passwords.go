package passwords

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
	"unicode/utf8"
)

func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Validate(s string) error {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) < 12 || len(s) > 1024 {
		return fmt.Errorf("password must contain at least 12 characters and at most 1024 UTF-8 bytes")
	}
	weak := strings.ToLower(strings.TrimSpace(s))
	if weak == "" {
		return fmt.Errorf("password is too weak")
	}
	if strings.Contains("password123456 qwerty123456 123456789012", weak) || len(strings.Trim(weak, string([]rune(weak)[0]))) == 0 {
		return fmt.Errorf("password is too weak")
	}
	return nil
}
func Hash(s string) (string, error) {
	if len(s) > 1024 {
		return "", fmt.Errorf("password too long")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	key := argon2.IDKey([]byte(s), salt, 2, 19456, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func Verify(encoded, s string) bool {
	if len(s) > 1024 {
		return false
	}
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" || p[2] != "v=19" || p[3] != "m=19456,t=2,p=1" {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(p[4])
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(p[5])
	if e != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(s), salt, 2, 19456, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
