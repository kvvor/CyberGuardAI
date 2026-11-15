package config

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// LoadLocal reads literal key/value configuration, never shell code. Existing
// process variables take precedence. Only one nearest configuration is loaded.
func LoadLocal() error {
	for _, path := range []string{".env.local", filepath.Join("..", ".env.local")} {
		f, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot read local configuration")
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 4096), 65536)
		values := map[string]string{}
		line := 0
		for s.Scan() {
			line++
			v := strings.TrimSpace(strings.TrimPrefix(s.Text(), "\ufeff"))
			if v == "" || strings.HasPrefix(v, "#") {
				continue
			}
			name, value, ok := strings.Cut(v, "=")
			name = strings.TrimSpace(name)
			value = strings.TrimSpace(value)
			if !ok || !envName.MatchString(name) {
				return fmt.Errorf("invalid local configuration at line %d", line)
			}
			if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
				value = value[1 : len(value)-1]
			}
			if _, ok := values[name]; ok {
				return fmt.Errorf("duplicate local configuration key at line %d", line)
			}
			values[name] = value
		}
		if s.Err() != nil {
			return fmt.Errorf("local configuration line exceeds limit")
		}
		for name, value := range values {
			if _, set := os.LookupEnv(name); !set {
				if err := os.Setenv(name, value); err != nil {
					return fmt.Errorf("cannot load local configuration")
				}
			}
		}
		return nil
	}
	return nil
}

func ValidateMasterKey() error {
	b, err := base64.StdEncoding.DecodeString(os.Getenv("PROVIDER_MASTER_KEY"))
	if err != nil || len(b) != 32 {
		return fmt.Errorf("PROVIDER_MASTER_KEY must contain 32 random bytes encoded as base64; run scripts/initialize-provider-key.ps1 once")
	}
	return nil
}
