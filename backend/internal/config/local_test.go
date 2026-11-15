package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteralLocalConfiguration(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("CG_EXISTING_TEST", "process")
	defer os.Unsetenv("CG_LITERAL_TEST")
	if err := os.WriteFile(".env.local", []byte("CG_EXISTING_TEST=file\nCG_LITERAL_TEST='value#with=$($HOME)'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := LoadLocal(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CG_EXISTING_TEST") != "process" || os.Getenv("CG_LITERAL_TEST") != "value#with=$($HOME)" {
		t.Fatal("configuration expanded or overwritten")
	}
}
func TestLocalConfigurationParentAndErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "backend"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Join(dir, "backend"))
	t.Setenv("CG_TEST_PARENT", "process")
	for _, body := range []string{"CG_TEST_PARENT=1\nCG_TEST_PARENT=2", "this is not configuration", strings.Repeat("x", 70000)} {
		if err := os.WriteFile(filepath.Join(dir, ".env.local"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := LoadLocal(); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
func TestMasterKeyValidation(t *testing.T) {
	for _, key := range []string{"", "bad", "c2hvcnQ="} {
		t.Setenv("PROVIDER_MASTER_KEY", key)
		if ValidateMasterKey() == nil {
			t.Fatal("invalid key accepted")
		}
	}
	t.Setenv("PROVIDER_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err := ValidateMasterKey(); err != nil {
		t.Fatal(err)
	}
}
