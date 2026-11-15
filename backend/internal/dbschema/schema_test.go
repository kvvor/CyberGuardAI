package dbschema

import (
	"errors"
	"strings"
	"testing"
)

func TestEvaluate(t *testing.T) {
	cases := []struct {
		version int
		dirty   bool
		want    error
	}{
		{Required, false, nil},
		{Required - 1, false, ErrOutdated},
		{2, false, ErrOutdated},
		{Required + 1, false, ErrNewer},
		{Required, true, ErrDirty},
	}
	for _, c := range cases {
		if got := Evaluate(c.version, c.dirty); got != c.want {
			t.Fatalf("version %d dirty %v: got %v want %v", c.version, c.dirty, got, c.want)
		}
	}
}

func TestExplainIsActionable(t *testing.T) {
	for _, err := range []error{ErrNotMigrated, ErrOutdated} {
		if !strings.Contains(Explain(err), "migrate") || !IsSchemaError(err) {
			t.Fatalf("no instruction for %v", err)
		}
	}
	if Explain(errors.New("other")) == "" || IsSchemaError(errors.New("other")) {
		t.Fatal("fallback")
	}
}
