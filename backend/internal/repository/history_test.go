package repository

import (
	"net/url"
	"testing"
)

func TestHistoryValidation(t *testing.T) {
	for _, s := range []string{"page=-1", "page_size=101", "mode=other", "sort=DROP+TABLE", "date_from=bad", "date_from=2026-02-02&date_to=2026-01-01"} {
		q, _ := url.ParseQuery(s)
		if _, e := ParseHistory(q); e == nil {
			t.Fatal(s)
		}
	}
	q, _ := url.ParseQuery("sort=risk_desc&date_from=2026-01-01&date_to=2026-01-01")
	f, e := ParseHistory(q)
	if e != nil || f.To.Sub(*f.From).Hours() != 24 {
		t.Fatal(f, e)
	}
}
