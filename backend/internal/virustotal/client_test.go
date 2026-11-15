package virustotal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLookupStatuses(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for code, want := range map[int]string{200: "completed", 400: "provider_error", 401: "authentication_failed", 403: "access_forbidden", 404: "not_found", 429: "rate_limited", 500: "provider_error", 504: "timeout"} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/files/"+hash || r.Header.Get("x-apikey") != "test-key" || r.ContentLength > 0 {
					t.Error("unsafe request")
				}
				w.WriteHeader(code)
				fmt.Fprintf(w, `{"data":{"id":%q,"type":"file","attributes":{"sha256":%q,"last_analysis_stats":{"malicious":12,"undetected":30},"last_analysis_date":1700000000,"last_analysis_results":{"engine":{"category":"malicious","result":"test"}}}}}`, hash, hash)
			}))
			defer s.Close()
			c := Client{Key: "test-key", Endpoint: s.URL}
			r := c.Lookup(context.Background(), hash)
			if r.Status != want {
				t.Fatalf("got %s want %s", r.Status, want)
			}
			if code == 200 && (r.Statistics["malicious"] != 12 || r.LastAnalysis == nil || len(r.Engines) != 1) {
				t.Fatal(r)
			}
		})
	}
}

func TestBoundariesAndDeduplication(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(404) }))
	defer s.Close()
	c := Client{Key: "test", Endpoint: s.URL}
	hash := strings.Repeat("a", 64)
	results := c.LookupMany(context.Background(), []string{hash, strings.ToUpper(hash), "invalid"}, nil)
	if requests != 1 || results[0].Status != "not_found" || results[1].Status != "not_found" || results[2].Status != "provider_error" {
		t.Fatal(requests, results)
	}
	requests = 0
	results = c.LookupMany(context.Background(), []string{hash, strings.Repeat("b", 64)}, func() bool { return false })
	if requests != 0 || results[1].Status != "rate_limited" {
		t.Fatal(results)
	}
	c.Key = ""
	if c.Lookup(context.Background(), hash).Status != "not_configured" {
		t.Fatal("missing credentials")
	}
}

func TestNetworkTimeoutAndRedirect(t *testing.T) {
	hash := strings.Repeat("a", 64)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	c := Client{Key: "test", Endpoint: s.URL, HTTP: &http.Client{Timeout: 10 * time.Millisecond}}
	if r := c.Lookup(context.Background(), hash); r.Status != "timeout" {
		t.Fatal(r)
	}
	s.Close()
	if r := c.Lookup(context.Background(), hash); r.Status != "network_error" {
		t.Fatal(r)
	}
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/leak", 302) }))
	defer s.Close()
	c.Endpoint = s.URL
	if r := c.Lookup(context.Background(), hash); r.Status != "provider_error" {
		t.Fatal(r)
	}
}

func TestMalformedReports(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":{"type":"file","id":"wrong"}}`, strings.Repeat("x", (2<<20)+1)} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c := Client{Key: "test", Endpoint: s.URL}
		if r := c.Lookup(context.Background(), strings.Repeat("a", 64)); r.Status != "provider_error" {
			t.Fatal(r)
		}
		s.Close()
	}
}
