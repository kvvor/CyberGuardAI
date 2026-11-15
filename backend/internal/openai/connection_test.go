package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectionStatuses(t *testing.T) {
	for _, tc := range []struct {
		status     int
		body, code string
	}{{200, `{"id":"model"}`, ""}, {401, `{}`, "PROVIDER_INVALID_CREDENTIALS"}, {429, `{"error":{"code":"insufficient_quota"}}`, "PROVIDER_INSUFFICIENT_QUOTA"}, {429, `{}`, "PROVIDER_RATE_LIMITED"}, {404, `{}`, "PROVIDER_UNSUPPORTED_MODEL"}, {200, `{}`, "PROVIDER_INVALID_OUTPUT"}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Error("inference attempted")
			}
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		c := Client{Key: "synthetic", Model: "model", Endpoint: server.URL}
		e := c.TestConnection(context.Background())
		server.Close()
		if tc.code == "" {
			if e != nil {
				t.Fatal(e)
			}
		} else if e == nil || e.Error() != tc.code {
			t.Fatal(tc, e)
		}
	}
}
