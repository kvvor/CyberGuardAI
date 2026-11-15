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
	}{
		{200, `{"id":"model"}`, ""},
		{401, `{"error":{"code":"invalid_api_key"}}`, "PROVIDER_INVALID_CREDENTIALS"},
		{403, `{}`, "PROVIDER_ACCESS_DENIED"},
		{429, `{"error":{"code":"insufficient_quota"}}`, "PROVIDER_INSUFFICIENT_QUOTA"},
		{429, `{}`, "PROVIDER_RATE_LIMITED"},
		{404, `{"error":{"code":"model_not_found"}}`, "PROVIDER_UNSUPPORTED_MODEL"},
		{500, `{}`, "PROVIDER_ERROR"},
		{200, `{}`, "PROVIDER_INVALID_OUTPUT"},
		{200, `{"id":"another-model"}`, "PROVIDER_INVALID_OUTPUT"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A connection test is a metadata read: it must never run inference.
			if r.Method != "GET" || r.URL.Path != "/models/model" || r.ContentLength > 0 {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		c := Client{Key: "synthetic", Model: "model", BaseURL: server.URL}
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
	if e := (&Client{Key: "k"}).TestConnection(context.Background()); e == nil || e.Error() != "PROVIDER_NOT_CONFIGURED" {
		t.Fatal(e)
	}
}

func TestListModelsIsLiveFilteredAndSorted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/models" || r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(`{"object":"list","data":[{"id":"text-embedding-x","created":50},{"id":"chat-old","created":10},{"id":"chat-new","created":30},{"id":"whisper-x","created":40},{"id":"","created":99},{"id":"tts-x","created":41}]}`))
	}))
	defer server.Close()
	models, e := (&Client{Key: "synthetic", BaseURL: server.URL}).ListModels(context.Background())
	if e != nil || len(models) != 2 || models[0].ID != "chat-new" || models[1].ID != "chat-old" {
		t.Fatal(models, e)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer bad.Close()
	if _, e := (&Client{Key: "synthetic", BaseURL: bad.URL}).ListModels(context.Background()); e == nil || e.Error() != "PROVIDER_INVALID_CREDENTIALS" {
		t.Fatal(e)
	}
	if _, e := (&Client{}).ListModels(context.Background()); e == nil {
		t.Fatal("missing key accepted")
	}
}
