package openai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ErrorCode maps a provider HTTP error to a stable CyberGuard failure code. It
// prefers the provider's machine-readable error code over the HTTP status.
func ErrorCode(status int, body []byte) string {
	var v struct {
		Error struct {
			Code  any    `json:"code"`
			Type  string `json:"type"`
			Param string `json:"param"`
		} `json:"error"`
	}
	json.Unmarshal(body, &v)
	code, _ := v.Error.Code.(string)
	switch code {
	case "insufficient_quota", "billing_hard_limit_reached", "billing_not_active":
		return "PROVIDER_INSUFFICIENT_QUOTA"
	case "invalid_api_key", "account_deactivated":
		return "PROVIDER_INVALID_CREDENTIALS"
	case "model_not_found", "unsupported_model":
		return "PROVIDER_UNSUPPORTED_MODEL"
	case "context_length_exceeded", "string_above_max_length":
		return "PROVIDER_INPUT_TOO_LARGE"
	case "rate_limit_exceeded":
		return "PROVIDER_RATE_LIMITED"
	case "unsupported_parameter", "unsupported_value", "invalid_json_schema":
		// The selected model cannot serve this strict structured request.
		return "PROVIDER_UNSUPPORTED_MODEL"
	}
	switch status {
	case 401:
		return "PROVIDER_INVALID_CREDENTIALS"
	case 403:
		return "PROVIDER_ACCESS_DENIED"
	case 404:
		return "PROVIDER_UNSUPPORTED_MODEL"
	case 429:
		if v.Error.Type == "insufficient_quota" {
			return "PROVIDER_INSUFFICIENT_QUOTA"
		}
		return "PROVIDER_RATE_LIMITED"
	case 408, 504:
		return "PROVIDER_TIMEOUT"
	case 400, 422:
		if v.Error.Param == "model" {
			return "PROVIDER_UNSUPPORTED_MODEL"
		}
		return "PROVIDER_REQUEST_REJECTED"
	}
	return "PROVIDER_ERROR"
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+path, nil)
	if e != nil {
		return nil, errors.New("INVALID_PROVIDER_SETTINGS")
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	resp, e := c.http(15 * time.Second).Do(req)
	if e != nil {
		return nil, transportError(ctx, e)
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if e != nil {
		return nil, transportError(ctx, e)
	}
	if len(body) > 4<<20 {
		return nil, errors.New("PROVIDER_INVALID_OUTPUT")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(ErrorCode(resp.StatusCode, body))
	}
	return body, nil
}

// TestConnection checks credential and model access through model metadata.
// It performs no inference, sends no email content and costs no tokens.
func (c *Client) TestConnection(ctx context.Context) error {
	if c.Key == "" || c.Model == "" {
		return errors.New("PROVIDER_NOT_CONFIGURED")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	body, e := c.get(ctx, "/models/"+url.PathEscape(c.Model))
	if e != nil {
		return e
	}
	var m struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &m) != nil || m.ID != c.Model {
		return errors.New("PROVIDER_INVALID_OUTPUT")
	}
	return nil
}

type Model struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
}

// nonText lists model families that cannot produce a text assessment. This is
// a display filter only: any model identifier can still be saved and the
// provider decides at request time whether it supports the request.
var nonText = []string{"embedding", "whisper", "tts", "dall-e", "image", "audio", "realtime", "moderation", "transcribe", "sora", "babbage", "davinci", "computer-use", "codex", "search", "instruct"}

// ListModels returns the models the credential can access, newest first, read
// live from the provider so the application never ships a stale model list.
func (c *Client) ListModels(ctx context.Context) ([]Model, error) {
	if c.Key == "" {
		return nil, errors.New("PROVIDER_NOT_CONFIGURED")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	body, e := c.get(ctx, "/models")
	if e != nil {
		return nil, e
	}
	var list struct {
		Data []Model `json:"data"`
	}
	if json.Unmarshal(body, &list) != nil || list.Data == nil {
		return nil, errors.New("PROVIDER_INVALID_OUTPUT")
	}
	models := []Model{}
	for _, m := range list.Data {
		if m.ID == "" || len(m.ID) > 128 {
			continue
		}
		skip := false
		for _, word := range nonText {
			skip = skip || strings.Contains(strings.ToLower(m.ID), word)
		}
		if !skip {
			models = append(models, m)
		}
	}
	sort.Slice(models, func(i, j int) bool {
		if models[i].Created != models[j].Created {
			return models[i].Created > models[j].Created
		}
		return models[i].ID < models[j].ID
	})
	if len(models) > 200 {
		models = models[:200]
	}
	return models, nil
}
