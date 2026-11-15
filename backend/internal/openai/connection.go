package openai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

func ErrorCode(status int, body []byte) string {
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(body, &v)
	if v.Error.Code == "insufficient_quota" {
		return "PROVIDER_INSUFFICIENT_QUOTA"
	}
	switch status {
	case 401, 403:
		return "PROVIDER_INVALID_CREDENTIALS"
	case 404:
		return "PROVIDER_UNSUPPORTED_MODEL"
	case 429:
		return "PROVIDER_RATE_LIMITED"
	case 408, 504:
		return "PROVIDER_TIMEOUT"
	case 400:
		return "PROVIDER_UNSUPPORTED_MODEL"
	default:
		return "PROVIDER_ERROR"
	}
}

// TestConnection checks model metadata, not model inference. It sends no email.
func (c *Client) TestConnection(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	endpoint := "https://api.openai.com/v1/models/" + url.PathEscape(c.Model)
	if c.Endpoint != "" {
		endpoint = c.Endpoint
	}
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return errors.New("INVALID_PROVIDER_SETTINGS")
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return errors.New("PROVIDER_TIMEOUT")
		}
		return errors.New("PROVIDER_NETWORK_FAILURE")
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(body) > 65536 {
		return errors.New("PROVIDER_INVALID_OUTPUT")
	}
	if resp.StatusCode != 200 {
		return errors.New(ErrorCode(resp.StatusCode, body))
	}
	var m struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &m) != nil || m.ID != c.Model {
		return errors.New("PROVIDER_INVALID_OUTPUT")
	}
	return nil
}
