// Package virustotal performs existing file reputation lookups only. It never
// accepts attachment bytes, uploads files, or follows provider redirects.
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Engine struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Result   string `json:"result"`
}
type Result struct {
	SHA256       string         `json:"sha256"`
	Status       string         `json:"status"`
	Source       string         `json:"source"`
	Statistics   map[string]int `json:"statistics,omitempty"`
	Engines      []Engine       `json:"engines,omitempty"`
	LastAnalysis *time.Time     `json:"last_analysis_at,omitempty"`
	CheckedAt    *time.Time     `json:"checked_at,omitempty"`
}
type Client struct {
	Key, Endpoint string
	HTTP          *http.Client
}

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func (c *Client) Lookup(ctx context.Context, hash string) Result {
	r := Result{SHA256: strings.ToLower(hash), Status: "provider_error", Source: "VirusTotal API v3"}
	if !sha256Pattern.MatchString(hash) {
		return r
	}
	if c.Key == "" {
		r.Status = "not_configured"
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = "https://www.virustotal.com/api/v3"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/files/"+r.SHA256, nil)
	if err != nil {
		return r
	}
	req.Header.Set("x-apikey", c.Key)
	client := http.Client{Timeout: 15 * time.Second}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	now := time.Now().UTC()
	r.CheckedAt = &now
	if err != nil {
		r.Status = "network_error"
		var ne net.Error
		if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) {
			r.Status = "timeout"
		}
		return r
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 401:
		r.Status = "authentication_failed"
		return r
	case 403:
		r.Status = "access_forbidden"
		return r
	case 404:
		r.Status = "not_found"
		return r
	case 429:
		r.Status = "rate_limited"
		return r
	case 408, 504:
		r.Status = "timeout"
		return r
	default:
		return r
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return r
	}
	var envelope struct {
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				SHA256  string                                       `json:"sha256"`
				Stats   map[string]int                               `json:"last_analysis_stats"`
				Date    int64                                        `json:"last_analysis_date"`
				Results map[string]struct{ Category, Result string } `json:"last_analysis_results"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &envelope) != nil {
		return r
	}
	d := envelope.Data
	if d.Type != "file" || !strings.EqualFold(d.ID, hash) || !strings.EqualFold(d.Attributes.SHA256, hash) || d.Attributes.Stats == nil {
		return r
	}
	stats := map[string]int{}
	for _, k := range []string{"malicious", "suspicious", "harmless", "undetected", "timeout", "confirmed-timeout", "failure", "type-unsupported"} {
		n := d.Attributes.Stats[k]
		if n < 0 || n > 10000 {
			return r
		}
		stats[k] = n
	}
	r.Statistics = stats
	if d.Attributes.Date > 0 {
		date := time.Unix(d.Attributes.Date, 0).UTC()
		r.LastAnalysis = &date
	}
	names := []string{}
	for name := range d.Attributes.Results {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		e := d.Attributes.Results[name]
		if (e.Category == "malicious" || e.Category == "suspicious") && len(r.Engines) < 32 {
			if len(name) > 128 || len(e.Result) > 512 {
				continue
			}
			r.Engines = append(r.Engines, Engine{name, e.Category, e.Result})
		}
	}
	r.Status = "completed"
	return r
}

// LookupMany is serial and deduplicates hashes. No automatic retry consumes a
// second quota unit. A caller may reserve quota before each distinct lookup.
func (c *Client) LookupMany(ctx context.Context, hashes []string, reserve func() bool) []Result {
	results := make([]Result, 0, len(hashes))
	seen := map[string]Result{}
	blocked := ""
	for _, hash := range hashes {
		hash = strings.ToLower(hash)
		if r, ok := seen[hash]; ok {
			results = append(results, r)
			continue
		}
		r := Result{SHA256: hash, Source: "VirusTotal API v3", Status: blocked}
		if !sha256Pattern.MatchString(hash) {
			r.Status = "provider_error"
		} else if blocked == "" {
			if reserve != nil && !reserve() {
				r.Status = "rate_limited"
			} else {
				r = c.Lookup(ctx, hash)
			}
		}
		if r.Status == "rate_limited" || r.Status == "authentication_failed" || r.Status == "access_forbidden" {
			blocked = r.Status
		}
		seen[hash] = r
		results = append(results, r)
	}
	return results
}
