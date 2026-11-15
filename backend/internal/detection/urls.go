package detection

import (
	"html"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

type errURL struct{}

func (errURL) Error() string { return "INVALID_URL" }

// NormalizeURL only decodes data locally; nothing is ever fetched. The boolean
// reports whether a known security wrapper was removed. Wrappers confer no trust.
func NormalizeURL(raw string) (string, bool, error) {
	normalized, wrapper, err := UnwrapURL(raw)
	return normalized, wrapper != "", err
}

// wrapped returns the destination carried inside a known link-rewriting
// service URL, or "" when u is not such a wrapper or cannot be decoded.
func wrapped(raw string, u *url.URL, host string) (string, string) {
	q := u.Query()
	switch {
	case strings.HasSuffix(host, ".safelinks.protection.outlook.com"):
		return q.Get("url"), "microsoft_safelinks"
	case host == "urldefense.proofpoint.com" && strings.HasPrefix(u.Path, "/v2/url"):
		// v2 encodes "%" as "-" and "/" as "_".
		target, err := url.QueryUnescape(strings.NewReplacer("-", "%", "_", "/").Replace(q.Get("u")))
		if err != nil {
			return "", ""
		}
		return target, "proofpoint_urldefense"
	case host == "urldefense.com" && strings.HasPrefix(u.EscapedPath(), "/v3/__"):
		// v3: https://urldefense.com/v3/__<destination>__;<token>!!<signature>$
		rest := raw[strings.Index(raw, "/v3/__")+len("/v3/__"):]
		end := strings.LastIndex(rest, "__;")
		if end <= 0 {
			return "", ""
		}
		return rest[:end], "proofpoint_urldefense"
	case (host == "www.google.com" || host == "google.com") && u.Path == "/url":
		if target := q.Get("q"); target != "" {
			return target, "google_redirect"
		}
		return q.Get("url"), "google_redirect"
	case host == "linkprotect.cudasvc.com" && strings.HasPrefix(u.Path, "/url"):
		return q.Get("a"), "barracuda_linkprotect"
	}
	return "", ""
}

// UnwrapURL normalizes an http(s) URL (entity decoding, lower-case scheme and
// host, IDNA to punycode) and unwraps known link-rewriting services. It
// returns the outermost wrapper name when one was removed.
func UnwrapURL(raw string) (string, string, error) {
	s := html.UnescapeString(strings.TrimSpace(raw))
	wrapper := ""
	for depth := 0; depth < 4; depth++ {
		if len(s) > 8192 {
			return "", wrapper, errURL{}
		}
		u, e := url.Parse(s)
		if e != nil {
			return "", wrapper, errURL{}
		}
		u.Scheme = strings.ToLower(u.Scheme)
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if (u.Scheme != "http" && u.Scheme != "https") || host == "" {
			return "", wrapper, errURL{}
		}
		ascii := host
		if net.ParseIP(host) == nil {
			if ascii, e = idna.Lookup.ToASCII(host); e != nil {
				return "", wrapper, errURL{}
			}
		}
		if port := u.Port(); port != "" {
			u.Host = net.JoinHostPort(ascii, port)
		} else if strings.Contains(ascii, ":") {
			u.Host = "[" + ascii + "]"
		} else {
			u.Host = ascii
		}
		if u.User == nil {
			if target, name := wrapped(s, u, ascii); target != "" {
				if wrapper == "" {
					wrapper = name
				}
				s = html.UnescapeString(strings.TrimSpace(target))
				continue
			}
		}
		return u.String(), wrapper, nil
	}
	return "", wrapper, errURL{}
}
