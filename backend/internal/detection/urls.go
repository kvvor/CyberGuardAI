package detection

import (
	"golang.org/x/net/idna"
	"html"
	"net"
	"net/url"
	"strings"
)

// NormalizeURL only decodes data locally. Wrappers confer no trust.
func NormalizeURL(raw string) (string, bool, error) {
	s := html.UnescapeString(strings.TrimSpace(raw))
	wrapped := false
	for depth := 0; depth < 4; depth++ {
		u, e := url.Parse(s)
		if e != nil {
			return "", wrapped, e
		}
		u.Scheme = strings.ToLower(u.Scheme)
		host := strings.ToLower(u.Hostname())
		if u.Scheme != "http" && u.Scheme != "https" || host == "" {
			return "", wrapped, &url.Error{Op: "parse", URL: "", Err: errURL{}}
		}
		ascii, e := idna.Lookup.ToASCII(host)
		if e != nil {
			return "", wrapped, e
		}
		if net.ParseIP(host) != nil {
			ascii = host
		}
		if port := u.Port(); port != "" {
			u.Host = net.JoinHostPort(ascii, port)
		} else if strings.Contains(ascii, ":") {
			u.Host = "[" + ascii + "]"
		} else {
			u.Host = ascii
		}
		if strings.HasSuffix(host, ".safelinks.protection.outlook.com") && u.User == nil {
			target := u.Query().Get("url")
			if target != "" {
				s = target
				wrapped = true
				continue
			}
		}
		return u.String(), wrapped, nil
	}
	return "", wrapped, errURL{}
}

type errURL struct{}

func (errURL) Error() string { return "INVALID_URL" }
