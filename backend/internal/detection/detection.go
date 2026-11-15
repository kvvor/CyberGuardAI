package detection

import (
	"cyberguard.local/backend/internal/emailparser"
	"fmt"
	"golang.org/x/net/html"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	ID       string `json:"id"`
	Rule     string `json:"rule_id"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
	Source   string `json:"evidence_source"`
	Code     string `json:"description_code"`
	Method   string `json:"analysis_method"`
	Status   string `json:"status"`
}
type IOC struct {
	Category   string   `json:"resource_category"`
	Original   string   `json:"original_value"`
	FindingIDs []string `json:"finding_ids"`
	Suspicion  string   `json:"suspicion_status"`
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Normalized string   `json:"normalized_value"`
	Defanged   string   `json:"defanged_value"`
	Source     string   `json:"source"`
}
type Mapping struct {
	ID       string   `json:"technique_id"`
	Name     string   `json:"technique_name"`
	Tactic   string   `json:"tactic"`
	Status   string   `json:"mapping_status"`
	Evidence []string `json:"evidence_ids"`
	URL      string   `json:"official_url"`
}
type Report struct {
	Verdict     string            `json:"verdict"`
	Score       int               `json:"risk_score"`
	Level       string            `json:"risk_level"`
	Version     string            `json:"scoring_version"`
	AttackTypes []string          `json:"attack_types"`
	Indicators  []Finding         `json:"indicators"`
	IOCs        []IOC             `json:"iocs"`
	MITRE       []Mapping         `json:"mitre_mappings"`
	Limitations []string          `json:"limitations"`
	Manual      bool              `json:"manual_review_required"`
	Email       emailparser.Email `json:"email"`
	AIStatus    string            `json:"ai_status"`
}

var urls = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
var emails = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
var hashes = regexp.MustCompile(`\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b`)

func Defang(s string) string {
	s = strings.ReplaceAll(s, "https://", "hxxps://")
	s = strings.ReplaceAll(s, "http://", "hxxp://")
	s = strings.ReplaceAll(s, ".", "[.]")
	return strings.ReplaceAll(s, "@", "[@]")
}
func Analyze(e emailparser.Email) Report {
	r := Report{Email: e, Verdict: "inconclusive", Level: "low", Version: "2.0.0", AttackTypes: []string{}, Indicators: []Finding{}, IOCs: []IOC{}, MITRE: []Mapping{}, Limitations: []string{"HEURISTIC_NOT_PROBABILITY", "AUTHENTICATION_HEADERS_UNVERIFIED", "NO_REPUTATION_LOOKUP"}, Manual: true, AIStatus: "not_requested"}
	r.Limitations = append(r.Limitations, e.Warnings...)
	add := func(rule, ev, source string, weight int) {
		if len(r.Indicators) >= 128 {
			return
		}
		if len(ev) > 2048 {
			ev = ev[:2048]
		}
		severity := "medium"
		if weight >= 25 {
			severity = "high"
		}
		r.Indicators = append(r.Indicators, Finding{fmt.Sprintf("e%d", len(r.Indicators)+1), rule, "static", severity, ev, source, rule, "deterministic", "observed"})
		r.Score += weight
	}
	attack := func(s string) {
		for _, x := range r.AttackTypes {
			if x == s {
				return
			}
		}
		r.AttackTypes = append(r.AttackTypes, s)
	}
	domain := func(s string) string {
		a, err := mail.ParseAddress(s)
		if err != nil {
			return ""
		}
		p := strings.Split(a.Address, "@")
		return strings.ToLower(p[len(p)-1])
	}
	if e.ReplyTo != "" && domain(e.Sender) != "" && domain(e.ReplyTo) != domain(e.Sender) {
		add("DOMAIN_MISMATCH", e.Sender+" / "+e.ReplyTo, "headers", 15)
		attack("impersonation")
	}
	if strings.Contains(strings.ToLower(e.Sender), "xn--") {
		add("PUNYCODE_SENDER", e.Sender, "headers", 10)
	}
	if a, err := mail.ParseAddress(e.Sender); err == nil {
		if displayed, err := mail.ParseAddress(a.Name); err == nil && !strings.EqualFold(displayed.Address, a.Address) {
			add("DISPLAY_NAME_SPOOFING", e.Sender, "headers", 25)
			attack("impersonation")
		}
		for _, brand := range []string{"microsoft", "paypal", "google", "apple", "amazon"} {
			host := domain(e.Sender)
			label := strings.Split(host, ".")[0]
			if strings.Contains(strings.ToLower(a.Name), brand) && host != brand+".com" && !strings.HasSuffix(host, "."+brand+".com") {
				add("BRAND_DOMAIN_MISMATCH", e.Sender, "headers", 15)
				attack("impersonation")
			}
			if label != brand && lookalike(label, brand) {
				add("LOOKALIKE_DOMAIN", host+" resembles "+brand, "headers", 20)
				attack("impersonation")
			}
		}
	}
	for _, value := range e.AuthenticationResults {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "spf=fail") || strings.Contains(lower, "dkim=fail") || strings.Contains(lower, "dmarc=fail") {
			add("REPORTED_AUTHENTICATION_FAILURE", value, "untrusted_header", 5)
		}
	}
	body := strings.ToLower(e.Text + " " + e.Subject + " " + e.HTML)
	for _, rule := range []struct {
		code   string
		terms  []string
		weight int
		kind   string
	}{{"CREDENTIAL_REQUEST", []string{"verify your password", "confirm your password", "enter your password", "подтвердите пароль", "құпия сөзіңізді"}, 30, "credential_phishing"}, {"URGENCY", []string{"urgent", "immediately", "срочно", "шұғыл"}, 10, "other"}, {"ACCOUNT_SUSPENSION", []string{"account suspended", "account will be closed", "аккаунт заблокирован"}, 20, "credential_phishing"}, {"PAYMENT_REQUEST", []string{"wire transfer", "new bank account", "pay this invoice", "переведите деньги"}, 20, "invoice_fraud"}, {"BEC_SECRECY", []string{"keep this confidential", "do not call", "gift cards"}, 25, "business_email_compromise"}} {
		for _, term := range rule.terms {
			if strings.Contains(body, term) {
				add(rule.code, term, "body", rule.weight)
				attack(rule.kind)
				break
			}
		}
	}
	seen := map[string]bool{}
	ioc := func(typ, value, source string) {
		if len(r.IOCs) >= 512 || len(value) > 2048 {
			return
		}
		norm := value
		if typ != "url" {
			norm = strings.ToLower(value)
		}
		k := typ + norm
		if seen[k] {
			return
		}
		seen[k] = true
		r.IOCs = append(r.IOCs, IOC{Type: typ, Value: value, Normalized: norm, Defanged: Defang(norm), Source: source, Original: value, Category: source, FindingIDs: []string{}, Suspicion: "unassessed"})
	}
	links := urls.FindAllString(e.Text, 512)
	doc, _ := html.Parse(strings.NewReader(e.HTML))
	var walk func(*html.Node)
	visited := 0
	walk = func(n *html.Node) {
		visited++
		if visited > 10000 {
			return
		}
		if n.Type == html.ElementNode && n.Data != "a" {
			for _, a := range n.Attr {
				if a.Key == "src" || a.Key == "href" {
					if normalized, _, err := NormalizeURL(a.Val); err == nil {
						ioc("url", normalized, "embedded_resource")
						for i := range r.IOCs {
							if r.IOCs[i].Normalized == normalized {
								r.IOCs[i].Original = a.Val
								if strings.Contains(strings.ToLower(normalized), "/track") || strings.Contains(strings.ToLower(normalized), "/pixel") || strings.Contains(strings.ToLower(normalized), "/beacon") {
									r.IOCs[i].Category = "tracking_url"
								}
							}
						}
					}
				}
			}
		}
		if n.Type == html.ElementNode && n.Data == "a" {
			href := ""
			for _, a := range n.Attr {
				if a.Key == "href" {
					href = a.Val
				}
			}
			if href != "" && len(links) < 512 {
				links = append(links, href)
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					shownURL, _, _ := NormalizeURL(strings.TrimSpace(n.FirstChild.Data))
					destURL, _, _ := NormalizeURL(href)
					shown, _ := url.Parse(shownURL)
					dest, _ := url.Parse(destURL)
					if shown != nil && dest != nil && shown.Hostname() != "" && !strings.EqualFold(shown.Hostname(), dest.Hostname()) {
						add("LINK_DESTINATION_MISMATCH", n.FirstChild.Data+" -> "+href, "html", 25)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	if doc != nil {
		walk(doc)
	}
	actionableSeen := map[string]bool{}
	for _, raw := range links {
		normalized, wrapped, normErr := NormalizeURL(strings.TrimRight(raw, ".,);"))
		if normErr != nil {
			continue
		}
		u, err := url.Parse(normalized)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.Host = strings.ToLower(u.Host)
		if actionableSeen[u.String()] {
			continue
		}
		actionableSeen[u.String()] = true
		category := "actionable_hyperlink"
		if wrapped {
			category = "security_wrapped"
		}
		ioc("url", u.String(), category)
		for i := range r.IOCs {
			if r.IOCs[i].Normalized == u.String() {
				r.IOCs[i].Original = raw
				r.IOCs[i].Category = category
			}
		}
		if net.ParseIP(u.Hostname()) == nil {
			ioc("domain", u.Hostname(), "url")
		}
		if net.ParseIP(u.Hostname()) != nil {
			ioc("ip", u.Hostname(), "url")
			add("IP_LINK", raw, "url", 20)
		}
		if u.User != nil || strings.Contains(u.Hostname(), "xn--") {
			add("SUSPICIOUS_URL", raw, "url", 15)
		}
	}
	for _, x := range emails.FindAllString(e.Text+" "+e.Sender+" "+e.ReplyTo, -1) {
		ioc("email", x, "email")
		parts := strings.Split(x, "@")
		ioc("domain", parts[len(parts)-1], "email")
	}
	for _, candidate := range strings.FieldsFunc(e.Text, func(c rune) bool {
		return !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':')
	}) {
		if ip := net.ParseIP(strings.Trim(candidate, ".")); ip != nil {
			ioc("ip", ip.String(), "body")
		}
	}
	for _, x := range hashes.FindAllString(e.Text, -1) {
		ioc("hash", x, "body")
	}
	for _, a := range e.Attachments {
		ioc("sha256", a.SHA256, "attachment")
		if a.Declared != "" && a.Declared != "application/octet-stream" && !strings.HasPrefix(a.Detected, a.Declared) && !(strings.HasPrefix(a.Declared, "text/") && strings.HasPrefix(a.Detected, "text/")) {
			add("MIME_SIGNATURE_MISMATCH", a.Filename+": "+a.Declared+" / "+a.Detected, "attachment", 15)
		}
		ext := strings.ToLower(filepath.Ext(a.Filename))
		if strings.Contains("|.exe|.dll|.js|.vbs|.ps1|.bat|.cmd|.scr|.hta|", "|"+ext+"|") {
			add("DANGEROUS_ATTACHMENT", a.Filename, "attachment", 35)
			attack("suspected_malware_delivery")
			attack("spearphishing_attachment")
		}
		if strings.Count(a.Filename, ".") > 1 {
			add("DOUBLE_EXTENSION", a.Filename, "attachment", 10)
		}
		if ext == ".docm" || ext == ".xlsm" {
			add("MACRO_CAPABLE_DOCUMENT", a.Filename, "attachment", 15)
		}
		if ext == ".zip" || ext == ".rar" || ext == ".7z" {
			add("ARCHIVE_NOT_INSPECTED", a.Filename, "attachment", 5)
		}
	}
	if r.Score > 100 {
		r.Score = 100
	}
	if r.Score >= 70 {
		r.Level = "critical"
	} else if r.Score >= 45 {
		r.Level = "high"
	} else if r.Score >= 20 {
		r.Level = "medium"
	}
	if r.Score >= 60 {
		r.Verdict = "phishing"
	} else if r.Score >= 20 {
		r.Verdict = "suspicious"
	}
	if r.Score >= 20 {
		ids := []string{}
		for _, f := range r.Indicators {
			ids = append(ids, f.ID)
		}
		r.MITRE = append(r.MITRE, Mapping{"T1566", "Phishing", "Initial Access", "suspected", ids, "https://attack.mitre.org/techniques/T1566/"})
		if len(links) > 0 {
			attack("spearphishing_link")
			r.MITRE = append(r.MITRE, Mapping{"T1566.002", "Spearphishing Link", "Initial Access", "suspected", ids, "https://attack.mitre.org/techniques/T1566/002/"})
		}
		for _, kind := range r.AttackTypes {
			if kind == "spearphishing_attachment" {
				attachmentIDs := []string{}
				for _, f := range r.Indicators {
					if f.Rule == "DANGEROUS_ATTACHMENT" {
						attachmentIDs = append(attachmentIDs, f.ID)
					}
				}
				r.MITRE = append(r.MITRE, Mapping{"T1566.001", "Spearphishing Attachment", "Initial Access", "suspected", attachmentIDs, "https://attack.mitre.org/techniques/T1566/001/"})
			}
		}
	}
	for i := range r.IOCs {
		for _, f := range r.Indicators {
			if strings.Contains(f.Evidence, r.IOCs[i].Value) || strings.Contains(f.Evidence, r.IOCs[i].Original) {
				r.IOCs[i].FindingIDs = append(r.IOCs[i].FindingIDs, f.ID)
				r.IOCs[i].Suspicion = "associated_with_finding"
			}
		}
	}
	return r
}
func lookalike(a, b string) bool {
	if a == b || len(a) < 3 {
		return false
	}
	normalized := strings.NewReplacer("0", "o", "1", "l", "rn", "m").Replace(a)
	if normalized == b {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	changes := 0
	for i := range a {
		if a[i] != b[i] {
			changes++
		}
	}
	return changes == 1
}
