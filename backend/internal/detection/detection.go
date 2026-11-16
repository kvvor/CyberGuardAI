// Package detection extracts deterministic technical evidence from a parsed
// email. It never scores or classifies: observations are facts for the analyst
// and for the contextual assessment, and none of them is a verdict.
package detection

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"cyberguard.local/backend/internal/emailparser"
	"cyberguard.local/backend/internal/virustotal"
	"golang.org/x/net/html"
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
	Wrapper    string   `json:"wrapper,omitempty"`
}

// Link is one hyperlink a reader can act on: what is shown and where it leads.
type Link struct {
	Text        string `json:"visible_text"`
	Destination string `json:"destination"`
	Original    string `json:"original_value"`
	Wrapper     string `json:"wrapper,omitempty"`
	Mismatch    bool   `json:"text_shows_different_host"`
	Kind        string `json:"kind"`
}
type Report struct {
	Evidence             []Evidence          `json:"evidence,omitempty"`
	Authentication       []Authentication    `json:"authentication,omitempty"`
	AttachmentReputation []virustotal.Result `json:"attachment_reputation,omitempty"`
	VirusTotalStatus     string              `json:"virustotal_status,omitempty"`
	Links                []Link              `json:"links,omitempty"`
	Verdict              string              `json:"verdict"`
	Score                int                 `json:"risk_score,omitempty"`
	Level                string              `json:"risk_level"`
	Version              string              `json:"scoring_version"`
	AttackTypes          []string            `json:"attack_types"`
	Indicators           []Finding           `json:"indicators"`
	IOCs                 []IOC               `json:"iocs"`
	Limitations          []string            `json:"limitations"`
	Manual               bool                `json:"manual_review_required"`
	Email                emailparser.Email   `json:"email"`
	AIStatus             string              `json:"ai_status"`
}

// EvidenceVersion identifies reports produced by the evidence pipeline. Older
// stored reports carry the weighted-score versions 1.0.0 and 2.0.0.
const EvidenceVersion = "3.0.0"

var urls = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
var emails = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
var hashes = regexp.MustCompile(`\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b`)
var bareHost = regexp.MustCompile(`(?i)^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/:?#].*)?$`)

// aiDirected matches text addressed to an automated reader. It is recorded as
// an observation because such text targets the analysis itself.
var aiDirected = regexp.MustCompile(`(?i)(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules|directions)|(?:classify|mark|treat|label)\s+this\s+(?:e-?mail|message)\s+as\s+(?:safe|legitimate|benign|not\s+phishing)|system\s+prompt|you\s+are\s+(?:an?\s+)?(?:ai|assistant|language\s+model)|игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие|прежние|системные)\s+(?:инструкции|указания)|считай(?:те)?\s+это\s+письмо\s+(?:безопасным|легитимным)`)

func Defang(s string) string {
	s = strings.ReplaceAll(s, "https://", "hxxps://")
	s = strings.ReplaceAll(s, "http://", "hxxp://")
	s = strings.ReplaceAll(s, ".", "[.]")
	return strings.ReplaceAll(s, "@", "[@]")
}

var nameDomain = regexp.MustCompile(`[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|info|biz|app|dev|ru|kz|de|uk|fr|eu|us|cn|online|site|xyz|top|shop|support|cloud|example)\b`)

// mixedScripts reports a single word that combines Latin letters with Cyrillic
// or Greek ones (for example "Micrоsоft"). Whole words in different
// alphabets next to each other are normal and are not reported.
func mixedScripts(s string) bool {
	for _, word := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) }) {
		latin, other := false, false
		for _, r := range word {
			switch {
			case unicode.Is(unicode.Latin, r):
				latin = true
			case unicode.Is(unicode.Cyrillic, r) || unicode.Is(unicode.Greek, r):
				other = true
			}
		}
		if latin && other {
			return true
		}
	}
	return false
}

func addressDomain(s string) string {
	a, err := mail.ParseAddress(s)
	if err != nil {
		if at := strings.LastIndex(s, "@"); at >= 0 {
			return strings.ToLower(strings.Trim(s[at+1:], "<> \t"))
		}
		return ""
	}
	p := strings.Split(a.Address, "@")
	return strings.ToLower(p[len(p)-1])
}

// related reports whether two hosts are identical or one is a subdomain of
// the other, so that "example.com" shown for "www.example.com" is not flagged.
func related(a, b string) bool {
	a, b = strings.ToLower(strings.TrimPrefix(a, "www.")), strings.ToLower(strings.TrimPrefix(b, "www."))
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func textContent(n *html.Node, limit int) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if b.Len() > limit {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		if n.Type == html.ElementNode && n.Data == "img" {
			for _, a := range n.Attr {
				if a.Key == "alt" && a.Val != "" {
					b.WriteString(a.Val + " ")
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	s := strings.Join(strings.Fields(b.String()), " ")
	if len(s) > limit {
		s = strings.ToValidUTF8(s[:limit], "")
	}
	return s
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// Analyze extracts observations, hyperlinks and indicators of compromise.
func Analyze(e emailparser.Email) Report {
	r := Report{Email: e, Verdict: "inconclusive", Level: "low", Version: EvidenceVersion, AttackTypes: []string{}, Indicators: []Finding{}, IOCs: []IOC{}, Links: []Link{}, Limitations: []string{}, Manual: true, AIStatus: "not_requested"}
	add := func(rule, ev, source string) {
		if len(r.Indicators) >= 128 {
			return
		}
		if len(ev) > 2048 {
			ev = strings.ToValidUTF8(ev[:2048], "")
		}
		for _, f := range r.Indicators {
			if f.Rule == rule && f.Evidence == ev {
				return
			}
		}
		r.Indicators = append(r.Indicators, Finding{fmt.Sprintf("observation-%d", len(r.Indicators)+1), rule, "technical_observation", "info", ev, source, rule, "deterministic", "observed_not_a_verdict"})
	}

	// Sender relationships. Each is a fact with common benign explanations
	// (mailing services, ticket systems); none decides the verdict.
	from := addressDomain(e.Sender)
	if e.ReplyTo != "" && from != "" && addressDomain(e.ReplyTo) != "" && !related(addressDomain(e.ReplyTo), from) {
		add("REPLY_TO_DOMAIN_DIFFERS", "From: "+e.Sender+" | Reply-To: "+e.ReplyTo, "headers")
	}
	for _, rp := range e.Headers["Return-Path"] {
		if d := addressDomain(rp); d != "" && from != "" && !related(d, from) {
			add("RETURN_PATH_DOMAIN_DIFFERS", "From: "+e.Sender+" | Return-Path: "+rp, "headers")
		}
		break
	}
	if strings.Contains(strings.ToLower(from), "xn--") {
		add("PUNYCODE_SENDER_DOMAIN", e.Sender, "headers")
	}
	// The display name is free text chosen by the sender. An address or domain
	// written there that differs from the real address, or letters from several
	// alphabets inside one word, are recorded as facts about how the sender
	// presents itself. They are common in impersonation and also occur in
	// ordinary mail (shared mailboxes, forwarding services).
	if name, address := emailparser.SplitAddress(e.Sender); name != "" && address != "" {
		real := addressDomain(address)
		if shown := emails.FindString(name); shown != "" && !strings.EqualFold(shown, address) {
			add("DISPLAY_NAME_CONTAINS_OTHER_ADDRESS", "display name: "+name+" | address: "+address, "headers")
		} else if shown == "" {
			for _, candidate := range nameDomain.FindAllString(strings.ToLower(name), 4) {
				if real != "" && !related(candidate, real) {
					add("DISPLAY_NAME_SHOWS_OTHER_DOMAIN", "display name: "+name+" | address: "+address, "headers")
					break
				}
			}
		}
		if mixedScripts(name) {
			add("DISPLAY_NAME_MIXES_ALPHABETS", "display name: "+name+" | address: "+address, "headers")
		}
	}
	for _, value := range e.AuthenticationResults {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "spf=fail") || strings.Contains(lower, "dkim=fail") || strings.Contains(lower, "dmarc=fail") {
			add("REPORTED_AUTHENTICATION_FAILURE", value, "untrusted_header")
		}
	}
	// The HTML part is checked as readable text: injected instructions are
	// typically hidden there (tiny or white text) rather than in the plain part.
	for _, body := range []string{e.Subject, e.Text, htmlText(e.HTML, 24000)} {
		if m := aiDirected.FindString(body); m != "" {
			add("TEXT_ADDRESSED_TO_AUTOMATED_ANALYSIS", m, "body")
		}
	}

	seen := map[string]int{}
	ioc := func(typ, value, original, category, source, wrapper string) {
		if value == "" || len(value) > 2048 {
			return
		}
		norm := value
		if typ != "url" {
			norm = strings.ToLower(value)
		}
		k := typ + "\x00" + norm
		if i, ok := seen[k]; ok {
			// An actionable occurrence outranks an embedded-resource occurrence.
			if rank(category) < rank(r.IOCs[i].Category) {
				r.IOCs[i].Category, r.IOCs[i].Source, r.IOCs[i].Original, r.IOCs[i].Wrapper = category, source, original, wrapper
			}
			return
		}
		if len(r.IOCs) >= 512 {
			if len(r.Limitations) == 0 || r.Limitations[len(r.Limitations)-1] != "IOC_LIMIT_REACHED" {
				r.Limitations = append(r.Limitations, "IOC_LIMIT_REACHED")
			}
			return
		}
		if len(original) > 2048 {
			original = original[:2048]
		}
		seen[k] = len(r.IOCs)
		r.IOCs = append(r.IOCs, IOC{Type: typ, Value: norm, Normalized: norm, Defanged: Defang(norm), Source: source, Original: original, Category: category, FindingIDs: []string{}, Suspicion: "unassessed", Wrapper: wrapper})
	}

	link := func(raw, text, kind string) {
		raw = strings.TrimSpace(raw)
		normalized, wrapper, err := UnwrapURL(raw)
		if err != nil {
			return
		}
		u, err := url.Parse(normalized)
		if err != nil || u.Hostname() == "" {
			return
		}
		category := "actionable_hyperlink"
		if kind == "form_action" {
			category = "form_action"
		}
		ioc("url", normalized, raw, category, kind, wrapper)
		host := u.Hostname()
		if net.ParseIP(host) != nil {
			ioc("ip", host, host, "link_host", "url", "")
			add("LINK_TO_IP_ADDRESS", normalized, "url")
		} else {
			ioc("domain", host, host, "link_host", "url", "")
		}
		if u.User != nil {
			add("URL_WITH_EMBEDDED_CREDENTIALS", normalized, "url")
		}
		if strings.Contains(host, "xn--") {
			add("PUNYCODE_LINK_HOST", normalized, "url")
		}
		mismatch := false
		if shown := strings.TrimSpace(text); shown != "" {
			candidate := strings.Fields(shown)[0]
			if bareHost.MatchString(candidate) && !strings.Contains(candidate, "://") {
				candidate = "https://" + candidate
			}
			if shownURL, _, err := UnwrapURL(candidate); err == nil {
				if su, err := url.Parse(shownURL); err == nil && su.Hostname() != "" && !related(su.Hostname(), host) {
					mismatch = true
					add("LINK_TEXT_SHOWS_DIFFERENT_HOST", shown+" -> "+normalized, "html")
				}
			}
		}
		if len(r.Links) < 128 {
			for _, existing := range r.Links {
				// The same destination repeated in the plain-text part adds nothing.
				if existing.Destination == normalized && (existing.Text == text || text == "") {
					return
				}
			}
			r.Links = append(r.Links, Link{Text: text, Destination: normalized, Original: raw, Wrapper: wrapper, Mismatch: mismatch, Kind: kind})
		}
	}

	if e.HTML != "" {
		doc, _ := html.Parse(strings.NewReader(e.HTML))
		visited := 0
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			visited++
			if visited > 20000 {
				return
			}
			if n.Type == html.ElementNode {
				switch n.Data {
				case "a", "area":
					href := strings.TrimSpace(attr(n, "href"))
					if strings.HasPrefix(strings.ToLower(href), "mailto:") {
						// A mailto link is an address to write to, not a web destination.
						target := href[len("mailto:"):]
						if q := strings.IndexAny(target, "?#"); q >= 0 {
							target = target[:q]
						}
						if unescaped, err := url.PathUnescape(target); err == nil {
							target = unescaped
						}
						for _, address := range emails.FindAllString(target, 4) {
							ioc("email", address, href, "email_address", "html_mailto", "")
							parts := strings.Split(address, "@")
							ioc("domain", parts[len(parts)-1], parts[len(parts)-1], "email_domain", "html_mailto", "")
						}
					} else if href != "" {
						link(href, textContent(n, 300), "html_link")
					}
				case "form":
					if action := attr(n, "action"); action != "" {
						add("HTML_FORM_SUBMITS_TO_URL", action, "html")
						link(action, "", "form_action")
					} else {
						add("HTML_FORM_PRESENT", "form without explicit action", "html")
					}
				default:
					for _, key := range []string{"src", "href", "background", "poster"} {
						value := attr(n, key)
						if value == "" {
							continue
						}
						normalized, wrapper, err := UnwrapURL(value)
						if err != nil {
							continue
						}
						category := "embedded_resource"
						lower := strings.ToLower(normalized)
						switch n.Data {
						case "img":
							category = "embedded_image"
							tiny := (attr(n, "width") == "1" || attr(n, "width") == "0") && (attr(n, "height") == "1" || attr(n, "height") == "0")
							if tiny || strings.Contains(lower, "/track") || strings.Contains(lower, "/pixel") || strings.Contains(lower, "/beacon") || strings.Contains(lower, "/open") {
								category = "tracking_url"
							}
						case "link":
							category = "stylesheet"
						case "script":
							category = "script_resource"
							add("HTML_REFERENCES_SCRIPT", normalized, "html")
						}
						ioc("url", normalized, value, category, "html_resource", wrapper)
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
	}
	for _, raw := range urls.FindAllString(e.Text, 512) {
		link(strings.TrimRight(raw, ".,);:!?]}>"), "", "text_link")
	}

	for _, x := range emails.FindAllString(e.Text+" "+e.Sender+" "+e.ReplyTo, 256) {
		ioc("email", x, x, "email_address", "email", "")
		parts := strings.Split(x, "@")
		ioc("domain", parts[len(parts)-1], parts[len(parts)-1], "email_domain", "email", "")
	}
	for _, candidate := range strings.FieldsFunc(e.Text, func(c rune) bool {
		return !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':')
	}) {
		candidate = strings.Trim(candidate, ".:")
		if strings.Count(candidate, ".") != 3 && strings.Count(candidate, ":") < 2 {
			continue
		}
		if ip := net.ParseIP(candidate); ip != nil {
			ioc("ip", ip.String(), candidate, "body_text", "body", "")
		}
	}
	for _, x := range hashes.FindAllString(e.Text, 64) {
		ioc("hash", x, x, "body_text", "body", "")
	}
	for _, a := range e.Attachments {
		ioc("sha256", a.SHA256, a.Filename, "attachment", "attachment", "")
		if typeDiffers(a.Declared, a.Detected) {
			add("ATTACHMENT_TYPE_DIFFERS_FROM_DECLARED", a.Filename+": declared "+a.Declared+", content looks like "+a.Detected, "attachment")
		}
		ext := strings.ToLower(filepath.Ext(a.Filename))
		executable := strings.Contains("|.exe|.dll|.js|.jse|.vbs|.vbe|.ps1|.bat|.cmd|.scr|.hta|.com|.msi|.lnk|.jar|.wsf|.iso|.img|", "|"+ext+"|")
		if executable {
			add("EXECUTABLE_ATTACHMENT_TYPE", a.Filename, "attachment")
			// Only an executable hidden behind a document-like extension is noted;
			// ordinary names such as "report.v2.final.pdf" are not.
			stem := strings.ToLower(strings.TrimSuffix(a.Filename, filepath.Ext(a.Filename)))
			if inner := filepath.Ext(stem); inner != "" && strings.Contains("|.pdf|.doc|.docx|.xls|.xlsx|.ppt|.pptx|.txt|.jpg|.jpeg|.png|.gif|.zip|.rtf|.csv|", "|"+inner+"|") {
				add("EXECUTABLE_BEHIND_DOCUMENT_EXTENSION", a.Filename, "attachment")
			}
		}
		if strings.Contains("|.docm|.xlsm|.pptm|.dotm|.xlam|", "|"+ext+"|") {
			add("MACRO_CAPABLE_DOCUMENT", a.Filename, "attachment")
		}
		if strings.Contains("|.zip|.rar|.7z|.gz|.tar|.cab|", "|"+ext+"|") {
			add("ARCHIVE_CONTENT_NOT_INSPECTED", a.Filename, "attachment")
		}
		if strings.Contains("|.mobileconfig|.mobileprovision|.reg|.inf|.ppkg|", "|"+ext+"|") {
			// Installing such a file changes device or system settings (for
			// example trusted certificates, VPN or mail accounts). The type is
			// noted; the content was not inspected and nothing says it is harmful.
			add("CONFIGURATION_PROFILE_ATTACHMENT", a.Filename, "attachment")
		}
		if ext == ".html" || ext == ".htm" || ext == ".svg" || ext == ".shtml" {
			add("HTML_ATTACHMENT", a.Filename, "attachment")
		}
	}
	for i := range r.IOCs {
		for _, f := range r.Indicators {
			if strings.Contains(f.Evidence, r.IOCs[i].Value) || (r.IOCs[i].Original != "" && strings.Contains(f.Evidence, r.IOCs[i].Original)) {
				r.IOCs[i].FindingIDs = append(r.IOCs[i].FindingIDs, f.ID)
				r.IOCs[i].Suspicion = "referenced_by_observation"
			}
		}
	}
	return r
}

// typeDiffers reports a declared MIME type that contradicts the recognised
// content signature. Unrecognised content (octet-stream, generic text) and
// ZIP-based office formats are normal and never reported.
func typeDiffers(declared, detected string) bool {
	declared, detected = strings.ToLower(declared), strings.ToLower(detected)
	if declared == "" || detected == "" || declared == "application/octet-stream" || detected == "application/octet-stream" || strings.HasPrefix(detected, "text/plain") || strings.HasPrefix(detected, declared) {
		return false
	}
	if strings.HasPrefix(declared, "text/") && strings.HasPrefix(detected, "text/") {
		return false
	}
	if detected == "application/zip" {
		for _, container := range []string{"zip", "openxmlformats", "opendocument", "java-archive", "vnd.ms-", "epub", "x-compressed"} {
			if strings.Contains(declared, container) {
				return false
			}
		}
	}
	return true
}

// rank orders IOC categories from most to least actionable for a reader.
func rank(category string) int {
	switch category {
	case "form_action":
		return 0
	case "actionable_hyperlink":
		return 1
	case "link_host", "attachment", "email_address", "email_domain", "body_text":
		return 2
	case "script_resource":
		return 3
	case "tracking_url":
		return 4
	case "embedded_image":
		return 5
	case "stylesheet":
		return 6
	}
	return 7
}

// Actionable reports whether an IOC category is something a reader can act on,
// as opposed to page furniture such as images, style sheets and tracking pixels.
func Actionable(category string) bool { return rank(category) <= 3 }
