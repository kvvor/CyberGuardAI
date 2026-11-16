package emailparser

import "testing"

func TestDecodeHeaderHandlesRealWorldEncodedWords(t *testing.T) {
	cases := map[string]string{
		// The reported defect: base64 with padding that should not be there.
		"=?UTF-8?B?VGVybXMgVXBkYXRlIEVmZmVjdGl2ZSBNb24sIE1hcmNoIDMwLCAyMDI2==?=": "Terms Update Effective Mon, March 30, 2026",
		"=?UTF-8?B?VGVybXMgVXBkYXRlIEVmZmVjdGl2ZSBNb24sIE1hcmNoIDMwLCAyMDI2?=":   "Terms Update Effective Mon, March 30, 2026",
		"=?utf-8?Q?Verd=C3=A4chtige_DEX-Aktivit=C3=A4t_erkannt?=":                "Verdächtige DEX-Aktivität erkannt",
		"=?ISO-8859-1?Q?Gr=FC=DFe?= =?UTF-8?B?0JzQuNGA?=":                        "GrüßeМир",
		"=?windows-1251?B?z/Do4uXy?=":                                            "Привет",
		"Re: =?UTF-8?B?0J7RgtGH0ZHRgg==?= for March":                             "Re: Отчёт for March",
		"plain subject": "plain subject",
		"":              "",
	}
	for raw, want := range cases {
		if got := DecodeHeader(raw); got != want {
			t.Errorf("%q: got %q, want %q", raw, got, want)
		}
	}
	// Undecodable words are left exactly as received, never dropped or guessed.
	for _, raw := range []string{"=?x-no-such-charset?B?QUJD?=", "=?UTF-8?B?!!!not-base64!!!?=", "=?UTF-8?B?/w==?=", "=?broken"} {
		if got := DecodeHeader(raw); got != raw {
			t.Errorf("%q changed to %q", raw, got)
		}
	}
	// Decoding does not normalise: a Cyrillic "о" inside a Latin word stays Cyrillic.
	deceptive := "Micrоsоft"
	if got := DecodeHeader("=?UTF-8?B?TWljctC+c9C+ZnQ=?="); got != deceptive {
		t.Fatalf("deceptive characters altered: %q", got)
	}
}

func TestSplitAddressSeparatesDisplayNameFromAddress(t *testing.T) {
	cases := []struct{ raw, name, address string }{
		{`Dana Whitfield <dana@northwind.example>`, "Dana Whitfield", "dana@northwind.example"},
		{`"ceo@northwind.example" <ceo.office@freemail.example>`, "ceo@northwind.example", "ceo.office@freemail.example"},
		// Unquoted special characters make a strict parser fail; the real address must still be found.
		{`Noreply@ledger.example | (ledger.example) #BIOH <emailfromweb3-mexk8@ledgermail.onmicrosoft.example>`, "Noreply@ledger.example | (ledger.example) #BIOH", "emailfromweb3-mexk8@ledgermail.onmicrosoft.example"},
		{`plain@example.test`, "", "plain@example.test"},
		{`<only@example.test>`, "", "only@example.test"},
		{`Just A Name`, "Just A Name", ""},
		{``, "", ""},
	}
	for _, c := range cases {
		if name, address := SplitAddress(c.raw); name != c.name || address != c.address {
			t.Errorf("%q: got (%q, %q)", c.raw, name, address)
		}
	}
}

func TestParsedEmailKeepsRawAndReadableHeaders(t *testing.T) {
	raw := "From: =?UTF-8?B?TWljctC+c9C+ZnQgU3VwcG9ydA==?= <notice@account-alerts.example>\r\nSubject: =?UTF-8?B?VGVybXMgVXBkYXRlIEVmZmVjdGl2ZSBNb24sIE1hcmNoIDMwLCAyMDI2==?=\r\n\r\nbody"
	e, err := Parse([]byte(raw), "terms.eml", "eml", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if e.Subject != "Terms Update Effective Mon, March 30, 2026" || e.RawSubject == "" || e.RawSubject == e.Subject {
		t.Fatalf("subject %q raw %q", e.Subject, e.RawSubject)
	}
	if e.SenderName != "Micrоsоft Support" || e.SenderAddress != "notice@account-alerts.example" || e.RawSender == "" {
		t.Fatalf("sender name %q address %q raw %q", e.SenderName, e.SenderAddress, e.RawSender)
	}
	// Nothing is recorded as "raw" when there was nothing to decode.
	plain, _ := Parse([]byte("From: a@example.test\r\nSubject: Hello\r\n\r\nx"), "p.eml", "eml", "", "")
	if plain.RawSubject != "" || plain.RawSender != "" || plain.SenderName != "" || plain.SenderAddress != "a@example.test" {
		t.Fatalf("%+v", plain)
	}
	// A pasted body has no file name; it used to be reported as ".".
	pasted, _ := Parse([]byte("just text"), "", "paste", "", "")
	if pasted.Filename != "" {
		t.Fatalf("file name invented for pasted text: %q", pasted.Filename)
	}
}
