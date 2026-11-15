# Evidence pipeline and verdict validation

Report format version `3.0.0`. Reports with versions `1.0.0` and `2.0.0` come
from the retired rule-weight detector; they stay readable and are labelled
"historical" everywhere.

```
upload / paste -> parser -> evidence engine -> VirusTotal (hashes, consent)
                                            -> OpenAI Responses (evidence, consent)
                                            -> backend validation -> verdict
                                            -> PostgreSQL -> UI, PDF, JSON
```

## 1. Parsing (`internal/emailparser`)

- **EML**: headers (From, Sender, Reply-To, Return-Path, To, Cc, Subject, Date,
  Message-ID, Received, Authentication-Results, Received-SPF, DKIM-Signature),
  RFC 2047 encoded words, nested MIME, base64 and quoted-printable, character
  set conversion, text and HTML bodies, attachments with SHA-256.
- **MSG**: Outlook properties plus the original Internet headers when the file
  contains them (`PidTagTransportMessageHeaders`). Without them the report says
  so (`MISSING_EMAIL_HEADERS`); nothing is invented. Sender falls back from the
  SMTP address to the stored address and display name; an Exchange-internal
  address is flagged (`MSG_SENDER_NOT_SMTP_ADDRESS`).
- **Paste**: text with a header block is parsed as a message; anything else is
  a body only, with no sender, date or authentication data.

Limits: 10 MB input, 20 MB decoded, MIME depth 12, 128 parts, 32 attachments,
bounded MSG reads with a time limit. Attachments are hashed, never executed.

## 2. Evidence (`internal/detection`)

The engine records facts. It assigns no scores, has no keyword rules and no
brand lists. Every observation has status `observed_not_a_verdict`.

Observations: Reply-To or Return-Path on another domain, punycode sender or
link host, a display name showing a different address, a header reporting an
authentication failure, a link to an IP address, a URL with a user-name part,
visible link text showing a different host than the destination, HTML forms,
script references, executable attachment types, an executable named like a
document (`invoice.pdf.exe`; ordinary names such as `report.v2.final.pdf` are
not flagged), macro-capable documents, archives, HTML attachments, content that
contradicts the declared type, and text addressed to an automated analyser
(prompt-injection attempts, including text hidden in HTML).

Links are stored as pairs: visible text, normalised destination, original
value and the security wrapper that was removed. Microsoft Safe Links,
Proofpoint URL Defense v2/v3, Google redirects and Barracuda Link Protection
are unwrapped locally. Hosts are lower-cased and converted to punycode.
**No URL is ever requested.**

Indicators are deduplicated and categorised. Clickable links, form targets,
hosts, addresses and attachment hashes are "actionable"; embedded images,
style sheets and tracking pixels are page furniture: they stay in the report
but are hidden by default in the UI, summarised (not listed) for the model and
omitted from the PDF.

### Email authentication

CyberGuard receives a message after delivery. It cannot reproduce SPF (that
needs the connecting SMTP client) and does not perform DKIM cryptographic
verification or DMARC alignment. It reports what the uploaded headers claim:

| Field | Values |
|---|---|
| `reported_result` | the header's value (`pass`, `fail`, `softfail`, `none`, …) or `unavailable` |
| `trust_status` | `untrusted_reported`, `trusted_reported`, `unavailable` |
| `verification_status` | `unable_to_verify`, `unavailable` (`verified` is reserved and never produced today) |
| `alignment_information` | properties the header reported (`header.from`, `smtp.mailfrom`, `header.d`) or `not_reported` |

`trusted_reported` is used only for the topmost `Authentication-Results`
header whose authserv-id is listed in `TRUSTED_AUTHSERV_IDS`. Without that
setting every result is untrusted, because uploaded headers can be forged.
`Received-SPF` is used when no SPF result is otherwise reported. A
`DKIM-Signature` without a reported result is "present, not verified", never a
pass. `Received` headers are kept in order and are not used to name an origin.

## 3. Model request (`internal/openai`)

One Responses API call: fixed instructions, the evidence as a separate JSON
input document, strict JSON-schema output, `store: false`, no tools, and no
optional sampling or reasoning parameters (not every model accepts them).

The input contains subject, bounded text (24 000 bytes per body; HTML reduced
to text), identified evidence items, reported authentication, the backend's
attachment reputation summary and the list of limitations. It never contains
attachment bytes, raw HTML, the raw header block, credentials or the account.
Inputs above 128 000 bytes are rejected before sending.

## 4. Validation

A response becomes a verdict only if all of this holds:

- complete, schema-conformant JSON with no extra fields;
- verdict, severity, confidence and category values from the allowed sets;
  confidence is qualitative only;
- every `evidence_ids` entry exists in the evidence list; the same item cannot
  both support and contradict;
- every quote occurs verbatim in the part it claims to come from;
- a verdict other than `inconclusive` cites at least one item or quote;
- **authentication claims** do not exceed what was reported: no
  `reported_pass` for a mechanism without a reported pass, no ignoring of a
  reported failure, no claim of independent verification;
- **attachment claim** matches the backend summary: detections cannot be
  played down and "no detections" cannot be claimed without a completed lookup
  for every attachment.

Violations give `PROVIDER_INVALID_OUTPUT` or `PROVIDER_UNSUPPORTED_CLAIM` and
the response is discarded. The stored `authentication_assessment` and
`attachment_assessment` are always the backend's values.

Limit of this validation: free-text explanations are not fact-checked
sentence by sentence. The typed fields and references are; prose is shown as
the model's interpretation.

## 5. Outcomes

| `ai_execution.status` | Meaning |
|---|---|
| `completed` | validated verdict stored |
| `not_requested` | no consent for OpenAI |
| `not_configured` | no key, or provider disabled |
| `authentication_failed`, `quota_exceeded`, `rate_limited`, `unsupported_model` | provider refused |
| `invalid_response` | response discarded by validation, truncated or refused |
| `timeout`, `network_error`, `provider_error` | provider unreachable or failing |

In every state except `completed` the analysis is stored as `partial` with all
evidence and VirusTotal results, `ai_assessment` absent and an empty
`final_verdict`. There is no heuristic fallback. The SQL `verdict` column holds
the placeholder `inconclusive` for such rows; history filters and dashboard
statistics exclude them from verdict counts.

## 6. Storage and reports

Bodies and the raw header map are not stored. The evidence list, validated
quotes, authentication table, indicators and reputation results are. PDF and
JSON exports are rendered from the stored row only. PDF text is localised
(en/ru/kk); control and bidirectional-override characters are removed.
