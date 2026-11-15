# Security model and residual risks

This is the result of a code review with regression tests. It is not a formal
penetration test.

## Authentication and sessions

- Passwords: salted Argon2id (19 MiB, 2 passes, 32-byte output), minimum 12
  characters.
- Session tokens: 256 random bits; PostgreSQL stores only SHA-256 hashes.
  Idle (30 min) and absolute (12 h) timeouts; all sessions are revoked on
  password change.
- Cookies: `HttpOnly`, `SameSite=Strict`, `Secure` when `COOKIE_SECURE=true`.
- CSRF: every non-GET request needs the session-bound token in `X-CSRF-Token`
  and an `Origin` header equal to `APP_ORIGIN`. CORS answers only that origin.
- Sign-in, registration and password change are limited to 10 attempts per
  minute per address; provider operations have a separate bucket.
- Registration is off unless `PUBLIC_REGISTRATION_ENABLED=true` and answers
  identically for new and existing addresses.
- A storage failure during session lookup is reported as a server error, not as
  an expired session.

## Authorisation

Every analysis, export, deletion, re-check and provider setting is selected by
`user_id` from the session. Another user's identifiers return `404`. Tests
cover cross-user reads, deletes, exports, re-checks, settings and statistics.

## Provider credentials

- AES-256-GCM at rest; associated data `provider:v1:<provider>:<user>` prevents
  moving a ciphertext between users or providers.
- `PROVIDER_MASTER_KEY` is validated at startup; saving is refused before any
  database write when it is unusable.
- Keys are never returned by the API, never written to logs, reports or
  exports, and are cleared from the browser form after saving. Nothing is put
  in `localStorage`.
- Outbound requests go only to the configured provider hosts, do not follow
  redirects and have size and time limits. Endpoint overrides are operator
  settings and must be https (http only for localhost).

## Untrusted email content

- Size, depth, part and attachment limits; MSG reads are bounded and recover
  from parser panics.
- No URL from an email is ever requested (no SSRF surface from message
  content), no remote image is loaded, no attachment is executed or unpacked.
- The UI renders all email-derived values as text. Indicators are shown
  defanged and are never links. The API sends
  `Content-Security-Policy: default-src 'none'` and `nosniff`.
- PDF export strips control and bidirectional-override characters.
- SQL uses parameters throughout; history search escapes `LIKE` wildcards.
- Prompt injection: see [ai-providers.md](ai-providers.md#prompt-injection).

## Privacy

- Nothing leaves the server without per-analysis consent, given separately for
  OpenAI and VirusTotal.
- OpenAI receives bounded evidence (subject, text, sender, links, attachment
  names and hashes) with `store: false`. Recipients are not sent.
- VirusTotal receives SHA-256 hashes only.
- Stored reports contain evidence excerpts and can include personal data.
  Deleting a report removes the row; it does not erase database backups or WAL.
  `RETENTION_DAYS` enables automatic deletion.

## Issues found and fixed in this review

| Issue | Fix |
|---|---|
| Storage errors swallowed and returned as bare `INTERNAL_ERROR` | classified, logged with request ID, schema check at startup and in `/health` |
| Saving provider settings shared the sign-in rate limit, so repeated tests could lock a user out of signing in | separate buckets |
| Keys with pasted whitespace were stored and later failed as "network error" | normalised and validated |
| A first save without a key created an "enabled" but unusable row | rejected |
| Incomplete analyses were counted and filtered as "inconclusive" verdicts | excluded from verdict statistics and filters |
| Model could state unverified authentication or clean attachments | typed claims validated against backend evidence |
| NUL characters in malformed mail are rejected by PostgreSQL `jsonb` | removed before storage |
| Session lookup failures signed users out | reported as server error |
| Hidden HTML text could carry instructions unnoticed | checked and recorded as evidence |

## Residual risks

- The application is designed for `localhost`. Before exposing it: HTTPS,
  `COOKIE_SECURE=true`, a reverse proxy with its own limits, and a review of
  rate limiting, which is in-memory, per address and not shared across
  processes or aware of proxies.
- No account lockout, no multi-factor authentication, no audit view.
- DKIM, SPF and DMARC are not independently verified.
- A manipulated or mistaken model can still return a wrong verdict that cites
  real evidence. Free-text explanations are not fact-checked.
- MSG parsing relies on third-party libraries without process isolation.
- Evidence excerpts are stored in clear text in PostgreSQL; protect the
  database and its backups.
- The master key lives in `.env.local`; anyone who can read that file and the
  database can decrypt saved provider keys. There is no key rotation tool.
- Dependencies were not audited for known vulnerabilities in this review.
