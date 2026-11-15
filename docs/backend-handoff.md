# Backend integration handoff

Implementation is in backend/. PostgreSQL is the only persistence backend.
Docker configuration and validation are deferred at the user's request.

## Run without containers

Set DATABASE_URL in the process environment. .env.example lists recognized
variables; .env is not automatically loaded. From backend/:

    go run ./cmd/cyberguardctl migrate
    go run ./cmd/cyberguardctl users create --email analyst@example.com --name Analyst
    go run ./cmd/server

Temporary credentials print only in an interactive terminal. CLI operations
users reset-password and users disable take --email and revoke existing sessions.
Default listener: 127.0.0.1:8080. Default Origin: http://localhost:3000.
Proxy /api from Vite, preserving Origin. Exact-origin credentialed CORS is supported; the same-origin frontend proxy is recommended.

## Authentication

Website registration is optional. Set `PUBLIC_REGISTRATION_ENABLED=true` in the
process environment and restart to enable it; the default is false. The startup
scripts load only database URLs from `.env.local`. Public configuration exposes
the flag as `public_signup` for frontend registration visibility.

POST /api/v1/auth/register accepts JSON email, display_name, password, and
confirm_password. Send the allowed Origin. Emails are trimmed/lowercased; names
are trimmed nonempty UTF-8 without controls (maximum 200 bytes). Passwords follow
the existing 12-character minimum and 1024-byte maximum. Unknown fields, weak
passwords and mismatched confirmation are rejected.

Valid requests return identical 202 `{code: REGISTRATION_ACCEPTED, message: ...}`
acknowledgments for new and existing emails. This does not prove account creation.
Redirect to login: registration creates no session. New accounts are active and
can log in immediately. Duplicate requests never modify existing accounts,
including disabled accounts and accounts awaiting CLI activation.

Errors: REGISTRATION_DISABLED / ORIGIN_INVALID (403), INVALID_REQUEST /
INVALID_REGISTRATION_INPUT (400), UNSUPPORTED_MEDIA_TYPE (415), RATE_LIMITED
(429 with Retry-After). Registration shares the 10-attempt/minute IP login limit,
bounded JSON input, and the global request concurrency limit. Limits are local to
one server process; email ownership verification and distributed anti-bot controls
are not implemented. CLI provisioning, reset, disable and activation remain intact.

Use /api/v1 URLs with credentials: 'include'. Login accepts email/password and
returns user {id,email,display_name}, password_change_required and csrf_token.
Keep CSRF in memory and send X-CSRF-Token on authenticated mutations. Cookies are
HttpOnly, SameSite=Strict; use COOKIE_SECURE=true with HTTPS.

Temporary login consumes the credential immediately. Redirect to /activate-account.
Setup sessions only allow activation and logout. Activation accepts new_password
and confirm_password and returns a rotated regular session. Expired setup requires
CLI reset. For reload recovery, read the cyberguard_csrf cookie (not the HttpOnly session
cookie). /auth/me rejects setup sessions by design.

Regular /auth/me returns user and reproducible session-bound CSRF for reloads.
Password change accepts current_password, new_password, confirm_password.
Success is 204 and requires login again. Logout returns 204.

Errors use {error:{code,message,request_id}}. Translate codes in the frontend.
401 UNAUTHENTICATED covers absent/expired sessions; 403 PASSWORD_CHANGE_REQUIRED
blocks setup access to application features. Invalid credentials use generic
401 INVALID_CREDENTIALS. Mutations require the exact allowed Origin.

## Analysis contract

See [AI provider integration](ai-providers.md) for authenticated provider settings,
encryption setup, consent, new execution metadata, URL observables and hybrid policy.
The provider API supports only OpenAI. Never persist entered keys in browser
storage or cookies. Clear key input after submitting; responses never echo it.

POST /analyses accepts JSON:
{"source_type":"paste","text":"Email body","sender":"sender@example.com","subject":"Review","external_processing_consent":false}

Multipart uploads use file (.eml or .msg, up to 10 MiB) and
external_processing_consent=true only after explicit consent. MSG flags partial
evidence; nested embedded emails are not analyzed.

GET /demo/samples returns six synthetic sample IDs. Create a demo with:
{"source_type":"demo","demo_sample_id":"credentials"}

201 response: {id,mode,created_at,status,report,explanations,recommendations,
ai_assessment?}. report contains verdict, risk_score, risk_level, scoring_version,
attack_types, indicators, iocs, mitre_mappings, limitations, manual_review_required,
ai_status and email metadata (including attachments). Narratives have en/ru/kk
keys. Static narratives are predefined. Demo mode uses predefined_demo and never
calls the model. Successful external calls use completed; new failures use failed or rate_limited (older reports may use unavailable)
and preserve static results. Rule-only reports are partial.

Raw bodies, full headers and binary attachments are removed before persistence.
Evidence snippets and metadata can still contain private data.

## History, statistics and export

GET /analyses?page=1&page_size=20&search=...&verdict=phishing&mode=live returns
{items,total,page,page_size}. sort accepts newest, oldest, risk_desc, risk_asc; date_from/date_to accept UTC dates or RFC3339 timestamps. Page sizes are bounded to 100.
GET /analyses/{id} reads; DELETE /analyses/{id} deletes with 204.
GET /analyses/{id}/export?format=pdf|json&lang=en|ru|kk downloads reports.
GET /dashboard/stats?period=7|30|90|all&mode=live|demo returns total_analyses,
verdict_distribution, risk_distribution, activity (date/count map),
activity_series ({date,count} array), common_indicators, common_attack_types and
mitre_frequency ({name,count} arrays).

Every query uses the session owner ID. Foreign IDs yield the same 404 as missing
IDs. Live is the default mode. Exports use cookies, never URL tokens. PDF embeds
Noto Sans under SIL OFL (license bundled in backend/internal/reports/assets).
All Kazakh-specific characters have glyph-coverage tests. Section labels and verdicts are localized; forensic evidence and technical codes remain verbatim.

## Validation and remaining work

Build, unit tests and go vet pass from backend/. Tests cover hashing, policy,
synthetic EML/MSG parsing, scoring, unauthorized access, Origin, rate limiting,
demo, PDF/Kazakh glyphs, and mocked OpenAI success/refusal/invalid-output/retries.

PostgreSQL 18 was available locally. Migrations were applied to `cyberguard` and
the isolated `cyberguard_test` database. The PostgreSQL lifecycle and HTTP tests
passed against `cyberguard_test`, including concurrent temporary-credential
redemption, activation, password changes, session revocation, EML/MSG/pasted
analysis, history, dashboard aggregates, report export, demo separation, and
two-user ownership checks. Integration tests explicitly reject any database
other than `cyberguard_test`. No paid OpenAI test ran.

The original complete MVP is not yet finished. Outstanding: database integration
and broader security tests; repository/service extraction from analysis handlers;
configurable processing limits;
broader labeled-corpus evaluation;
broader hostile-parser testing; frontend end-to-end verification. Docker stays deferred.


Retention: RETENTION_DAYS=0 disables automatic deletion; positive values enable
hourly cleanup of older reports. SESSION_IDLE_TIMEOUT and SESSION_ABSOLUTE_TIMEOUT
configure session expiry. PostgreSQL cleanup execution remains unverified.

Current validation: PostgreSQL service is running and pg_isready succeeds. Administrator
authentication is pending local secure entry. See local-windows.md for exact setup
and startup commands. The HTTP integration suite was executed against PostgreSQL
and passed. `go build ./...`, `go test ./...`, and `go vet ./...` passed. The race
suite is the remaining validation blocker because this Windows environment has no
GCC toolchain. OpenAPI validation is automated and passing. No paid OpenAI call or
Docker operation was performed.
