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
Proxy /api from Vite, preserving Origin. No cross-origin credential sharing.

## Authentication

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
calls the model. Successful external calls use completed; failures use unavailable
and preserve static results. Rule-only reports are partial.

Raw bodies, full headers and binary attachments are removed before persistence.
Evidence snippets and metadata can still contain private data.

## History, statistics and export

GET /analyses?page=1&page_size=20&search=...&verdict=phishing&mode=live returns
{items,page,page_size}, newest first. Page sizes are bounded to 100.
GET /analyses/{id} reads; DELETE /analyses/{id} deletes with 204.
GET /analyses/{id}/export?format=pdf|json&lang=en|ru|kk downloads reports.
GET /dashboard/stats?period=7|30|90|all&mode=live|demo returns total_analyses,
verdict_distribution, risk_distribution, activity (date/count map),
activity_series ({date,count} array), common_indicators, common_attack_types and
mitre_frequency ({name,count} arrays).

Every query uses the session owner ID. Foreign IDs yield the same 404 as missing
IDs. Live is the default mode. Exports use cookies, never URL tokens. PDF embeds
Noto Sans under SIL OFL (license bundled in backend/internal/reports/assets).
All Kazakh-specific characters have glyph-coverage tests. Technical evidence
and codes remain verbatim; full localized section labels are pending.

## Validation and remaining work

Build, unit tests and go vet pass from backend/. Tests cover hashing, policy,
synthetic EML/MSG parsing, scoring, unauthorized access, Origin, rate limiting,
demo, PDF/Kazakh glyphs, and mocked OpenAI success/refusal/invalid-output/retries.

The PostgreSQL lifecycle test skips without TEST_DATABASE_URL, which must name an
isolated migrated test database. Migrations, concurrent redemption, persistence,
dashboard queries and end-to-end ownership have not been exercised on PostgreSQL.
No paid OpenAI test ran.

The original complete MVP is not yet finished. Outstanding: database integration
and broader security tests; repository/service extraction from analysis handlers;
date filters/sorting; configurable processing limits;
comprehensive spoofing/lookalike/authentication rules; broader IOC extraction;
richer localized report labels; OpenAI usage and Retry-After support; fully typed
nested OpenAPI schemas; frontend end-to-end verification. Docker stays deferred.


Retention: RETENTION_DAYS=0 disables automatic deletion; positive values enable
hourly cleanup of older reports. SESSION_IDLE_TIMEOUT and SESSION_ABSOLUTE_TIMEOUT
configure session expiry. PostgreSQL cleanup execution remains unverified.
