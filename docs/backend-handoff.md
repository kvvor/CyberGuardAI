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

See [evidence pipeline](evidence-pipeline.md), [VirusTotal](virustotal.md), and
[OpenAPI](openapi.yaml). Upload EML/MSG or paste email text. Provider credentials
are configured in Settings. OpenAI and VirusTotal have separate per-analysis
consent. New reports use validated model verdicts; missing AI produces partial
results without an AI assessment. Historical records remain readable.

See [checkpoint](rework-checkpoint.md) for exact validation and remaining work.
