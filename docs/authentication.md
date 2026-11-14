# Authentication operations

Create accounts with `cyberguardctl users create --email EMAIL --name NAME`.
The CLI generates a 256-bit temporary secret, prints it once to an interactive
terminal, and stores only an Argon2id hash. Deliver credentials out of band over
a trusted channel. No default credentials exist. Optional website registration
uses POST /api/v1/auth/register when PUBLIC_REGISTRATION_ENABLED=true (disabled
by default), creating active accounts with permanent passwords.

Temporary login consumes the credential under a PostgreSQL row lock and issues
a 15-minute setup session. Activation invalidates all old sessions and establishes
a permanent password and fresh regular session. Expired setup requires
`cyberguardctl users reset-password --email EMAIL`. Disable uses
`cyberguardctl users disable --email EMAIL` and revokes existing sessions.

Passwords accept Unicode passphrases of at least 12 characters and at most 1024
UTF-8 bytes, without composition requirements. Hash verification bounds encoded
Argon2 parameters to avoid excessive work on malformed database values.

Regular sessions default to 30-minute idle and 12-hour absolute expiration.
SESSION_IDLE_TIMEOUT and SESSION_ABSOLUTE_TIMEOUT accept Go duration strings.
Passwords changes invalidate all sessions and require reauthentication.

The HttpOnly cyberguard_session cookie authenticates requests. cyberguard_csrf is
a readable, session-bound CSRF cookie for reload recovery, not an authentication
credential. Send its value as X-CSRF-Token on authenticated mutations. The server
checks both Origin and the stored CSRF hash. Cookies use SameSite=Strict and
COOKIE_SECURE controls HTTPS-only delivery. All secrets remain out of logs.

Database lifecycle/concurrency tests are implemented but require a migrated,
isolated TEST_DATABASE_URL. They have not been run against a live server here.
