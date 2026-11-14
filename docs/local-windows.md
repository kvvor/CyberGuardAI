# Local Windows startup (no Docker)

PostgreSQL 18 service: postgresql-x64-18. Executables:
`D:\Programs\PostgreSQL\bin`. Backend: `127.0.0.1:8080`.

Run these commands in your own PowerShell terminal. Never paste passwords into
chat, command-line arguments, source code, or Git.

```powershell
Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend" -ErrorAction Stop
powershell -NoProfile -File .\scripts\setup-postgres.ps1
```

The script prompts for the administrator password using secure local input. It
creates cyberguard_app only if absent, and cyberguard/cyberguard_test databases
only if absent. Existing role passwords and databases are never reset. An existing
application role requires its current password. Credentials are saved to ignored
.env.local; protect this file using your Windows user permissions.

Apply application migrations, start the backend, or run integration tests:

```powershell
Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend" -ErrorAction Stop
powershell -NoProfile -File .\scripts\backend.ps1 -Mode migrate
powershell -NoProfile -File .\scripts\backend.ps1 -Mode start
# In a second terminal:
powershell -NoProfile -File .\scripts\backend.ps1 -Mode test
```

The test command applies migrations only to cyberguard_test and never drops a
database. Tests create random accounts and delete their own test data. Do not put
real user data in cyberguard_test. The runtime role must not be a superuser.

Provision a user in a terminal after loading the application environment:

```powershell
Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend" -ErrorAction Stop
foreach ($line in Get-Content -LiteralPath .env.local) {
    if ($line -match '^DATABASE_URL=(.+)$') { $env:DATABASE_URL=$Matches[1] }
}
Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend\backend" -ErrorAction Stop
go run ./cmd/cyberguardctl users create --email analyst@example.com --name Analyst
```

The temporary password appears once in that terminal. Deliver it over a trusted
channel. Reset uses `users reset-password --email EMAIL`; disable uses
`users disable --email EMAIL`.

Process configuration examples (no credentials):

```powershell
$env:APP_ADDRESS='127.0.0.1:8080'
$env:APP_ORIGIN='http://localhost:3000'
$env:SESSION_IDLE_TIMEOUT='30m'
$env:SESSION_ABSOLUTE_TIMEOUT='12h'
$env:RETENTION_DAYS='0'
```

Use the frontend proxy for /api. Exact-origin credentialed CORS is supported, but
localhost and 127.0.0.1 are different sites for SameSite cookies. Use the proxy or
consistent hostnames; do not weaken SameSite to compensate.

From backend/, run `go build ./...`, `go test ./...`, `go vet ./...`, and
`go test -race ./...`. On Windows the race detector requires a compatible GCC
toolchain in PATH; the current environment has no gcc, so race execution is
blocked until a compiler is provided. Ordinary builds/tests do not require it.
