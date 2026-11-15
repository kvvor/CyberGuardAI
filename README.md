# CyberGuard AI

Security, made clear.

CyberGuard AI analyses a suspicious email that you upload (`.eml`, `.msg`) or
paste, and tells you whether it looks like phishing and why. It is an analysis
application for individual messages, not a mail gateway.

How a verdict is produced:

1. The Go backend parses the message and extracts technical evidence: sender
   relationships, reported authentication results, links with their visible
   text and real destination, attachments and their SHA-256 hashes.
2. With your consent, attachment **hashes** are looked up at VirusTotal. Files
   are never uploaded.
3. With your consent, the bounded evidence is sent to the OpenAI model you
   selected, which returns a structured assessment.
4. The backend validates that assessment against the evidence (references,
   quotes, authentication and attachment claims). Only a validated assessment
   becomes a verdict. If anything fails, you get the evidence and the real
   failure state, never a substitute verdict.

There are no rule weights and no risk percentage. Verdict, severity and
confidence are a model assessment of the listed evidence, not a probability.
No tool detects every phishing email; treat the result as decision support.

## Run it on Windows 10/11

Requirements: Go, Node.js and a local PostgreSQL. Docker is not needed.
Full step-by-step guide in Russian: [docs/local-windows.md](docs/local-windows.md).

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-postgres.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-backend.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-frontend.ps1
```

Then open <http://localhost:3000>, register, add your OpenAI and VirusTotal
keys in **Settings**, and analyse an email.

After updating the application files, run `scripts\setup.ps1` again (or just
restart with `start-backend.ps1`, which applies pending database migrations).

## Documentation

- [Windows installation (RU)](docs/local-windows.md)
- [Evidence pipeline and verdict validation](docs/evidence-pipeline.md)
- [Provider settings, OpenAI and error states](docs/ai-providers.md)
- [VirusTotal hash lookups, quotas and licence limits](docs/virustotal.md)
- [Security model and residual risks](docs/security.md)
- [Detection evaluation and the regression corpus](docs/evaluation.md)
- [Authentication](docs/authentication.md)
- [API contract](docs/openapi.yaml)
- [Verification status and known limitations](docs/rework-checkpoint.md)

## Development checks

```powershell
# backend (from backend\)
go build ./...
go vet ./...
go test ./...                                  # unit tests; PostgreSQL tests are skipped
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ..\scripts\backend.ps1 -Mode test   # with cyberguard_test

# frontend (from frontend\)
npm.cmd ci
npm.cmd run test
npm.cmd run lint
npm.cmd run build
```

Automated tests use local mock providers and never call OpenAI or VirusTotal.
`go run ./cmd/mockproviders` (from `backend\`) starts the same mocks for manual
end-to-end testing without real keys; see [docs/ai-providers.md](docs/ai-providers.md).
